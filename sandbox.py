import uuid
import os
import shutil
import tempfile
import subprocess
import json
import time
from pathlib import Path
from typing import Any, List, Optional

_DOCKER_AVAILABLE_CACHE = None

def is_docker_available() -> bool:
    global _DOCKER_AVAILABLE_CACHE
    if _DOCKER_AVAILABLE_CACHE is not None:
        return _DOCKER_AVAILABLE_CACHE

    if not shutil.which("docker"):
        _DOCKER_AVAILABLE_CACHE = False
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=1.5)
        _DOCKER_AVAILABLE_CACHE = (res.returncode == 0)
    except Exception:
        _DOCKER_AVAILABLE_CACHE = False
    return _DOCKER_AVAILABLE_CACHE


def build_docker_image_if_missing():
    try:
        res = subprocess.run(["docker", "images", "-q", "agentic-security-platform"], capture_output=True, text=True)
        if not res.stdout.strip():
            print("Building agentic-security-platform Docker image for sandbox...")
            subprocess.run(["docker", "build", "-t", "agentic-security-platform", "."], check=True)
    except Exception as e:
        print(f"Failed to check/build Docker image: {e}")

class EphemeralSandbox:
    def __init__(self) -> None:
        self.scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        self.timestamp = time.time()
        self.docker_available = is_docker_available()
        if self.docker_available:
            build_docker_image_if_missing()

    def run_git_scan(self, repo_url: str, branch: str, enabled_providers: Optional[List[str]] = None, platform_instance: Any = None, scan_profile: str = "comprehensive") -> dict[str, Any]:
        git_temp_dir = Path(tempfile.mkdtemp(prefix=f"git_{self.scan_id}_"))
        try:
            cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(git_temp_dir)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
            if res.returncode != 0:
                return self._fallback_error(f"Failed to clone repository {repo_url} (branch: {branch}). Git error: {res.stderr}")
            
            repo_name = repo_url.split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            if not repo_name:
                repo_name = "repository"
                
            report = self.run_scan(str(git_temp_dir), enabled_providers, platform_instance, scan_profile=scan_profile)
            self._sanitize_findings(report, repo_name, git_temp_dir)
            return report
        except subprocess.TimeoutExpired:
            return self._fallback_error("Git clone operation timed out after 30s")
        except Exception as e:
            return self._fallback_error(f"Git sandbox scan exception: {e}")
        finally:
            if git_temp_dir.exists():
                shutil.rmtree(git_temp_dir)

    def run_scan(self, source_path: str, enabled_providers: Optional[List[str]] = None, platform_instance: Any = None, scan_profile: str = "comprehensive") -> dict[str, Any]:
        resolved_path = Path(source_path).resolve()
        if not resolved_path.exists():
            return {
                "scan_id": self.scan_id,
                "timestamp": self.timestamp,
                "summary": {
                    "finding_count": 0,
                    "provider_count": 4,
                    "risk_level": "low",
                    "covered_cwes": [],
                    "warnings": ["Source path does not exist"]
                },
                "findings": []
            }

        if self.docker_available:
            return self._run_in_docker(resolved_path, enabled_providers, scan_profile=scan_profile)
        else:
            return self._run_in_host_isolation(resolved_path, enabled_providers, platform_instance, scan_profile=scan_profile)

    def _run_in_docker(self, resolved_path: Path, enabled_providers: Optional[List[str]], scan_profile: str = "comprehensive") -> dict[str, Any]:
        temp_out_dir = Path(tempfile.mkdtemp(prefix=f"out_{self.scan_id}_"))
        report_file_host = temp_out_dir / "report.json"
        
        try:
            # Load security policy to configure docker parameters
            from agentic_security_platform import load_security_policy
            policy = load_security_policy(resolved_path)
            sandbox_policy = policy.get("sandbox", {})
            
            network_mode = "none" if not sandbox_policy.get("network", False) else "bridge"
            cpus_val = str(sandbox_policy.get("cpu", "1.0"))
            mem_val = str(sandbox_policy.get("memory", "512m")).lower().replace("b", "")
            timeout_val = float(sandbox_policy.get("timeout", 60.0))
            
            cmd = [
                "docker", "run", "--rm",
                "--network", network_mode,
                "--cpus", cpus_val,
                "--memory", mem_val,
                "-v", f"{resolved_path}:/scan_target:ro",
                "-v", f"{temp_out_dir}:/scan_output:rw",
                "agentic-security-platform",
                "python", "agentic_security_platform.py", "--no-sandbox", "--scan-profile", scan_profile, "/scan_target", "--output", "/scan_output/report.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_val)
            
            if report_file_host.exists():
                try:
                    report_data = json.loads(report_file_host.read_text(encoding="utf-8"))
                    report_data["scan_id"] = self.scan_id
                    report_data["timestamp"] = self.timestamp
                    self._sanitize_findings(report_data, resolved_path.name, resolved_path)
                    return report_data
                except Exception as e:
                    return self._fallback_error(f"Failed to parse report: {e}")
            else:
                return self._fallback_error(f"Docker sandbox execution failed or timeout. Stderr: {result.stderr}")
        except subprocess.TimeoutExpired:
            return self._fallback_error(f"Docker sandbox execution timed out after {timeout_val}s")
        except Exception as e:
            return self._fallback_error(f"Docker sandbox execution exception: {e}")
        finally:
            if temp_out_dir.exists():
                shutil.rmtree(temp_out_dir)

    def _run_in_host_isolation(self, resolved_path: Path, enabled_providers: Optional[List[str]], platform_instance: Any, scan_profile: str = "comprehensive") -> dict[str, Any]:
        temp_dir = Path(tempfile.mkdtemp(prefix=f"sandbox_{self.scan_id}_"))
        temp_repo_path = temp_dir / "repo"
        
        try:
            self._copy_source_files(resolved_path, temp_repo_path)
            
            if not platform_instance:
                from agentic_security_platform import AgenticSecurityPlatform
                platform_instance = AgenticSecurityPlatform()
                
            # If the source_path is a file, we run review on the file copy itself, not a directory
            scan_target = temp_repo_path
            if resolved_path.is_file():
                scan_target = temp_repo_path / resolved_path.name

            report = platform_instance.run_review(str(scan_target), enabled_providers=enabled_providers, use_sandbox=False, scan_profile=scan_profile)
            
            report["scan_id"] = self.scan_id
            report["timestamp"] = self.timestamp
            
            self._sanitize_findings(report, resolved_path.name, resolved_path)
            return report
        except Exception as e:
            return self._fallback_error(f"Host sandbox isolation execution exception: {e}")
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    def _copy_source_files(self, src: Path, dest: Path):
        from agentic_security_platform import IGNORE_DIRS, SUPPORTED_EXTENSIONS, MAX_FILE_SIZE_BYTES
        dest.mkdir(parents=True, exist_ok=True)
        
        def is_scannable_or_config(path: Path) -> bool:
            ext = path.suffix.lower()
            name = path.name.lower()
            if ext in SUPPORTED_EXTENSIONS:
                return True
            # Allow IaC, secrets, SCA files, and security policy files to be copied to sandbox
            is_iac_or_dep_config = (
                ext in [".tf", ".yaml", ".yml", ".json", ".lock", ".txt", ".mod", ".sum", ".dockerfile"] or
                name in ["dockerfile", "jenkinsfile", "security.yaml", "security.yml", ".security.yaml", ".security.yml", "requirements.txt"]
            )
            return is_iac_or_dep_config

        if src.is_file():
            if is_scannable_or_config(src) and src.stat().st_size <= MAX_FILE_SIZE_BYTES:
                shutil.copy2(src, dest / src.name)
            return

        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            
            rel_dir = Path(dirpath).relative_to(src)
            dest_dir = dest / rel_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for filename in filenames:
                file_path = Path(dirpath) / filename
                if is_scannable_or_config(file_path):
                    try:
                        if file_path.stat().st_size <= MAX_FILE_SIZE_BYTES:
                            shutil.copy2(file_path, dest_dir / filename)
                    except Exception:
                        pass

    def _sanitize_findings(self, report: dict[str, Any], original_name: str, repo_path: Path):
        findings = report.get("findings", [])
        from cwe_helper import get_remediation
        import re
        import hashlib
        
        # Determine if the repository/asset is internet-exposed
        internet_exposed = self._is_internet_exposed(repo_path)
        
        # 1. Sanitize file paths, delete code, and add base remediations
        for f in findings:
            if "code" in f:
                del f["code"]
            if "file" in f:
                file_str = f["file"]
                file_path = Path(file_str)
                parts = list(file_path.parts)
                
                matched_idx = -1
                for idx, part in enumerate(parts):
                    if part == "repo" or part == "scan_target" or part.startswith("git_") or part.startswith("sandbox_"):
                        matched_idx = idx
                
                if matched_idx != -1:
                    f["file"] = str(Path(original_name) / Path(*parts[matched_idx+1:]))
                else:
                    f["file"] = file_str
            
            cwe_id = f.get("cwe", "CWE-999")
            f["cve"] = f.get("cve", "N/A")
            f["remediation"] = get_remediation(cwe_id)

        # 2. Group findings for deduplication
        grouped: dict[tuple[str, Any, str], list[dict[str, Any]]] = {}
        for f in findings:
            file_name = f.get("file", "unknown")
            line = f.get("line")
            cwe_id = f.get("cwe", "CWE-999")
            key = (file_name, line, cwe_id)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        deduplicated = []
        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for (file_name, line, cwe_id), group in grouped.items():
            # Pick representative base (highest severity, then longest description)
            group.sort(key=lambda x: (severity_priority.get(x.get("severity", "low").lower(), 1), len(x.get("description", ""))), reverse=True)
            base = group[0].copy()
            
            # Determine all detectors
            detectors = []
            for f in group:
                det = self._get_detector_name(f)
                if det not in detectors:
                    detectors.append(det)
            detectors.sort()
            
            # Calculate combined confidence
            confidence = self._calculate_combined_confidence(detectors)
            
            # Extract code line content for sink
            sink = ""
            if line is not None:
                try:
                    if repo_path.is_file():
                        target_file = repo_path
                    else:
                        parts = Path(file_name).parts
                        if len(parts) > 1:
                            sub_path = Path(*parts[1:])
                        else:
                            sub_path = Path(file_name)
                        target_file = repo_path / sub_path
                        
                    if target_file.exists():
                        lines = target_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                        if 1 <= line <= len(lines):
                            sink = lines[line - 1].strip()
                except Exception:
                    pass
            
            # Generate stable normalized location
            clean_sink = re.sub(r'#.*$', '', sink)
            clean_sink = re.sub(r'//.*$', '', clean_sink)
            normalized_code_location = "".join(clean_sink.split()).lower()
            if not normalized_code_location:
                normalized_code_location = f"line-{line}"
                
            # Compute spec-compliant SHA-256 fingerprint
            content_str = f"{original_name}:{file_name}:{cwe_id}:{sink}:{normalized_code_location}"
            fingerprint = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
            
            # Calculate CVSS and Exploitability
            cvss = self._get_cvss_base(base)
            expl_str = self._get_exploitability(base)
            expl_factor = 1.0 if expl_str == "HIGH" else (0.85 if expl_str == "MEDIUM" else 0.70)
            
            # Calculate Reachability
            reachable = self._is_reachable(base, repo_path)
            reach_factor = 1.0 if reachable else 0.5
            
            # Combined factors
            conf_factor = confidence / 100.0
            exposure_factor = 1.0 if internet_exposed else 0.7
            
            # Calculate final risk score
            risk_score = cvss * expl_factor * reach_factor * conf_factor * exposure_factor
            risk_score = round(risk_score, 1)
            
            # Determine Risk Severity
            if risk_score >= 9.0:
                risk_severity = "critical"
            elif risk_score >= 7.0:
                risk_severity = "high"
            elif risk_score >= 4.0:
                risk_severity = "medium"
            else:
                risk_severity = "low"
                
            base["detected_by"] = detectors
            base["confidence"] = confidence
            base["fingerprint"] = fingerprint
            
            # Enrich findings with risk parameters
            base["cvss"] = cvss
            base["reachable"] = "YES" if reachable else "NO"
            base["internet_exposed"] = "YES" if internet_exposed else "NO"
            base["exploitability"] = expl_str
            base["risk_score"] = risk_score
            base["severity"] = risk_severity
            
            deduplicated.append(base)

        report["findings"] = deduplicated
        
        # Load security policy and run gate check
        from agentic_security_platform import load_security_policy
        policy = load_security_policy(repo_path)
        
        critical_count = sum(1 for f in deduplicated if f.get("severity") == "critical")
        high_count = sum(1 for f in deduplicated if f.get("severity") == "high")
        medium_count = sum(1 for f in deduplicated if f.get("severity") == "medium")
        low_count = sum(1 for f in deduplicated if f.get("severity") == "low")
        
        counts = {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        }
        
        fail_on = policy.get("fail_on", ["critical", "high"])
        thresholds = policy.get("thresholds", {"critical": 0, "high": 0})
        
        gate_failed = False
        reasons = []
        
        for sev, limit in thresholds.items():
            count = counts.get(sev.lower(), 0)
            if count > limit:
                gate_failed = True
                reasons.append(f"{sev.upper()} findings count ({count}) exceeds threshold ({limit})")
                
        for sev in fail_on:
            sev_lower = sev.lower()
            if sev_lower not in thresholds:
                count = counts.get(sev_lower, 0)
                if count > 0:
                    gate_failed = True
                    reasons.append(f"Security policy fails on {sev.upper()} severity ({count} found)")
                    
        report["gate_status"] = "SECURITY GATE FAILED" if gate_failed else "PASS"
        report["gate_reasons"] = reasons
        report["policy"] = policy
        
        # Update summary finding_count & risk level
        if "summary" in report:
            report["summary"]["finding_count"] = len(deduplicated)
            if gate_failed:
                report["summary"]["risk_level"] = "high"

    def _is_internet_exposed(self, repo_path: Path) -> bool:
        try:
            if repo_path.is_file():
                content = repo_path.read_text(encoding="utf-8", errors="ignore").lower()
                if "expose " in content:
                    return True
                if any(fw in content for fw in ["fastapi", "flask", "django", "express", "spring"]):
                    return True
                return False
            
            for dirpath, _, filenames in os.walk(repo_path):
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    if file_path.suffix.lower() in [".py", ".json", ".yml", ".yaml", ".dockerfile"] or file_path.name.lower() == "dockerfile":
                        try:
                            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                            if "expose " in content:
                                return True
                            if "ports:" in content:
                                return True
                            if any(fw in content for fw in ["fastapi", "flask", "django", "express", "spring"]):
                                return True
                        except Exception:
                            pass
        except Exception:
            pass
        return False

    def _is_reachable(self, finding: dict[str, Any], repo_path: Path) -> bool:
        cwe_id = finding.get("cwe", "CWE-999")
        file_name = finding.get("file", "")
        
        if cwe_id == "CWE-798":
            return True
            
        if cwe_id == "CWE-1104":
            pkg = finding.get("package", "").lower()
            if not pkg:
                return True
            try:
                if repo_path.is_file():
                    content = repo_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if pkg in content or f"import {pkg}" in content:
                        return True
                    return False
                
                for dirpath, _, filenames in os.walk(repo_path):
                    for filename in filenames:
                        file_path = Path(dirpath) / filename
                        if file_path.suffix.lower() in [".py", ".js", ".go", ".java"]:
                            try:
                                content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
                                if pkg in content or f"import {pkg}" in content or f"require('{pkg}')" in content or f'require("{pkg}")' in content:
                                    return True
                            except Exception:
                                pass
                return False
            except Exception:
                return True
                
        rule = finding.get("rule", "").lower()
        if "open-security-group" in rule or "public-s3" in rule or "exposed-socket" in rule:
            return True
            
        return True

    def _get_cvss_base(self, finding: dict[str, Any]) -> float:
        cwe_id = finding.get("cwe", "CWE-999")
        if "cvss" in finding:
            try:
                return float(finding["cvss"])
            except ValueError:
                pass
                
        mapping = {
            "CWE-77": 9.8,
            "CWE-78": 9.8,
            "CWE-79": 6.1,
            "CWE-89": 9.8,
            "CWE-94": 9.8,
            "CWE-798": 9.8,
            "CWE-295": 6.5,
            "CWE-502": 9.8,
            "CWE-1104": 7.5,
            "CWE-250": 7.2,
            "CWE-284": 8.5,
            "CWE-311": 5.3,
        }
        return mapping.get(cwe_id, 6.5)

    def _get_exploitability(self, finding: dict[str, Any]) -> str:
        cwe_id = finding.get("cwe", "CWE-999")
        high_cwes = ["CWE-798", "CWE-284"]
        medium_cwes = ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-1104"]
        
        if cwe_id in high_cwes:
            return "HIGH"
        elif cwe_id in medium_cwes:
            return "MEDIUM"
        return "LOW"

    def _get_detector_name(self, finding: dict[str, Any]) -> str:
        rule = finding.get("rule", "").lower()
        f_type = finding.get("type", "").upper()
        
        if rule.startswith("ast-"):
            return "AST"
        elif rule.startswith("bandit-"):
            return "Bandit"
        elif rule.startswith("codeql-") or rule == "codeql-integrated":
            return "CodeQL"
        elif f_type == "SCA" or rule.startswith("sca-"):
            return "SCA"
        elif f_type == "SECRET" or rule.endswith("-secret-key") or rule == "gitleaks-secret":
            return "SecretScanner"
        elif f_type == "IAC":
            return "IaCScanner"
        elif rule.startswith("ai-") or "openai" in rule or "claude" in rule or "ollama" in rule or "cursor" in rule:
            prov = rule.split("ai-")[-1] if rule.startswith("ai-") else rule
            if "openai" in prov:
                return "AI (OpenAI)"
            elif "claude" in prov:
                return "AI (Claude)"
            elif "ollama" in prov:
                return "AI (Ollama)"
            elif "cursor" in prov:
                return "AI (Cursor)"
            return "AI"
        else:
            if "ai" in rule:
                return "AI"
            return "AST"

    def _calculate_combined_confidence(self, detectors: list[str]) -> int:
        confidences = {
            "AST": 0.70,
            "Bandit": 0.80,
            "CodeQL": 0.85,
            "AI (OpenAI)": 0.65,
            "AI (Claude)": 0.70,
            "AI (Ollama)": 0.55,
            "AI (Cursor)": 0.60,
            "AI": 0.60,
            "SecretScanner": 0.90,
            "SCA": 0.90,
            "IaCScanner": 0.85
        }
        
        prod = 1.0
        for d in detectors:
            conf = confidences.get(d, 0.60)
            prod *= (1.0 - conf)
            
        combined = 1.0 - prod
        return int(round(combined * 100))

    def _fallback_error(self, message: str) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "summary": {
                "finding_count": 0,
                "provider_count": 4,
                "risk_level": "low",
                "covered_cwes": [],
                "warnings": [message]
            },
            "findings": []
        }
