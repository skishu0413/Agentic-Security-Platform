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
            self._sanitize_findings(report, repo_name)
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
            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--cpus", "1.0",
                "--memory", "512m",
                "-v", f"{resolved_path}:/scan_target:ro",
                "-v", f"{temp_out_dir}:/scan_output:rw",
                "agentic-security-platform",
                "python", "agentic_security_platform.py", "--no-sandbox", "--scan-profile", scan_profile, "/scan_target", "--output", "/scan_output/report.json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60.0)
            
            if report_file_host.exists():
                try:
                    report_data = json.loads(report_file_host.read_text(encoding="utf-8"))
                    report_data["scan_id"] = self.scan_id
                    report_data["timestamp"] = self.timestamp
                    self._sanitize_findings(report_data, resolved_path.name)
                    return report_data
                except Exception as e:
                    return self._fallback_error(f"Failed to parse report: {e}")
            else:
                return self._fallback_error(f"Docker sandbox execution failed or timeout. Stderr: {result.stderr}")
        except subprocess.TimeoutExpired:
            return self._fallback_error("Docker sandbox execution timed out after 60s")
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
            
            self._sanitize_findings(report, resolved_path.name)
            return report
        except Exception as e:
            return self._fallback_error(f"Host sandbox isolation execution exception: {e}")
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    def _copy_source_files(self, src: Path, dest: Path):
        from agentic_security_platform import IGNORE_DIRS, SUPPORTED_EXTENSIONS, MAX_FILE_SIZE_BYTES
        dest.mkdir(parents=True, exist_ok=True)
        
        if src.is_file():
            if src.suffix.lower() in SUPPORTED_EXTENSIONS and src.stat().st_size <= MAX_FILE_SIZE_BYTES:
                shutil.copy2(src, dest / src.name)
            return

        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
            
            rel_dir = Path(dirpath).relative_to(src)
            dest_dir = dest / rel_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for filename in filenames:
                file_path = Path(dirpath) / filename
                if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    try:
                        if file_path.stat().st_size <= MAX_FILE_SIZE_BYTES:
                            shutil.copy2(file_path, dest_dir / filename)
                    except Exception:
                        pass

    def _sanitize_findings(self, report: dict[str, Any], original_name: str):
        findings = report.get("findings", [])
        from cwe_helper import get_remediation, generate_fingerprint
        
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
            rule = f.get("rule", "unknown")
            file_name = f.get("file", "unknown")
            line = f.get("line")
            
            f["cve"] = f.get("cve", "N/A")
            f["remediation"] = get_remediation(cwe_id)
            f["fingerprint"] = generate_fingerprint(file_name, line, rule, cwe_id)

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
