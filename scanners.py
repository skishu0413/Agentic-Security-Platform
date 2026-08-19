from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import re
import math
import tempfile
from pathlib import Path
from typing import Any


class ScannerIntegration:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def run_bandit(self) -> list[dict[str, Any]]:
        bandit_path = shutil.which("bandit")
        if not bandit_path:
            # Fallback 1: Check project workspace .venv folder relative to this script
            candidate_project = Path(__file__).parent / ".venv" / "bin" / "bandit"
            if candidate_project.exists() and os.access(candidate_project, os.X_OK):
                bandit_path = str(candidate_project)
            else:
                # Fallback 2: Check same folder as active python executable
                executable_dir = Path(sys.executable).parent
                candidate_exec = executable_dir / "bandit"
                if candidate_exec.exists() and os.access(candidate_exec, os.X_OK):
                    bandit_path = str(candidate_exec)
        
        if not bandit_path:
            return []

        result = subprocess.run(
            [
                bandit_path, "-r", str(self.root), "-f", "json",
                "-x", ".git,.github,.venv,venv,env,node_modules,__pycache__,.pytest_cache,.codeql,.idea,.vscode,dist,build,assets,out,target,bin,obj,.next,.nuxt,.cache,coverage,htmlcov"
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            stdout = result.stdout or ""
            if "{" in stdout and "}" in stdout:
                stdout = stdout[stdout.index("{"):stdout.rindex("}") + 1]
            payload = json.loads(stdout or "{}")
            return payload.get("results", [])
        except json.JSONDecodeError:
            return []

    def run_codeql(self) -> list[dict[str, Any]]:
        if shutil.which("codeql") is None:
            return []
        result = subprocess.run(
            ["codeql", "database", "create", str(self.root / ".codeql"), "--source-root", str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        return [{"tool": "codeql", "status": "database-created"}]


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = - sum([p * math.log(p, 2) for p in probabilities])
    return entropy

def mask_secret(secret: str, provider: str) -> str:
    if len(secret) <= 8:
        return "********"
    if provider == "github" and secret.startswith("ghp_"):
        return "ghp_" + "*" * (len(secret) - 4)
    if provider == "openai" and secret.startswith("sk-proj-"):
        return "sk-proj-" + "*" * (len(secret) - 8)
    if provider == "openai" and secret.startswith("sk-"):
        return "sk-" + "*" * (len(secret) - 3)
    if provider == "anthropic" and secret.startswith("sk-ant-sid01-"):
        return "sk-ant-sid01-" + "*" * (len(secret) - 13)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

class SecretScanner:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.gitleaks_path = shutil.which("gitleaks")

    def scan(self) -> list[dict[str, Any]]:
        if self.gitleaks_path:
            return self._run_gitleaks()
        else:
            return self._run_regex_fallback()

    def _run_gitleaks(self) -> list[dict[str, Any]]:
        temp_report = Path(tempfile.mktemp(prefix="gitleaks_report_", suffix=".json"))
        try:
            cmd = [
                self.gitleaks_path, "detect",
                "--no-git",
                "--report-format", "json",
                "--report-path", str(temp_report),
                "--source", str(self.root)
            ]
            subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if temp_report.exists() and temp_report.stat().st_size > 0:
                try:
                    findings_raw = json.loads(temp_report.read_text(encoding="utf-8"))
                    results = []
                    for f in findings_raw:
                        rule_id = f.get("RuleID", "generic").lower()
                        provider = rule_id.split("-")[0] if "-" in rule_id else rule_id
                        secret_val = f.get("Secret", "")
                        masked = mask_secret(secret_val, provider)
                        
                        results.append({
                            "type": "SECRET",
                            "provider": provider,
                            "file": f.get("File", ""),
                            "line": f.get("StartLine", 1),
                            "secret": masked,
                            "severity": "critical",
                            "rule": f.get("RuleID", "gitleaks-secret"),
                            "cwe": "CWE-798",
                            "description": f"Exposed secret detected: {f.get('Description', 'Hardcoded credential')}"
                        })
                    return results
                except Exception:
                    pass
            return []
        finally:
            if temp_report.exists():
                os.remove(temp_report)

    def _run_regex_fallback(self) -> list[dict[str, Any]]:
        from agentic_security_platform import SUPPORTED_EXTENSIONS, IGNORE_DIRS, MAX_FILE_SIZE_BYTES
        
        patterns = {
            "aws": re.compile(r'\b(AKIA|ASIA|AGPA|AIDA|AROA|ASCA)[A-Z0-9]{16}\b'),
            "github": re.compile(r'\bghp_[A-Za-z0-9_]{36,255}\b'),
            "openai": re.compile(r'\bsk-(?:proj-)?[a-zA-Z0-9]{32,}\b'),
            "anthropic": re.compile(r'\bsk-ant-sid01-[a-zA-Z0-9-_]{93}\b'),
            "google": re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
            "slack": re.compile(r'\bxox[baprs]-[0-9]{10,12}-[a-zA-Z0-9]{24,48}\b'),
            "jwt": re.compile(r'\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\b'),
            "ssh_key": re.compile(r'-----BEGIN[A-Z0-9\s_]+PRIVATE\s+KEY-----'),
            "db_url": re.compile(r'\b(?:mongodb|postgres|postgresql|mysql|mssql|redis|sqlite|oracle):\/\/[A-Za-z0-9-_~%]+:[A-Za-z0-9-_~%]+@[A-Za-z0-9.-]+:[0-9]+\b'),
            "env_assignment": re.compile(r'\b(?:API_KEY|SECRET|PASSWORD|PASS|TOKEN|CREDENTIALS|PWD)\s*=\s*[\'"]?([A-Za-z0-9-_~!@#$%^&*()_+]{16,})[\'"]?', re.IGNORECASE)
        }

        results = []
        
        def scan_file(file_path: Path):
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    return
                
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                
                for idx, line in enumerate(lines, start=1):
                    for provider, pattern in patterns.items():
                        if provider == "env_assignment":
                            match = pattern.search(line)
                            if match:
                                value = match.group(1)
                                if calculate_entropy(value) > 3.0:
                                    masked = mask_secret(value, "generic")
                                    results.append({
                                        "type": "SECRET",
                                        "provider": "generic",
                                        "file": str(file_path),
                                        "line": idx,
                                        "secret": masked,
                                        "severity": "critical",
                                        "rule": "generic-secret-entropy",
                                        "cwe": "CWE-798",
                                        "description": "Detected high-entropy credential assignment in .env file or configuration."
                                    })
                        else:
                            match = pattern.search(line)
                            if match:
                                secret_val = match.group(0)
                                masked = mask_secret(secret_val, provider)
                                results.append({
                                    "type": "SECRET",
                                    "provider": provider,
                                    "file": str(file_path),
                                    "line": idx,
                                    "secret": masked,
                                    "severity": "critical",
                                    "rule": f"{provider}-secret-key",
                                    "cwe": "CWE-798",
                                    "description": f"Detected hardcoded {provider.upper()} access key/secret."
                                })
            except Exception:
                pass

        if self.root.is_file():
            scan_file(self.root)
        else:
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    if file_path.suffix.lower() in SUPPORTED_EXTENSIONS or file_path.name.lower() == ".env" or file_path.suffix.lower() == ".env":
                        scan_file(file_path)
                        
        return results


def parse_version(v_str: str) -> list[int]:
    if v_str.startswith('v'):
        v_str = v_str[1:]
    v_clean = v_str.split('-')[0].split('+')[0]
    digits = re.findall(r'\d+', v_clean)
    return [int(d) for d in digits[:3]]

def version_matches_constraint(installed: str, constraint: str) -> bool:
    try:
        inst_parts = parse_version(installed)
        if not inst_parts:
            return False
        
        match = re.match(r'^([<>=]+)\s*([\d.]+)', constraint.strip())
        if not match:
            return False
        
        op, limit_str = match.groups()
        limit_parts = parse_version(limit_str)
        
        while len(inst_parts) < 3: inst_parts.append(0)
        while len(limit_parts) < 3: limit_parts.append(0)
        
        if op == "<":
            return inst_parts < limit_parts
        elif op == "<=":
            return inst_parts <= limit_parts
        elif op == ">":
            return inst_parts > limit_parts
        elif op == ">=":
            return inst_parts >= limit_parts
        elif op == "==":
            return inst_parts == limit_parts
    except Exception:
        pass
    return False

class ScaScanner:
    LOCAL_VULN_DB = [
        {
            "package": "log4j-core",
            "constraint": "<2.15.0",
            "cve": "CVE-2021-44228",
            "severity": "critical",
            "fix": "Upgrade dependency to version 2.15.0 or later"
        },
        {
            "package": "spring-core",
            "constraint": "<5.3.18",
            "cve": "CVE-2022-22965",
            "severity": "critical",
            "fix": "Upgrade dependency to version 5.3.18 or later"
        },
        {
            "package": "lodash",
            "constraint": "<4.17.21",
            "cve": "CVE-2020-8203",
            "severity": "high",
            "fix": "Upgrade dependency to version 4.17.21 or later"
        },
        {
            "package": "requests",
            "constraint": "<2.31.0",
            "cve": "CVE-2023-32681",
            "severity": "medium",
            "fix": "Upgrade dependency to version 2.31.0 or later"
        },
        {
            "package": "urllib3",
            "constraint": "<1.26.17",
            "cve": "CVE-2023-43804",
            "severity": "high",
            "fix": "Upgrade dependency to version 1.26.17 or later"
        },
        {
            "package": "django",
            "constraint": "<3.2.20",
            "cve": "CVE-2023-41164",
            "severity": "high",
            "fix": "Upgrade dependency to version 3.2.20 or later"
        },
        {
            "package": "express",
            "constraint": "<4.19.2",
            "cve": "CVE-2024-29025",
            "severity": "medium",
            "fix": "Upgrade dependency to version 4.19.2 or later"
        },
        {
            "package": "minimist",
            "constraint": "<1.2.6",
            "cve": "CVE-2021-44906",
            "severity": "high",
            "fix": "Upgrade dependency to version 1.2.6 or later"
        },
        {
            "package": "cryptography",
            "constraint": "<41.0.0",
            "cve": "CVE-2023-23931",
            "severity": "high",
            "fix": "Upgrade dependency to version 41.0.0 or later"
        },
        {
            "package": "openssl",
            "constraint": "<3.0.7",
            "cve": "CVE-2022-3602",
            "severity": "high",
            "fix": "Upgrade dependency to version 3.0.7 or later"
        }
    ]

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.osv_scanner_path = shutil.which("osv-scanner")
        self.all_dependencies: list[dict[str, Any]] = []

    def scan(self) -> list[dict[str, Any]]:
        if self.osv_scanner_path:
            return self._run_osv_scanner()
        else:
            return self._run_local_fallback()

    def _run_osv_scanner(self) -> list[dict[str, Any]]:
        try:
            cmd = [self.osv_scanner_path, "--format", "json", "-r", str(self.root)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.stdout:
                data = json.loads(result.stdout)
                results = []
                for res in data.get("results", []):
                    source = res.get("source", {}).get("path", "")
                    for pkg in res.get("packages", []):
                        name = pkg.get("package", {}).get("name", "")
                        version = pkg.get("package", {}).get("version", "")
                        if name and version:
                            self.all_dependencies.append({
                                "package": name,
                                "version": version,
                                "file": source
                            })
                        for vuln in pkg.get("vulnerabilities", []):
                            cve_ids = [alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")]
                            cve = cve_ids[0] if cve_ids else vuln.get("id", "GHSA-unknown")
                            severity = "high"
                            if "critical" in vuln.get("summary", "").lower() or "critical" in vuln.get("details", "").lower():
                                severity = "critical"
                            results.append({
                                "type": "SCA",
                                "package": name,
                                "installed": version,
                                "affected": "Matched OSV database",
                                "cve": cve,
                                "fix": "Upgrade dependency",
                                "severity": severity,
                                "file": source,
                                "line": 1,
                                "rule": f"sca-{name}",
                                "cwe": "CWE-1104",
                                "description": f"Vulnerable dependency {name} ({version}) detected via OSV: {vuln.get('summary', 'Vulnerable package version.')}"
                            })
                return results
        except Exception:
            pass
        return self._run_local_fallback()

    def _run_local_fallback(self) -> list[dict[str, Any]]:
        from agentic_security_platform import IGNORE_DIRS
        
        results = []
        
        supported_files = {
            "requirements.txt": self._parse_requirements_txt,
            "package-lock.json": self._parse_package_lock_json,
            "pom.xml": self._parse_pom_xml,
            "go.mod": self._parse_go_mod,
            "cargo.lock": self._parse_cargo_lock,
            "gemfile.lock": self._parse_gemfile_lock,
            "composer.lock": self._parse_composer_lock,
            "poetry.lock": self._parse_poetry_lock,
            "pipfile.lock": self._parse_pipfile_lock,
            "yarn.lock": self._parse_yarn_lock,
            "pnpm-lock.yaml": self._parse_pnpm_lock_yaml,
            "build.gradle": self._parse_build_gradle
        }

        def process_dependency_file(file_path: Path):
            name = file_path.name.lower()
            if name not in supported_files:
                return
            
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                parser = supported_files[name]
                parsed_packages = parser(content)
                
                for pkg_name, version, line in parsed_packages:
                    self.all_dependencies.append({
                        "package": pkg_name,
                        "version": version,
                        "file": str(file_path)
                    })
                    for vuln in self.LOCAL_VULN_DB:
                        if vuln["package"] == pkg_name:
                            if version_matches_constraint(version, vuln["constraint"]):
                                results.append({
                                    "type": "SCA",
                                    "package": pkg_name,
                                    "installed": version,
                                    "affected": vuln["constraint"],
                                    "cve": vuln["cve"],
                                    "fix": vuln["fix"],
                                    "severity": vuln["severity"],
                                    "file": str(file_path),
                                    "line": line,
                                    "rule": f"sca-{pkg_name}",
                                    "cwe": "CWE-1104",
                                    "description": f"Vulnerable dependency {pkg_name} ({version}) matched constraint {vuln['constraint']}. CVE: {vuln['cve']}."
                                })
            except Exception:
                pass

        if self.root.is_file():
            process_dependency_file(self.root)
        else:
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    if file_path.name.lower() in supported_files:
                        process_dependency_file(file_path)

        return results

    def _parse_requirements_txt(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([a-zA-Z0-9-_]+)\s*(?:==|<=|>=|~=|<|>)\s*([a-zA-Z0-9.-]+)', line)
            if match:
                packages.append((match.group(1).lower(), match.group(2), idx))
        return packages

    def _parse_package_lock_json(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        try:
            data = json.loads(content)
            pkgs = data.get("packages", {})
            if pkgs:
                for name, details in pkgs.items():
                    clean_name = name.split("node_modules/")[-1] if "node_modules/" in name else name
                    version = details.get("version")
                    if clean_name and version:
                        packages.append((clean_name.lower(), version, 1))
            else:
                deps = data.get("dependencies", {})
                for name, details in deps.items():
                    version = details.get("version")
                    if name and version:
                        packages.append((name.lower(), version, 1))
        except Exception:
            pass
        return packages

    def _parse_pom_xml(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        in_dependency = False
        curr_artifact = None
        curr_version = None
        start_line = 1
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if "<dependency>" in line_strip:
                in_dependency = True
                curr_artifact = None
                curr_version = None
                start_line = idx
            elif "</dependency>" in line_strip:
                if in_dependency and curr_artifact and curr_version:
                    packages.append((curr_artifact.lower(), curr_version, start_line))
                in_dependency = False
            elif in_dependency:
                art_match = re.search(r'<artifactId>(.*?)</artifactId>', line_strip)
                if art_match:
                    curr_artifact = art_match.group(1)
                ver_match = re.search(r'<version>(.*?)</version>', line_strip)
                if ver_match:
                    curr_version = ver_match.group(1)
        return packages

    def _parse_go_mod(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        in_require = False
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if line_strip.startswith("require ("):
                in_require = True
            elif line_strip.startswith(")") and in_require:
                in_require = False
            elif line_strip.startswith("require "):
                parts = line_strip.split()
                if len(parts) >= 3:
                    module = parts[1].split("/")[-1]
                    version = parts[2]
                    packages.append((module.lower(), version, idx))
            elif in_require:
                parts = line_strip.split()
                if len(parts) >= 2:
                    module = parts[0].split("/")[-1]
                    version = parts[1]
                    packages.append((module.lower(), version, idx))
        return packages

    def _parse_cargo_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        curr_name = None
        start_line = 1
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if line_strip == "[[package]]":
                curr_name = None
                start_line = idx
            elif line_strip.startswith("name = "):
                curr_name = line_strip.split("=")[-1].strip().replace('"', '')
            elif line_strip.startswith("version = ") and curr_name:
                version = line_strip.split("=")[-1].strip().replace('"', '')
                packages.append((curr_name.lower(), version, start_line))
        return packages

    def _parse_gemfile_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            match = re.match(r'^\s{4}([a-zA-Z0-9-_]+)\s*\(([\d.]+)\)', line)
            if match:
                packages.append((match.group(1).lower(), match.group(2), idx))
        return packages

    def _parse_composer_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        try:
            data = json.loads(content)
            pkgs = data.get("packages", [])
            for p in pkgs:
                name = p.get("name")
                clean_name = name.split("/")[-1] if "/" in name else name
                version = p.get("version")
                if clean_name and version:
                    packages.append((clean_name.lower(), version, 1))
        except Exception:
            pass
        return packages

    def _parse_poetry_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        curr_name = None
        start_line = 1
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if line_strip == "[[package]]":
                curr_name = None
                start_line = idx
            elif line_strip.startswith("name = "):
                curr_name = line_strip.split("=")[-1].strip().replace('"', '')
            elif line_strip.startswith("version = ") and curr_name:
                version = line_strip.split("=")[-1].strip().replace('"', '')
                packages.append((curr_name.lower(), version, start_line))
        return packages

    def _parse_pipfile_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        try:
            data = json.loads(content)
            for section in ["default", "develop"]:
                sec_data = data.get(section, {})
                for name, details in sec_data.items():
                    version = details.get("version", "").replace("==", "")
                    if name and version:
                        packages.append((name.lower(), version, 1))
        except Exception:
            pass
        return packages

    def _parse_yarn_lock(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        curr_name = None
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith("#"):
                continue
            if line_strip.endswith(":"):
                name_part = line_strip.split("@")[0].replace('"', '')
                curr_name = name_part.split("/")[-1] if "/" in name_part else name_part
            elif line_strip.startswith("version ") and curr_name:
                version = line_strip.split("version")[-1].strip().replace('"', '')
                packages.append((curr_name.lower(), version, idx))
        return packages

    def _parse_pnpm_lock_yaml(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            match = re.match(r'^\s*/([a-zA-Z0-9-_]+)/([\d.]+)(?::)?$', line_strip)
            if match:
                packages.append((match.group(1).lower(), match.group(2), idx))
        return packages

    def _parse_build_gradle(self, content: str) -> list[tuple[str, str, int]]:
        packages = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            match = re.search(r'[\'"]([a-zA-Z0-9.-]+):([a-zA-Z0-9.-]+):([a-zA-Z0-9.-]+)[\'"]', line_strip)
            if match:
                packages.append((match.group(2).lower(), match.group(3), idx))
        return packages


class IacScanner:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.trivy_path = shutil.which("trivy")
        self.checkov_path = shutil.which("checkov")

    def scan(self) -> list[dict[str, Any]]:
        return self._run_local_fallback()

    def _run_local_fallback(self) -> list[dict[str, Any]]:
        from agentic_security_platform import IGNORE_DIRS
        results = []

        def check_file(file_path: Path):
            name = file_path.name.lower()
            ext = file_path.suffix.lower()
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                
                # 1. Dockerfile
                if name == "dockerfile" or ext == ".dockerfile":
                    results.extend(self._scan_dockerfile(file_path, content))
                # 2. Docker Compose
                elif name in ["docker-compose.yml", "docker-compose.yaml"]:
                    results.extend(self._scan_docker_compose(file_path, content))
                # 3. Terraform
                elif ext == ".tf":
                    results.extend(self._scan_terraform(file_path, content))
                # 4. GitLab CI
                elif name == ".gitlab-ci.yml":
                    results.extend(self._scan_gitlab_ci(file_path, content))
                # 5. Jenkinsfile
                elif name == "jenkinsfile" or ext == ".jenkinsfile":
                    results.extend(self._scan_jenkinsfile(file_path, content))
                # 6. YAML files (.yml / .yaml)
                elif ext in [".yml", ".yaml"]:
                    if ".github/workflows" in str(file_path.as_posix()):
                        results.extend(self._scan_github_actions(file_path, content))
                    elif "apiversion:" in content.lower() and "kind:" in content.lower():
                        results.extend(self._scan_kubernetes(file_path, content))
                    elif "awstemplateformatversion" in content.lower():
                        results.extend(self._scan_cloudformation(file_path, content))
            except Exception:
                pass

        if self.root.is_file():
            check_file(self.root)
        else:
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    check_file(file_path)

        return results

    def _scan_dockerfile(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        
        has_user_instr = False
        last_user = ""
        user_line = 1
        
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if line_strip.startswith("#"):
                continue
            
            if line_strip.startswith("USER "):
                has_user_instr = True
                last_user = line_strip.split("USER")[-1].strip()
                user_line = idx
            
            if "/var/run/docker.sock" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "docker-exposed-socket",
                    "cwe": "CWE-284",
                    "severity": "critical",
                    "description": "Exposed host Docker socket referenced in Dockerfile instructions.",
                    "remediation": "Do not copy or map the host's /var/run/docker.sock socket within Dockerfiles."
                })

        if not has_user_instr:
            results.append({
                "type": "IAC",
                "file": str(file_path),
                "line": 1,
                "rule": "docker-run-as-root",
                "cwe": "CWE-250",
                "severity": "high",
                "description": "Container runs as root. Missing non-root USER instruction.",
                "remediation": "Add 'USER appuser' or another non-root identifier to the Dockerfile build stages."
            })
        elif last_user.lower() == "root" or last_user == "0":
            results.append({
                "type": "IAC",
                "file": str(file_path),
                "line": user_line,
                "rule": "docker-run-as-root",
                "cwe": "CWE-250",
                "severity": "high",
                "description": "Container runs explicitly as root via 'USER root' or 'USER 0'.",
                "remediation": "Switch build stage execution to a non-root UID or non-privileged user profile."
            })

        return results

    def _scan_docker_compose(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            
            if re.search(r'privileged:\s*true', line_strip):
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "compose-privileged-mode",
                    "cwe": "CWE-250",
                    "severity": "high",
                    "description": "Container configured with privileged: true in Docker Compose configuration.",
                    "remediation": "Remove privileged: true to run the container with restricted host namespace scopes."
                })
            
            if "/var/run/docker.sock" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "compose-exposed-socket",
                    "cwe": "CWE-284",
                    "severity": "critical",
                    "description": "Host Docker socket /var/run/docker.sock mounted inside Docker Compose container.",
                    "remediation": "Remove host socket mounts to prevent container breakout risks."
                })
            
            if re.search(r'user:\s*["\']?(root|0)["\']?', line_strip):
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "compose-runs-as-root",
                    "cwe": "CWE-250",
                    "severity": "medium",
                    "description": "Container explicitly configured to run as root/0 user.",
                    "remediation": "Map service execution to a non-root UID (e.g. user: 1000:1000)."
                })
                
        return results

    def _scan_terraform(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            
            if "0.0.0.0/0" in line_strip and ("cidr_blocks" in line_strip or "cidr" in line_strip):
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "tf-open-security-group",
                    "cwe": "CWE-284",
                    "severity": "high",
                    "description": "Security Group ingress rule allows public open CIDR access (0.0.0.0/0).",
                    "remediation": "Restrict CIDR blocks to specific secure IP addresses or trusted security groups."
                })
            
            if "public-read" in line_strip and "acl" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "tf-public-s3",
                    "cwe": "CWE-284",
                    "severity": "high",
                    "description": "S3 bucket ACL configured for public-read access.",
                    "remediation": "Configure Private ACLs and lock access down using S3 Public Access Blocks."
                })
                
            if "encrypted" in line_strip and "false" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "tf-missing-encryption",
                    "cwe": "CWE-311",
                    "severity": "medium",
                    "description": "Block storage volume encryption set to false.",
                    "remediation": "Set 'encrypted = true' to protect data at rest."
                })
                
        return results

    def _scan_kubernetes(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            
            if re.search(r'privileged:\s*true', line_strip):
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "k8s-privileged-pod",
                    "cwe": "CWE-250",
                    "severity": "high",
                    "description": "Kubernetes container securityContext permits privileged mode.",
                    "remediation": "Disable privileged mode (remove 'privileged: true') to restrict pod permissions."
                })
            
            if "/var/run/docker.sock" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "k8s-exposed-socket",
                    "cwe": "CWE-284",
                    "severity": "critical",
                    "description": "Kubernetes volume mounts host path /var/run/docker.sock socket.",
                    "remediation": "Remove host path socket mounts to prevent container breakouts."
                })
            
            if re.search(r'runAsUser:\s*0', line_strip) or re.search(r'runAsNonRoot:\s*false', line_strip):
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "k8s-run-as-root",
                    "cwe": "CWE-250",
                    "severity": "medium",
                    "description": "Kubernetes pod securityContext allows root execution.",
                    "remediation": "Define runAsNonRoot: true and runAsUser with a non-zero UID."
                })
                
        return results

    def _scan_cloudformation(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            
            if "0.0.0.0/0" in line_strip and "CidrIp" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "cfn-open-security-group",
                    "cwe": "CWE-284",
                    "severity": "high",
                    "description": "CloudFormation security group ingress CidrIp allows public access (0.0.0.0/0).",
                    "remediation": "Restrict CidrIp targets to secure, trusted CIDR ranges."
                })
            
            if "PublicRead" in line_strip and "AccessControl" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "cfn-public-s3",
                    "cwe": "CWE-284",
                    "severity": "high",
                    "description": "CloudFormation S3 Bucket AccessControl set to PublicRead.",
                    "remediation": "Configure Private AccessControl policies and restrict public sharing."
                })
                
        return results

    def _scan_github_actions(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            
            if "write-all" in line_strip and "permissions" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "gha-dangerous-permissions",
                    "cwe": "CWE-284",
                    "severity": "high",
                    "description": "GitHub Actions permissions block contains write-all permissions.",
                    "remediation": "Restrict write permissions to specific individual actions scopes (e.g., contents: read)."
                })
        return results

    def _scan_gitlab_ci(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if "privileged" in line_strip and "true" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "gitlab-unsafe-runner",
                    "cwe": "CWE-250",
                    "severity": "high",
                    "description": "GitLab CI runner configures privileged mode execution.",
                    "remediation": "Disable privileged execution permissions for build runners."
                })
        return results

    def _scan_jenkinsfile(self, file_path: Path, content: str) -> list[dict[str, Any]]:
        results = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            if "privileged" in line_strip and "true" in line_strip:
                results.append({
                    "type": "IAC",
                    "file": str(file_path),
                    "line": idx,
                    "rule": "jenkins-unsafe-runner",
                    "cwe": "CWE-250",
                    "severity": "high",
                    "description": "Jenkinsfile defines privileged execution podTemplates.",
                    "remediation": "Remove privileged build runner mappings inside Jenkins configuration stages."
                })
        return results
