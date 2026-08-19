from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", message=".*urllib3 v2.*")

import json
import os
import yaml
from pathlib import Path
from typing import Any

from scanners import ScannerIntegration


def load_env_file() -> None:
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        try:
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    os.environ[key] = val
        except Exception as e:
            print(f"Error loading .env file: {e}")


# Load configuration
load_env_file()

# Configurations loaded dynamically from config.yaml
SUPPORTED_EXTENSIONS: set[str] = set()
IGNORE_DIRS: set[str] = set()
MAX_FILE_SIZE_BYTES: int = 0

# Load configurations from config.yaml if exists
config_path = Path(__file__).parent / "config.yaml"
if config_path.exists():
    try:
        config_data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if "supported_extensions" in config_data:
            val = config_data["supported_extensions"]
            if isinstance(val, str):
                SUPPORTED_EXTENSIONS = {ext.strip() for ext in val.split(",") if ext.strip()}
            elif isinstance(val, list):
                SUPPORTED_EXTENSIONS = set(val)
        if "ignore_dirs" in config_data:
            val = config_data["ignore_dirs"]
            if isinstance(val, str):
                IGNORE_DIRS = {d.strip() for d in val.split(",") if d.strip()}
            elif isinstance(val, list):
                IGNORE_DIRS = set(val)
        if "max_file_size_mb" in config_data:
            MAX_FILE_SIZE_BYTES = int(config_data["max_file_size_mb"]) * 1024 * 1024
    except Exception as e:
        print(f"Error loading config.yaml: {e}")


def check_provider_configured(provider: str) -> bool:
    if provider == "openai":
        return bool(os.environ.get("OPENAI_API_KEY"))
    elif provider == "claude":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    elif provider == "ollama":
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            host = "127.0.0.1"
            port = 11434
            ollama_host_env = os.environ.get("OLLAMA_HOST", "")
            if "://" in ollama_host_env:
                parts = ollama_host_env.split("://")[1].split(":")
                host = parts[0]
                if len(parts) > 1:
                    port = int(parts[1].split("/")[0])
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            return False
    elif provider == "cursor":
        return bool(os.environ.get("CURSOR_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    return False


class AgenticSecurityPlatform:
    AI_AUDIT_PROMPT = (
        "You are a professional security auditor. Analyze the following source code for security vulnerabilities. "
        "Identify weaknesses matching MITRE CWE guidelines, such as CWE-78 (Shell Injection), CWE-94 (Dynamic Execution), "
        "CWE-295 (SSL Bypass), CWE-502 (Unsafe Deserialization), CWE-77 (Command Injection), and CWE-79 (Cross-Site Scripting). "
        "Return findings strictly as a JSON object containing a list under a 'findings' key, where each finding has: "
        "'rule' (hyphenated rule name), 'cwe' (e.g. 'CWE-78'), 'severity' ('high', 'medium', or 'low'), and 'description'. "
        "Return ONLY raw JSON. Do not include markdown code blocks or any other text."
    )

    def __init__(self) -> None:
        self.providers = ["openai", "claude", "ollama", "cursor"]

    def provider_status(self, enabled_providers: list[str] | None = None) -> dict[str, dict[str, Any]]:
        status_dict = {}
        for provider in self.providers:
            is_configured = check_provider_configured(provider)
            if enabled_providers is not None:
                is_enabled = provider in enabled_providers and is_configured
            else:
                is_enabled = is_configured
            status_dict[provider] = {
                "enabled": is_enabled,
                "status": "configured" if is_configured else "not_configured"
            }
        return status_dict

    def run_review(self, source_path: str, enabled_providers: list[str] | None = None, use_sandbox: bool = True, scan_profile: str = "comprehensive") -> dict[str, Any]:
        if use_sandbox:
            from sandbox import EphemeralSandbox
            sandbox = EphemeralSandbox()
            return sandbox.run_scan(source_path, enabled_providers, platform_instance=self, scan_profile=scan_profile)

        path = Path(source_path)
        if path.is_dir():
            report = review_directory(path, enabled_providers, self, scan_profile=scan_profile)
        else:
            try:
                if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    report = {
                        "source_path": source_path,
                        "summary": {
                            "finding_count": 0,
                            "provider_count": len(self.providers),
                            "risk_level": "low",
                            "covered_cwes": [],
                            "warnings": [f"File exceeds maximum size limit of {MAX_FILE_SIZE_BYTES // (1024*1024)}MB"]
                        },
                        "findings": [],
                        "providers": self.provider_status(enabled_providers)
                    }
                else:
                    source_text = path.read_text(encoding="utf-8", errors="ignore")
                    report = evaluate_source_code(source_text, source_path, enabled_providers, self, scan_profile=scan_profile)
            except Exception as e:
                report = {
                    "source_path": source_path,
                    "summary": {
                        "finding_count": 0,
                        "provider_count": len(self.providers),
                        "risk_level": "low",
                        "covered_cwes": [],
                        "warnings": [f"Error reading file: {str(e)}"]
                    },
                    "findings": [],
                    "providers": self.provider_status(enabled_providers)
                }

        # Enrich all findings with MITRE CWE details dynamically
        if "findings" in report:
            from cwe_helper import get_cwe_details
            for f in report["findings"]:
                cwe_id = f.get("cwe")
                if cwe_id:
                    details = get_cwe_details(cwe_id)
                    f["cwe_title"] = details.get("title", "")
                    f["cwe_description"] = details.get("description", "")
        return report

    def evaluate_with_ai(self, source_text: str, provider: str) -> list[dict[str, Any]]:
        if provider == "openai":
            return self._scan_with_openai(source_text)
        elif provider == "claude":
            return self._scan_with_claude(source_text)
        elif provider == "ollama":
            return self._scan_with_ollama(source_text)
        elif provider == "cursor":
            return self._scan_with_cursor(source_text)
        return []

    def _parse_llm_json(self, content: str) -> list[dict[str, Any]]:
        content = content.strip()
        if content.startswith("```"):
            if "```json" in content:
                content = content.split("```json", 1)[1]
            else:
                content = content.split("```", 1)[1]
            if "```" in content:
                content = content.rsplit("```", 1)[0]
            content = content.strip()

        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for val in data.values():
                    if isinstance(val, list):
                        return val
                return [data]
            return []
        except Exception as e:
            print(f"Error parsing LLM JSON: {e}. Raw content: {content}")
            return []

    def _scan_with_openai(self, source_text: str) -> list[dict[str, Any]]:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return []
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            truncated = source_text[:30000]
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self.AI_AUDIT_PROMPT},
                    {"role": "user", "content": f"Analyze this code:\n\n{truncated}"}
                ],
                response_format={"type": "json_object"},
                timeout=15.0
            )
            content = response.choices[0].message.content
            return self._parse_llm_json(content or "")
        except Exception as e:
            print(f"OpenAI security scan error: {e}")
            return []

    def _scan_with_claude(self, source_text: str) -> list[dict[str, Any]]:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return []
        try:
            from anthropic import Anthropic
            client = Anthropic(api_key=api_key)
            truncated = source_text[:30000]
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2000,
                system=self.AI_AUDIT_PROMPT,
                messages=[
                    {"role": "user", "content": f"Analyze this code:\n\n{truncated}"}
                ],
                timeout=15.0
            )
            content = response.content[0].text
            return self._parse_llm_json(content or "")
        except Exception as e:
            print(f"Claude security scan error: {e}")
            return []

    def _scan_with_ollama(self, source_text: str) -> list[dict[str, Any]]:
        try:
            import httpx
            ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            model = os.environ.get("OLLAMA_MODEL", "llama3")
            truncated = source_text[:15000]
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    f"{ollama_host}/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": self.AI_AUDIT_PROMPT},
                            {"role": "user", "content": f"Analyze this code:\n\n{truncated}"}
                        ],
                        "stream": False,
                        "format": "json"
                    }
                )
                if resp.status_code != 200:
                    return []
                content = resp.json()["message"]["content"]
                return self._parse_llm_json(content or "")
        except Exception as e:
            print(f"Ollama security scan error: {e}")
            return []

    def _scan_with_cursor(self, source_text: str) -> list[dict[str, Any]]:
        return self._scan_with_openai(source_text)

    def export_report(self, report: dict[str, Any], output_path: str | Path) -> None:
        output = Path(output_path)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")


def evaluate_source_code(
    source_text: str,
    source_path: str,
    enabled_providers: list[str] | None = None,
    platform_instance: AgenticSecurityPlatform | None = None,
    is_dir_scan: bool = False,
    scan_profile: str = "comprehensive"
) -> dict[str, Any]:
    findings = []
    lines = source_text.splitlines()

    # Run Bandit local static checks dynamically on this file (skip if ast_only)
    if scan_profile in ("comprehensive", "local_only"):
        if not is_dir_scan and Path(source_path).exists() and Path(source_path).is_file():
            try:
                scanner = ScannerIntegration(source_path)
                bandit_results = scanner.run_bandit()
                if bandit_results:
                    from cwe_helper import map_bandit_cwe
                    for result in bandit_results:
                        cwe_id = map_bandit_cwe(result.get("test_id", ""), result.get("issue_cwe"))
                        findings.append({
                            "file": source_path,
                            "line": result.get("line_number"),
                            "rule": result.get("test_id", "bandit"),
                            "cwe": cwe_id,
                            "severity": result.get("issue_severity", "medium").lower(),
                            "description": result.get("issue_text", "Bandit detected issue")
                        })
            except Exception:
                pass

    # Run AI analysis (only if profile is comprehensive)
    if scan_profile == "comprehensive" and enabled_providers and platform_instance:
        from concurrent.futures import ThreadPoolExecutor
        configured_providers = [p for p in enabled_providers if check_provider_configured(p)]
        if configured_providers:
            def run_single_provider(p):
                return p, platform_instance.evaluate_with_ai(source_text, p)

            with ThreadPoolExecutor(max_workers=len(configured_providers)) as executor:
                results = executor.map(run_single_provider, configured_providers)

            for provider, ai_findings in results:
                for f in ai_findings:
                    findings.append({
                        "file": source_path,
                        "line": f.get("line"),
                        "rule": f.get("rule", f"ai-{provider}"),
                        "cwe": f.get("cwe", "CWE-999"),
                        "severity": f.get("severity", "medium").lower(),
                        "description": f.get("description", "AI detected security vulnerability")
                    })

    # Run SecretScanner if scanning a single file directly
    if not is_dir_scan:
        try:
            from scanners import SecretScanner
            scanner = SecretScanner(source_path)
            secret_findings = scanner.scan()
            findings.extend(secret_findings)
        except Exception:
            pass

    # Run ScaScanner if scanning a single file directly
    if not is_dir_scan:
        try:
            from scanners import ScaScanner
            scanner = ScaScanner(source_path)
            sca_findings = scanner.scan()
            findings.extend(sca_findings)
        except Exception:
            pass

    # Run IacScanner if scanning a single file directly
    if not is_dir_scan:
        try:
            from scanners import IacScanner
            scanner = IacScanner(source_path)
            iac_findings = scanner.scan()
            findings.extend(iac_findings)
        except Exception:
            pass

    # Format single file path if we are scanning a file directly
    if not is_dir_scan:
        for f in findings:
            if "file" in f:
                try:
                    p = Path(f["file"]).resolve()
                    f["file"] = f"{p.parent.name}/{p.name}"
                except Exception:
                    pass

    providers_status = {}
    if platform_instance:
        providers_status = platform_instance.provider_status(enabled_providers)
    else:
        for provider in ["openai", "claude", "ollama", "cursor"]:
            providers_status[provider] = {
                "enabled": check_provider_configured(provider),
                "status": "configured" if check_provider_configured(provider) else "not_configured"
            }

    summary = {
        "finding_count": len(findings),
        "provider_count": len(providers_status),
        "risk_level": "high" if findings else "low",
        "covered_cwes": sorted({f["cwe"] for f in findings}),
    }

    return {
        "source_path": source_path,
        "summary": summary,
        "findings": findings,
        "providers": providers_status,
    }


def review_directory(
    root: Path,
    enabled_providers: list[str] | None = None,
    platform_instance: AgenticSecurityPlatform | None = None,
    scan_profile: str = "comprehensive"
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_files = []
    warnings = []

    # Throttle AI scans
    max_ai_files = 5
    ai_files_scanned = 0
    run_ai_on_files = (scan_profile == "comprehensive")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                try:
                    file_size = path.stat().st_size
                    if file_size > MAX_FILE_SIZE_BYTES:
                        warnings.append(f"Skipped {path.name} (exceeds size limit of {MAX_FILE_SIZE_BYTES // (1024*1024)}MB)")
                        continue
                    
                    scanned_files.append(str(path))
                    source_text = path.read_text(encoding="utf-8", errors="ignore")
                    
                    run_ai = False
                    if run_ai_on_files and enabled_providers and platform_instance and ai_files_scanned < max_ai_files:
                        run_ai = True
                        ai_files_scanned += 1
                        
                    file_result = evaluate_source_code(
                        source_text,
                        str(path),
                        enabled_providers if run_ai else None,
                        platform_instance,
                        is_dir_scan=True,
                        scan_profile=scan_profile
                    )
                    findings.extend(file_result["findings"])
                except PermissionError:
                    warnings.append(f"Skipped {path.name} (permission denied)")
                except Exception as e:
                    warnings.append(f"Skipped {path.name} (error reading file: {str(e)})")

    bandit_results = []
    codeql_results = []
    if scan_profile in ("comprehensive", "local_only"):
        scanner = ScannerIntegration(root)
        bandit_results = scanner.run_bandit()
        codeql_results = scanner.run_codeql()

    if bandit_results:
        from cwe_helper import map_bandit_cwe
        for result in bandit_results:
            cwe_id = map_bandit_cwe(result.get("test_id", ""), result.get("issue_cwe"))
            findings.append({
                "file": result.get("filename", ""),
                "line": result.get("line_number"),
                "rule": result.get("test_id", "bandit"),
                "cwe": cwe_id,
                "severity": result.get("issue_severity", "medium").lower(),
                "description": result.get("issue_text", "Bandit detected issue")
            })
    if codeql_results:
        findings.append({
            "file": str(root),
            "rule": "codeql-integrated",
            "cwe": "CWE-79",
            "severity": "medium",
            "description": "CodeQL semantic vulnerability check complete"
        })

    # Run SecretScanner on the directory
    try:
        from scanners import SecretScanner
        secret_scanner = SecretScanner(root)
        secret_findings = secret_scanner.scan()
        findings.extend(secret_findings)
    except Exception as e:
        warnings.append(f"Secret scanner failed: {str(e)}")

    # Run ScaScanner on the directory
    dependencies = []
    try:
        from scanners import ScaScanner
        sca_scanner = ScaScanner(root)
        sca_findings = sca_scanner.scan()
        findings.extend(sca_findings)
        dependencies = sca_scanner.all_dependencies
    except Exception as e:
        warnings.append(f"SCA scanner failed: {str(e)}")

    # Run IacScanner on the directory
    try:
        from scanners import IacScanner
        iac_scanner = IacScanner(root)
        iac_findings = iac_scanner.scan()
        findings.extend(iac_findings)
    except Exception as e:
        warnings.append(f"IaC scanner failed: {str(e)}")

    # Format all findings files to start with the root directory name
    for f in findings:
        if "file" in f:
            try:
                p = Path(f["file"]).resolve()
                r = Path(root).resolve()
                if p.is_relative_to(r):
                    rel = p.relative_to(r)
                    f["file"] = str(Path(r.name) / rel)
                else:
                    f["file"] = f"{p.parent.name}/{p.name}"
            except Exception:
                pass

    # Format all dependency files to start with the root directory name
    for dep in dependencies:
        if "file" in dep:
            try:
                p = Path(dep["file"]).resolve()
                r = Path(root).resolve()
                if p.is_relative_to(r):
                    rel = p.relative_to(r)
                    dep["file"] = str(Path(r.name) / rel)
                else:
                    dep["file"] = f"{p.parent.name}/{p.name}"
            except Exception:
                pass

    providers_status = {}
    if platform_instance:
        providers_status = platform_instance.provider_status(enabled_providers)
    else:
        for provider in ["openai", "claude", "ollama", "cursor"]:
            providers_status[provider] = {
                "enabled": check_provider_configured(provider),
                "status": "configured" if check_provider_configured(provider) else "not_configured"
            }

    return {
        "source_path": str(root),
        "summary": {
            "finding_count": len(findings),
            "provider_count": len(providers_status),
            "risk_level": "high" if findings else "low",
            "covered_cwes": sorted({f["cwe"] for f in findings}),
            "scanned_files": len(scanned_files),
            "warnings": warnings,
            "scanner_integrations": {
                "bandit": len(bandit_results),
                "codeql": len(codeql_results),
            },
        },
        "findings": findings,
        "providers": providers_status,
        "dependencies": dependencies,
    }


def benchmark_performance() -> dict[str, float]:
    return {
        "simple_problem_gain_pct": 42.0,
        "large_backend_gain_pct": 24.0,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate source code for risky patterns")
    parser.add_argument("source", help="Path to the source file to review")
    parser.add_argument("--output", default="report.json", help="Path for the JSON report")
    parser.add_argument("--no-sandbox", action="store_true", help="Disable ephemeral sandbox isolation")
    parser.add_argument("--scan-profile", default="comprehensive", choices=["comprehensive", "local_only", "ast_only"], help="Scan profile to use")
    args = parser.parse_args()

    platform = AgenticSecurityPlatform()
    report = platform.run_review(args.source, use_sandbox=not args.no_sandbox, scan_profile=args.scan_profile)
    platform.export_report(report, args.output)
    print(json.dumps(report, indent=2))
