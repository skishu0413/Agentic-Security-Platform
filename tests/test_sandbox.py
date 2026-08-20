import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock
from sandbox import EphemeralSandbox

def test_sandbox_creates_valid_scan_id():
    sandbox = EphemeralSandbox()
    assert sandbox.scan_id.startswith("scan_")
    assert len(sandbox.scan_id) > 5

def test_sandbox_executes_host_isolated_scan_and_wipes_workspace(tmp_path):
    # Setup mock project directory with unsafe file
    src_dir = tmp_path / "my_mock_project"
    src_dir.mkdir()
    
    unsafe_file = src_dir / "risky.py"
    unsafe_file.write_text(
        "import subprocess\n"
        "subprocess.run('echo hello', shell=True)\n"
        "eval('1+1')\n",
        encoding="utf-8"
    )
    
    sandbox = EphemeralSandbox()
    # Explicitly force host-isolation mode for the test
    sandbox.docker_available = False
    
    report = sandbox.run_scan(str(src_dir))
    
    # 1. Check scan_id and timestamp are injected
    assert "scan_id" in report
    assert report["scan_id"] == sandbox.scan_id
    assert "timestamp" in report
    
    # 2. Check findings are extracted correctly via copy
    assert report["summary"]["finding_count"] >= 2
    
    # 3. Check findings file path sanitization
    for finding in report["findings"]:
        # Verify absolute temp workspace path is NOT in the finding file path
        file_path = finding["file"]
        assert "sandbox_" not in file_path
        assert "tmp" not in file_path
        # Verify path starts with original source directory name
        assert file_path.startswith("my_mock_project")
        
        # Verify metadata additions
        assert "fingerprint" in finding
        assert len(finding["fingerprint"]) == 64
        assert finding["cve"] == "N/A"
        assert "remediation" in finding
        
    # 4. Check workspace wipe: verify no sandbox_* directories remain in /tmp
    temp_root = Path(os.getenv("TMPDIR", "/tmp"))
    matching_dirs = list(temp_root.glob(f"sandbox_{sandbox.scan_id}_*"))
    assert len(matching_dirs) == 0

def test_sandbox_run_git_scan_clones_and_wipes(tmp_path, monkeypatch):
    # Create a mock repo folder containing a file
    mock_git_source = tmp_path / "mock_git_source"
    mock_git_source.mkdir()
    (mock_git_source / "risky.py").write_text("eval('1+1')\n", encoding="utf-8")
    
    # Spy variables
    cloned_to = None
    
    original_run = subprocess.run
    def mock_subprocess_run(cmd, *args, **kwargs):
        nonlocal cloned_to
        if isinstance(cmd, list) and len(cmd) > 2 and cmd[0] == "git" and cmd[1] == "clone":
            cloned_to = Path(cmd[-1])
            # Simulate successful clone by copying mock_git_source files to cloned_to
            shutil.copytree(mock_git_source, cloned_to, dirs_exist_ok=True)
            # Return mock successful process
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            return mock_proc
        return original_run(cmd, *args, **kwargs)
        
    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    
    sandbox = EphemeralSandbox()
    sandbox.docker_available = False
    
    report = sandbox.run_git_scan("https://github.com/test-org/test-repo.git", "main")
    
    # Verify clone was called and temp folder was created
    assert cloned_to is not None
    assert cloned_to.exists() is False # Wiped after scan!
    
    # Verify report findings have correct repo basename mapping
    assert report["summary"]["finding_count"] >= 1
    assert report["findings"][0]["file"].startswith("test-repo")
    
    # Check fingerprint, CVE and remediation
    finding = report["findings"][0]
    assert "fingerprint" in finding
    assert len(finding["fingerprint"]) == 64  # SHA-256
    assert finding["cve"] == "N/A"
    assert "remediation" in finding
    assert len(finding["remediation"]) > 10


def test_secret_scanner_regex_fallback_finds_keys(tmp_path):
    from scanners import SecretScanner
    
    # Create mock project files
    project_dir = tmp_path / "mock_project"
    project_dir.mkdir()
    
    # 1. Python file with OpenAI sk key
    py_file = project_dir / "app.py"
    py_file.write_text(
        "OPENAI_KEY = 'sk-abcdef1234567890abcdef1234567890abcd'\n"
        "GITHUB_TOKEN = 'ghp_secretValue1234567890123456789012345'\n",
        encoding="utf-8"
    )
    
    # 2. .env file with high-entropy credential
    env_file = project_dir / ".env"
    env_file.write_text(
        "DATABASE_URL = 'postgresql://user:super_secret_pass_12345@localhost:5432/db'\n"
        "SLACK_TOKEN=FAKE_SLACK_TOKEN_FOR_TESTING_ONLY\n",
        encoding="utf-8"
    )
    
    scanner = SecretScanner(project_dir)
    # Force fallback regex mode
    scanner.gitleaks_path = None
    
    findings = scanner.scan()
    
    # Check that secrets are detected
    assert len(findings) >= 3
    
    # Verify properties
    for f in findings:
        assert f["type"] == "SECRET"
        assert f["cwe"] == "CWE-798"
        assert f["severity"] == "critical"
        
        # Verify the actual secret is masked and not leaked in raw form
        secret_val = f["secret"]
        assert "*" in secret_val
        assert "super_secret_pass" not in secret_val
        assert "secretValue" not in secret_val


def test_secret_scanner_gitleaks_integration(tmp_path, monkeypatch):
    from scanners import SecretScanner
    
    scanner = SecretScanner(tmp_path)
    scanner.gitleaks_path = "/usr/bin/gitleaks"
    
    # Mock subprocess.run to write mock gitleaks output json to report-path
    original_run = subprocess.run
    def mock_subprocess_run(cmd, *args, **kwargs):
        report_path = None
        for idx, val in enumerate(cmd):
            if val == "--report-path":
                report_path = cmd[idx+1]
                break
        
        if report_path:
            mock_gitleaks_finding = [
                {
                    "Description": "GitHub Personal Access Token",
                    "StartLine": 5,
                    "EndLine": 5,
                    "Match": "ghp_mockSecretPattern123456789012345678",
                    "Secret": "ghp_mockSecretPattern123456789012345678",
                    "File": "config.js",
                    "RuleID": "github-pat"
                }
            ]
            Path(report_path).write_text(json.dumps(mock_gitleaks_finding), encoding="utf-8")
        
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        return mock_proc

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    
    findings = scanner.scan()
    
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "SECRET"
    assert f["provider"] == "github"
    assert f["file"] == "config.js"
    assert f["line"] == 5
    assert f["cwe"] == "CWE-798"
    assert f["severity"] == "critical"
    # Verify secret is masked
    assert f["secret"].startswith("ghp_")
    assert "*" in f["secret"]
    assert "mockSecret" not in f["secret"]


def test_sca_scanner_finds_vulnerable_pom_xml_dependency(tmp_path):
    from scanners import ScaScanner
    
    # Create mock pom.xml
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "      <version>2.14.1</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n",
        encoding="utf-8"
    )
    
    scanner = ScaScanner(tmp_path)
    scanner.osv_scanner_path = None
    
    findings = scanner.scan()
    assert len(findings) == 1
    
    f = findings[0]
    assert f["type"] == "SCA"
    assert f["package"] == "log4j-core"
    assert f["installed"] == "2.14.1"
    assert f["affected"] == "<2.15.0"
    assert f["cve"] == "CVE-2021-44228"
    assert f["severity"] == "critical"
    assert "pom.xml" in f["file"]


def test_sca_scanner_finds_vulnerable_requirements_txt(tmp_path):
    from scanners import ScaScanner
    
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.28.0\n"
        "django==3.2.10\n",
        encoding="utf-8"
    )
    
    scanner = ScaScanner(tmp_path)
    scanner.osv_scanner_path = None
    
    findings = scanner.scan()
    assert len(findings) == 2
    
    django_finding = [f for f in findings if f["package"] == "django"][0]
    assert django_finding["type"] == "SCA"
    assert django_finding["installed"] == "3.2.10"
    assert django_finding["cve"] == "CVE-2023-41164"
    assert django_finding["severity"] == "high"


def test_sca_scanner_osv_integration(tmp_path, monkeypatch):
    from scanners import ScaScanner
    
    scanner = ScaScanner(tmp_path)
    scanner.osv_scanner_path = "/usr/bin/osv-scanner"
    
    # Mock subprocess.run output
    def mock_subprocess_run(cmd, *args, **kwargs):
        mock_output = {
            "results": [
                {
                    "source": {
                        "path": "package-lock.json",
                        "type": "lockfile"
                    },
                    "packages": [
                        {
                            "package": {
                                "name": "lodash",
                                "version": "4.17.15"
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-jrfm-c6fg-c3gp",
                                    "aliases": ["CVE-2020-8203"],
                                    "summary": "Prototype pollution vulnerability in lodash",
                                    "details": "Lodash before 4.17.21 is vulnerable to prototype pollution"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        mock_proc = MagicMock()
        mock_proc.stdout = json.dumps(mock_output)
        mock_proc.returncode = 0
        return mock_proc

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)
    
    findings = scanner.scan()
    assert len(findings) == 1
    
    f = findings[0]
    assert f["type"] == "SCA"
    assert f["package"] == "lodash"
    assert f["installed"] == "4.17.15"
    assert f["cve"] == "CVE-2020-8203"
    assert f["severity"] == "high"
    assert f["file"] == "package-lock.json"


def test_sbom_generation_formats():
    import sbom_generator
    
    mock_dependencies = [
        {"package": "requests", "version": "2.28.0", "file": "requirements.txt"},
        {"package": "lodash", "version": "4.17.15", "file": "package-lock.json"},
        {"package": "log4j-core", "version": "2.14.1", "file": "pom.xml"}
    ]
    
    cdx = sbom_generator.generate_cyclonedx("test-repo", mock_dependencies)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert cdx["metadata"]["component"]["name"] == "test-repo"
    assert len(cdx["components"]) == 3
    
    req_comp = [c for c in cdx["components"] if c["name"] == "requests"][0]
    assert req_comp["version"] == "2.28.0"
    assert req_comp["purl"] == "pkg:pypi/requests@2.28.0"
    
    spdx = sbom_generator.generate_spdx("test-repo", mock_dependencies)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["name"] == "test-repo"
    assert len(spdx["packages"]) == 3
    
    req_pkg = [p for p in spdx["packages"] if p["name"] == "requests"][0]
    assert req_pkg["versionInfo"] == "2.28.0"
    assert req_pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.28.0"


def test_sbom_endpoint_success():
    import app
    from fastapi.testclient import TestClient
    
    app.last_scan_result = {
        "source_path": "/Users/test/workspace/my-repo",
        "dependencies": [
            {"package": "requests", "version": "2.28.0", "file": "requirements.txt"}
        ]
    }
    
    client = TestClient(app.app)
    
    res = client.get("/api/dashboard/sbom?format=cyclonedx")
    assert res.status_code == 200
    data = res.json()
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) == 1
    
    res = client.get("/api/dashboard/sbom?format=spdx")
    assert res.status_code == 200
    data = res.json()
    assert data["spdxVersion"] == "SPDX-2.3"
    assert len(data["packages"]) == 1


def test_iac_scanner_detects_dockerfile_root_user(tmp_path):
    from scanners import IacScanner
    
    # Create mock Dockerfile running as root
    docker_file = tmp_path / "Dockerfile"
    docker_file.write_text(
        "FROM alpine:3.18\n"
        "RUN apk add --no-cache curl\n"
        "COPY . /app\n"
        "ENTRYPOINT [\"python3\", \"/app/main.py\"]\n",
        encoding="utf-8"
    )
    
    scanner = IacScanner(tmp_path)
    findings = scanner.scan()
    
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "IAC"
    assert f["rule"] == "docker-run-as-root"
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-250"


def test_iac_scanner_detects_kubernetes_privileged_pod(tmp_path):
    from scanners import IacScanner
    
    # Create mock Kubernetes file
    k8s_file = tmp_path / "pod.yaml"
    k8s_file.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: privileged-pod\n"
        "spec:\n"
        "  containers:\n"
        "  - name: exploit-container\n"
        "    image: alpine:latest\n"
        "    securityContext:\n"
        "      privileged: true\n"
        "    volumeMounts:\n"
        "    - mountPath: /var/run/docker.sock\n"
        "      name: docker-socket\n",
        encoding="utf-8"
    )
    
    scanner = IacScanner(tmp_path)
    findings = scanner.scan()
    
    privileged_rules = [f["rule"] for f in findings]
    assert "k8s-privileged-pod" in privileged_rules
    assert "k8s-exposed-socket" in privileged_rules


def test_iac_scanner_detects_terraform_open_ingress(tmp_path):
    from scanners import IacScanner
    
    # Create mock Terraform security group ingress rule
    tf_file = tmp_path / "security.tf"
    tf_file.write_text(
        "resource \"aws_security_group\" \"allow_all\" {\n"
        "  ingress {\n"
        "    from_port   = 0\n"
        "    to_port     = 0\n"
        "    protocol    = \"-1\"\n"
        "    cidr_blocks = [\"0.0.0.0/0\"]\n"
        "  }\n"
        "}\n",
        encoding="utf-8"
    )
    
    scanner = IacScanner(tmp_path)
    findings = scanner.scan()
    
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "IAC"
    assert f["rule"] == "tf-open-security-group"
    assert f["severity"] == "high"


def test_deduplication_engine_groups_vulnerabilities(tmp_path):
    from sandbox import EphemeralSandbox
    
    # Create a sandbox instance
    sb = EphemeralSandbox()
    
    # Create mock findings list containing duplicate reports from different tools on the same file/line/cwe
    report = {
        "findings": [
            {
                "file": "/scan_target/users.py",
                "line": 81,
                "cwe": "CWE-89",
                "rule": "ast-shell-injection",
                "severity": "medium",
                "description": "AST detected SQL Injection"
            },
            {
                "file": "/scan_target/users.py",
                "line": 81,
                "cwe": "CWE-89",
                "rule": "bandit-B608",
                "severity": "high",
                "description": "Bandit detected SQL Injection"
            },
            {
                "file": "/scan_target/users.py",
                "line": 81,
                "cwe": "CWE-89",
                "rule": "ai-openai",
                "severity": "critical",
                "description": "AI detected SQL Injection"
            }
        ]
    }
    
    # Create target file with some code content
    project_dir = tmp_path / "mock_repo"
    project_dir.mkdir()
    users_file = project_dir / "users.py"
    content = ["# Empty line\n"] * 100
    content[80] = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')  # SQL Injection\n"
    users_file.write_text("".join(content), encoding="utf-8")
    
    # Run sanitize_findings
    sb._sanitize_findings(report, "mock_repo", project_dir)
    
    # Check that findings are merged
    findings = report["findings"]
    assert len(findings) == 1
    
    f = findings[0]
    assert f["file"] == "mock_repo/users.py"
    assert f["line"] == 81
    assert f["cwe"] == "CWE-89"
    # Assert CVSS exploitability reachability and risk calculations
    assert f["cvss"] == 9.8
    assert f["reachable"] == "YES"
    assert f["internet_exposed"] == "NO"
    assert f["exploitability"] == "MEDIUM"
    # 9.8 (cvss) * 0.85 (exploitability) * 1.0 (reachable) * 0.98 (confidence) * 0.7 (not exposed) = 5.7169 -> 5.7
    assert f["risk_score"] == 5.7
    assert f["severity"] == "medium"
    
    # Detectors: AST, Bandit, AI (OpenAI)
    assert "AST" in f["detected_by"]
    assert "Bandit" in f["detected_by"]
    assert "AI (OpenAI)" in f["detected_by"]
    
    # Combined confidence should be high (1 - 0.3 * 0.2 * 0.35 = 1 - 0.021 = 98%)
    assert f["confidence"] == 98
    
    # Check stable SHA-256 fingerprint exists
    assert len(f["fingerprint"]) == 64


def test_risk_score_calculation_internet_exposed(tmp_path):
    from sandbox import EphemeralSandbox
    
    sb = EphemeralSandbox()
    
    # Mock report with one finding
    report = {
        "findings": [
            {
                "file": "/scan_target/app.py",
                "line": 10,
                "cwe": "CWE-78",
                "rule": "ast-shell-injection",
                "severity": "medium",
                "description": "AST Shell injection"
            }
        ]
    }
    
    # Create target directory containing exposing ports/framework (ex: EXPOSE 80 in Dockerfile)
    project_dir = tmp_path / "mock_web_repo"
    project_dir.mkdir()
    (project_dir / "Dockerfile").write_text("EXPOSE 80\n", encoding="utf-8")
    (project_dir / "app.py").write_text("import os\n# line 10\nos.system(user_input)\n", encoding="utf-8")
    
    # Run sanitize_findings
    sb._sanitize_findings(report, "mock_web_repo", project_dir)
    
    findings = report["findings"]
    assert len(findings) == 1
    f = findings[0]
    
    # Verify risk parameters
    assert f["cvss"] == 9.8
    assert f["reachable"] == "YES"
    assert f["internet_exposed"] == "YES"
    assert f["exploitability"] == "MEDIUM"
    
    # 9.8 (cvss) * 0.85 (exploitability) * 1.0 (reachable) * 0.70 (confidence) * 1.0 (exposed) = 5.831 -> 5.8
    assert f["risk_score"] == 5.8
    assert f["severity"] == "medium"


def test_remediation_and_apply_endpoints(tmp_path):
    import app
    from fastapi.testclient import TestClient
    
    # 1. Create a dummy scan finding in the global last_scan_result
    fingerprint = "remediation-test-fingerprint-12345"
    
    project_dir = tmp_path / "patch_test_repo"
    project_dir.mkdir()
    target_file = project_dir / "app.py"
    target_file.write_text("subprocess.run(user_input, shell=True)\n", encoding="utf-8")
    
    app.last_scan_result = {
        "source_path": str(project_dir),
        "findings": [
            {
                "file": "patch_test_repo/app.py",
                "line": 1,
                "cwe": "CWE-78",
                "rule": "ast-shell-injection",
                "severity": "medium",
                "description": "AST Shell injection",
                "fingerprint": fingerprint
            }
        ]
    }
    
    client = TestClient(app.app)
    
    # 2. Test POST /api/remediation/remediate (action = explain)
    res = client.post("/api/remediation/remediate", json={
        "fingerprint": fingerprint,
        "action": "explain"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["fingerprint"] == fingerprint
    assert data["action"] == "explain"
    assert "why" in data["details"]
    assert "subprocess" in data["details"]["original_code"]
    assert isinstance(data["details"]["data_flow"], list)
    assert len(data["details"]["data_flow"]) > 0
    assert "step" in data["details"]["data_flow"][0]
    assert "type" in data["details"]["data_flow"][0]
    assert "label" in data["details"]["data_flow"][0]
    assert "code" in data["details"]["data_flow"][0]
    
    # 3. Test POST /api/remediation/apply
    res = client.post("/api/remediation/apply", json={
        "fingerprint": fingerprint,
        "original_code": "subprocess.run(user_input, shell=True)",
        "patch_code": "subprocess.run(['safe_cmd'], shell=False)"
    })
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    # Verify file content is updated
    updated_content = target_file.read_text(encoding="utf-8")
    assert "safe_cmd" in updated_content
    assert "shell=True" not in updated_content


def test_local_remediation_templates_have_valid_schemas():
    from app import LOCAL_REMEDIATION_TEMPLATES
    
    for cwe, data in LOCAL_REMEDIATION_TEMPLATES.items():
        assert "why" in data
        assert "source" in data
        assert "sink" in data
        assert "exploit" in data
        assert "cwe" in data
        assert "fix_desc" in data
        assert "original_code" in data
        assert "secure_code" in data
        assert "data_flow" in data
        assert isinstance(data["data_flow"], list)
        for node in data["data_flow"]:
            assert "step" in node
            assert "type" in node
            assert "label" in node
            assert "code" in node
            assert "description" in node


def test_github_pr_simulation_and_webhook_endpoints():
    import app
    from fastapi.testclient import TestClient
    
    # 1. Setup mock last_scan_result findings in app
    app.last_scan_result = {
        "findings": [
            {
                "file": "app/auth.py",
                "line": 87,
                "cwe": "CWE-89",
                "severity": "critical",
                "description": "SQL Injection vulnerability",
                "fingerprint": "pr-test-finding-fingerprint",
                "rule": "ast-sql-injection"
            }
        ]
    }
    
    client = TestClient(app.app)
    
    # 2. Test POST /api/github/simulate
    res = client.post("/api/github/simulate", json={
        "repo_name": "test-owner/test-repo",
        "pr_number": 100,
        "commit_sha": "abcdef12345",
        "branch": "feature/test"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["repo_name"] == "test-owner/test-repo"
    assert data["pr_number"] == 100
    assert data["check_run"]["conclusion"] == "failure"
    assert "CWE-89" in data["check_run"]["annotations"][0]["title"]
    assert "app/auth.py" in data["pr_comments"][0]["file"]
    
    # 3. Test GET /api/github/scans
    res_list = client.get("/api/github/scans")
    assert res_list.status_code == 200
    assert len(res_list.json()) > 0
    assert res_list.json()[0]["repo_name"] == "test-owner/test-repo"
    
    # 4. Test POST /api/github/webhook
    res_webhook = client.post("/api/github/webhook", json={
        "action": "opened",
        "number": 101,
        "repository": {"full_name": "test-owner/webhook-repo"},
        "pull_request": {
            "head": {
                "sha": "98765fedcba",
                "ref": "feature/webhook-branch"
            }
        }
    })
    assert res_webhook.status_code == 200
    assert res_webhook.json()["status"] == "processed"
    assert res_webhook.json()["result"]["repo_name"] == "test-owner/webhook-repo"
    assert res_webhook.json()["result"]["pr_number"] == 101


def test_security_policy_enforcement_and_gating(tmp_path):
    import yaml
    from sandbox import EphemeralSandbox
    from agentic_security_platform import load_security_policy
    
    # 1. Create a mock repository with a policy yaml file
    repo_dir = tmp_path / "mock-repo"
    repo_dir.mkdir()
    
    policy_data = {
        "security": {
            "fail_on": ["low"],
            "scanners": {
                "sast": True,
                "secrets": False, # disable secrets scanner
                "dependencies": True,
                "iac": True,
                "ai_review": False
            },
            "thresholds": {
                "critical": 0,
                "high": 0,
                "low": 1 # fail if > 1 Low finding
            },
            "sandbox": {
                "network": False,
                "timeout": 45,
                "memory": "512MB",
                "cpu": 1
            }
        }
    }
    
    policy_file = repo_dir / "security.yaml"
    policy_file.write_text(yaml.dump(policy_data), encoding="utf-8")
    
    # 2. Assert load_security_policy parses it correctly
    policy = load_security_policy(repo_dir)
    assert policy["scanners"]["secrets"] is False
    assert policy["scanners"]["sast"] is True
    assert policy["thresholds"]["low"] == 1
    assert policy["sandbox"]["timeout"] == 45
    
    # 3. Add a file with a credential string and check that it's ignored since secrets scanner is disabled
    secret_file = repo_dir / "keys.py"
    secret_file.write_text("AWS_KEY = 'AKIAIOSFODNN7INVALID'\n", encoding="utf-8")
    
    # 4. Trigger sandbox scan on mock-repo
    sandbox = EphemeralSandbox()
    report = sandbox.run_scan(str(repo_dir), scan_profile="local_only")
    
    # 5. Assert findings do NOT include secrets (since scanner was disabled in policy)
    findings = report.get("findings", [])
    assert not any(f.get("cwe") == "CWE-798" for f in findings)
    
    # 6. Assert gate_status is PASS (since 0 findings found)
    assert report.get("gate_status") == "PASS"
    
    # 7. Add two High findings to mock-repo (e.g. Dockerfile root user configurations)
    dockerfile = repo_dir / "Dockerfile"
    dockerfile.write_text("FROM alpine\nUSER root\n", encoding="utf-8")
    
    dockerfile2 = repo_dir / "docker-compose.yml"
    dockerfile2.write_text("version: '3'\nservices:\n  web:\n    privileged: true\n", encoding="utf-8")
    
    # Trigger scan again
    report2 = sandbox.run_scan(str(repo_dir), scan_profile="local_only")
    findings2 = report2.get("findings", [])
    
    # We should have at least 2 findings (Dockerfile USER root and compose privileged mode)
    print("FINDINGS2 IS:", findings2)
    assert len(findings2) >= 2
    
    # 8. Assert gate_status is SECURITY GATE FAILED (since 2 high findings exceeds threshold of 1)
    assert report2.get("gate_status") == "SECURITY GATE FAILED"
    assert len(report2.get("gate_reasons", [])) > 0


def test_sarif_export_generation_and_endpoint():
    import app
    from fastapi.testclient import TestClient
    from sarif_generator import generate_sarif_report
    
    # 1. Setup mock last_scan_result findings in app
    app.last_scan_result = {
        "findings": [
            {
                "file": "app/auth.py",
                "line": 87,
                "cwe": "CWE-89",
                "cwe_title": "SQL Injection",
                "cwe_description": "SQL injection description",
                "severity": "critical",
                "description": "SQL Injection vulnerability",
                "fingerprint": "sarif-test-finding-fingerprint",
                "rule": "ast-sql-injection"
            }
        ]
    }
    
    # 2. Test helper function
    sarif_data = generate_sarif_report(app.last_scan_result)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "Agentic Security Platform"
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["ruleId"] == "ast-sql-injection"
    assert sarif_data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/auth.py"
    
    # 3. Test HTTP endpoint
    client = TestClient(app.app)
    res = client.get("/api/dashboard/sarif")
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["version"] == "2.1.0"
    assert len(res_data["runs"][0]["results"]) == 1
