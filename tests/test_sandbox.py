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
    assert len(findings) >= 4
    
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
