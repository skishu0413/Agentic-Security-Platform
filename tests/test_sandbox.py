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
