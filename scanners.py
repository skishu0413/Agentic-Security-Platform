from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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
