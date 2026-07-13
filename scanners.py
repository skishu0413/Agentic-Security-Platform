from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class ScannerIntegration:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def run_bandit(self) -> list[dict[str, Any]]:
        if shutil.which("bandit") is None:
            return []
        result = subprocess.run(
            ["bandit", "-r", str(self.root), "-f", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            return []
        try:
            payload = json.loads(result.stdout or "{}")
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
