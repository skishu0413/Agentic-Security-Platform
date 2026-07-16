from __future__ import annotations

from typing import Any
from cwe import Database

db = Database()

def get_cwe_details(cwe_id: str) -> dict[str, str]:
    """Resolve the title and description for a given CWE ID using the cwe library."""
    cwe_id = cwe_id.strip().upper()
    if not cwe_id.startswith("CWE-"):
        return {"title": cwe_id, "description": "Unknown CWE identifier."}

    # Extract digits: CWE-78 -> 78
    cwe_number_str = cwe_id.split("-")[-1]
    if cwe_number_str.isdigit():
        cwe_number = int(cwe_number_str)
        try:
            weakness = db.get(cwe_number)
            if weakness:
                return {
                    "title": weakness.name or f"CWE-{cwe_number} Definition",
                    "description": weakness.description or "No description available."
                }
        except Exception:
            pass

    return {
        "title": f"{cwe_id} Vulnerability",
        "description": "Vulnerability description not found in local database. Please verify CWE ID."
    }


def map_bandit_cwe(test_id: str, issue_cwe: dict[str, Any] | None = None) -> str:
    """Map a Bandit result dynamically using its issue_cwe metadata."""
    if issue_cwe and isinstance(issue_cwe, dict):
        cwe_id = issue_cwe.get("id")
        if cwe_id:
            if isinstance(cwe_id, int):
                return f"CWE-{cwe_id}"
            if isinstance(cwe_id, str):
                if not cwe_id.startswith("CWE-"):
                    return f"CWE-{cwe_id}"
                return cwe_id

    # Fallback to standard general injection CWE
    return "CWE-77"
