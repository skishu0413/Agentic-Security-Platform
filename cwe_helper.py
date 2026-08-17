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


def get_remediation(cwe_id: str) -> str:
    """Provide professional remediation guidelines based on CWE ID."""
    cwe_id = cwe_id.strip().upper()
    remediations = {
        "CWE-78": "Avoid executing system shell commands. Use python standard library modules (e.g., subprocess with shell=False and pass arguments as a list) or native APIs.",
        "CWE-94": "Avoid dynamic code execution (eval, exec). Use safe parsing alternatives (e.g., ast.literal_eval or json deserialization) instead.",
        "CWE-295": "Ensure SSL certificate verification is enabled (do not set verify=False in requests or equivalent connection libraries).",
        "CWE-502": "Do not deserialize untrusted data using standard library pickle or yaml.load. Use secure formats like JSON, or yaml.safe_load.",
        "CWE-77": "Sanitize all parameters passed to external commands. Avoid dynamic string building; use parameterized executions or API-level boundaries.",
        "CWE-79": "Use contextual auto-escaping templating engines (e.g., Jinja2, React) and sanitize user inputs before rendering them on UI web pages."
    }
    return remediations.get(cwe_id, "Perform strict input validation, enforce boundary/type checking, and implement strict output encoding/sanitization for all external inputs.")


import hashlib

def generate_fingerprint(file: str, line: int | None, rule: str, cwe: str) -> str:
    """Generate a deterministic SHA-256 fingerprint for a finding."""
    line_str = str(line) if line is not None else "0"
    content = f"{file}:{line_str}:{rule}:{cwe}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
