import json
import hashlib
from pathlib import Path
from typing import Any, Dict

def generate_sarif_report(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", [])
    
    # 1. Collect unique rules
    rules_map = {}
    for f in findings:
        cwe = f.get("cwe", "CWE-999")
        rule_id = f.get("rule", cwe)
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.get("rule", cwe).replace("-", "_"),
                "shortDescription": {
                    "text": f"{cwe}: {f.get('cwe_title', 'Vulnerability')}"
                },
                "fullDescription": {
                    "text": f.get("cwe_description", f.get("description", "Vulnerability detected."))
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html" if "-" in cwe else "https://cwe.mitre.org"
            }
            
    rules_list = list(rules_map.values())
    
    # 2. Map findings to SARIF results
    results = []
    for f in findings:
        cwe = f.get("cwe", "CWE-999")
        rule_id = f.get("rule", cwe)
        file_path = f.get("file", "unknown")
        line_no = f.get("line", 1)
        desc = f.get("description", "Vulnerability detected.")
        severity_str = f.get("severity", "medium").lower()
        
        # Map severity to SARIF level
        level = "warning"
        if severity_str in ["critical", "high"]:
            level = "error"
        elif severity_str == "low":
            level = "note"
            
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": desc
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": line_no,
                            "endLine": line_no
                        }
                    }
                }
            ]
        }
        results.append(result)
        
    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agentic Security Platform",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/skishu0413/Agentic-Security-Platform",
                        "rules": rules_list
                    }
                },
                "results": results
            }
        ]
    }
    
    return sarif_doc
