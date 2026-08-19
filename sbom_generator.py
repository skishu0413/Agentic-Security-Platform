import datetime
import uuid
from typing import Any

def generate_cyclonedx(repo_name: str, dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate a standard CycloneDX JSON v1.5 SBOM representation."""
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    
    components = []
    seen = set()
    for dep in dependencies:
        name = dep.get("package", "")
        version = dep.get("version", "")
        file_path = dep.get("file", "requirements.txt")
        if not name or not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        
        purl_type = get_purl_type(file_path)
        purl = f"pkg:{purl_type}/{name}@{version}"
        
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        })
        
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Agentic-Security-Platform",
                        "version": "0.1.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": repo_name
            }
        },
        "components": components
    }

def generate_spdx(repo_name: str, dependencies: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate a standard SPDX JSON v2.3 SBOM representation."""
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    doc_namespace = f"https://spdx.org/spdxdocs/{repo_name}-{uuid.uuid4()}"
    
    packages = []
    relationships = []
    
    seen = set()
    for dep in dependencies:
        name = dep.get("package", "")
        version = dep.get("version", "")
        file_path = dep.get("file", "requirements.txt")
        if not name or not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        
        purl_type = get_purl_type(file_path)
        purl = f"pkg:{purl_type}/{name}@{version}"
        spdx_id = f"SPDXRef-Package-{name}-{version}".replace("@", "-").replace("/", "-").replace("_", "-")
        
        packages.append({
            "name": name,
            "SPDXID": spdx_id,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl
                }
            ]
        })
        
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES"
        })
        
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": repo_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [
                "Tool: Agentic-Security-Platform-0.1.0"
            ]
        },
        "packages": packages,
        "relationships": relationships
    }

def get_purl_type(file_name: str) -> str:
    name = file_name.lower()
    if "requirements.txt" in name or "poetry.lock" in name or "pipfile.lock" in name:
        return "pypi"
    if "package-lock.json" in name or "yarn.lock" in name or "pnpm-lock.yaml" in name:
        return "npm"
    if "pom.xml" in name or "build.gradle" in name:
        return "maven"
    if "go.mod" in name:
        return "golang"
    if "cargo.lock" in name:
        return "cargo"
    if "gemfile.lock" in name:
        return "gem"
    if "composer.lock" in name:
        return "composer"
    return "generic"
