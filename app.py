from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", message=".*urllib3 v2.*")

import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

import json
import os
import signal
from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from contextlib import asynccontextmanager
from agentic_security_platform import AgenticSecurityPlatform, check_provider_configured

@asynccontextmanager
async def lifespan(app: FastAPI):
    import logging
    for logger_name in ["httpx", "httpcore"]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
    yield

app = FastAPI(title="Agentic Security Platform", version="0.1.0", lifespan=lifespan)
platform = AgenticSecurityPlatform()

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response: Response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Store last scan result for dashboard
last_scan_result: dict[str, Any] = {
    "summary": {"finding_count": 0, "scanned_files": 0, "covered_cwes": []},
    "findings": [],
    "providers": {
        "openai": {"enabled": check_provider_configured("openai")},
        "claude": {"enabled": check_provider_configured("claude")},
        "ollama": {"enabled": check_provider_configured("ollama")},
        "cursor": {"enabled": check_provider_configured("cursor")},
    },
}


class ReviewRequest(BaseModel):
    source_type: str = "local"  # "local" or "git"
    source_path: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = "main"
    scan_profile: str = "comprehensive"  # "comprehensive", "local_only", "ast_only"
    providers: Optional[List[str]] = None


class ReviewResponse(BaseModel):
    status: str
    report: dict[str, Any]


from sandbox import EphemeralSandbox

def run_request_scan(req: ReviewRequest) -> dict[str, Any]:
    sandbox = EphemeralSandbox()
    if req.source_type == "git":
        if not req.repo_url:
            raise HTTPException(status_code=400, detail="repo_url is required for git source type")
        report = sandbox.run_git_scan(
            repo_url=req.repo_url,
            branch=req.branch or "main",
            enabled_providers=req.providers,
            platform_instance=platform,
            scan_profile=req.scan_profile
        )
    else:
        if not req.source_path:
            raise HTTPException(status_code=400, detail="source_path is required for local source type")
        path = Path(req.source_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="source path not found")
        report = sandbox.run_scan(
            source_path=str(path),
            enabled_providers=req.providers,
            platform_instance=platform,
            scan_profile=req.scan_profile
        )
    return report


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/review", response_model=ReviewResponse)
def review(req: ReviewRequest) -> ReviewResponse:
    report = run_request_scan(req)
    return ReviewResponse(status="ok", report=report)


@app.get("/api/dashboard/stats")
def get_dashboard_stats() -> dict[str, Any]:
    return last_scan_result


@app.get("/api/dashboard/export")
def export_dashboard_stats():
    formatted_json = json.dumps(last_scan_result, indent=2)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=security_report.json"}
    )


@app.get("/api/dashboard/sarif")
def export_sarif():
    if not last_scan_result:
        raise HTTPException(status_code=400, detail="No scan report available. Run a scan first.")
        
    from sarif_generator import generate_sarif_report
    sarif_data = generate_sarif_report(last_scan_result)
    formatted_json = json.dumps(sarif_data, indent=2)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=security_report.sarif"}
    )


@app.get("/api/dashboard/sbom")
def export_sbom(format: str = "cyclonedx"):
    if not last_scan_result:
        raise HTTPException(status_code=400, detail="No scan report available. Run a scan first.")
    
    repo_name = "application"
    source_path = last_scan_result.get("source_path", "")
    if source_path:
        repo_name = Path(source_path).name
    
    dependencies = last_scan_result.get("dependencies", [])
    
    import sbom_generator
    if format.lower() == "spdx":
        sbom = sbom_generator.generate_spdx(repo_name, dependencies)
        filename = f"{repo_name}_sbom_spdx.json"
    else:
        sbom = sbom_generator.generate_cyclonedx(repo_name, dependencies)
        filename = f"{repo_name}_sbom_cyclonedx.json"
        
    formatted_json = json.dumps(sbom, indent=2)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.post("/api/dashboard/scan")
def dashboard_scan(req: ReviewRequest) -> dict[str, Any]:
    global last_scan_result
    report = run_request_scan(req)
    last_scan_result = report
    return {
        "status": "ok",
        "findings_count": report["summary"]["finding_count"],
        "scanned_files": report["summary"].get("scanned_files", 0),
        "scan_id": report.get("scan_id"),
    }


class RemediationRequest(BaseModel):
    fingerprint: str
    action: str  # "explain", "patch", "dataflow"

class ApplyPatchRequest(BaseModel):
    fingerprint: str
    original_code: str
    patch_code: str

LOCAL_REMEDIATION_TEMPLATES = {
    "CWE-78": {
        "why": "Using shell=True in subprocess calls spawns an intermediary shell process, allowing execution of untrusted commands via command separators (e.g. ;, &&).",
        "source": "Untrusted process parameters or external environment arguments.",
        "sink": "subprocess.run(..., shell=True) execution command statement.",
        "exploit": "Injecting input values containing shell delimiters to run arbitrary commands (e.g. user_input = '; rm -rf /').",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "fix_desc": "Set shell=False and pass commands and parameters as a secure arguments array/list of strings.",
        "original_code": "subprocess.run(user_command, shell=True)",
        "secure_code": "subprocess.run([\"command\", \"validated_argument\"], shell=False, check=True)",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "Process Parameter Capture", "code": "user_command = request.args[\"cmd\"]", "description": "Untrusted execution command argument is captured."},
            {"step": 2, "type": "PROPAGATION", "label": "Arguments Preparation", "code": "payload = f\"ping {user_command}\"", "description": "Command string is prepared via parameter formatting."},
            {"step": 3, "type": "SINK", "label": "System Shell Execution", "code": "subprocess.run(payload, shell=True)", "description": "Prepared string is passed to OS shell for execution."}
        ]
    },
    "CWE-94": {
        "why": "Passing untrusted input strings directly to eval() or exec() executes arbitrary code within the current Python interpreter environment.",
        "source": "Untrusted query parameter or user-submitted string.",
        "sink": "eval() or exec() invocation statements.",
        "exploit": "Inputting a payload that utilizes Python built-ins to invoke host processes (e.g., eval('__import__(\"os\").system(...)')).",
        "cwe": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
        "fix_desc": "Use dictionary mapping structures or parse data with safe serializers such as ast.literal_eval.",
        "original_code": "eval(user_input)",
        "secure_code": "import ast\nast.literal_eval(user_input)",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "Untrusted Parameter Input", "code": "user_input = request.json[\"code\"]", "description": "Dynamic payload input is received."},
            {"step": 2, "type": "PROPAGATION", "label": "Memory Load", "code": "statement = user_input", "description": "Input payload loaded into runtime memory state."},
            {"step": 3, "type": "SINK", "label": "Interpreter Evaluation", "code": "eval(statement)", "description": "Python interpreter evaluates string payload directly."}
        ]
    },
    "CWE-89": {
        "why": "Concatenating untrusted input parameters directly into SQL query strings allows attackers to manipulate the database query execution structure.",
        "source": "Untrusted user query inputs.",
        "sink": "cursor.execute() or database query invocation.",
        "exploit": "Passing payload inputs (e.g. `' OR '1'='1`) to bypass authentication checks or fetch/manipulate arbitrary rows.",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "fix_desc": "Use parameterized queries or prepared statements instead of string formatting/concatenation.",
        "original_code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
        "secure_code": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "HTTP Request Parameter", "code": "user_id = request.args.get('id')", "description": "Untrusted request parameter is loaded."},
            {"step": 2, "type": "PROPAGATION", "label": "String Concatenation", "code": "sql_query = f'SELECT * FROM users WHERE id = {user_id}'", "description": "Parameter value concatenated directly into query string definition."},
            {"step": 3, "type": "SINK", "label": "Database Engine Execution", "code": "cursor.execute(sql_query)", "description": "Concatenated command string passed directly to query engine."}
        ]
    },
    "CWE-798": {
        "why": "Hardcoded secrets and API keys are stored directly in plaintext within version control, making them accessible to any reader of the source code repository.",
        "source": "Plaintext secret token string in source code file.",
        "sink": "Variable assignment or service client initialization.",
        "exploit": "Cloning the repository and extracting key secrets or API tokens to run requests against services.",
        "cwe": "CWE-798: Use of Hardcoded Credentials",
        "fix_desc": "Store keys securely in system environment variables or cloud secret managers and load them dynamically.",
        "original_code": "API_KEY = \"sk-abcdef1234567890abcdef1234567890abcd\"",
        "secure_code": "import os\nAPI_KEY = os.environ.get(\"API_KEY\")",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "Plaintext definition", "code": "API_KEY = \"sk-abcdef123456...\"", "description": "Private key string hardcoded in version control."},
            {"step": 2, "type": "PROPAGATION", "label": "Client Setup", "code": "client = Client(api_key=API_KEY)", "description": "API client initialized with hardcoded key credentials."},
            {"step": 3, "type": "SINK", "label": "External Service Query", "code": "client.query_data()", "description": "Hardcoded keys sent to external API endpoints."}
        ]
    },
    "CWE-250": {
        "why": "Running a container build as root allows potential breakouts and host system hijacking if processes in the container are compromised.",
        "source": "Dockerfile build recipe file.",
        "sink": "Missing USER configuration or USER root specification.",
        "exploit": "Triggering container escape vulnerabilities to escalate privileges and access host system namespace files.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "fix_desc": "Define and switch execution context to a non-privileged app user in build recipes.",
        "original_code": "FROM alpine\nRUN apk add ...",
        "secure_code": "FROM alpine\nRUN adduser -D appuser && chown -R appuser /app\nUSER appuser",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "Base Image Recipe", "code": "FROM alpine", "description": "Container base image setup."},
            {"step": 2, "type": "PROPAGATION", "label": "Dependency Build", "code": "RUN apk add curl", "description": "Build command execution layers run as root context."},
            {"step": 3, "type": "SINK", "label": "Container Context Entrypoint", "code": "CMD [\"sh\"]", "description": "Entrypoint executed with unrestricted host escape space."}
        ]
    },
    "CWE-284": {
        "why": "Allowing public open access to cloud buckets, open security group ingress, or mounting host Docker sockets creates excessive permission interfaces.",
        "source": "IaC config definitions (tf, yaml).",
        "sink": "Public ACL block or host volume mount declaration.",
        "exploit": "Scanning public endpoints to extract S3 files directly, or leveraging mounted sockets inside a container to run root commands on the host.",
        "cwe": "CWE-284: Improper Access Control",
        "fix_desc": "Set private ACL structures and remove host socket mounts.",
        "original_code": "acl = \"public-read\"",
        "secure_code": "acl = \"private\"",
        "data_flow": [
            {"step": 1, "type": "SOURCE", "label": "Public Privilege Declaration", "code": "acl = \"public-read\"", "description": "Open public access permission specified."},
            {"step": 2, "type": "PROPAGATION", "label": "Resource Setup", "code": "bucket = s3.create(acl)", "description": "Bucket configuration references permission parameters."},
            {"step": 3, "type": "SINK", "label": "Public Access Interface", "code": "s3.deploy()", "description": "Cloud bucket initialized and exposed anonymously."}
        ]
    }
}

def apply_code_patch(source_path: str, relative_file: str, line_no: int | None, original_line: str, new_code: str) -> bool:
    try:
        workspace = Path(source_path).resolve()
        parts = Path(relative_file).parts
        if len(parts) > 1:
            sub_path = Path(*parts[1:])
        else:
            sub_path = Path(relative_file)
            
        target_file = (workspace / sub_path).resolve()
        if not target_file.exists():
            return False
            
        content = target_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        
        # 1. Try line-based replacement
        if line_no is not None and 1 <= line_no <= len(lines):
            target_line = lines[line_no - 1]
            if not original_line or original_line.strip() in target_line.strip() or target_line.strip() in original_line.strip():
                lines[line_no - 1] = new_code
                target_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return True
                
        # 2. String-based replacement fallback
        if original_line and original_line.strip() in content:
            new_content = content.replace(original_line.strip(), new_code.strip())
            target_file.write_text(new_content, encoding="utf-8")
            return True
            
    except Exception:
        pass
    return False

@app.post("/api/remediation/remediate")
def get_remediation_details(req: RemediationRequest) -> dict[str, Any]:
    global last_scan_result
    findings = last_scan_result.get("findings", [])
    
    finding = None
    for f in findings:
        if f.get("fingerprint") == req.fingerprint:
            finding = f
            break
            
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    cwe_id = finding.get("cwe", "CWE-999")
    file_name = finding.get("file", "")
    line_no = finding.get("line")
    
    sink_code = ""
    source_path = last_scan_result.get("source_path", "")
    if source_path and file_name and line_no is not None:
        try:
            workspace = Path(source_path).resolve()
            parts = Path(file_name).parts
            if len(parts) > 1:
                sub_path = Path(*parts[1:])
            else:
                sub_path = Path(file_name)
            target_file = (workspace / sub_path).resolve()
            if target_file.exists():
                lines = target_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                if 1 <= line_no <= len(lines):
                    sink_code = lines[line_no - 1].strip()
        except Exception:
            pass
            
    remediation_data = None
    try:
        remediation_data = platform.generate_remediation_with_ai(finding, sink_code)
    except Exception:
        pass
        
    if not remediation_data:
        remediation_data = LOCAL_REMEDIATION_TEMPLATES.get(cwe_id)
        if not remediation_data:
            remediation_data = {
                "why": f"This code uses a pattern mapped to {cwe_id} which represents a potential security vulnerability.",
                "source": "Untrusted input parameters.",
                "sink": sink_code or "Vulnerable instruction line.",
                "exploit": "Varying exploit payloads depending on execution scope.",
                "cwe": f"{cwe_id}: Mapped security vulnerability pattern",
                "fix_desc": "Refactor code to sanitize parameter inputs and validate arguments.",
                "original_code": sink_code or "Vulnerable line of code",
                "secure_code": f"# Secured replacement code\n{sink_code or 'pass'}",
                "data_flow": [
                    {"step": 1, "type": "SOURCE", "label": "Untrusted parameter input", "code": sink_code or "Insecure input", "description": "Data enters system from untrusted source."},
                    {"step": 2, "type": "PROPAGATION", "label": "Data propagation path", "code": sink_code or "Insecure code line", "description": "Data is passed to sink without sanitization."},
                    {"step": 3, "type": "SINK", "label": "Vulnerable execution", "code": sink_code or "Insecure execution", "description": f"Sink executes instructions triggering risk mapped to {cwe_id}."}
                ]
            }
            
    if not remediation_data.get("original_code"):
        remediation_data["original_code"] = sink_code or "Insecure code line"
        
    return {
        "fingerprint": req.fingerprint,
        "action": req.action,
        "details": remediation_data
    }

@app.post("/api/remediation/apply")
def apply_patch(req: ApplyPatchRequest) -> dict[str, str]:
    global last_scan_result
    findings = last_scan_result.get("findings", [])
    
    finding = None
    for f in findings:
        if f.get("fingerprint") == req.fingerprint:
            finding = f
            break
            
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    source_path = last_scan_result.get("source_path", "")
    file_name = finding.get("file", "")
    line_no = finding.get("line")
    
    if not source_path or not file_name:
        raise HTTPException(status_code=400, detail="Missing workspace context for patch application")
        
    success = apply_code_patch(source_path, file_name, line_no, req.original_code, req.patch_code)
    if success:
        return {"status": "success", "message": f"Successfully applied security patch to {file_name} on line {line_no}!"}
    else:
        raise HTTPException(status_code=500, detail="Failed to locate original code for patch application. Code may have changed.")


# Store simulated GitHub PR scans history
github_pr_scans: list[dict[str, Any]] = []

class GitHubPRSimulationRequest(BaseModel):
    repo_name: str = "Agentic-Security-Platform"
    pr_number: int = 42
    commit_sha: str = "a1b2c3d4e5f6g7h8i9j0"
    branch: str = "feature/auth-bypass"

@app.post("/api/github/simulate")
def simulate_github_pr_scan(req: GitHubPRSimulationRequest) -> dict[str, Any]:
    global last_scan_result, github_pr_scans
    
    findings = last_scan_result.get("findings", [])
    if not findings:
        findings = [
            {
                "file": "app/auth.py",
                "line": 87,
                "cwe": "CWE-89",
                "severity": "critical",
                "description": "Untrusted request input reaches SQL execution.",
                "fingerprint": "mock-github-pr-sql-injection-fingerprint",
                "rule": "ast-sql-injection"
            }
        ]
        
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    
    gate_failed = False
    if last_scan_result.get("gate_status") == "SECURITY GATE FAILED":
        gate_failed = True
    else:
        gate_failed = (critical > 0 or high > 0)
        
    conclusion = "failure" if gate_failed else "success"
    check_title = "Security Gate Failed" if gate_failed else "Security Gate Passed"
    
    annotations = []
    pr_comments = []
    for f in findings:
        severity = f.get("severity", "medium").upper()
        cwe_id = f.get("cwe", "CWE-999")
        file_path = f.get("file", "app.py")
        line_no = f.get("line", 1)
        desc = f.get("description", "Security vulnerability detected.")
        
        remediation_advice = "Validate and sanitize input parameters before passing to sink operations."
        local_remedy = LOCAL_REMEDIATION_TEMPLATES.get(cwe_id)
        if local_remedy:
            remediation_advice = local_remedy.get("fix_desc", remediation_advice)
            
        annotation = {
            "path": file_path,
            "start_line": line_no,
            "end_line": line_no,
            "annotation_level": "failure" if f.get("severity") in ["critical", "high"] else "warning",
            "title": f"{cwe_id}: {f.get('rule', 'Vulnerability')}",
            "message": f"{desc}\n\nSuggested remediation:\n{remediation_advice}"
        }
        annotations.append(annotation)
        
        pr_comment = {
            "file": file_path,
            "line": line_no,
            "body": f"### ⚠️ {cwe_id}\n\n{desc}\n\n**Suggested remediation:**\n{remediation_advice}"
        }
        pr_comments.append(pr_comment)
        
    summary = f"{critical} Critical, {high} High, {medium} Medium, {low} Low findings detected."
    
    pr_scan_report = {
        "repo_name": req.repo_name,
        "pr_number": req.pr_number,
        "commit_sha": req.commit_sha,
        "branch": req.branch,
        "timestamp": "2026-08-19T08:38:06-04:00",
        "check_run": {
            "name": "Agentic Security Check",
            "status": "completed",
            "conclusion": conclusion,
            "title": check_title,
            "summary": summary,
            "annotations": annotations
        },
        "pr_comments": pr_comments
    }
    
    github_pr_scans.insert(0, pr_scan_report)
    return pr_scan_report

@app.get("/api/github/scans")
def get_github_pr_scans() -> list[dict[str, Any]]:
    return github_pr_scans

@app.post("/api/github/webhook")
async def github_webhook(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
        
    pr = body.get("pull_request")
    repository = body.get("repository", {})
    
    if not pr:
        return {"status": "ignored", "reason": "Not a pull request event"}
        
    pr_number = body.get("number", 1)
    repo_name = repository.get("full_name", "unknown/repo")
    commit_sha = pr.get("head", {}).get("sha", "unknown-sha")
    branch = pr.get("head", {}).get("ref", "main")
    
    sim_request = GitHubPRSimulationRequest(
        repo_name=repo_name,
        pr_number=pr_number,
        commit_sha=commit_sha,
        branch=branch
    )
    result = simulate_github_pr_scan(sim_request)
    return {"status": "processed", "result": result}


@app.get("/")
def serve_dashboard() -> FileResponse:
    return FileResponse("static/index.html", media_type="text/html")


@app.post("/api/shutdown")
def shutdown() -> dict[str, str]:
    def exit_server():
        os.kill(os.getpid(), signal.SIGTERM)
    
    import threading
    threading.Thread(target=exit_server, daemon=True).start()
    return {"status": "shutting down"}


app.mount("/static", StaticFiles(directory="static"), name="static")
