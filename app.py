from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agentic_security_platform import AgenticSecurityPlatform, check_provider_configured

app = FastAPI(title="Agentic Security Platform", version="0.1.0")
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
    source_path: str
    providers: Optional[List[str]] = None


class ReviewResponse(BaseModel):
    status: str
    report: dict[str, Any]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/review", response_model=ReviewResponse)
def review(req: ReviewRequest) -> ReviewResponse:
    path = Path(req.source_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="source file not found")
    report = platform.run_review(str(path), enabled_providers=req.providers)
    return ReviewResponse(status="ok", report=report)


@app.get("/api/dashboard/stats")
def get_dashboard_stats() -> dict[str, Any]:
    return last_scan_result


@app.get("/api/dashboard/export")
def export_dashboard_stats():
    from fastapi import Response
    formatted_json = json.dumps(last_scan_result, indent=2)
    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=security_report.json"}
    )


@app.post("/api/dashboard/scan")
def dashboard_scan(req: ReviewRequest) -> dict[str, Any]:
    global last_scan_result
    path = Path(req.source_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="source path not found")
    report = platform.run_review(str(path), enabled_providers=req.providers)
    last_scan_result = report
    return {
        "status": "ok",
        "findings_count": report["summary"]["finding_count"],
        "scanned_files": report["summary"].get("scanned_files", 0),
    }


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
