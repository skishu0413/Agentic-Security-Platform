from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agentic_security_platform import AgenticSecurityPlatform

app = FastAPI(title="Agentic Security Platform", version="0.1.0")
platform = AgenticSecurityPlatform()

# Store last scan result for dashboard
last_scan_result: dict[str, Any] = {
    "summary": {"finding_count": 0, "scanned_files": 0, "covered_cwes": []},
    "findings": [],
    "providers": {"openai": {"enabled": True}, "claude": {"enabled": True}, "ollama": {"enabled": True}},
}



class ReviewRequest(BaseModel):
    source_path: str


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
    report = platform.run_review(str(path))
    return ReviewResponse(status="ok", report=report)


@app.get("/api/dashboard/stats")
def get_dashboard_stats() -> dict[str, Any]:
    return last_scan_result


@app.post("/api/dashboard/scan")
def dashboard_scan(req: ReviewRequest) -> dict[str, Any]:
    global last_scan_result
    path = Path(req.source_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="source path not found")
    report = platform.run_review(str(path))
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
