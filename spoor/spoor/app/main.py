"""Spoor API. In-memory, per-session state (no database needed for a stateless analysis tool)."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .evaluate import evaluate
from .generator import generate
from .parsers import ingest
from .pipeline import analyze

ROOT = Path(__file__).resolve().parent.parent
MAX_FILES = 12
MAX_BYTES = 40 * 1024 * 1024
MAX_SESSIONS = 40

app = FastAPI(title="Spoor", version="1.0.0", description="Follow the intruder's trail: log forensics with explainable attack timelines.")
SESSIONS: "OrderedDict[str, dict]" = OrderedDict()


def _session(sid: Optional[str], create=False) -> tuple:
    if sid and sid in SESSIONS:
        SESSIONS.move_to_end(sid)
        return sid, SESSIONS[sid]
    if not create:
        raise HTTPException(404, "No logs loaded for this session. Generate a scenario or upload log files first.")
    sid = uuid.uuid4().hex[:12]
    SESSIONS[sid] = {}
    while len(SESSIONS) > MAX_SESSIONS:
        SESSIONS.popitem(last=False)
    return sid, SESSIONS[sid]


def _summary(parsed: dict, sid: str, extra: Optional[dict] = None) -> dict:
    return {
        "sid": sid, "events": len(parsed["events"]), "files": parsed["files"], "warnings": parsed["warnings"],
        "quarantined": parsed["quarantine_total"], "duplicates_dropped": parsed["duplicates_dropped"],
        **(extra or {}),
    }


class GenerateReq(BaseModel):
    seed: Optional[int] = Field(None, ge=0, le=10**9)
    scale: float = Field(1.0, ge=0.3, le=3.0)


@app.get("/api/health")
def health():
    return {"status": "ok", "sessions": len(SESSIONS)}


@app.post("/api/generate")
def api_generate(req: GenerateReq, x_session: Optional[str] = Header(None)):
    seed = req.seed if req.seed is not None else int(time.time() * 1000) % 1_000_000
    now = datetime.now(timezone.utc)
    g = generate(seed, now, req.scale)
    parsed = ingest(list(g["files"].items()), now)
    sid, s = _session(x_session, create=True)
    s.clear()
    s.update(parsed=parsed, files=g["files"], truth=g["truth"], report=None, events=parsed["events"], seed=seed)
    return _summary(parsed, sid, {"seed": seed, "synthetic": True})


@app.post("/api/upload")
async def api_upload(files: List[UploadFile] = File(...), x_session: Optional[str] = Header(None)):
    if not files:
        raise HTTPException(400, "Choose at least one log file.")
    if len(files) > MAX_FILES:
        raise HTTPException(413, f"Upload at most {MAX_FILES} files at a time.")
    blobs, total = [], 0
    for f in files:
        data = await f.read()
        total += len(data)
        if total > MAX_BYTES:
            raise HTTPException(413, f"Upload is larger than {MAX_BYTES // 1024 // 1024} MB. Split the logs and try again.")
        blobs.append((f.filename or "upload.log", data))
    parsed = ingest(blobs, datetime.now(timezone.utc))
    if not parsed["events"]:
        raise HTTPException(422, "No usable events found. " + (" ".join(parsed["warnings"]) or
                            "Supported: syslog/auth.log, nginx/Apache access logs, flow CSV, generic CSV and JSON lines."))
    sid, s = _session(x_session, create=True)
    s.clear()
    s.update(parsed=parsed, files=None, truth=None, report=None, events=parsed["events"], seed=None)
    return _summary(parsed, sid, {"synthetic": False})


@app.post("/api/analyze")
def api_analyze(x_session: Optional[str] = Header(None)):
    sid, s = _session(x_session)
    s["report"] = analyze(s["parsed"])
    return s["report"]


@app.get("/api/events")
def api_events(ids: str = Query(..., description="comma-separated event ids"), x_session: Optional[str] = Header(None)):
    _, s = _session(x_session)
    try:
        want = [int(x) for x in ids.split(",") if x.strip()][:300]
    except ValueError:
        raise HTTPException(400, "ids must be integers")
    ev = s["events"]
    return [{"id": i, "file": ev[i].file, "line": ev[i].line, "ts": ev[i].ts.strftime("%Y-%m-%d %H:%M:%S"),
             "raw": ev[i].raw[:400]} for i in want if 0 <= i < len(ev)]


@app.get("/api/evaluate")
def api_evaluate(x_session: Optional[str] = Header(None)):
    _, s = _session(x_session)
    if not s.get("truth"):
        raise HTTPException(409, "Evaluation needs ground truth, which only exists for generated scenarios.")
    if not s.get("report"):
        raise HTTPException(409, "Run the analysis first.")
    out = evaluate(s["report"], {e.id: e for e in s["events"]}, s["truth"])
    out["truth"] = {k: v for k, v in s["truth"].items() if k not in ("attack_lines", "decoy_lines")}
    return out


@app.get("/api/download/logs")
def api_download_logs(x_session: Optional[str] = Header(None), sid: Optional[str] = None):
    _, s = _session(x_session or sid)
    if not s.get("files"):
        raise HTTPException(409, "Only generated scenarios can be downloaded; uploaded files are already yours.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in s["files"].items():
            z.writestr(name, text)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="spoor-scenario-{s["seed"]}.zip"'})


@app.get("/api/report.json")
def api_report(x_session: Optional[str] = Header(None), sid: Optional[str] = None):
    _, s = _session(x_session or sid)
    if not s.get("report"):
        raise HTTPException(409, "Run the analysis first.")
    rep = {k: v for k, v in s["report"].items() if k != "quarantine"}
    for inc in rep["incidents"]:
        inc.pop("evidence_ids", None)
    return Response(json.dumps(rep, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="spoor-report.json"'})


@app.exception_handler(Exception)
async def unhandled(_, exc):                                   # never leak a stack trace to the UI
    return JSONResponse({"detail": "Unexpected server error while processing the logs. The input was not modified."}, status_code=500)


app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")
