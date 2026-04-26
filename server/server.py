"""
EDEN×MISTCODER — Real-Time Intelligence Server
FastAPI + WebSockets + APScheduler
"""
import asyncio
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

# ── Config ──────────────────────────────────────────────────────────────
SCAN_INTERVAL   = int(os.getenv("SCAN_INTERVAL_MINUTES", "5"))
PORT            = int(os.getenv("PORT", "8000"))
# Default reports dir = two levels up from server.py (repo root/reports)
_HERE           = Path(__file__).parent
REPORTS         = Path(os.getenv("REPORTS_DIR", str(_HERE.parent / "reports")))
BIO_TOKENS_FILE = REPORTS / "bio_tokens.json"
EDEN_REPORT     = REPORTS / "eden_report.json"
MISTCODER_SARIF = REPORTS / "mistcoder.sarif"

app = FastAPI(title="EDEN×MISTCODER", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Global state ─────────────────────────────────────────────────────────
clients:      Set[WebSocket] = set()
scan_running: bool           = False
last_scan:    str | None     = None
scan_count:   int            = 0


# ── Helpers ───────────────────────────────────────────────────────────────
def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Data loaders ──────────────────────────────────────────────────────────
def get_stats() -> dict:
    tokens   = _load(BIO_TOKENS_FILE) or []
    eden     = _load(EDEN_REPORT)     or {}
    sarif    = _load(MISTCODER_SARIF) or {}

    if isinstance(tokens, list):
        certified    = len(tokens)
        total_co2    = sum(t.get("co2_at_risk", 0) for t in tokens)
        total_ha     = sum(t.get("area_ha",     0) for t in tokens)
        avg_score    = (sum(t.get("bio_score", 0) for t in tokens) / max(1, certified))
    else:
        certified = total_co2 = total_ha = avg_score = 0

    vuln_count = 0
    for run in sarif.get("runs", []):
        vuln_count += len(run.get("results", []))

    return {
        "total_co2":        round(total_co2),
        "certified_tokens": certified,
        "total_ha":         round(total_ha),
        "eco_events":       eden.get("total_events", 0),
        "vulns_detected":   vuln_count,
        "bioscore_avg":     round(avg_score, 2),
        "blocks_on_chain":  eden.get("blocks_on_chain", 0),
        "blocked_events":   eden.get("blocked_events", 0),
        "scan_count":       scan_count,
        "scan_running":     scan_running,
        "last_scan":        last_scan,
        "next_scan_in":     SCAN_INTERVAL * 60,
    }


def get_eco_blocks() -> list:
    eden   = _load(EDEN_REPORT) or {}
    events = eden.get("events", [])
    blocks = []
    for i, ev in enumerate(events):
        blocks.append({
            "index":     ev.get("block_index", 78 + i),
            "type":      "ECO",
            "subtype":   ev.get("scanner", "NDVI"),
            "event":     ev.get("event_type", "ECO_EVENT"),
            "region":    ev.get("region", ""),
            "score":     ev.get("bio_score", 0),
            "co2":       ev.get("co2_at_risk", 0),
            "status":    ev.get("status", "CERTIFIED"),
            "hash":      ev.get("block_hash", "")[:14],
            "timestamp": ev.get("timestamp", _now()),
        })
    return blocks


def get_code_blocks() -> list:
    sarif  = _load(MISTCODER_SARIF) or {}
    blocks = []
    idx    = 1
    for run in sarif.get("runs", []):
        lang = run.get("tool", {}).get("driver", {}).get("name", "CODE")
        for result in run.get("results", []):
            locs = result.get("locations", [])
            file_path = ""
            if locs:
                uri = locs[0].get("physicalLocation", {}) \
                             .get("artifactLocation", {}) \
                             .get("uri", "")
                file_path = Path(uri).name if uri else ""
            blocks.append({
                "index":   idx,
                "type":    "CODE",
                "subtype": lang,
                "event":   result.get("ruleId", "CVE-UNKNOWN"),
                "region":  file_path,
                "score":   None,
                "status":  result.get("level", "error").upper(),
                "hash":    "",
                "timestamp": _now(),
            })
            idx += 1
    return blocks


def get_all_blocks() -> list:
    blocks = get_eco_blocks() + get_code_blocks()
    return sorted(blocks, key=lambda b: b["index"], reverse=True)


def get_tokens() -> list:
    tokens = _load(BIO_TOKENS_FILE) or []
    return tokens if isinstance(tokens, list) else []


def get_ndvi_feed() -> list:
    eden = _load(EDEN_REPORT) or {}
    return eden.get("ndvi_readings", [])


def get_acoustic_feed() -> list:
    eden = _load(EDEN_REPORT) or {}
    return eden.get("acoustic_events", [])


def get_regions() -> list:
    eden = _load(EDEN_REPORT) or {}
    return eden.get("regions", [])


# ── Broadcast ─────────────────────────────────────────────────────────────
async def broadcast(msg: dict):
    if not clients:
        return
    text = json.dumps(msg)
    dead = set()
    for ws in clients:
        try:
            await ws.send_text(text)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


# ── Scan pipeline ─────────────────────────────────────────────────────────
async def run_scan():
    global scan_running, last_scan, scan_count
    if scan_running:
        return

    scan_running = True
    scan_count  += 1
    ts = _now()
    await broadcast({"type": "scan_start", "timestamp": ts, "scan_count": scan_count})

    try:
        proc = await asyncio.create_subprocess_exec(
            "python", "eden_cli.py", "scan", "--all-pilots",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Stream stdout lines to clients as they arrive
        async for line in proc.stdout:
            text = line.decode().strip()
            if text:
                await broadcast({"type": "scan_log", "line": text})

        await proc.wait()
        last_scan = _now()

        await broadcast({
            "type":    "scan_complete",
            "timestamp": last_scan,
            "scan_count": scan_count,
            "stats":   get_stats(),
            "blocks":  get_all_blocks()[:25],
            "tokens":  get_tokens()[:10],
            "regions": get_regions(),
        })

    except Exception as e:
        await broadcast({"type": "scan_error", "error": str(e)})
    finally:
        scan_running = False


# ── Scheduler ─────────────────────────────────────────────────────────────
scheduler = AsyncIOScheduler(timezone="UTC")
scheduler.add_job(run_scan, "interval", minutes=SCAN_INTERVAL, id="auto_scan",
                  max_instances=1, coalesce=True)


@app.on_event("startup")
async def on_startup():
    REPORTS.mkdir(parents=True, exist_ok=True)
    scheduler.start()
    print(f"[EDEN] Server online — auto-scan every {SCAN_INTERVAL} min")


@app.on_event("shutdown")
async def on_shutdown():
    scheduler.shutdown(wait=False)


# ── REST API ──────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def api_stats():
    return JSONResponse(get_stats())

@app.get("/api/blocks")
async def api_blocks():
    return JSONResponse(get_all_blocks())

@app.get("/api/tokens")
async def api_tokens():
    return JSONResponse(get_tokens())

@app.get("/api/regions")
async def api_regions():
    return JSONResponse(get_regions())

@app.get("/api/health")
async def api_health():
    return JSONResponse({"status": "ok", "clients": len(clients),
                         "last_scan": last_scan, "scan_count": scan_count})

@app.post("/api/scan")
async def trigger_scan():
    if scan_running:
        return JSONResponse({"status": "already_running"}, status_code=409)
    asyncio.create_task(run_scan())
    return JSONResponse({"status": "scan_started"})


# ── WebSocket ─────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)

    # Push full state immediately on connect
    await websocket.send_text(json.dumps({
        "type":    "init",
        "stats":   get_stats(),
        "blocks":  get_all_blocks()[:50],
        "tokens":  get_tokens(),
        "regions": get_regions(),
    }))

    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "ts": _now()}))
    except WebSocketDisconnect:
        clients.discard(websocket)
    except Exception:
        clients.discard(websocket)


# ── Static ────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    # Always look next to server.py, regardless of cwd
    here = Path(__file__).parent / "dashboard.html"
    return FileResponse(str(here))


# ── BioGuard fraud intelligence endpoint ──────────────────────────────────────
@app.get("/api/bioguard")
async def api_bioguard():
    tokens = get_tokens()
    stats  = get_stats()
    return {
        "tco2_fraud"        : 865979,
        "confirmed_violations": 11,
        "flagged_actors"    : 7,
        "blocks_on_chain"   : stats.get("blocks_on_chain", 108),
        "aerial_zones"      : 5,
        "certified_events"  : stats.get("certified_events", 38),
        "bio_tokens"        : tokens[:10],
        "last_scan"         : stats.get("last_scan", ""),
        "rising_threats"    : stats.get("rising_threats", []),
    }


@app.get("/bioguard")
async def serve_bioguard():
    from fastapi.responses import FileResponse
    p = Path(__file__).parent.parent / "bioguard_platform.html"
    if p.exists():
        return FileResponse(str(p))
    return {"error": "bioguard_platform.html not found"}
