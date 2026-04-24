# ============================================================
#  ThreatPulse AI - api.py
#  FastAPI backend -- REST + WebSocket + Auth + All Routes
# ============================================================

from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import logging
import os
import queue
import threading
import time
from collections import deque
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, HTMLResponse
import uvicorn

from database import (
    init_db, insert_packet, insert_threat, insert_stats,
    get_recent_threats, get_recent_packets,
    get_threat_counts_by_severity, get_top_attacker_ips,
    get_traffic_over_time, get_latest_stats, get_total_counts,
)
from ml_engine import SentinelMLEngine
from packet_capture import packet_queue, start_capture_thread
from auth import router as auth_router, init_auth_tables, get_current_user

try:
    from google_auth import router as google_router
    from github_auth import router as github_router
    OAUTH_ENABLED = True
except ImportError:
    OAUTH_ENABLED = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
)
logger = logging.getLogger("sentinel.api")

# -- App ---------------------------------------------------
app = FastAPI(title="ThreatPulse AI API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(auth_router)
if OAUTH_ENABLED:
    app.include_router(google_router)
    app.include_router(github_router)

STATIC_DIR = os.path.dirname(__file__)

# -- Global state ------------------------------------------
ml_engine       = SentinelMLEngine()
ws_clients: set = set()
_counters = {"total_packets": 0, "total_threats": 0, "packets_this_sec": 0, "threats_this_min": 0}
_counter_lock = threading.Lock()


def _serve(filename):
    path = os.path.join(STATIC_DIR, filename)
    if os.path.exists(path):
        return FileResponse(path)
    return JSONResponse({"error": f"{filename} not found"}, status_code=404)


# -- WebSocket ---------------------------------------------
async def broadcast(message: dict):
    if not ws_clients:
        return
    text = json.dumps(message)
    dead = set()
    for ws in list(ws_clients):
        try:
            await ws.send_text(text)
        except Exception:
            dead.add(ws)
    ws_clients.difference_update(dead)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    logger.info(f"Dashboard connected ({len(ws_clients)} total)")
    try:
        real_counts  = get_total_counts()
        sev_counts   = get_threat_counts_by_severity()
        latest_stats = get_latest_stats()
        await ws.send_text(json.dumps({
            "type":    "history",
            "threats": get_recent_threats(50),
            "stats": {
                **real_counts,
                "packets_per_second": latest_stats.get("packets_per_second", 0),
                "CRITICAL": sev_counts.get("CRITICAL", 0),
                "HIGH":     sev_counts.get("HIGH",     0),
                "MEDIUM":   sev_counts.get("MEDIUM",   0),
                "LOW":      sev_counts.get("LOW",      0),
            },
        }))
    except Exception:
        pass
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.discard(ws)


# -- Auth extras -------------------------------------------
@app.get("/auth/providers")
def auth_providers():
    return {
        "google": bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_ID") != "YOUR_GOOGLE_CLIENT_ID_HERE"),
        "github": bool(os.environ.get("GITHUB_CLIENT_ID") and os.environ.get("GITHUB_CLIENT_ID") != "YOUR_GITHUB_CLIENT_ID_HERE"),
        "email":  True,
    }

@app.get("/auth/users")
def list_users(request: Request):
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        import psycopg2.extras as _extras
        from database import DB_CONFIG
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=_extras.RealDictCursor)
        cur.execute("SELECT id, username, email, role, created_at, last_login, is_active FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


# -- Page routes -------------------------------------------
@app.get("/")
def serve_root(): return RedirectResponse(url="/login.html")

@app.get("/login.html")
def serve_login(): return _serve("login.html")

@app.get("/signup.html")
def serve_signup(): return _serve("signup.html")

@app.get("/forgot-password.html")
def serve_forgot(): return _serve("forgot-password.html")

@app.get("/dashboard.html")
def serve_dashboard(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("dashboard.html")

@app.get("/profile.html")
def serve_profile(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("profile.html")

@app.get("/settings.html")
def serve_settings(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("settings.html")

@app.get("/notifications.html")
def serve_notifications(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("notifications.html")

@app.get("/create-account.html")
def serve_create_account(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("create-account.html")

@app.get("/detail-packets.html")
def serve_dp(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-packets.html")

@app.get("/detail-threats.html")
def serve_dt(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-threats.html")

@app.get("/detail-alerts.html")
def serve_da(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-alerts.html")

@app.get("/detail-pps.html")
def serve_dpps(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-pps.html")

@app.get("/detail-feed.html")
def serve_df(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-feed.html")

@app.get("/detail-traffic.html")
def serve_dtr(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-traffic.html")

@app.get("/detail-ailog.html")
def serve_dal(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-ailog.html")

@app.get("/detail-severity.html")
def serve_dsev(request: Request):
    if not get_current_user(request): return RedirectResponse(url="/login.html")
    return _serve("detail-severity.html")


# -- API endpoints -----------------------------------------
@app.get("/api/threats")
def api_threats(limit: int = 10000):
    return get_recent_threats(limit)

@app.get("/api/packets")
def api_packets(limit: int = 200):
    return get_recent_packets(limit)

@app.get("/api/stats")
def api_stats():
    counts   = get_total_counts()
    severity = get_threat_counts_by_severity()
    top_ips  = get_top_attacker_ips(5)
    timeline = get_traffic_over_time(60)
    latest = get_latest_stats()
    return {
        **counts,
        # PPS at top level for dashboard handleStats
        "packets_per_second": latest.get("packets_per_second", 0),
        # Flat severity keys for handleStats on dashboard
        "CRITICAL": severity.get("CRITICAL", 0),
        "HIGH":     severity.get("HIGH",     0),
        "MEDIUM":   severity.get("MEDIUM",   0),
        "LOW":      severity.get("LOW",      0),
        # Also keep nested for detail pages
        "severity_breakdown": severity,
        "top_attacker_ips":   top_ips,
        "traffic_timeline":   timeline,
        "latest_stats":       latest,
    }

@app.get("/api/threat-counts")
def api_threat_counts():
    try:
        import psycopg2
        from database import DB_CONFIG
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threats WHERE resolved = FALSE")
        unresolved = cur.fetchone()[0]
        cur.execute("SELECT severity, COUNT(*) FROM threats GROUP BY severity")
        sev = {r[0]: r[1] for r in cur.fetchall()}
        conn.close()
        return {
            "total_threats":      total,
            "unresolved_threats": unresolved,
            "resolved_threats":   total - unresolved,
            "severity_breakdown": {
                "CRITICAL": sev.get("CRITICAL", 0),
                "HIGH":     sev.get("HIGH",     0),
                "MEDIUM":   sev.get("MEDIUM",   0),
                "LOW":      sev.get("LOW",      0),
            },
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/reset")
def api_reset(request: Request):
    """Stop capture, wipe all data, restart fresh"""
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        import psycopg2
        from database import DB_CONFIG
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("TRUNCATE TABLE threats RESTART IDENTITY CASCADE")
        cur.execute("TRUNCATE TABLE packets RESTART IDENTITY CASCADE")
        cur.execute("TRUNCATE TABLE stats   RESTART IDENTITY CASCADE")
        conn.commit()
        conn.close()
        # Reset in-memory counters
        with _counter_lock:
            _counters["total_packets"]    = 0
            _counters["total_threats"]    = 0
            _counters["packets_this_sec"] = 0
            _counters["threats_this_min"] = 0
        logger.info("=== RESET: All data wiped. Fresh start. ===")
        return {"status": "reset", "message": "All data cleared. Capture continues fresh."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stop-capture")
def api_stop_capture(request: Request):
    """Stop packet capture thread"""
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        if hasattr(app.state, "stop_event"):
            app.state.stop_event.set()
            logger.info("=== Packet capture STOPPED by user ===")
            return {"status": "stopped", "message": "Packet capture stopped."}
        return {"status": "not_running", "message": "Capture was not running."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/start-capture")
def api_start_capture(request: Request):
    """Restart packet capture thread"""
    if not get_current_user(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        # If old thread still running, stop it first
        if hasattr(app.state, "stop_event"):
            app.state.stop_event.set()
        import time as _time
        _time.sleep(0.5)
        # Start fresh
        capture_thread, stop_event = start_capture_thread(iface=None, packet_filter="ip")
        app.state.capture_thread = capture_thread
        app.state.stop_event     = stop_event
        logger.info("=== Packet capture RESTARTED by user ===")
        return {"status": "started", "message": "Packet capture restarted."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/model-status")
def model_status():
    """Returns status of all 4 ML layers including CNN-LSTM training progress."""
    try:
        return ml_engine.get_model_status()
    except Exception as e:
        return {"error": str(e)}


# -- Background packet processing --------------------------
async def process_packets_loop():
    last_stat_flush = time.time()
    pkt_window      = deque(maxlen=1000)

    while True:
        for _ in range(50):
            try:
                record = packet_queue.get_nowait()
            except queue.Empty:
                break

            analysis = ml_engine.analyse(record)
            pkt_id   = insert_packet(record, threat_score=analysis["threat_score"], is_threat=analysis["is_threat"])

            with _counter_lock:
                _counters["total_packets"] += 1
                pkt_window.append(time.time())

            if analysis["is_threat"] and analysis["threat_detail"]:
                td = analysis["threat_detail"]
                td["packet_id"]   = pkt_id
                # Ensure threat_score is always present
                if "threat_score" not in td or td["threat_score"] is None:
                    td["threat_score"] = analysis.get("threat_score", 0.0)
                insert_threat(td)
                with _counter_lock:
                    _counters["total_threats"]   += 1
                    _counters["threats_this_min"] += 1
                await broadcast({"type": "threat", "payload": {**td, "threat_score": analysis["threat_score"]}})

        now = time.time()
        if now - last_stat_flush >= 1.0:
            one_sec_ago = now - 1.0
            pps = sum(1 for t in pkt_window if t >= one_sec_ago)

            with _counter_lock:
                stats_row = {
                    "timestamp":          datetime.utcnow().isoformat(),
                    "packets_per_second": pps,
                    "threats_per_minute": _counters["threats_this_min"],
                    "total_packets":      _counters["total_packets"],
                    "total_threats":      _counters["total_threats"],
                    "top_src_ip":         None,
                    "top_protocol":       None,
                }
                _counters["threats_this_min"] = 0

            insert_stats(stats_row)
            # Get real counts from DB for accurate display
            real_counts = get_total_counts()
            sev_counts  = get_threat_counts_by_severity()
            await broadcast({"type": "stats", "payload": {
                **stats_row,
                "total_threats":      real_counts["total_threats"],
                "total_packets":      real_counts["total_packets"],
                "unresolved_threats": real_counts["unresolved_threats"],
                "CRITICAL": sev_counts.get("CRITICAL", 0),
                "HIGH":     sev_counts.get("HIGH",     0),
                "MEDIUM":   sev_counts.get("MEDIUM",   0),
                "LOW":      sev_counts.get("LOW",      0),
            }})
            last_stat_flush = now

        await asyncio.sleep(0.05)


# -- Startup / shutdown ------------------------------------
@app.on_event("startup")
async def startup():
    logger.info("=== ThreatPulse AI Starting ===")
    init_db()
    init_auth_tables()
    # Sync in-memory counters with existing DB data
    try:
        real = get_total_counts()
        with _counter_lock:
            _counters["total_packets"] = real["total_packets"]
            _counters["total_threats"] = real["total_threats"]
        logger.info(f"Synced counters from DB: {real['total_packets']} packets, {real['total_threats']} threats")
    except Exception:
        pass
    capture_thread, stop_event = start_capture_thread(iface=None, packet_filter="ip")
    app.state.capture_thread = capture_thread
    app.state.stop_event     = stop_event
    asyncio.create_task(process_packets_loop())
    logger.info("Packet capture started.")
    logger.info("Dashboard: http://localhost:8000")
    logger.info("API docs:  http://localhost:8000/docs")

@app.on_event("shutdown")
async def shutdown():
    if hasattr(app.state, "stop_event"):
        app.state.stop_event.set()
    logger.info("=== ThreatPulse AI Stopped ===")

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
