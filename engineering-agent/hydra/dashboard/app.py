"""
╔══════════════════════════════════════════════════════════════╗
║  HYDRA Dashboard — FastAPI + WebSocket Real-Time Dashboard  ║
║  Live scan progress, agent activity, findings timeline      ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hydra.dashboard.app")

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logger.info("FastAPI not installed — dashboard unavailable")


STATIC_DIR = Path(__file__).parent / "static"


def create_app(coordinator=None, artifact_store=None) -> Optional[Any]:
    """Create the FastAPI dashboard application."""
    if not HAS_FASTAPI:
        return None

    app = FastAPI(title="HYDRA Dashboard", version="3.0")

    # Serve static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    connections: List[WebSocket] = []

    @app.get("/", response_class=HTMLResponse)
    async def index():
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            return index_file.read_text(encoding="utf-8")
        return "<h1>HYDRA Dashboard</h1><p>Static files not found.</p>"

    @app.get("/api/status")
    async def status():
        return {
            "status": "running",
            "version": "3.0",
            "timestamp": time.time(),
            "agents": coordinator.get_agent_status() if coordinator else {},
        }

    @app.get("/api/findings")
    async def findings():
        if artifact_store:
            return {"findings": artifact_store.list_findings() if hasattr(artifact_store, 'list_findings') else []}
        return {"findings": []}

    @app.get("/api/scans")
    async def scans():
        if coordinator:
            return {"scans": coordinator.get_scan_history() if hasattr(coordinator, 'get_scan_history') else []}
        return {"scans": []}

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        connections.append(ws)
        try:
            while True:
                data = await ws.receive_text()
                # Echo status updates
                await ws.send_json({
                    "type": "status",
                    "timestamp": time.time(),
                    "data": json.loads(data) if data else {},
                })
        except WebSocketDisconnect:
            connections.remove(ws)

    return app
