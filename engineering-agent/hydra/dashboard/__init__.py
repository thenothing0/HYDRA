"""
╔══════════════════════════════════════════════════════════════╗
║  Real-Time Dashboard — FastAPI + WebSocket Backend         ║
║  Live swarm status, task queue, attack graph, findings     ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hydra.dashboard")


class DashboardState:
    """Centralized state for the dashboard."""

    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.agents: Dict[str, Dict] = {}
        self.queue_depths: Dict[str, int] = {}
        self.findings: List[Dict] = []
        self.metrics: Dict[str, Any] = {}
        self.attack_graph_data: Optional[Dict] = None
        self._events: List[Dict] = []

    def add_event(self, event_type: str, data: Dict[str, Any]):
        event = {
            "type": event_type, "data": data,
            "timestamp": time.time(),
        }
        self._events.append(event)
        if len(self._events) > 1000:
            self._events = self._events[-500:]

    def get_state(self) -> Dict[str, Any]:
        return {
            "scans": self.scans,
            "agents": self.agents,
            "queue_depths": self.queue_depths,
            "findings_count": len(self.findings),
            "recent_findings": self.findings[-20:],
            "metrics": self.metrics,
            "recent_events": self._events[-50:],
            "timestamp": time.time(),
        }


class DashboardServer:
    """
    FastAPI-based real-time dashboard backend.
    
    Features:
      - REST API for dashboard data
      - WebSocket for live updates
      - Scan status monitoring
      - Agent activity feed
      - Attack graph visualization data
      - Findings timeline
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.state = DashboardState()
        self._websocket_clients: Set = set()
        self._app = None

    def create_app(self):
        """Create the FastAPI application."""
        try:
            from fastapi import FastAPI, WebSocket, WebSocketDisconnect
            from fastapi.responses import HTMLResponse, JSONResponse
            from fastapi.middleware.cors import CORSMiddleware
        except ImportError:
            logger.warning(
                "FastAPI not installed — dashboard unavailable. "
                "Install with: pip install fastapi uvicorn"
            )
            return None

        app = FastAPI(
            title="HYDRA Dashboard",
            version="2.0.0",
            description="Real-time security orchestration dashboard",
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/")
        async def index():
            return HTMLResponse(self._get_dashboard_html())

        @app.get("/api/status")
        async def get_status():
            return JSONResponse(self.state.get_state())

        @app.get("/api/scans")
        async def get_scans():
            return JSONResponse({"scans": self.state.scans})

        @app.get("/api/agents")
        async def get_agents():
            return JSONResponse({"agents": self.state.agents})

        @app.get("/api/findings")
        async def get_findings():
            return JSONResponse({
                "findings": self.state.findings[-100:],
                "total": len(self.state.findings),
            })

        @app.get("/api/metrics")
        async def get_metrics():
            return JSONResponse(self.state.metrics)

        @app.get("/api/graph")
        async def get_graph():
            return JSONResponse(
                self.state.attack_graph_data or {"nodes": [], "edges": []}
            )

        @app.get("/api/metrics/prometheus")
        async def prometheus_metrics():
            from hydra.observability import metrics
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(
                metrics.to_prometheus(),
                media_type="text/plain",
            )

        @app.get("/api/health")
        async def health_check():
            return JSONResponse({"status": "ok", "uptime": time.time()})

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self._websocket_clients.add(websocket)
            try:
                while True:
                    await websocket.send_json(self.state.get_state())
                    await asyncio.sleep(2)
            except WebSocketDisconnect:
                self._websocket_clients.discard(websocket)
            except Exception:
                self._websocket_clients.discard(websocket)

        self._app = app
        return app

    async def broadcast(self, event: Dict[str, Any]):
        """Broadcast an event to all WebSocket clients."""
        dead = set()
        for ws in self._websocket_clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        self._websocket_clients -= dead

    async def start(self):
        """Start the dashboard server."""
        app = self.create_app()
        if not app:
            return

        try:
            import uvicorn
            config = uvicorn.Config(
                app, host=self.host, port=self.port,
                log_level="warning",
            )
            server = uvicorn.Server(config)
            logger.info(
                f"📊 Dashboard running at http://{self.host}:{self.port}"
            )
            await server.serve()
        except ImportError:
            logger.warning("uvicorn not installed — dashboard unavailable")

    def _get_dashboard_html(self) -> str:
        """Embedded dashboard frontend."""
        return """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>HYDRA Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a1a;color:#e0e0e0;}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:20px 30px;border-bottom:1px solid #333;}
.header h1{font-size:1.5em;background:linear-gradient(90deg,#00d2ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;padding:20px;}
.card{background:#1a1a2e;border:1px solid #333;border-radius:12px;padding:20px;}
.card h2{font-size:1.1em;color:#00d2ff;margin-bottom:10px;}
.metric{font-size:2em;font-weight:bold;color:#7b2ff7;}
.status-ok{color:#44cc44;}
.status-err{color:#ff4444;}
#events{max-height:300px;overflow-y:auto;font-family:monospace;font-size:12px;}
.event{padding:4px 0;border-bottom:1px solid #222;}
</style></head><body>
<div class="header"><h1>🔥 HYDRA Dashboard</h1></div>
<div class="grid">
<div class="card"><h2>System Status</h2><div id="status">Loading...</div></div>
<div class="card"><h2>Active Scans</h2><div id="scans" class="metric">0</div></div>
<div class="card"><h2>Findings</h2><div id="findings" class="metric">0</div></div>
<div class="card"><h2>Agents</h2><div id="agents">Loading...</div></div>
<div class="card" style="grid-column:span 2"><h2>Event Feed</h2><div id="events"></div></div>
</div>
<script>
const ws=new WebSocket(`ws://${location.host}/ws`);
ws.onmessage=function(e){
const d=JSON.parse(e.data);
document.getElementById('status').innerHTML='<span class="status-ok">● Online</span>';
document.getElementById('scans').textContent=Object.keys(d.scans||{}).length;
document.getElementById('findings').textContent=d.findings_count||0;
const agentHtml=Object.entries(d.agents||{}).map(([k,v])=>`<div>${k}: ${v.status||'unknown'}</div>`).join('');
document.getElementById('agents').innerHTML=agentHtml||'No agents';
const eventsHtml=(d.recent_events||[]).slice(-20).reverse().map(e=>`<div class="event">[${new Date(e.timestamp*1000).toLocaleTimeString()}] ${e.type}: ${JSON.stringify(e.data).slice(0,80)}</div>`).join('');
document.getElementById('events').innerHTML=eventsHtml;
};
ws.onerror=function(){document.getElementById('status').innerHTML='<span class="status-err">● Disconnected</span>';};
</script></body></html>"""
