from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from api.auth import router as auth_router
from api.alerts import router as alerts_router
from api.assets import router as assets_router
from api.dashboard import router as dashboard_router
from api.detections import router as detections_router
from api.events import router as events_router
from api.incidents import router as incidents_router
from api.soc import router as soc_router
from api.store import router as store_router
from api.ai import router as ai_router
from specula_logging.logger import get_logger
from storage.database import init_db

logger = get_logger(__name__)

# ─── CORS ──────────────────────────────────────────────────────────────────────
_raw_origins = os.getenv(
    "SPECULA_ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
)
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ─── Security headers middleware ────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        if os.getenv("SPECULA_ENV", "dev") == "prod":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# ─── Request logging middleware ─────────────────────────────────────────────────
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "HTTP %s %s → %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response


# ─── WebSocket notification bus ────────────────────────────────────────────────
class NotificationBus:
    """Bus simple pour diffuser les nouvelles alertes critiques aux clients WS."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)
        logger.info("WS client connecté (%d total)", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections = [c for c in self._connections if c is not ws]
        logger.info("WS client déconnecté (%d restants)", len(self._connections))

    async def broadcast(self, payload: dict[str, Any]) -> None:
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


bus = NotificationBus()


# ─── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Specula API",
    version="0.2.0",
    description="Specula SOC Platform API",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Middlewares (ordre : dernier ajouté = premier exécuté)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# Prometheus metrics
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
    logger.info("Prometheus /metrics activé")
except ImportError:
    logger.warning("prometheus-fastapi-instrumentator non disponible, /metrics désactivé")

# Routers
app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(soc_router)
app.include_router(dashboard_router)
app.include_router(store_router)
app.include_router(ai_router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    from storage.ai_analysis_repository import reset_stuck
    n = reset_stuck()
    if n:
        logger.warning("IA: %d analyse(s) bloquée(s) remises en erreur (redémarrage).", n)
    logger.info("SQLite initialisé — annotations d'incidents prêtes.")
    import threading
    threading.Thread(target=_warm_cache, daemon=True).start()
    threading.Thread(target=_auto_analyse_new_incidents, daemon=True).start()


def _warm_cache() -> None:
    import time, concurrent.futures
    time.sleep(5)  # Minimal — stale-while-revalidate gère les rechargements
    from api.dependencies import (
        assets_service, alerts_service,
        detections_service, unified_incidents_service,
    )
    # Séquentiel : detections en premier (incidents en dépend via le pipeline)
    # puis assets/alerts en parallèle (indépendants)
    for name, fn in [
        ("detections", lambda: detections_service.list_detections()),
        ("incidents",  lambda: unified_incidents_service.list_incidents()),
    ]:
        try:
            fn()
            logger.info("Cache préchauffé : %s", name)
        except Exception as e:
            logger.warning("Préchauffage '%s' ignoré : %s", name, e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(assets_service.list_assets): "assets",
            pool.submit(alerts_service.list_alerts): "alerts",
        }
        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
                logger.info("Cache préchauffé : %s", name)
            except Exception as e:
                logger.warning("Préchauffage '%s' ignoré : %s", name, e)


def _auto_analyse_new_incidents() -> None:
    """Lance l'analyse IA sur les incidents high/critical ouverts sans analyse existante."""
    import time, subprocess, sys, json
    time.sleep(45)  # Après le warmup cache
    from ai.ollama_client import is_available
    if not is_available():
        return
    from storage.database import get_connection
    from storage.ai_analysis_repository import get
    from storage.incident_store_repository import get_incident_by_id
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """SELECT incident_id FROM incidents
                   WHERE severity IN ('critical','high')
                     AND status IN ('open','investigating')
                   ORDER BY last_seen DESC LIMIT 10"""
            ).fetchall()
        for row in rows:
            iid = row["incident_id"]
            existing = get(iid)
            if existing and existing.get("status") in ("done", "running", "pending"):
                continue
            incident = get_incident_by_id(iid)
            if not incident:
                continue
            incident["id"] = iid
            payload = json.dumps({"incident_id": iid, "incident": incident, "related": []})
            worker = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ai", "worker.py"))
            proc = subprocess.Popen(
                [sys.executable, worker],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True, env={**os.environ, "OLLAMA_MODEL": "qwen2.5:1.5b", "OLLAMA_TIMEOUT": "300"},
            )
            proc.stdin.write(payload)
            proc.stdin.close()
            logger.info("IA auto-analyse lancée pour %s", iid)
            time.sleep(5)  # Espacer pour ne pas saturer Ollama
    except Exception as e:
        logger.warning("Auto-analyse IA ignorée : %s", e)


# ─── Health ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": app.version,
        "env": os.getenv("SPECULA_ENV", "dev"),
    }


# ─── WebSocket : alertes critiques temps réel ──────────────────────────────────
@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket) -> None:
    """
    WebSocket pour recevoir les nouvelles alertes critiques en temps réel.
    Le client se connecte et reçoit un push à chaque nouvel incident critique.

    Usage frontend :
        const ws = new WebSocket('ws://localhost:8000/ws/incidents');
        ws.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    await bus.connect(websocket)
    try:
        # Envoi d'un ping de bienvenue
        await websocket.send_json({"type": "connected", "message": "Specula WS ready"})
        # Maintenir la connexion vivante
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Heartbeat
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        await bus.disconnect(websocket)
