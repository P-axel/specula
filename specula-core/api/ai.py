"""
Endpoint analyse IA — arrière-plan via subprocess.
Le subprocess survit au reload uvicorn.
"""
import json
import logging
import os
import subprocess
import sys
from typing import Any

from fastapi import APIRouter, HTTPException

from storage import ai_analysis_repository
from storage.incident_store_repository import get_incident_by_id
from storage.database import get_connection

router = APIRouter(prefix="/api/v1/incidents", tags=["ai"])
logger = logging.getLogger(__name__)

_running: set[str] = set()


def _get_related(incident_id: str, asset: str | None, src_ip: str | None) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT raw_json FROM incidents
               WHERE incident_id != ?
                 AND datetime(last_seen) >= datetime('now', '-48 hours')
                 AND (asset_name = ? OR raw_json LIKE ?)
               ORDER BY last_seen DESC LIMIT 8""",
            (incident_id, asset or "", f'%"{src_ip}"%' if src_ip else "%"),
        ).fetchall()
    results = []
    for row in rows:
        try:
            results.append(json.loads(row["raw_json"]))
        except Exception:
            pass
    return results


def _launch_worker(incident_id: str, incident: dict, related: list) -> None:
    """Lance le worker dans un subprocess indépendant (survit au reload uvicorn)."""
    payload = json.dumps({"incident_id": incident_id, "incident": incident, "related": related})
    worker = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ai", "worker.py"))
    proc = subprocess.Popen(
        [sys.executable, worker],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        # Hérite de l'env parent mais force le bon modèle
        env={**os.environ, "OLLAMA_MODEL": "qwen2.5:1.5b", "OLLAMA_TIMEOUT": "300"},
    )
    proc.stdin.write(payload)
    proc.stdin.close()
    # Ne pas attendre — le process tourne en arrière-plan


@router.get("/{incident_id}/analyse")
def get_analysis(incident_id: str) -> dict[str, Any]:
    row = ai_analysis_repository.get(incident_id)
    if not row:
        return {"status": "none"}
    return row


@router.post("/{incident_id}/analyse")
def analyse_incident(incident_id: str) -> dict[str, Any]:
    existing = ai_analysis_repository.get(incident_id)
    if existing and existing.get("status") == "running":
        return {"status": "running"}
    if existing and existing.get("status") == "done":
        return existing

    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident introuvable.")

    # L'IA n'est fiable que sur les incidents réseau (Suricata)
    # Les incidents système/endpoint Wazuh (dpkg, auditd, ports) génèrent des faux positifs IA
    domain = str(incident.get("incident_domain") or incident.get("kind") or "").lower()
    engine = str(incident.get("dominant_engine") or "").lower()
    if domain not in ("network", "réseau") and engine == "wazuh":
        return {
            "status": "not_applicable",
            "reason": "L'analyse IA est réservée aux incidents réseau. Les événements système Wazuh (dpkg, auditd, ports) sont mieux qualifiés par l'analyste humain."
        }

    from ai.ollama_client import is_available
    if not is_available():
        raise HTTPException(
            status_code=503,
            detail="Ollama non disponible. Démarrez Specula avec l'option [3]."
        )

    related = _get_related(incident_id, incident.get("asset_name"), incident.get("src_ip"))

    ai_analysis_repository.set_running(incident_id)
    try:
        _launch_worker(incident_id, incident, related)
    except Exception as e:
        ai_analysis_repository.set_error(incident_id, f"Impossible de lancer le worker: {e}")
        logger.exception("Erreur lancement worker IA pour %s", incident_id)
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "running"}
