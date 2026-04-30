import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from api.dependencies import assets_service, unified_incidents_service
from storage.database import get_connection

router = APIRouter(tags=["assets"])
logger = logging.getLogger(__name__)


def _risk_score_from_incidents(incidents: list[dict]) -> int:
    """Score 0-100 basé sur les incidents ouverts d'un actif."""
    open_inc = [i for i in incidents if i.get("status") in ("open", "investigating")]
    if not open_inc:
        return 0
    sev_weights = {"critical": 40, "high": 20, "medium": 8, "low": 2}
    score = sum(sev_weights.get(str(i.get("severity", "")).lower(), 0) for i in open_inc)
    return min(score, 100)


def _incidents_for_asset(asset_name: str) -> list[dict]:
    """Récupère les incidents liés à un actif (par nom ou IP)."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """SELECT incident_id, title, severity, status, risk_score,
                          first_seen, last_seen, dominant_engine, signals_count
                   FROM incidents
                   WHERE asset_name = ?
                   ORDER BY last_seen DESC LIMIT 50""",
                (asset_name,),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


@router.get("/assets")
def list_assets() -> list[dict]:
    try:
        assets = assets_service.list_assets()
        return [asset.to_dict() for asset in assets]
    except Exception as exc:
        logger.warning("Wazuh indisponible, /assets retourne liste vide: %s", exc)
        return []


@router.get("/assets/{asset_id}/summary")
def asset_summary(asset_id: str) -> dict[str, Any]:
    """Vue enrichie d'un actif : incidents, score de risque, statuts."""
    try:
        asset = assets_service.get_asset(asset_id)
    except Exception:
        asset = None

    # Cherche les incidents par asset_id (hostname ou IP)
    identifiers = [asset_id]
    if asset:
        d = asset.to_dict()
        for key in ("name", "hostname", "ip_address"):
            val = d.get(key)
            if val and val not in identifiers:
                identifiers.append(val)

    all_incidents: list[dict] = []
    seen_ids: set = set()
    for ident in identifiers:
        for inc in _incidents_for_asset(ident):
            if inc["incident_id"] not in seen_ids:
                seen_ids.add(inc["incident_id"])
                all_incidents.append(inc)

    all_incidents.sort(key=lambda x: x.get("last_seen") or "", reverse=True)

    open_inc  = [i for i in all_incidents if i.get("status") in ("open", "investigating")]
    closed_inc = [i for i in all_incidents if i.get("status") in ("resolved", "false_positive")]
    critical_open = [i for i in open_inc if str(i.get("severity","")).lower() == "critical"]

    return {
        "asset": asset.to_dict() if asset else {"asset_id": asset_id, "name": asset_id},
        "risk_score": _risk_score_from_incidents(all_incidents),
        "stats": {
            "total":    len(all_incidents),
            "open":     len(open_inc),
            "critical": len(critical_open),
            "closed":   len(closed_inc),
        },
        "recent_incidents": all_incidents[:10],
    }


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str) -> dict:
    try:
        asset = assets_service.get_asset(asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset.to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Wazuh indisponible, /assets/%s introuvable: %s", asset_id, exc)
        raise HTTPException(status_code=404, detail="Asset not found")