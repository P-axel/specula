from fastapi import APIRouter

from api.dependencies import alerts_service

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(limit: int = 100) -> list[dict]:
    return alerts_service.list_alerts(limit=limit)


@router.get("/alerts/raw")
def list_raw_wazuh_alerts(limit: int = 20) -> list[dict]:
    return alerts_service.list_wazuh_alert_payloads(limit=limit)