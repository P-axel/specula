from fastapi import APIRouter

from api.dependencies import alerts_service, network_alerts_service
from api.utils.fixtures import load_json_fixture_list
from config.settings import settings

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts() -> list[dict]:
    if settings.use_test_fixtures:
        return load_json_fixture_list("alerts")

    alerts = alerts_service.list_alerts()
    return [alert.to_dict() for alert in alerts]


@router.get("/alerts/raw")
def list_raw_wazuh_alerts(limit: int = 20) -> list[dict]:
    if settings.use_test_fixtures:
        return load_json_fixture_list("alerts")[:limit]

    return alerts_service.list_wazuh_alert_payloads(limit=limit)


@router.get("/alerts/network")
def list_network_alerts(limit: int = 50) -> dict:
    if settings.use_test_fixtures:
        items = [
            item
            for item in load_json_fixture_list("alerts")
            if str(item.get("engine", "")).lower() == "suricata"
        ][:limit]
        return {
            "theme": "network",
            "count": len(items),
            "items": items,
        }

    items = network_alerts_service.list_network_alerts(limit=limit)
    return {
        "theme": "network",
        "count": len(items),
        "items": items,
    }