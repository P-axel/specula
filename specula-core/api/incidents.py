from fastapi import APIRouter

from api.dependencies import alerts_service, network_incidents_service
from api.utils.fixtures import load_json_fixture_list
from config.settings import settings

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
def list_incidents(limit: int = 100) -> list[dict]:
    if settings.use_test_fixtures:
        return load_json_fixture_list("incidents")[:limit]

    return alerts_service.list_incidents(limit=limit)


@router.get("/incidents/network")
def list_network_incidents(limit: int = 50) -> dict:
    if settings.use_test_fixtures:
        items = [
            item
            for item in load_json_fixture_list("incidents")
            if str(item.get("kind", "")).lower() == "network"
            or str(item.get("engine", "")).lower() == "suricata"
        ][:limit]
        return {
            "theme": "network",
            "count": len(items),
            "items": items,
        }

    items = network_incidents_service.list_network_incidents(limit=limit)
    return {
        "theme": "network",
        "count": len(items),
        "items": items,
    }