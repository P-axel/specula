from fastapi import APIRouter
from api.dependencies import alerts_service, network_alerts_service
from api.utils.fixtures import load_json_fixture_list
from config.settings import settings

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(limit: int = 100) -> list[dict]:
    if settings.use_test_fixtures:
        return load_json_fixture_list("alerts")[:limit]

    return alerts_service.list_alerts(limit=limit)


@router.get("/alerts/raw")
def list_raw_wazuh_alerts(limit: int = 20) -> list[dict]:
    if settings.use_test_fixtures:
        return load_json_fixture_list("alerts")[:limit]

    return alerts_service.list_wazuh_alert_payloads(limit=limit)


@router.get("/alerts/network")
def list_network_alerts(limit: int = 50) -> dict:
    if settings.use_test_fixtures:
        all_items = load_json_fixture_list("alerts")
        items = [item for item in all_items if _is_network_alert_fixture(item)][:limit]
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


def _is_network_alert_fixture(item: dict) -> bool:
    event = item.get("event") if isinstance(item.get("event"), dict) else {}
    observer = item.get("observer") if isinstance(item.get("observer"), dict) else {}
    network = item.get("network") if isinstance(item.get("network"), dict) else {}
    source_context = item.get("source_context") if isinstance(item.get("source_context"), dict) else {}
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    raw_alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}

    engine_candidates = [
        item.get("engine"),
        item.get("source_engine"),
        item.get("source"),
        event.get("provider"),
        observer.get("product"),
        source_context.get("source"),
    ]

    category_candidates = [
        item.get("category"),
        event.get("category"),
        event.get("type"),
        network.get("protocol"),
        network.get("application"),
        raw.get("event_type"),
        raw_alert.get("category"),
    ]

    tags = item.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]

    engines = {str(value).strip().lower() for value in engine_candidates if value}
    categories = {str(value).strip().lower() for value in category_candidates if value}
    tags_normalized = {str(tag).strip().lower() for tag in tags if tag}

    if "suricata" in engines:
        return True

    if "network" in tags_normalized:
        return True

    if any(
        value in categories
        for value in {
            "network_alert",
            "network_http",
            "network_dns",
            "network_tls",
            "suspicious_http",
            "dns_anomaly",
            "tls_anomaly",
            "exploit_attempt",
            "malware",
            "intrusion_detection",
            "network_scan",
            "http",
            "dns",
            "tls",
        }
    ):
        return True

    return False