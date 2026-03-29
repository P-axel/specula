from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter

from api.dependencies import (
    alerts_service,
    assets_service,
    detections_service,
    network_alerts_service,
    network_incidents_service,
    themes_service,
    unified_events_service,
)
from specula_logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["dashboard"])


def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _to_dict_item(item: Any) -> dict:
    if isinstance(item, dict):
        return item
    if hasattr(item, "to_dict") and callable(item.to_dict):
        return item.to_dict()
    return {}


def _to_dict_list(items: list[Any]) -> list[dict]:
    return [_to_dict_item(item) for item in items]


def _dashboard_detection_dicts() -> list[dict]:
    try:
        return _to_dict_list(detections_service.list_detections())
    except Exception as exc:
        logger.exception("Erreur récupération détections dashboard: %s", exc)
        return []


@router.get("/dashboard/overview")
def dashboard_overview() -> dict:
    assets = _to_dict_list(assets_service.list_assets())
    alerts = _to_dict_list(alerts_service.list_alerts())
    detections = _dashboard_detection_dicts()
    events = _to_dict_list(unified_events_service.list_event_dicts(limit=500))

    network_detections = _to_dict_list(themes_service.list_network_detections(limit=500))
    network_alerts = _to_dict_list(network_alerts_service.list_network_alerts(limit=500))
    network_incidents = _to_dict_list(
        network_incidents_service.list_network_incidents(limit=500)
    )

    active_assets = [
        asset for asset in assets
        if str(asset.get("status", "")).lower() == "active"
    ]
    inactive_assets = [
        asset for asset in assets
        if str(asset.get("status", "")).lower() != "active"
    ]

    open_alerts = [
        alert for alert in alerts
        if str(alert.get("status", alert.get("state", ""))).lower() == "open"
    ]

    critical_alerts = [
        alert for alert in alerts
        if "critical" in str(alert.get("severity", "")).lower()
    ]

    healthy_assets = [
        asset for asset in assets
        if str(asset.get("health_state", "")).lower() == "healthy"
    ]
    warning_assets = [
        asset for asset in assets
        if str(asset.get("health_state", "")).lower() == "warning"
    ]
    critical_assets = [
        asset for asset in assets
        if str(asset.get("health_state", "")).lower() == "critical"
    ]

    return {
        "assets": {
            "total": len(assets),
            "active": len(active_assets),
            "inactive": len(inactive_assets),
            "healthy": len(healthy_assets),
            "warning": len(warning_assets),
            "critical": len(critical_assets),
        },
        "soc": {
            "events_total": len(events),
            "detections_total": len(detections),
            "alerts_total": len(alerts),
            "alerts_open": len(open_alerts),
            "alerts_critical": len(critical_alerts),
        },
        "network": {
            "detections_total": len(network_detections),
            "alerts_total": len(network_alerts),
            "incidents_total": len(network_incidents),
        },
    }


@router.get("/dashboard/network-overview")
def dashboard_network_overview() -> dict:
    theme_items = _to_dict_list(themes_service.list_network_detections(limit=500))
    alert_items = _to_dict_list(network_alerts_service.list_network_alerts(limit=500))
    incident_items = _to_dict_list(
        network_incidents_service.list_network_incidents(limit=500)
    )

    return {
        "detections_total": len(theme_items),
        "alerts_total": len(alert_items),
        "incidents_total": len(incident_items),
    }


@router.get("/dashboard/severity-distribution")
def dashboard_severity_distribution() -> dict:
    detections = _dashboard_detection_dicts()

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for item in detections:
        severity = str(item.get("severity", "")).lower()

        if "critical" in severity:
            counts["critical"] += 1
        elif "high" in severity:
            counts["high"] += 1
        elif "medium" in severity:
            counts["medium"] += 1
        elif "low" in severity:
            counts["low"] += 1
        else:
            counts["info"] += 1

    return counts


@router.get("/dashboard/top-assets")
def dashboard_top_assets() -> list[dict]:
    detections = _dashboard_detection_dicts()
    counter: Counter = Counter()

    for item in detections:
        asset_name = item.get("asset_name") or item.get("asset_id") or "unknown"
        counter[asset_name] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@router.get("/dashboard/top-categories")
def dashboard_top_categories() -> list[dict]:
    detections = _dashboard_detection_dicts()
    counter: Counter = Counter()

    for item in detections:
        category = item.get("type") or item.get("category") or "uncategorized"
        counter[category] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@router.get("/dashboard/top-platforms")
def dashboard_top_platforms() -> list[dict]:
    assets = _to_dict_list(assets_service.list_assets())
    counter: Counter = Counter()

    for asset in assets:
        platform = asset.get("platform") or asset.get("os_name") or "unknown"
        counter[str(platform).lower()] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@router.get("/dashboard/top-groups")
def dashboard_top_groups() -> list[dict]:
    assets = _to_dict_list(assets_service.list_assets())
    counter: Counter = Counter()

    for asset in assets:
        groups = asset.get("groups") or []
        if isinstance(groups, str):
            groups = [groups]

        for group in groups:
            group_name = str(group).strip()
            if group_name:
                counter[group_name] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@router.get("/dashboard/recent-assets")
def dashboard_recent_assets() -> list[dict]:
    assets = _to_dict_list(assets_service.list_assets())
    sortable_assets: list[tuple[datetime, dict]] = []

    for asset in assets:
        dt = _safe_parse_datetime(asset.get("last_seen"))
        if dt is None:
            continue
        sortable_assets.append((dt, asset))

    sortable_assets.sort(key=lambda item: item[0], reverse=True)

    return [
        {
            "asset_id": asset.get("asset_id"),
            "name": asset.get("name"),
            "status": asset.get("status"),
            "platform": asset.get("platform"),
            "last_seen": asset.get("last_seen"),
            "last_seen_relative": asset.get("last_seen_relative"),
            "health_state": asset.get("health_state"),
        }
        for _, asset in sortable_assets[:5]
    ]


@router.get("/dashboard/watchlist-assets")
def dashboard_watchlist_assets() -> list[dict]:
    assets = _to_dict_list(assets_service.list_assets())

    watchlist = [
        asset for asset in assets
        if str(asset.get("status", "")).lower() in {"inactive", "disconnected", "never_connected"}
        or str(asset.get("health_state", "")).lower() in {"warning", "critical"}
    ]

    def sort_key(asset: dict) -> tuple[int, datetime]:
        severity_order = {
            "critical": 0,
            "warning": 1,
            "healthy": 2,
        }
        health_state = str(asset.get("health_state", "")).lower()
        dt = _safe_parse_datetime(asset.get("last_seen")) or datetime.min.replace(
            tzinfo=timezone.utc
        )
        return (severity_order.get(health_state, 3), dt)

    watchlist.sort(key=sort_key)

    return [
        {
            "asset_id": asset.get("asset_id"),
            "name": asset.get("name"),
            "status": asset.get("status"),
            "platform": asset.get("platform"),
            "criticality": asset.get("criticality"),
            "last_seen": asset.get("last_seen"),
            "last_seen_relative": asset.get("last_seen_relative"),
            "health_state": asset.get("health_state"),
        }
        for asset in watchlist[:5]
    ]


@router.get("/dashboard/telemetry-health")
def dashboard_telemetry_health() -> dict:
    assets = _to_dict_list(assets_service.list_assets())

    healthy = 0
    warning = 0
    critical = 0
    unknown = 0

    for asset in assets:
        state = str(asset.get("health_state", "")).lower()

        if state == "healthy":
            healthy += 1
        elif state == "warning":
            warning += 1
        elif state == "critical":
            critical += 1
        else:
            unknown += 1

    return {
        "healthy": healthy,
        "warning": warning,
        "critical": critical,
        "unknown": unknown,
        "total": len(assets),
    }


@router.get("/dashboard/activity")
def dashboard_activity() -> list[dict]:
    detections = _dashboard_detection_dicts()
    now = datetime.now(timezone.utc)

    buckets: list[str] = []
    bucket_map: dict[str, int] = defaultdict(int)

    for hours_ago in range(11, -1, -1):
        dt = now - timedelta(hours=hours_ago)
        label = dt.strftime("%H:00")
        buckets.append(label)
        bucket_map[label] = 0

    for item in detections:
        timestamp = (
            item.get("created_at")
            or item.get("timestamp")
            or item.get("metadata", {}).get("occurred_at")
        )
        dt = _safe_parse_datetime(timestamp)
        if dt is None:
            continue

        label = dt.astimezone(timezone.utc).strftime("%H:00")
        if label in bucket_map:
            bucket_map[label] += 1

    return [{"time": label, "count": bucket_map[label]} for label in buckets]