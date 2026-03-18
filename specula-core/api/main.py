from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.suricata import router as suricata_router
from detection.engine import DetectionEngine
from services.alerts_service import AlertsService
from services.assets_service import AssetsService
from services.detections_service import DetectionsService
from services.detections_aggregator import DetectionsAggregator
from services.events_service import EventsService
from services.network_alerts_service import NetworkAlertsService
from services.network_incidents_service import NetworkIncidentsService
from services.plugin_registry import PluginRegistry
from services.themes_service import ThemesService
from services.translated_detections_service import TranslatedDetectionsService
from services.unified_correlator import UnifiedCorrelator
from services.unified_incidents_service import UnifiedIncidentsService
from services.wazuh_events_service import WazuhEventsService
from specula_logging.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Specula API",
    version="0.1.0",
    description="API minimale du noyau Specula",
)

app.include_router(suricata_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------
# Services existants
# ---------------------------------------------------------------------

assets_service = AssetsService()
wazuh_events_service = WazuhEventsService()
alerts_service = AlertsService()
detections_service = DetectionsService()
detection_engine = DetectionEngine()
translated_detections_service = TranslatedDetectionsService()

themes_service = ThemesService()
network_alerts_service = NetworkAlertsService()
network_incidents_service = NetworkIncidentsService()

events_service = EventsService(
    event_repository=None,
    detection_engine=detection_engine,
    detections_service=detections_service,
)

# ---------------------------------------------------------------------
# Couche modulaire multi-sources
# ---------------------------------------------------------------------

# Adapte ce chemin selon ton environnement si besoin.
DEFAULT_EVE_PATH = Path("/var/log/suricata/eve.json")

plugin_registry = PluginRegistry.build_default(
    eve_path=DEFAULT_EVE_PATH,
    enable_suricata=DEFAULT_EVE_PATH.exists(),
)

detections_aggregator = DetectionsAggregator(
    providers=plugin_registry.get_detection_providers()
)

unified_correlator = UnifiedCorrelator(window_minutes=30)

unified_incidents_service = UnifiedIncidentsService(
    aggregator=detections_aggregator,
    correlator=unified_correlator,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/assets")
def list_assets() -> list[dict]:
    assets = assets_service.list_assets()
    return [asset.to_dict() for asset in assets]


@app.get("/assets/{asset_id}")
def get_asset(asset_id: str) -> dict:
    asset = assets_service.get_asset(asset_id)

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    return asset.to_dict()


@app.get("/events")
def list_events() -> list[dict]:
    events = wazuh_events_service.list_agent_status_events()
    return [event.to_dict() for event in events]


@app.get("/alerts")
def list_alerts() -> list[dict]:
    alerts = alerts_service.list_alerts()
    return [alert.to_dict() for alert in alerts]


@app.get("/alerts/raw")
def list_raw_wazuh_alerts(limit: int = 20) -> list[dict]:
    return alerts_service.list_wazuh_alert_payloads(limit=limit)


@app.get("/alerts/network")
def list_network_alerts(limit: int = 50) -> dict:
    items = network_alerts_service.list_network_alerts(limit=limit)
    return {
        "theme": "network",
        "count": len(items),
        "items": items,
    }


@app.get("/detections")
def list_detections(limit: int = 100) -> list[dict]:
    detections = alerts_service.list_business_detections(limit=limit)
    return detections


@app.get("/detections/translated")
def list_translated_detections() -> list[dict]:
    try:
        detections = translated_detections_service.list_translated_detections()
        return [detection.to_dict() for detection in detections]
    except Exception as exc:
        logger.exception("Erreur sur /detections/translated, fallback vers /detections: %s", exc)
        return list_detections()


@app.get("/themes/network")
def list_network_theme(limit: int = 50) -> dict:
    items = themes_service.list_network_detections(limit=limit)
    return {
        "theme": "network",
        "count": len(items),
        "items": items,
    }


@app.get("/incidents")
def list_incidents(limit: int = 100) -> list[dict]:
    return alerts_service.list_incidents(limit=limit)


@app.get("/incidents/network")
def list_network_incidents(limit: int = 50) -> dict:
    items = network_incidents_service.list_network_incidents(limit=limit)
    return {
        "theme": "network",
        "count": len(items),
        "items": items,
    }


# ---------------------------------------------------------------------
# Nouvelles routes SOC multi-sources
# ---------------------------------------------------------------------

@app.get("/incidents/soc")
def list_soc_incidents(limit: int = 50) -> dict:
    items = unified_incidents_service.list_incidents(limit=limit)
    return {
        "theme": "soc",
        "count": len(items),
        "providers": detections_aggregator.list_providers(),
        "items": items,
    }


@app.get("/incidents/soc/overview")
def soc_incidents_overview(limit: int = 50) -> dict:
    overview = unified_incidents_service.get_overview(limit=limit)
    overview["providers"] = detections_aggregator.list_providers()
    return overview


def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _dashboard_detection_dicts() -> list[dict]:
    try:
        translated = [
            detection.to_dict()
            for detection in translated_detections_service.list_translated_detections()
        ]

        if translated:
            return translated

        logger.warning("Aucune détection traduite, fallback vers /detections")
        return list_detections()

    except Exception as exc:
        logger.exception("Erreur translated detections, fallback vers /detections: %s", exc)
        return list_detections()


@app.get("/dashboard/overview")
def dashboard_overview() -> dict:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]
    alerts = [alert.to_dict() for alert in alerts_service.list_alerts()]
    detections = _dashboard_detection_dicts()
    events = [event.to_dict() for event in wazuh_events_service.list_agent_status_events()]

    network_detections = themes_service.list_network_detections(limit=500)
    network_alerts = network_alerts_service.list_network_alerts(limit=500)
    network_incidents = network_incidents_service.list_network_incidents(limit=500)

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
        "assets_total": len(assets),
        "assets_active": len(active_assets),
        "assets_inactive": len(inactive_assets),
        "assets_healthy": len(healthy_assets),
        "assets_warning": len(warning_assets),
        "assets_critical": len(critical_assets),
        "alerts_total": len(alerts),
        "alerts_open": len(open_alerts),
        "alerts_critical": len(critical_alerts),
        "detections_total": len(detections),
        "events_total": len(events),
        "network_detections_total": len(network_detections),
        "network_alerts_total": len(network_alerts),
        "network_incidents_total": len(network_incidents),
    }


@app.get("/dashboard/network-overview")
def dashboard_network_overview() -> dict:
    theme_items = themes_service.list_network_detections(limit=500)
    alert_items = network_alerts_service.list_network_alerts(limit=500)
    incident_items = network_incidents_service.list_network_incidents(limit=500)

    return {
        "detections_total": len(theme_items),
        "alerts_total": len(alert_items),
        "incidents_total": len(incident_items),
    }


@app.get("/dashboard/severity-distribution")
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


@app.get("/dashboard/top-assets")
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


@app.get("/dashboard/top-categories")
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


@app.get("/dashboard/top-platforms")
def dashboard_top_platforms() -> list[dict]:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]
    counter: Counter = Counter()

    for asset in assets:
        platform = (
            asset.get("platform")
            or asset.get("os_name")
            or "unknown"
        )
        counter[str(platform).lower()] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@app.get("/dashboard/top-groups")
def dashboard_top_groups() -> list[dict]:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]
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


@app.get("/dashboard/recent-assets")
def dashboard_recent_assets() -> list[dict]:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]

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


@app.get("/dashboard/watchlist-assets")
def dashboard_watchlist_assets() -> list[dict]:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]

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
        dt = _safe_parse_datetime(asset.get("last_seen")) or datetime.min.replace(tzinfo=timezone.utc)
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


@app.get("/dashboard/telemetry-health")
def dashboard_telemetry_health() -> dict:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]

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


@app.get("/dashboard/activity")
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