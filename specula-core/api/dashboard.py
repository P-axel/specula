from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from detection.engine import DetectionEngine
from services.wazuh_events_service import WazuhEventsService
from services.events_service import EventsService
from services.alerts_service import AlertsService
from services.assets_service import AssetsService
from services.detections_service import DetectionsService

app = FastAPI(
    title="Specula API",
    version="0.1.0",
    description="API minimale du noyau Specula",
)

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

assets_service = AssetsService()
wazuh_events_service = WazuhEventsService()
alerts_service = AlertsService()

detections_service = DetectionsService()
detection_engine = DetectionEngine()

events_service = EventsService(
    event_repository=None,
    detection_engine=detection_engine,
    detections_service=detections_service,
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


@app.get("/detections")
def list_detections() -> list[dict]:
    events = wazuh_events_service.list_agent_status_events()

    detections: list[dict] = []

    for event in events:
        raw_payload = event.raw_payload or {}
        status = raw_payload.get("status", "unknown")

        if status == "active":
            severity = "info"
        elif status in {"disconnected", "inactive", "never_connected"}:
            severity = "high"
        else:
            severity = event.severity or "low"

        detections.append(
            {
                "id": event.event_id,
                "name": event.title,
                "severity": severity,
                "source": event.source,
                "asset_id": event.asset_id,
                "asset_name": raw_payload.get("name"),
                "timestamp": event.occurred_at,
                "category": "agent_status",
                "status": status,
                "ip_address": raw_payload.get("ip"),
                "manager": raw_payload.get("manager"),
                "platform": (raw_payload.get("os") or {}).get("platform"),
            }
        )

    return detections


def _safe_parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return None


@app.get("/dashboard/overview")
def dashboard_overview() -> dict:
    assets = [asset.to_dict() for asset in assets_service.list_assets()]
    alerts = [alert.to_dict() for alert in alerts_service.list_alerts()]
    detections = list_detections()
    events = [event.to_dict() for event in wazuh_events_service.list_agent_status_events()]

    active_assets = [a for a in assets if str(a.get("status", "")).lower() == "active"]
    inactive_assets = [a for a in assets if str(a.get("status", "")).lower() != "active"]

    open_alerts = [
        a for a in alerts
        if str(a.get("status", a.get("state", ""))).lower() == "open"
    ]

    critical_alerts = [
        a for a in alerts
        if "critical" in str(a.get("severity", "")).lower()
    ]

    return {
        "assets_total": len(assets),
        "assets_active": len(active_assets),
        "assets_inactive": len(inactive_assets),
        "alerts_total": len(alerts),
        "alerts_open": len(open_alerts),
        "alerts_critical": len(critical_alerts),
        "detections_total": len(detections),
        "events_total": len(events),
    }


@app.get("/dashboard/severity-distribution")
def dashboard_severity_distribution() -> dict:
    detections = list_detections()

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
    detections = list_detections()
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
    detections = list_detections()
    counter: Counter = Counter()

    for item in detections:
        category = item.get("category") or "uncategorized"
        counter[category] += 1

    return [
        {"name": name, "count": count}
        for name, count in counter.most_common(5)
    ]


@app.get("/dashboard/activity")
def dashboard_activity() -> list[dict]:
    detections = list_detections()
    now = datetime.now(timezone.utc)

    buckets = []
    bucket_map: dict[str, int] = defaultdict(int)

    for hours_ago in range(11, -1, -1):
        dt = now - timedelta(hours=hours_ago)
        label = dt.strftime("%H:00")
        buckets.append(label)
        bucket_map[label] = 0

    for item in detections:
        dt = _safe_parse_datetime(item.get("timestamp"))
        if dt is None:
            continue

        label = dt.astimezone(timezone.utc).strftime("%H:00")
        if label in bucket_map:
            bucket_map[label] += 1

    return [{"time": label, "count": bucket_map[label]} for label in buckets]