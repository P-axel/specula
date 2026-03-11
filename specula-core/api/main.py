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
    detections_service.clear()

    events = wazuh_events_service.list_agent_status_events()
    events_service.ingest(events)

    detections = detections_service.list_detections()
    return [detection.to_dict() for detection in detections]