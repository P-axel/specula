from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.events_service import EventsService
from services.alerts_service import AlertsService
from services.assets_service import AssetsService

app = FastAPI(
    title="Specula API",
    version="0.1.0",
    description="API minimale du noyau Specula",
)

# Autoriser le front Specula (Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = AssetsService()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/assets")
def list_assets() -> list[dict]:
    assets = service.list_assets()
    return [asset.to_dict() for asset in assets]


@app.get("/assets/{asset_id}")
def get_asset(asset_id: str) -> dict:
    asset = service.get_asset(asset_id)

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    return asset.to_dict()

@app.get("/events")
def list_events() -> list[dict]:
    events = events_service.list_agent_status_events()
    return [event.to_dict() for event in events]


@app.get("/alerts")
def list_alerts() -> list[dict]:
    alerts = alerts_service.list_alerts()
    return [alert.to_dict() for alert in alerts]    