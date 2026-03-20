from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.alerts import router as alerts_router
from api.assets import router as assets_router
from api.dashboard import router as dashboard_router
from api.detections import router as detections_router
from api.events import router as events_router
from api.incidents import router as incidents_router
from api.soc import router as soc_router

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

app.include_router(assets_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(soc_router)
app.include_router(dashboard_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}