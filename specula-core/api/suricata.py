from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Query

from services.suricata_service import SuricataService

router = APIRouter(prefix="/suricata", tags=["suricata"])

EVE_PATH = Path("deploy/master/suricata/logs/eve.json")
suricata_service = SuricataService(EVE_PATH)


@router.get("/status")
def suricata_status() -> dict:
    return suricata_service.get_status()


@router.get("/events/raw")
def get_suricata_raw_events(
    limit: int = Query(default=50, ge=1, le=1000),
    event_type: list[str] | None = Query(default=None),
) -> dict:
    items = suricata_service.list_raw_events(limit=limit, event_types=event_type)
    return {
        "source": "suricata",
        "count": len(items),
        "items": items,
    }


@router.get("/events")
def get_suricata_events(
    limit: int = Query(default=50, ge=1, le=1000),
    event_type: list[str] | None = Query(default=None),
) -> dict:
    items = suricata_service.list_events(limit=limit, event_types=event_type)
    return {
        "source": "suricata",
        "count": len(items),
        "items": items,
    }


@router.get("/detections")
def get_suricata_detections(
    limit: int = Query(default=50, ge=1, le=1000),
) -> dict:
    items = suricata_service.list_detections(limit=limit)
    return {
        "source": "suricata",
        "count": len(items),
        "items": items,
    }


@router.get("/detections/summary")
def get_suricata_detection_summary(
    limit: int = Query(default=50, ge=1, le=1000),
) -> dict:
    items = suricata_service.list_detection_summaries(limit=limit)
    return {
        "source": "suricata",
        "count": len(items),
        "items": items,
    }