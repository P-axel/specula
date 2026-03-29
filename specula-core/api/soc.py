from fastapi import APIRouter

from api.dependencies import detections_aggregator, unified_incidents_service

router = APIRouter(tags=["soc"])


@router.get("/incidents/soc")
def list_soc_incidents(limit: int = 50) -> dict:
    items = unified_incidents_service.list_incidents(limit=limit)

    return {
        "theme": "soc",
        "count": len(items),
        "providers": detections_aggregator.list_providers(),
        "items": items,
    }


@router.get("/incidents/soc/overview")
def soc_incidents_overview(limit: int = 50) -> dict:
    overview = unified_incidents_service.get_overview(limit=limit)
    overview["providers"] = detections_aggregator.list_providers()
    return overview


@router.get("/soc/detections")
def list_soc_detections(limit: int = 50) -> dict:
    items = detections_aggregator.list_detections(limit=limit)
    return {
        "theme": "soc",
        "providers": detections_aggregator.list_providers(),
        "count": len(items),
        "items": items,
    }