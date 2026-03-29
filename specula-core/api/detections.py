from fastapi import APIRouter

from api.dependencies import detections_service

router = APIRouter(tags=["detections"])


@router.get("/detections")
def list_detections(limit: int = 100) -> list[dict]:
    items = detections_service.list_detections()
    if limit <= 0:
        return items
    return items[:limit]