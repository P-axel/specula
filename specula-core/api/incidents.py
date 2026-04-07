from fastapi import APIRouter

from api.dependencies import unified_incidents_service

router = APIRouter(tags=["incidents"])


@router.get("/incidents")
def list_incidents(limit: int = 100) -> list[dict]:
    return unified_incidents_service.list_incidents(limit=limit)