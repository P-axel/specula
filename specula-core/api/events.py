from fastapi import APIRouter

from api.dependencies import unified_events_service

router = APIRouter(tags=["events"])


@router.get("/events")
def list_events(limit: int = 100) -> list[dict]:
    return unified_events_service.list_event_dicts(limit=limit)