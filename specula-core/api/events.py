from fastapi import APIRouter

from api.dependencies import wazuh_events_service

router = APIRouter(tags=["events"])


@router.get("/events")
def list_events() -> list[dict]:
    events = wazuh_events_service.list_agent_status_events()
    return [event.to_dict() for event in events]