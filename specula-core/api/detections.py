from fastapi import APIRouter, Query
from typing import Optional, List, Dict, Any

from providers.provider_manager import ProviderManager

router = APIRouter(tags=["detections"])

provider_manager = ProviderManager()


@router.get("/detections")
def list_detections(
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return provider_manager.list_detections(
        source=source,
        limit=limit,
        offset=offset,
    )