import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from api.dependencies import detections_service

router = APIRouter(tags=["detections"])
logger = logging.getLogger(__name__)


class Detection(BaseModel):
    id: str
    source: str
    message: Optional[str] = Field(None)
    timestamp: str

    class Config:
        extra = "allow"


@router.get("/detections", response_model=List[Detection])
def list_detections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: Optional[str] = Query(None),
) -> List[Any]:
    try:
        results = detections_service.list_detections(source=source)
        results = results[offset: offset + limit]

        for det in results:
            if not isinstance(det, dict):
                continue
            if not det.get("message"):
                det["message"] = det.get("title") or det.get("name") or "No description"
            # Normalise engine/source en string (peut être None ou dict)
            engine = det.get("engine") or det.get("source_engine") or det.get("source")
            if not isinstance(engine, str):
                engine = None
            det["engine"] = engine
            det["source"] = engine or ""
        return results

    except Exception as e:
        logger.warning("/detections indisponible: %s", e)
        return []
