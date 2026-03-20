from fastapi import APIRouter

from api.dependencies import alerts_service, translated_detections_service
from specula_logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["detections"])


@router.get("/detections")
def list_detections(limit: int = 100) -> list[dict]:
    return alerts_service.list_business_detections(limit=limit)


@router.get("/detections/translated")
def list_translated_detections() -> list[dict]:
    try:
        detections = translated_detections_service.list_translated_detections()
        return [detection.to_dict() for detection in detections]
    except Exception as exc:
        logger.exception(
            "Erreur sur /detections/translated, fallback vers /detections: %s",
            exc,
        )
        return list_detections()