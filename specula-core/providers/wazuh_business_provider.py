from __future__ import annotations

import logging
from typing import Any, List, Dict

from providers.base_provider import DetectionProvider
from services.transformation.detections_service import DetectionsService

logger = logging.getLogger(__name__)


class WazuhBusinessProvider(DetectionProvider):
    """
    Provider métier Wazuh.

    Fournit les détections enrichies issues du pipeline Specula :
    - normalisation
    - enrichissement
    - scoring
    - déduplication

    ⚠️ Ne retourne PAS les données brutes Wazuh.
    """

    name = "wazuh"

    def __init__(self) -> None:
        self.detections_service = DetectionsService()

    def list_detections(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            detections = self.detections_service.list_detections()
        except Exception as e:
            logger.error("Failed to retrieve detections from service: %s", e, exc_info=True)
            return []

        if not detections:
            return []

        # tri par timestamp décroissant (plus récent en premier)
        detections = self._sort_by_timestamp(detections)

        # enrichissement léger (fallback sécurité)
        detections = [self._ensure_minimum_fields(d) for d in detections]

        if limit > 0:
            detections = detections[:limit]

        return detections

    def _sort_by_timestamp(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def get_ts(d: Dict[str, Any]) -> str:
            return (
                d.get("timestamp")
                or d.get("event", {}).get("created")
                or ""
            )

        try:
            return sorted(detections, key=get_ts, reverse=True)
        except Exception:
            logger.warning("Failed to sort detections by timestamp")
            return detections

    def _ensure_minimum_fields(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Garantit un minimum exploitable pour le frontend / corrélation.
        """
        event = detection.setdefault("event", {})
        risk = detection.setdefault("risk", {})
        detection_block = detection.setdefault("detection", {})

        # event
        event.setdefault("kind", "alert")
        event.setdefault("category", "security_event")
        event.setdefault("severity", "info")

        # detection
        detection_block.setdefault("engine", "wazuh")
        detection_block.setdefault("provider", "wazuh")
        detection_block.setdefault("status", "observed")

        # risk
        risk.setdefault("score", 0)
        risk.setdefault("level", "info")
        risk.setdefault("confidence", 0.5)

        return detection