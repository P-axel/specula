from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List

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
    """

    name = "wazuh"

    def __init__(self, detections_service: DetectionsService | None = None) -> None:
        self.detections_service = detections_service or DetectionsService()

    def list_detections(self, limit: int = 200) -> List[Dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be >= 1")

        try:
            detections = self.detections_service.list_detections()
        except Exception:
            logger.exception("Failed to retrieve detections from service")
            raise

        if not detections:
            return []

        normalized = [self._ensure_minimum_fields(deepcopy(d)) for d in detections]
        normalized = self._sort_by_timestamp(normalized)

        return normalized[:limit]

    def _sort_by_timestamp(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def parse_ts(d: Dict[str, Any]) -> datetime:
            value = d.get("timestamp") or d.get("event", {}).get("created")
            if not value or not isinstance(value, str):
                return datetime.min
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return datetime.min

        return sorted(detections, key=parse_ts, reverse=True)

    def _ensure_minimum_fields(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        event = detection.get("event")
        if not isinstance(event, dict):
            event = {}
            detection["event"] = event

        risk = detection.get("risk")
        if not isinstance(risk, dict):
            risk = {}
            detection["risk"] = risk

        detection_block = detection.get("detection")
        if not isinstance(detection_block, dict):
            detection_block = {}
            detection["detection"] = detection_block

        event.setdefault("kind", "alert")
        event.setdefault("category", "security_event")
        event.setdefault("severity", "info")

        detection_block.setdefault("engine", "wazuh")
        detection_block.setdefault("provider", "wazuh")
        detection_block.setdefault("status", "observed")

        risk.setdefault("score", 0)
        risk.setdefault("level", "info")
        risk.setdefault("confidence", 0.5)

        return detection