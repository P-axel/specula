from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List

from providers.base_provider import DetectionProvider
from services.transformation.detections_service import DetectionsService

logger = logging.getLogger(__name__)


class SuricataBusinessProvider(DetectionProvider):
    """
    Provider métier Suricata.

    Fournit les détections réseau enrichies issues du pipeline Specula :
    - normalisation
    - enrichissement
    - scoring
    - déduplication
    """

    name = "suricata"

    def __init__(self, detections_service: DetectionsService | None = None) -> None:
        self.detections_service = detections_service or DetectionsService()

    def list_detections(
        self,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if offset < 0:
            raise ValueError("offset must be >= 0")

        try:
            detections = self.detections_service.list_detections(source="suricata")
        except Exception:
            logger.exception("Failed to retrieve Suricata detections")
            raise

        if not detections:
            return []

        enriched = [self._enrich_network_context(deepcopy(d)) for d in detections]
        enriched = self._sort_by_timestamp(enriched)

        if offset > 0:
            enriched = enriched[offset:]

        return enriched[:limit]

    def _sort_by_timestamp(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def parse_ts(d: Dict[str, Any]) -> datetime:
            value = d.get("timestamp")
            if not value or not isinstance(value, str):
                return datetime.min

            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return datetime.min

        return sorted(detections, key=parse_ts, reverse=True)

    def _safe_score(self, value: Any, default: int = 0) -> int:
        try:
            if value is None:
                return default
            return int(value)
        except (TypeError, ValueError):
            return default

    def _enrich_network_context(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ajoute du contexte réseau exploitable SOC.
        """

        event = detection.setdefault("event", {})
        network = detection.setdefault("network", {})
        detection_block = detection.setdefault("detection", {})
        risk = detection.setdefault("risk", {})

        category = event.get("category")
        current_score = self._safe_score(risk.get("score"), 0)

        if category == "network_scan":
            detection_block["threat"] = "reconnaissance"
            risk["score"] = max(current_score, 60)

        elif category == "network_dns":
            detection_block["threat"] = "dns_activity"

        elif category == "network_tls":
            detection_block["threat"] = "encrypted_traffic"

        elif category == "malware":
            detection_block["threat"] = "malware_communication"
            risk["score"] = max(current_score, 80)

        direction = network.get("direction")
        if direction == "to_server":
            detection["flow"] = "inbound"
        elif direction == "to_client":
            detection["flow"] = "outbound"

        detection_block.setdefault("engine", "suricata")
        detection_block.setdefault("provider", "suricata")
        detection_block.setdefault("status", "observed")
        risk.setdefault("confidence", 0.7)

        return detection