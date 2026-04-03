from __future__ import annotations

import logging
from typing import Any, List, Dict

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

    def __init__(self) -> None:
        self.detections_service = DetectionsService()

    def list_detections(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            detections = self.detections_service.list_detections(source="suricata")
        except Exception as e:
            logger.error("Failed to retrieve Suricata detections: %s", e, exc_info=True)
            return []

        if not detections:
            return []

        detections = self._sort_by_timestamp(detections)
        detections = [self._enrich_network_context(d) for d in detections]

        if limit > 0:
            detections = detections[:limit]

        return detections

    def _sort_by_timestamp(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def get_ts(d: Dict[str, Any]) -> str:
            return d.get("timestamp") or ""

        try:
            return sorted(detections, key=get_ts, reverse=True)
        except Exception:
            return detections

    def _enrich_network_context(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ajoute du contexte réseau exploitable SOC.
        """

        event = detection.setdefault("event", {})
        network = detection.setdefault("network", {})
        detection_block = detection.setdefault("detection", {})
        risk = detection.setdefault("risk", {})

        # classification simple
        category = event.get("category")

        if category == "network_scan":
            detection_block["threat"] = "reconnaissance"
            risk["score"] = max(risk.get("score", 0), 60)

        elif category == "network_dns":
            detection_block["threat"] = "dns_activity"

        elif category == "network_tls":
            detection_block["threat"] = "encrypted_traffic"

        elif category == "malware":
            detection_block["threat"] = "malware_communication"
            risk["score"] = max(risk.get("score", 0), 80)

        # direction logique
        if network.get("direction") == "to_server":
            detection["flow"] = "inbound"
        elif network.get("direction") == "to_client":
            detection["flow"] = "outbound"

        # fallback propre
        detection_block.setdefault("engine", "suricata")
        detection_block.setdefault("provider", "suricata")
        detection_block.setdefault("status", "observed")

        risk.setdefault("confidence", 0.7)

        return detection