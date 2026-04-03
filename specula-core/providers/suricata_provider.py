from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Dict

from connectors.suricata.connector import SuricataConnector
from normalization.suricata_normalizer import SuricataNormalizer
from providers.base_provider import DetectionProvider

logger = logging.getLogger(__name__)


class SuricataProvider(DetectionProvider):
    """
    Provider Suricata (bas niveau).

    Rôle :
    - récupérer les événements Suricata (eve.json)
    - normaliser les événements
    - exposer des détections brutes prêtes pour Specula

    ⚠️ Pas d’enrichissement métier ici
    """

    name = "suricata"

    def __init__(self, eve_path: str | Path) -> None:
        self.connector = SuricataConnector(eve_path)
        self.normalizer = SuricataNormalizer()

    def list_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            raw_events = self.connector.fetch_events(limit=limit)
        except Exception as e:
            logger.error("Failed to fetch Suricata events: %s", e, exc_info=True)
            return []

        detections: List[Dict[str, Any]] = []

        for event in raw_events:
            try:
                normalized = self.normalizer.normalize(event)
                if normalized:
                    detections.append(normalized)
            except Exception as e:
                logger.warning("Failed to normalize Suricata event: %s", e, exc_info=True)

        return detections

    def get_status(self) -> Dict[str, Any]:
        try:
            return self.connector.get_status()
        except Exception as e:
            logger.error("Failed to get Suricata status: %s", e, exc_info=True)
            return {
                "status": "error",
                "message": str(e),
            }