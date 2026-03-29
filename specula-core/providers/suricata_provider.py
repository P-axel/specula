from __future__ import annotations

from pathlib import Path
from typing import Any

from connectors.suricata.connector import SuricataConnector
from normalization.suricata_normalizer import SuricataNormalizer
from providers.base_provider import DetectionProvider


class SuricataProvider(DetectionProvider):
    """
    Provider Suricata.

    Rôle :
    - point d'entrée unique pour Suricata
    - récupère les événements via le connector
    - les normalise via le normalizer
    - retourne des détections prêtes pour Specula
    """

    name = "suricata"

    def __init__(self, eve_path: str | Path) -> None:
        self.connector = SuricataConnector(eve_path)
        self.normalizer = SuricataNormalizer()

    def list_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        raw_events = self.connector.fetch_events(limit=limit)
        return [self.normalizer.normalize(event) for event in raw_events]

    def get_status(self) -> dict[str, Any]:
        return self.connector.get_status()