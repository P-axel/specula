from __future__ import annotations

from typing import Any

from providers.base_provider import DetectionProvider
from services.transformation.detections_service import DetectionsService


class WazuhBusinessProvider(DetectionProvider):
    """
    Provider métier Wazuh.

    Contrairement à WazuhProvider, ce provider ne retourne pas les
    détections brutes/normalisées du connecteur, mais les détections
    finales issues du pipeline métier Specula :
    - génération
    - scoring
    - déduplication
    - décision d'alerte
    """

    name = "wazuh"

    def __init__(self) -> None:
        self.detections_service = DetectionsService()

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        items = self.detections_service.list_detections()

        if limit <= 0:
            return items

        return items[:limit]