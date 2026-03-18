from __future__ import annotations

from pathlib import Path
from typing import Any

from providers.base_provider import DetectionProvider
from services.suricata_service import SuricataService


class SuricataProvider(DetectionProvider):
    """
    Provider modulaire Suricata.
    Adapte SuricataService au contrat DetectionProvider.
    """

    name = "suricata"

    def __init__(self, eve_path: str | Path) -> None:
        self.service = SuricataService(eve_path)

    def list_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.service.list_detection_summaries(limit=limit)