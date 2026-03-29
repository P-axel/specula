from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from services.ingestion.suricata_service import SuricataService

class ThemesService:
    """
    Service de vues thématiques Specula.

    Objectif :
    - regrouper les signaux par thème métier
    - rester indépendant des outils sources
    """

    def __init__(self) -> None:
        eve_path = Path(
            os.getenv("SPECULA_SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
        )
        self.suricata_service = SuricataService(eve_path)

    def list_network_detections(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Vue réseau actuelle : Suricata.
        Plus tard, on pourra y ajouter Zeek, firewall, IDS cloud, etc.
        """
        return self.suricata_service.list_detection_summaries(limit=limit)