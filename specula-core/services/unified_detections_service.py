from __future__ import annotations

from typing import Any

from services.suricata_service import SuricataService
# plus tard:
# from services.wazuh_detection_service import WazuhDetectionService
# from services.auth_detection_service import AuthDetectionService


class UnifiedDetectionsService:
    def __init__(self, eve_path: str) -> None:
        self.suricata_service = SuricataService(eve_path)
        # self.wazuh_service = WazuhDetectionService()
        # self.auth_service = AuthDetectionService()

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        items.extend(self.suricata_service.list_detection_summaries(limit=limit))

        # Plus tard
        # items.extend(self.wazuh_service.list_detection_summaries(limit=limit))
        # items.extend(self.auth_service.list_detection_summaries(limit=limit))

        items.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
        return items[:limit]