from __future__ import annotations

import logging
from typing import Dict, List, Any, Optional

from providers.wazuh_business_provider import WazuhBusinessProvider
from providers.suricata_business_provider import SuricataBusinessProvider

logger = logging.getLogger(__name__)


class ProviderManager:
    def __init__(self) -> None:
        self.providers: Dict[str, Any] = {
            "wazuh": WazuhBusinessProvider(),
            "suricata": SuricataBusinessProvider(),
        }

    def list_detections(
        self,
        source: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:

        if source:
            provider = self.providers.get(source)

            if not provider:
                logger.warning("Unknown provider requested: %s", source)
                return []

            try:
                return provider.list_detections(limit=limit, offset=offset)
            except Exception as e:
                logger.error("Provider %s failed: %s", source, e, exc_info=True)
                return []

        detections: List[Dict[str, Any]] = []

        for name, provider in self.providers.items():
            try:
                data = provider.list_detections(limit=limit, offset=0)
                detections.extend(data)
            except Exception as e:
                logger.error("Provider %s failed: %s", name, e, exc_info=True)
                continue

        # tri global
        detections.sort(
            key=lambda d: str(
                d.get("timestamp")
                or d.get("created_at")
                or ""
            ),
            reverse=True,
        )

        # pagination globale
        if offset > 0:
            detections = detections[offset:]

        if limit > 0:
            detections = detections[:limit]

        return detections

    def get_status(self) -> Dict[str, Any]:
        status = {}

        for name, provider in self.providers.items():
            try:
                status[name] = provider.get_status()
            except Exception as e:
                status[name] = {
                    "status": "error",
                    "message": str(e),
                }

        return status