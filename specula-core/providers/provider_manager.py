from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

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
                data = provider.list_detections(limit=limit + offset)
                return data[offset:offset + limit]
            except Exception:
                logger.exception("Provider %s failed", source)
                return []

        detections: List[Dict[str, Any]] = []

        for name, provider in self.providers.items():
            try:
                data = provider.list_detections(limit=limit + offset)
                detections.extend(data)
            except Exception:
                logger.exception("Provider %s failed", name)
                continue

        detections.sort(key=self._sort_key, reverse=True)
        return detections[offset:offset + limit]

    @staticmethod
    def _sort_key(item: Dict[str, Any]) -> datetime:
        raw_value = item.get("timestamp") or item.get("created_at") or ""

        if not isinstance(raw_value, str) or not raw_value.strip():
            return datetime.min

        try:
            return datetime.fromisoformat(raw_value.strip().replace("Z", "+00:00"))
        except ValueError:
            return datetime.min

    def get_status(self) -> Dict[str, Any]:
        status = {}

        for name, provider in self.providers.items():
            try:
                status[name] = provider.get_status()
            except Exception as exc:
                status[name] = {
                    "status": "error",
                    "message": str(exc),
                }

        return status