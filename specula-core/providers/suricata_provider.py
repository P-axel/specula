from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

from connectors.suricata.connector import SuricataConnector
from normalization.suricata_normalizer import SuricataNormalizer
from providers.base_provider import DetectionProvider

logger = logging.getLogger(__name__)


class SuricataProvider(DetectionProvider):
    name = "suricata"

    def __init__(self, eve_path: str | Path) -> None:
        self.connector = SuricataConnector(eve_path)
        self.normalizer = SuricataNormalizer()

    def fetch(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        items = self.list_detections(limit=limit + offset)
        return items[offset:] if offset > 0 else items

    def list_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            raw_events = self.connector.fetch_events(limit=limit)
        except Exception as e:
            logger.error("Failed to fetch Suricata events: %s", e, exc_info=True)
            return []

        detections: List[Dict[str, Any]] = []

        for event in raw_events:
            try:
                if not isinstance(event, dict):
                    continue

                if str(event.get("event_type") or "").strip().lower() != "alert":
                    continue

                alert = event.get("alert") or {}
                if not isinstance(alert, dict):
                    continue

                signature = str(alert.get("signature") or "").strip()
                severity_code = alert.get("severity")

                normalized = self.normalizer.normalize(event)
                if not normalized:
                    continue

                severity_map = {
                    1: "critical",
                    2: "high",
                    3: "medium",
                    4: "low",
                }

                try:
                    severity_code_int = int(severity_code)
                except Exception:
                    severity_code_int = None

                severity = severity_map.get(severity_code_int, "medium")
                risk_score_map = {
                    "critical": 90,
                    "high": 75,
                    "medium": 55,
                    "low": 30,
                }

                flat_detection = {
                    "id": normalized.get("event", {}).get("id"),
                    "title": signature or "Suricata alert",
                    "name": signature or "Suricata alert",
                    "timestamp": normalized.get("timestamp"),
                    "category": "network_alert",
                    "theme": "network",
                    "severity": severity,
                    "priority": severity,
                    "risk_score": risk_score_map.get(severity, 50),
                    "source": "suricata",
                    "source_engine": "suricata",
                    "engine": "suricata",
                    "src_ip": normalized.get("source", {}).get("ip"),
                    "dest_ip": normalized.get("destination", {}).get("ip"),
                    "status": "open",
                    "description": signature or "Suricata alert",
                    "summary": signature or "Suricata alert",
                    "confidence": normalized.get("risk", {}).get("confidence"),
                    "rule_id": alert.get("signature_id"),
                    "raw_detection": normalized,
                }

                detections.append(flat_detection)

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
