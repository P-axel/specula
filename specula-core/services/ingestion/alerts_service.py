from __future__ import annotations

from typing import Any

from config.settings import settings
from providers.wazuh_provider import WazuhProvider
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class AlertsService:
    """
    Service d'ingestion autour des alertes Wazuh.
    """

    def __init__(self) -> None:
        self.provider: WazuhProvider | None = None

        if settings.specula_enable_wazuh and settings.wazuh_indexer_url:
            self.provider = WazuhProvider(
                base_url=settings.wazuh_indexer_url,
                username=settings.wazuh_indexer_username,
                password=settings.wazuh_indexer_password,
                verify_ssl=settings.wazuh_verify_tls,
                timeout=settings.wazuh_timeout,
                auth_type="basic",
            )
        else:
            logger.info("AlertsService initialisé sans provider Wazuh")

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        if self.provider is None:
            logger.info("Wazuh désactivé, aucune alerte Wazuh à retourner")
            return []

        logger.info("Génération des alertes depuis les détections Wazuh")

        try:
            detections = self.provider.list_detections(limit=limit)
        except Exception as exc:
            logger.warning("Impossible de générer les alertes Wazuh: %s", exc)
            return []

        alerts: list[dict[str, Any]] = []

        for detection in detections:
            event = detection.get("event", {}) or {}
            host = detection.get("host", {}) or {}
            risk = detection.get("risk", {}) or {}
            rule = detection.get("rule", {}) or {}
            user = detection.get("user", {}) or {}
            process = detection.get("process", {}) or {}
            file_data = detection.get("file", {}) or {}

            severity = str(
                event.get("severity") or detection.get("severity") or "info"
            ).strip().lower()
            if severity not in {"medium", "high", "critical"}:
                continue

            title = (
                rule.get("name")
                or detection.get("detection", {}).get("title")
                or detection.get("title")
                or "Wazuh alert"
            )

            description = (
                detection.get("wazuh", {}).get("full_log")
                or detection.get("description")
                or detection.get("detection", {}).get("title")
                or rule.get("name")
                or title
            )

            alerts.append(
                {
                    "id": event.get("id") or detection.get("id"),
                    "timestamp": detection.get("timestamp") or detection.get("created_at"),
                    "engine": "wazuh",
                    "source_engine": "wazuh",
                    "theme": "system",
                    "category": event.get("category") or detection.get("category"),
                    "title": title,
                    "severity": severity,
                    "priority": risk.get("level") or detection.get("priority") or severity,
                    "risk_score": risk.get("score") or detection.get("risk_score"),
                    "confidence": risk.get("confidence") or detection.get("confidence"),
                    "action": event.get("action"),
                    "asset_name": host.get("hostname") or host.get("id") or detection.get("asset_name"),
                    "asset_id": host.get("id") or detection.get("asset_id"),
                    "hostname": host.get("hostname") or detection.get("hostname"),
                    "user_name": user.get("name") or detection.get("user_name"),
                    "process_name": process.get("name") or detection.get("process_name"),
                    "file_path": file_data.get("path") or detection.get("file_path"),
                    "rule_id": rule.get("id") or detection.get("rule_id"),
                    "description": description,
                    "summary": rule.get("name") or detection.get("summary") or title,
                    "raw": detection.get("raw"),
                    "evidence": detection,
                }
            )

        logger.info("%s alert(s) générée(s)", len(alerts))
        return alerts

    def list_wazuh_alert_payloads(self, limit: int = 100) -> list[dict[str, Any]]:
        if self.provider is None:
            logger.info("Wazuh désactivé, aucun payload brut à retourner")
            return []

        logger.info("Récupération des alertes Wazuh brutes")

        try:
            items = self.provider.connector.fetch_alerts(limit=limit)
        except Exception as exc:
            logger.warning("Impossible de récupérer les alertes Wazuh brutes: %s", exc)
            return []

        logger.info("%s alerte(s) Wazuh brute(s) récupérée(s)", len(items))
        return items