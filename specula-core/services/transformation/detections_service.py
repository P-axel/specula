from __future__ import annotations

from typing import Any, Dict, List, Optional

from config.settings import settings
from providers.suricata_provider import SuricataProvider
from providers.wazuh_provider import WazuhProvider
from services.transformation.alert_decision_service import AlertDecisionService
from services.transformation.detection_deduplicator import DetectionDeduplicator
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class DetectionsService:
    def __init__(self) -> None:
        logger.debug("Initialisation de DetectionsService")

        self.wazuh_provider: WazuhProvider | None = None
        if settings.specula_enable_wazuh and settings.wazuh_indexer_url:
            self.wazuh_provider = WazuhProvider(
                base_url=settings.wazuh_indexer_url,
                username=settings.wazuh_indexer_username,
                password=settings.wazuh_indexer_password,
                verify_ssl=settings.wazuh_verify_tls,
                timeout=settings.wazuh_timeout,
                auth_type="basic",
            )
        else:
            logger.info("Provider Wazuh désactivé")

        self.suricata_provider: Optional[SuricataProvider] = None
        if settings.specula_suricata_eve_path:
            self.suricata_provider = SuricataProvider(settings.specula_suricata_eve_path)
            logger.info(
                "Suricata provider activé avec eve path: %s",
                settings.specula_suricata_eve_path,
            )
        else:
            logger.warning(
                "Aucun chemin Suricata eve.json configuré, provider Suricata désactivé"
            )

        self.deduplicator = DetectionDeduplicator()
        self.decision = AlertDecisionService()

    def list_detections(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        logger.info("Pipeline complet de détection démarré (source=%s)", source)

        detections: List[Dict[str, Any]] = []
        detections.extend(self._collect_wazuh_detections(source))
        detections.extend(self._collect_suricata_detections(source))

        logger.debug("Après ingestion providers: %s détection(s)", len(detections))

        if source:
            detections = [d for d in detections if self._detect_source(d) == source]
            logger.debug("Après filtrage source=%s: %s détection(s)", source, len(detections))

        detections = self._deduplicate(detections)
        detections = self._apply_alert_decision(detections)

        detections.sort(
            key=lambda item: str(item.get("timestamp") or item.get("created_at") or ""),
            reverse=True,
        )

        logger.info("%s détection(s) finale(s)", len(detections))
        return detections

    def _collect_wazuh_detections(self, source: Optional[str]) -> List[Dict[str, Any]]:
        if source not in (None, "wazuh"):
            return []

        if self.wazuh_provider is None:
            return []

        try:
            detections = self.wazuh_provider.list_detections(limit=200)
            logger.info("Wazuh detections récupérées: %s", len(detections))
            return detections
        except Exception as exc:
            logger.error("Erreur récupération détections Wazuh: %s", exc)
            return []

    def _collect_suricata_detections(self, source: Optional[str]) -> List[Dict[str, Any]]:
        if source not in (None, "suricata"):
            return []

        if self.suricata_provider is None:
            return []

        try:
            detections = self.suricata_provider.list_detections(limit=200)
            logger.info("Suricata detections récupérées: %s", len(detections))
            return detections
        except Exception as exc:
            logger.error("Erreur récupération détections Suricata: %s", exc)
            return []

    def _deduplicate(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            result = self.deduplicator.deduplicate(detections)
            logger.debug("Après déduplication: %s détection(s)", len(result))
            return result
        except Exception as exc:
            logger.error("Erreur déduplication: %s", exc)
            return detections

    def _apply_alert_decision(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for detection in detections:
            try:
                detection["alert_status"] = self.decision.alert_status(detection)
                detection["alert_reason"] = self.decision.alert_reason(detection)
            except Exception as exc:
                logger.error("Erreur décision alerte: %s", exc)
                detection["alert_status"] = "unknown"
                detection["alert_reason"] = "error"

        return detections

    @staticmethod
    def _detect_source(detection: Dict[str, Any]) -> Optional[str]:
        return (
            detection.get("source_context", {}).get("source")
            or detection.get("event", {}).get("provider")
            or detection.get("detection", {}).get("provider")
        )