from __future__ import annotations

from typing import List, Dict, Any

from services.ingestion.alerts_service import AlertsService
from services.transformation.detection_engine import DetectionEngine
from services.transformation.detection_deduplicator import DetectionDeduplicator
from services.transformation.alert_decision_service import AlertDecisionService
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class DetectionsService:
    def __init__(self) -> None:
        self.alerts_service = AlertsService()
        self.engine = DetectionEngine()
        self.deduplicator = DetectionDeduplicator()
        self.decision = AlertDecisionService()

    def list_detections(self) -> List[Dict[str, Any]]:
        logger.info("Pipeline complet de détection")

        try:
            alerts = self.alerts_service.list_wazuh_alert_payloads()
        except Exception as exc:
            logger.error("Erreur récupération alertes Wazuh: %s", exc)
            return []

        detections: List[Dict[str, Any]] = []

        # 1. génération des détections
        for alert in alerts:
            try:
                detections.extend(self.engine.from_wazuh_alert(alert))
            except Exception as exc:
                logger.warning("Erreur processing alert: %s", exc)
                continue

        logger.debug("Après génération: %s détections", len(detections))

        # 2. déduplication
        try:
            detections = self.deduplicator.deduplicate(detections)
        except Exception as exc:
            logger.error("Erreur déduplication: %s", exc)

        logger.debug("Après déduplication: %s détections", len(detections))

        # 3. décision (enrichissement)
        for detection in detections:
            try:
                detection["alert_status"] = self.decision.alert_status(detection)
                detection["alert_reason"] = self.decision.alert_reason(detection)
            except Exception:
                detection["alert_status"] = "unknown"
                detection["alert_reason"] = "error"

        # 4. tri final
        detections.sort(
            key=lambda item: str(
                item.get("timestamp")
                or item.get("created_at")
                or ""
            ),
            reverse=True,
        )

        logger.info("%s détection(s) finales", len(detections))
        return detections