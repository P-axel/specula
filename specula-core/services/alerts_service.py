from typing import Any, Dict, List

from common.alert import Alert
from connectors.wazuh.alerts import WazuhAlertsConnector
from connectors.wazuh.client import WazuhClient
from config.settings import settings
from normalization.alert_normalizer import AlertNormalizer
from services.detection_deduplicator import DetectionDeduplicator
from services.detection_engine import DetectionEngine
from services.incident_correlator import IncidentCorrelator
from services.risk_scoring import RiskScoringService
from services.wazuh_events_service import WazuhEventsService
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class AlertsService:
    def __init__(self) -> None:
        self.events_service = WazuhEventsService()

        indexer_client = WazuhClient(
            base_url=settings.wazuh_indexer_url,
            username=settings.wazuh_indexer_username,
            password=settings.wazuh_indexer_password,
            verify_ssl=settings.wazuh_verify_tls,
            timeout=settings.wazuh_timeout,
            auth_type="basic",
        )

        self.connector = WazuhAlertsConnector(indexer_client)
        self.detection_engine = DetectionEngine()
        self.risk_scoring = RiskScoringService()
        self.deduplicator = DetectionDeduplicator(window_minutes=15)
        self.incident_correlator = IncidentCorrelator(window_minutes=30)

    def list_alerts(self) -> List[Alert]:
        logger.info("Génération des alertes depuis les événements")
        events = self.events_service.list_agent_status_events()

        alerts: List[Alert] = []

        for event in events:
            if event.severity in {"medium", "high", "critical"}:
                alerts.append(AlertNormalizer.from_event(event.to_dict()))

        logger.info("%s alert(s) générée(s)", len(alerts))
        return alerts

    def list_wazuh_alert_payloads(self, limit: int = 100) -> List[Dict[str, Any]]:
        logger.info("Récupération des alertes Wazuh brutes")

        try:
            items = self.connector.list_alerts(limit=limit)
        except Exception as exc:
            logger.warning(
                "Impossible de récupérer les alertes Wazuh brutes: %s",
                exc,
            )
            return []

        alerts: List[Dict[str, Any]] = []

        for item in items:
            rule = item.get("rule") or {}
            agent = item.get("agent") or {}
            data = item.get("data") or {}

            alerts.append(
                {
                    "id": item.get("id") or item.get("_id"),
                    "_id": item.get("_id"),
                    "timestamp": item.get("timestamp") or item.get("@timestamp"),
                    "rule": {
                        "id": rule.get("id"),
                        "level": rule.get("level"),
                        "description": rule.get("description"),
                        "groups": rule.get("groups") or [],
                    },
                    "agent": {
                        "id": agent.get("id"),
                        "name": agent.get("name"),
                        "ip": agent.get("ip"),
                    },
                    "data": data,
                    "srcip": item.get("srcip") or data.get("srcip"),
                    "raw": item,
                }
            )

        logger.info("%s alerte(s) Wazuh brute(s) récupérée(s)", len(alerts))
        return alerts

    def list_business_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Pipeline principal de détection Specula :

        Wazuh alerts
            ↓
        DetectionEngine (traduction métier)
            ↓
        Risk scoring
            ↓
        Déduplication
            ↓
        Tri par risque
        """
        logger.info("Transformation des alertes Wazuh en détections métier")

        alerts = self.list_wazuh_alert_payloads(limit=limit)
        detections: List[Dict[str, Any]] = []

        for alert in alerts:
            translated = self.detection_engine.from_wazuh_alert(alert)

            for detection in translated:
                scored_detection = self.risk_scoring.score_detection(detection)
                detections.append(scored_detection)

        detections = self.deduplicator.deduplicate(detections)

        detections.sort(
            key=lambda item: (
                int(item.get("risk_score", 0)),
                str(item.get("created_at") or item.get("timestamp") or ""),
            ),
            reverse=True,
        )

        logger.info(
            "%s détection(s) métier générée(s) après scoring et déduplication",
            len(detections),
        )
        return detections

    def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Corrèle les détections en incidents pour offrir une vue analyste.
        """
        logger.info("Corrélation des détections en incidents")

        detections = self.list_business_detections(limit=limit)
        incidents = self.incident_correlator.correlate(detections)

        logger.info("%s incident(s) corrélé(s)", len(incidents))
        return incidents