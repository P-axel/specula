from typing import List

from common.alert import Alert
from normalization.alert_normalizer import AlertNormalizer
from services.wazuh_events_service import WazuhEventsService
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class AlertsService:
    def __init__(self) -> None:
        self.events_service = WazuhEventsService()

    def list_alerts(self) -> List[Alert]:
        logger.info("Génération des alertes depuis les événements")
        events = self.events_service.list_agent_status_events()

        alerts = []
        for event in events:
            if event.severity in {"medium", "high", "critical"}:
                alerts.append(AlertNormalizer.from_event(event.to_dict()))

        logger.info("%s alert(s) générée(s)", len(alerts))
        return alerts