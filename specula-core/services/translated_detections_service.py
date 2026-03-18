from typing import List

from common.detection import Detection
from detection.detection_translator import DetectionTranslator
from services.alerts_service import AlertsService
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class TranslatedDetectionsService:
    def __init__(self) -> None:
        self.alerts_service = AlertsService()

    def list_translated_detections(self) -> List[Detection]:
        logger.info("Traduction des alertes Wazuh en détections métier")

        alerts = self.alerts_service.list_wazuh_alert_payloads()
        translated: List[Detection] = []

        for alert in alerts:
            detection = DetectionTranslator.translate_wazuh_alert(alert)

            if detection is not None:
                translated.append(detection)

        translated.sort(
            key=lambda detection: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    str(detection.severity).lower(),
                    5,
                ),
                detection.created_at,
            )
        )

        logger.info("%s détection(s) traduite(s)", len(translated))
        return translated