from typing import List

from common.event import Event
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class EventsService:
    def __init__(self, event_repository=None, detection_engine=None, detections_service=None) -> None:
        self.event_repository = event_repository
        self.detection_engine = detection_engine
        self.detections_service = detections_service

    def ingest(self, events: List[Event]) -> None:
        logger.info("Ingestion de %s événement(s)", len(events))

        for event in events:
            logger.debug("Traitement event %s", event)

            if self.event_repository:
                self.event_repository.save(event)

            if self.detection_engine:
                detections = self.detection_engine.run(event)

                if detections:
                    logger.info("%s detection(s) générée(s)", len(detections))

                    if self.detections_service:
                        self.detections_service.add_detections(detections)

    def list_detections(self):
        if not self.detections_service:
            return []

        return self.detections_service.list_detections()

    def clear_detections(self) -> None:
        if self.detections_service:
            self.detections_service.clear()