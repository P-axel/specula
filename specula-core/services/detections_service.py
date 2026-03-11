from typing import List

from common.detection import Detection


class DetectionsService:
    def __init__(self) -> None:
        self._detections: List[Detection] = []

    def add_detections(self, detections: List[Detection]) -> None:
        self._detections.extend(detections)

    def list_detections(self) -> List[Detection]:
        return self._detections

    def clear(self) -> None:
        self._detections.clear()