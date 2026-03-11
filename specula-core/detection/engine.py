from typing import List

from common.detection import Detection
from detection.rules.repeated_high_severity import RepeatedHighSeverityRule


class DetectionEngine:
    def __init__(self) -> None:
        self.rules = [
            RepeatedHighSeverityRule(),
        ]

    def run(self, event) -> List[Detection]:
        detections: List[Detection] = []

        for rule in self.rules:
            result = rule.evaluate(event)
            if result:
                if isinstance(result, list):
                    detections.extend(result)
                else:
                    detections.append(result)

        return detections