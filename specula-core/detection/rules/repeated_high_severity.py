from collections import defaultdict, deque
from datetime import timedelta
from uuid import uuid4

from common.detection import Detection


class RepeatedHighSeverityRule:
    def __init__(self) -> None:
        self.window = defaultdict(deque)
        self.threshold = 3

    def evaluate(self, event):
        asset_id = getattr(event, "asset_id", None)
        severity = getattr(event, "severity", None)
        timestamp = getattr(event, "timestamp", None)

        if not asset_id or not timestamp:
            return None

        if severity not in ["high", "critical", 8, 9, 10]:
            return None

        queue = self.window[asset_id]
        queue.append((timestamp, getattr(event, "id", None)))

        cutoff = timestamp - timedelta(minutes=5)
        while queue and queue[0][0] < cutoff:
            queue.popleft()

        if len(queue) >= self.threshold:
            event_ids = [evt_id for _, evt_id in queue if evt_id]

            return Detection(
                id=str(uuid4()),
                type="repeated_high_severity",
                title="Multiples événements sévères détectés",
                description=f"L'asset {asset_id} a reçu plusieurs événements sévères en moins de 5 minutes.",
                severity="high",
                confidence=0.85,
                source="specula",
                asset_id=asset_id,
                event_ids=event_ids,
                metadata={"count": len(queue)},
            )

        return None