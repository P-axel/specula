from typing import Any, Dict

from common.alert import Alert


class AlertNormalizer:
    @staticmethod
    def from_event(event: Dict[str, Any]) -> Alert:
        event_id = str(event.get("event_id", "unknown"))
        source = str(event.get("source", "unknown"))
        title = str(event.get("title", "Untitled alert"))
        severity = str(event.get("severity", "low"))
        asset_id = event.get("asset_id")

        return Alert(
            alert_id=f"alert-{event_id}",
            rule_id="generic-event-rule",
            source=source,
            title=title,
            severity=severity,
            status="open",
            asset_id=asset_id,
            event_id=event_id,
            description=f"Generated from event {event_id}",
            raw_payload=event,
        )