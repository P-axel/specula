from common.detection import Detection


class AgentActiveRule:
    def evaluate(self, event):
        if event.source_event_type != "agent_status":
            return None

        raw = event.raw_payload or {}
        status = raw.get("status")

        if status != "active":
            return None

        return Detection(
            detection_id=f"agent-active-{event.asset_id}",
            name="Agent active",
            severity="info",
            source="specula",
            asset_id=event.asset_id,
            occurred_at=event.occurred_at,
            description=event.title,
        )