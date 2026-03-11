from common.detection import Detection


class AgentInactiveRule:
    def evaluate(self, event):
        if event.source != "wazuh":
            return None

        if event.source_event_type != "agent_status":
            return None

        if event.severity != "medium":
            return None

        return Detection(
            id=f"detection-agent-inactive-{event.event_id}",
            type="agent_inactive",
            title=f"Agent inactif détecté pour {event.asset_id}",
            description="Specula a détecté un agent Wazuh non actif.",
            severity="medium",
            confidence=0.95,
            source="specula",
            asset_id=event.asset_id,
            event_ids=[event.event_id],
            metadata={
                "origin_source": event.source,
                "origin_event_type": event.source_event_type,
                "original_title": event.title,
            },
        )