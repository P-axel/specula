from typing import Any, Dict

from common.event import Event


class EventNormalizer:
    @staticmethod
    def from_wazuh_agent(agent: Dict[str, Any]) -> Event:
        agent_id = str(agent.get("id", "unknown"))
        agent_name = str(agent.get("name", "unknown"))
        status = str(agent.get("status", "unknown"))
        last_keepalive = agent.get("lastKeepAlive")

        title = f"Wazuh agent {agent_name} status is {status}"

        severity = "low"
        if status.lower() != "active":
            severity = "medium"

        return Event(
               event_id=f"wazuh-agent-status-{agent_id}",
               source="wazuh",
                event_type="status",
                source_event_type="agent_status",
                title=title,
                severity=severity,
                 asset_id=agent_id,
                 src_ip=agent.get("ip"),
                 occurred_at=last_keepalive,
                 raw_payload=agent,
)

    @staticmethod
    def from_suricata_alert(alert: Dict[str, Any]) -> Event:
        suricata_alert = alert.get("alert", {})

        event_id = str(alert.get("timestamp", "unknown"))
        signature = str(suricata_alert.get("signature", "Unknown Suricata alert"))
        severity_value = suricata_alert.get("severity", 3)

        severity = "low"
        if severity_value == 1:
            severity = "high"
        elif severity_value == 2:
            severity = "medium"

        return Event(
            event_id=f"suricata-{event_id}",
            source="suricata",
            source_event_type="network_alert",
            title=signature,
            severity=severity,
            src_ip=alert.get("src_ip"),
            dest_ip=alert.get("dest_ip"),
            occurred_at=alert.get("timestamp"),
            raw_payload=alert,
        )