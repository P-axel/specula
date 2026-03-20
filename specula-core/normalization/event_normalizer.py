from typing import Any, Dict

from common.event import Event


class EventNormalizer:
    @staticmethod
    def from_wazuh_agent(agent: Dict[str, Any]) -> Event:
        agent_id = str(agent.get("id") or "unknown")
        agent_name = str(agent.get("name") or "unknown")
        status = str(agent.get("status") or "unknown").strip().lower()
        last_keepalive = agent.get("lastKeepAlive")
        agent_ip = agent.get("ip")

        title = f"Wazuh agent {agent_name} status is {status}"
        description = f"Agent Wazuh {agent_name} with status {status}."
        summary = title

        severity = "info"
        if status in {"disconnected", "never_connected", "pending"}:
            severity = "medium"
        elif status not in {"active"}:
            severity = "low"

        return Event(
            event_id=f"wazuh-agent-status-{agent_id}",
            source="wazuh",
            source_type="host",
            source_event_type="agent_status",
            event_type="status",
            title=title,
            description=description,
            summary=summary,
            category="agent_status",
            severity=severity,
            confidence=0.95,
            asset_id=agent_id,
            asset_name=agent_name,
            hostname=agent_name,
            status=status,
            src_ip=agent_ip,
            occurred_at=last_keepalive,
            tags=["wazuh", "agent", "status"],
            metadata={
                "agent_status": status,
                "manager": agent.get("manager"),
                "version": agent.get("version"),
                "groups": agent.get("groups") or [],
                "os": agent.get("os"),
            },
            raw_payload=agent,
        )

    @staticmethod
    def from_suricata_alert(alert: Dict[str, Any]) -> Event:
        suricata_alert = alert.get("alert", {})

        timestamp = str(alert.get("timestamp") or "unknown")
        signature = str(suricata_alert.get("signature") or "Unknown Suricata alert")
        signature_id = str(suricata_alert.get("signature_id") or "")
        category_raw = str(suricata_alert.get("category") or "")
        severity_value = suricata_alert.get("severity", 3)

        severity = EventNormalizer._map_suricata_severity(severity_value)
        category = EventNormalizer._map_suricata_category(signature, category_raw)

        return Event(
            event_id=f"suricata-{timestamp}-{signature_id or 'no-rule'}",
            source="suricata",
            source_type="network",
            source_event_type="network_alert",
            event_type="alert",
            title=signature,
            description=category_raw or signature,
            summary=signature,
            category=category,
            severity=severity,
            confidence=0.80,
            src_ip=alert.get("src_ip"),
            src_port=EventNormalizer._safe_int(alert.get("src_port")),
            dest_ip=alert.get("dest_ip"),
            dest_port=EventNormalizer._safe_int(alert.get("dest_port")),
            protocol=alert.get("proto"),
            rule_id=signature_id or None,
            signature=signature,
            occurred_at=alert.get("timestamp"),
            tags=["suricata", "network", category],
            metadata={
                "suricata_category": category_raw,
                "flow_id": alert.get("flow_id"),
                "app_proto": alert.get("app_proto"),
                "event_type": alert.get("event_type"),
            },
            raw_payload=alert,
        )

    @staticmethod
    def from_wazuh_alert(alert: Dict[str, Any]) -> Event:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        data = alert.get("data", {})

        rule_id = str(rule.get("id") or "")
        title = str(rule.get("description") or "Wazuh alert")
        level = rule.get("level", 0)
        groups = [str(x).lower() for x in (rule.get("groups") or [])]

        severity = EventNormalizer._map_wazuh_severity(level)
        category = EventNormalizer._map_wazuh_category(groups)

        event_id = str(alert.get("id") or alert.get("_id") or f"wazuh-{rule_id or 'unknown'}")
        asset_id = str(agent.get("id") or "") or None
        asset_name = agent.get("name")
        hostname = agent.get("name")

        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or alert.get("srcip")
            or alert.get("src_ip")
        )
        dest_ip = (
            data.get("dstip")
            or data.get("destip")
            or data.get("dest_ip")
            or alert.get("dstip")
            or alert.get("dest_ip")
        )

        user_name = (
            data.get("dstuser")
            or data.get("srcuser")
            or data.get("user")
            or data.get("username")
        )
        process_name = data.get("process") or data.get("process_name")
        file_path = data.get("file") or data.get("path") or data.get("filename")

        return Event(
            event_id=event_id,
            source="wazuh",
            source_type="host",
            source_event_type="security_alert",
            event_type="alert",
            title=title,
            description=title,
            summary=title,
            category=category,
            severity=severity,
            confidence=0.75,
            asset_id=asset_id,
            asset_name=asset_name,
            hostname=hostname,
            src_ip=src_ip,
            dest_ip=dest_ip,
            user_name=user_name,
            process_name=process_name,
            file_path=file_path,
            rule_id=rule_id or None,
            signature=title,
            occurred_at=alert.get("timestamp"),
            tags=["wazuh", "host", category],
            metadata={
                "wazuh_level": level,
                "wazuh_groups": groups,
                "decoder": alert.get("decoder"),
                "location": alert.get("location"),
            },
            raw_payload=alert,
        )

    @staticmethod
    def _map_suricata_severity(value: Any) -> str:
        try:
            severity = int(value)
        except (TypeError, ValueError):
            return "info"

        if severity == 1:
            return "high"
        if severity == 2:
            return "medium"
        if severity == 3:
            return "low"
        return "info"

    @staticmethod
    def _map_suricata_category(signature: str, category_raw: str) -> str:
        haystack = f"{signature} {category_raw}".lower()

        if "scan" in haystack:
            return "network_scan"
        if "dns" in haystack:
            return "dns_activity"
        if "tls" in haystack or "ssl" in haystack:
            return "tls_activity"
        if "http" in haystack or "web" in haystack:
            return "web_activity"
        if "malware" in haystack:
            return "malware"
        if "exploit" in haystack:
            return "exploit_attempt"
        if "intrusion" in haystack:
            return "intrusion_detection"
        return "network_alert"

    @staticmethod
    def _map_wazuh_severity(value: Any) -> str:
        try:
            level = int(value)
        except (TypeError, ValueError):
            return "info"

        if level >= 15:
            return "critical"
        if level >= 10:
            return "high"
        if level >= 7:
            return "medium"
        if level >= 4:
            return "low"
        return "info"

    @staticmethod
    def _map_wazuh_category(groups: list[str]) -> str:
        if "authentication_failed" in groups or "authentication_failures" in groups:
            return "identity_activity"
        if "rootcheck" in groups:
            return "host_anomaly"
        if "syscheck" in groups or "fim" in groups or "file_integrity" in groups:
            return "file_integrity"
        if "malware" in groups:
            return "malware"
        if "vulnerability" in groups:
            return "vulnerability"
        if "process" in groups or "sysmon" in groups:
            return "process_activity"
        return "system_activity"

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except (TypeError, ValueError):
            return None