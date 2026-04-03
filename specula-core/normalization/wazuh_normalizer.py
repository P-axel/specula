from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

from common.asset import Asset

logger = logging.getLogger(__name__)


class WazuhNormalizer:
    SOURCE = "wazuh"
    DATASET = "wazuh"
    OBSERVER_VENDOR = "Wazuh"
    OBSERVER_PRODUCT = "Wazuh"
    OBSERVER_TYPE = "siem"

    @staticmethod
    def from_wazuh_agent(agent: Dict[str, Any]) -> Asset:
        if not isinstance(agent, dict):
            raise TypeError("agent must be a dict")

        os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}

        raw_ip = agent.get("ip")
        normalized_ip: str = ""

        if isinstance(raw_ip, list):
            for candidate in raw_ip:
                try:
                    normalized_ip = str(ip_address(str(candidate).strip()))
                    break
                except ValueError:
                    continue
        elif raw_ip is not None:
            try:
                normalized_ip = str(ip_address(str(raw_ip).strip()))
            except ValueError:
                normalized_ip = str(raw_ip).strip()

        agent_id = str(agent.get("id") or "").strip()
        agent_name = str(agent.get("name") or agent.get("hostname") or "").strip()
        platform = str(os_info.get("platform") or agent.get("platform") or "").strip()
        os_name = str(os_info.get("name") or agent.get("os_name") or "").strip()
        os_version = str(os_info.get("version") or agent.get("os_version") or "").strip()
        architecture = str(os_info.get("arch") or agent.get("architecture") or "").strip()
        status = str(agent.get("status") or "unknown").strip().lower()

        return Asset(
            asset_id=agent_id,
            name=agent_name,
            hostname=agent_name,
            ip_address=normalized_ip,
            asset_type=WazuhNormalizer._detect_asset_type_static(agent_name, platform),
            platform=platform,
            os_name=os_name,
            os_version=os_version,
            architecture=architecture,
            status=status,
            manager=str(agent.get("manager") or "").strip(),
            node_name=str(agent.get("node_name") or "").strip(),
            version=str(agent.get("version") or "").strip(),
            groups=WazuhNormalizer._normalize_groups_static(agent.get("groups") or agent.get("group")),
            last_seen=agent.get("lastKeepAlive"),
            registered_at=agent.get("dateAdd")
            or agent.get("registeredDate")
            or agent.get("register_date"),
            raw_payload=agent,
        )

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw_event, dict):
            raise TypeError("raw_event must be a dict")

        if isinstance(raw_event.get("rule"), dict):
            return self._normalize_alert(raw_event)

        if raw_event.get("status") is not None and raw_event.get("id") is not None:
            return self._normalize_agent_status(raw_event)

        return self._normalize_alert(raw_event)

    def _normalize_alert(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        rule = self._as_dict(raw_event.get("rule"))
        agent = self._as_dict(raw_event.get("agent"))
        data = self._as_dict(raw_event.get("data"))
        manager = self._as_dict(raw_event.get("manager"))

        level = self._to_int(rule.get("level"))
        severity_label = self._map_wazuh_severity(level)
        groups = self._normalize_groups(rule.get("groups"))

        src_ip = self._normalize_ip(data.get("srcip") or raw_event.get("src_ip"))
        dest_ip = self._normalize_ip(data.get("dstip") or raw_event.get("dest_ip"))

        hostname = self._normalize_str(agent.get("name"))
        asset_id = self._normalize_str(agent.get("id"))
        title = self._normalize_str(rule.get("description")) or "Wazuh alert"
        timestamp = self._normalize_timestamp(raw_event.get("timestamp") or raw_event.get("@timestamp"))

        confidence = 0.75

        normalized = {
            "timestamp": timestamp,
            "event": {
                "id": self._build_alert_event_id(raw_event),
                "kind": "alert",
                "category": self._map_wazuh_category(groups),
                "type": "security_event",
                "dataset": self.DATASET,
                "module": "wazuh",
                "provider": self.SOURCE,
                "severity": severity_label,
                "severity_code": level,
            },
            "observer": {
                "vendor": self.OBSERVER_VENDOR,
                "product": self.OBSERVER_PRODUCT,
                "type": self.OBSERVER_TYPE,
                "name": self._normalize_str(manager.get("name")) or "wazuh-manager",
            },
            "host": {
                "id": asset_id,
                "hostname": hostname,
                "ip": self._normalize_ip(agent.get("ip")),
            },
            "source": {"ip": src_ip},
            "destination": {"ip": dest_ip},
            "rule": {
                "id": self._normalize_str(rule.get("id")),
                "name": title,
                "category": self._map_wazuh_category(groups),
                "severity": severity_label,
            },
            "detection": {
                "engine": "wazuh",
                "title": title,
                "rule_id": self._normalize_str(rule.get("id")),
                "severity": level,
                "severity_label": severity_label,
            },
            "risk": {
                "score": self._map_risk_score_from_wazuh(level),
                "level": severity_label,
                "confidence": confidence,
            },
            "related": {
                "ip": self._unique_list([src_ip, dest_ip]),
                "hosts": self._unique_list([hostname]),
            },
            "tags": self._unique_list(["wazuh", *groups]),
            "raw": raw_event,
        }

        return self._drop_none(normalized) or {}

    def _normalize_agent_status(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = self._normalize_str(raw_event.get("id")) or "unknown"
        agent_name = self._normalize_str(raw_event.get("name")) or "unknown"
        status = (self._normalize_str(raw_event.get("status")) or "unknown").lower()
        agent_ip = self._normalize_ip(raw_event.get("ip"))

        return self._drop_none({
            "event": {
                "id": f"wazuh-agent-status-{agent_id}",
                "kind": "event",
                "category": "agent_status",
                "type": "status",
                "severity": self._map_agent_status_severity(status),
            },
            "host": {
                "id": agent_id,
                "hostname": agent_name,
                "ip": agent_ip,
                "status": status,
            },
            "risk": {
                "score": self._map_agent_status_risk(status),
            },
            "raw": raw_event,
        })

    def _build_alert_event_id(self, raw_event: Dict[str, Any]) -> str:
        event_id = self._normalize_str(raw_event.get("id") or raw_event.get("_id"))
        if event_id:
            return f"wazuh-alert-{event_id}"
        return "wazuh-alert-unknown"

    def _map_wazuh_severity(self, value: Any) -> str:
        level = self._to_int(value)
        if level is None:
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

    def _map_wazuh_category(self, groups: List[str]) -> str:
        if "authentication_failed" in groups:
            return "identity_activity"
        if "malware" in groups:
            return "malware"
        return "system_activity"

    def _map_risk_score_from_wazuh(self, value: Any) -> Optional[int]:
        level = self._to_int(value)
        if level is None:
            return None
        if level >= 15:
            return 95
        if level >= 10:
            return 80
        if level >= 7:
            return 60
        if level >= 4:
            return 35
        return 15

    def _map_agent_status_severity(self, status: str) -> str:
        return "medium" if status != "active" else "info"

    def _map_agent_status_risk(self, status: str) -> int:
        return 50 if status != "active" else 10

    def _normalize_groups(self, groups: Any) -> List[str]:
        if isinstance(groups, list):
            return [str(x).strip().lower() for x in groups if x]
        return []

    @staticmethod
    def _normalize_groups_static(groups: Any) -> Optional[List[str]]:
        if isinstance(groups, list):
            return [str(x).strip().lower() for x in groups if x] or None
        return None

    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except Exception:
            return None

    def _normalize_ip(self, value: Any) -> Optional[str]:
        try:
            return str(ip_address(str(value)))
        except Exception:
            return None

    def _normalize_str(self, value: Any) -> Optional[str]:
        return str(value).strip() if value else None

    def _to_int(self, value: Any) -> Optional[int]:
        try:
            return int(value)
        except Exception:
            return None

    def _unique_list(self, values: List[Any]) -> Optional[List[Any]]:
        return list(dict.fromkeys([v for v in values if v]))

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _drop_none(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self._drop_none(v) for k, v in value.items() if v is not None}
        if isinstance(value, list):
            return [self._drop_none(v) for v in value if v is not None]
        return value

    @staticmethod
    def _detect_asset_type_static(name: Optional[str], platform: Optional[str]) -> str:
        if platform and "windows" in platform.lower():
            return "workstation"
        return "server"