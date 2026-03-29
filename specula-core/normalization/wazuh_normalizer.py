from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

from common.asset import Asset

logger = logging.getLogger(__name__)


class WazuhNormalizer:
    """
    Normalizeur canonique Wazuh -> schéma commun Specula.

    Il gère principalement :
    - les alertes Wazuh
    - les états d'agents Wazuh

    Même schéma de sortie que SuricataNormalizer pour faciliter :
    - corrélation
    - scoring
    - création d'incidents
    - ajout futur d'autres sources
    """

    SOURCE = "wazuh"
    DATASET = "wazuh"
    OBSERVER_VENDOR = "Wazuh"
    OBSERVER_PRODUCT = "Wazuh"
    OBSERVER_TYPE = "siem"

    @staticmethod
    def from_wazuh_agent(agent: Dict[str, Any]) -> Asset:
        """
        Construit un objet Asset à partir d'un agent Wazuh brut.
        Utilisé par connectors.wazuh.agents.WazuhAgentsConnector.
        """
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
            if not normalized_ip and raw_ip:
                normalized_ip = str(raw_ip[0]).strip()
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
        manager = str(agent.get("manager") or "").strip()
        node_name = str(agent.get("node_name") or "").strip()
        version = str(agent.get("version") or "").strip()

        asset_type = WazuhNormalizer._detect_asset_type_static(agent_name, platform)

        return Asset(
            asset_id=agent_id,
            name=agent_name,
            hostname=agent_name,
            ip_address=normalized_ip,
            asset_type=asset_type,
            platform=platform,
            os_name=os_name,
            os_version=os_version,
            architecture=architecture,
            status=status,
            manager=manager,
            node_name=node_name,
            version=version,
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

        event_kind = self._detect_event_kind(raw_event)

        if event_kind == "agent_status":
            return self._normalize_agent_status(raw_event)

        return self._normalize_alert(raw_event)

    def _normalize_alert(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        rule = self._as_dict(raw_event.get("rule"))
        agent = self._as_dict(raw_event.get("agent"))
        data = self._as_dict(raw_event.get("data"))
        manager = self._as_dict(raw_event.get("manager"))
        decoder = self._as_dict(raw_event.get("decoder"))

        level = self._to_int(rule.get("level"))
        severity_label = self._map_wazuh_severity(level)
        groups = self._normalize_groups(rule.get("groups"))

        src_ip = self._normalize_ip(
            data.get("srcip")
            or data.get("src_ip")
            or raw_event.get("srcip")
            or raw_event.get("src_ip")
        )
        dest_ip = self._normalize_ip(
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destip")
            or data.get("dest_ip")
            or raw_event.get("dstip")
            or raw_event.get("dest_ip")
        )

        src_port = self._to_int(
            data.get("srcport") or data.get("src_port") or raw_event.get("src_port")
        )
        dest_port = self._to_int(
            data.get("dstport") or data.get("dst_port") or data.get("dest_port")
        )
        protocol = self._normalize_protocol(data.get("protocol") or raw_event.get("protocol"))

        user_name = self._normalize_str(
            data.get("dstuser")
            or data.get("srcuser")
            or data.get("user")
            or data.get("username")
        )
        process_name = self._normalize_str(data.get("process") or data.get("process_name"))
        process_pid = self._to_int(data.get("pid") or data.get("process_id"))
        file_path = self._normalize_str(data.get("file") or data.get("path") or data.get("filename"))
        file_hash_sha256 = self._normalize_str(data.get("sha256"))
        file_hash_md5 = self._normalize_str(data.get("md5"))

        hostname = self._normalize_str(agent.get("name"))
        asset_id = self._normalize_str(agent.get("id"))
        title = self._normalize_str(rule.get("description")) or "Wazuh alert"
        timestamp = self._normalize_timestamp(raw_event.get("timestamp") or raw_event.get("@timestamp"))
        category = self._map_wazuh_category(groups)

        logger.debug(
            "WAZUH RAW ALERT | id=%s rule_id=%s level=%s agent=%s src=%s dst=%s",
            raw_event.get("id") or raw_event.get("_id"),
            rule.get("id"),
            level,
            hostname,
            src_ip,
            dest_ip,
        )

        normalized = {
            "timestamp": timestamp,
            "event": {
                "id": self._build_alert_event_id(raw_event),
                "kind": "alert",
                "category": category,
                "type": "alert",
                "action": None,
                "dataset": self.DATASET,
                "module": self._normalize_str(decoder.get("name")) or "wazuh",
                "provider": self.SOURCE,
                "outcome": self._infer_outcome_from_groups(groups),
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
                "os": {
                    "platform": self._safe_get_str(agent, "os", "platform"),
                    "name": self._safe_get_str(agent, "os", "name"),
                    "version": self._safe_get_str(agent, "os", "version"),
                    "architecture": self._safe_get_str(agent, "os", "arch"),
                },
            },
            "source": {
                "ip": src_ip,
                "port": src_port,
            },
            "destination": {
                "ip": dest_ip,
                "port": dest_port,
            },
            "client": None,
            "server": None,
            "network": {
                "transport": protocol,
                "protocol": protocol,
                "application": None,
                "direction": None,
                "community_id": None,
                "type": self._detect_network_type(src_ip, dest_ip),
            },
            "user": {
                "name": user_name,
            } if user_name else None,
            "process": {
                "name": process_name,
                "pid": process_pid,
            } if process_name or process_pid is not None else None,
            "file": {
                "path": file_path,
                "hash": self._drop_none({
                    "md5": file_hash_md5,
                    "sha256": file_hash_sha256,
                }),
            } if file_path or file_hash_md5 or file_hash_sha256 else None,
            "url": None,
            "dns": None,
            "http": None,
            "tls": None,
            "rule": {
                "id": self._normalize_str(rule.get("id")),
                "name": title,
                "category": category,
                "severity": severity_label,
                "groups": groups,
            },
            "detection": {
                "engine": "wazuh",
                "provider": "wazuh",
                "title": title,
                "rule_id": self._normalize_str(rule.get("id")),
                "severity": level,
                "severity_label": severity_label,
                "action": None,
                "category": category,
                "status": "observed",
            },
            "risk": {
                "score": self._map_risk_score_from_wazuh(level),
                "level": severity_label,
                "confidence": 0.75,
            },
            "related": {
                "ip": self._unique_list([src_ip, dest_ip, self._normalize_ip(agent.get("ip"))]),
                "hosts": self._unique_list([hostname]),
                "hash": self._unique_list([file_hash_md5, file_hash_sha256]),
                "rule_ids": self._unique_list([self._normalize_str(rule.get("id"))]),
                "usernames": self._unique_list([user_name]),
                "process_names": self._unique_list([process_name]),
            },
            "tags": self._unique_list(["wazuh", "host", "alert", category, *groups]),
            "source_context": {
                "source": self.SOURCE,
                "source_type": "host",
                "ingest_type": "alert",
            },
            "wazuh": {
                "alert_id": self._normalize_str(raw_event.get("id") or raw_event.get("_id")),
                "location": self._normalize_str(raw_event.get("location")),
                "full_log": self._normalize_str(raw_event.get("full_log")),
                "decoder": decoder or None,
                "manager": manager or None,
                "agent": agent or None,
                "rule": {
                    "id": self._normalize_str(rule.get("id")),
                    "level": level,
                    "description": title,
                    "groups": groups,
                    "pci_dss": rule.get("pci_dss"),
                    "gdpr": rule.get("gdpr"),
                    "hipaa": rule.get("hipaa"),
                    "nist_800_53": rule.get("nist_800_53"),
                    "mitre": rule.get("mitre"),
                } if rule else None,
                "data": data or None,
            },
            "raw": raw_event,
        }

        return self._drop_none(normalized) or {}

    def _normalize_agent_status(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = self._normalize_str(raw_event.get("id")) or "unknown"
        agent_name = self._normalize_str(raw_event.get("name")) or "unknown"
        status = (self._normalize_str(raw_event.get("status")) or "unknown").lower()
        agent_ip = self._normalize_ip(raw_event.get("ip"))
        timestamp = self._normalize_timestamp(raw_event.get("lastKeepAlive") or raw_event.get("dateAdd"))
        platform = self._safe_get_str(raw_event, "os", "platform")

        severity = self._map_agent_status_severity(status)

        logger.debug(
            "WAZUH RAW AGENT | agent_id=%s name=%s status=%s ip=%s",
            agent_id,
            agent_name,
            status,
            agent_ip,
        )

        normalized = {
            "timestamp": timestamp,
            "event": {
                "id": f"wazuh-agent-status-{agent_id}",
                "kind": "event",
                "category": "agent_status",
                "type": "status",
                "action": status,
                "dataset": self.DATASET,
                "module": "agent",
                "provider": self.SOURCE,
                "outcome": "success" if status == "active" else "unknown",
                "severity": severity,
                "severity_code": None,
            },
            "observer": {
                "vendor": self.OBSERVER_VENDOR,
                "product": self.OBSERVER_PRODUCT,
                "type": self.OBSERVER_TYPE,
                "name": self._normalize_str(raw_event.get("manager")) or "wazuh-manager",
            },
            "host": {
                "id": agent_id,
                "hostname": agent_name,
                "ip": agent_ip,
                "os": {
                    "platform": platform,
                    "name": self._safe_get_str(raw_event, "os", "name"),
                    "version": self._safe_get_str(raw_event, "os", "version"),
                    "architecture": self._safe_get_str(raw_event, "os", "arch"),
                },
                "type": self._detect_asset_type(agent_name, platform),
                "status": status,
                "version": self._normalize_str(raw_event.get("version")),
                "groups": raw_event.get("groups") or raw_event.get("group"),
            },
            "source": {
                "ip": agent_ip,
            },
            "destination": None,
            "client": None,
            "server": None,
            "network": {
                "type": self._detect_network_type(agent_ip, None),
            },
            "user": None,
            "process": None,
            "file": None,
            "url": None,
            "dns": None,
            "http": None,
            "tls": None,
            "rule": None,
            "detection": None,
            "risk": {
                "score": self._map_agent_status_risk(status),
                "level": severity,
                "confidence": 0.95,
            },
            "related": {
                "ip": self._unique_list([agent_ip]),
                "hosts": self._unique_list([agent_name]),
                "hash": None,
                "rule_ids": None,
                "usernames": None,
                "process_names": None,
            },
            "tags": self._unique_list(["wazuh", "agent", "status", status]),
            "source_context": {
                "source": self.SOURCE,
                "source_type": "host",
                "ingest_type": "inventory",
            },
            "wazuh": {
                "agent": raw_event,
            },
            "raw": raw_event,
        }

        return self._drop_none(normalized) or {}

    def _detect_event_kind(self, raw_event: Dict[str, Any]) -> str:
        if isinstance(raw_event.get("rule"), dict):
            return "alert"
        if raw_event.get("status") is not None and raw_event.get("id") is not None:
            return "agent_status"
        return "alert"

    def _build_alert_event_id(self, raw_event: Dict[str, Any]) -> str:
        event_id = self._normalize_str(raw_event.get("id") or raw_event.get("_id"))
        if event_id:
            return f"wazuh-alert-{event_id}"

        ts = self._normalize_str(raw_event.get("timestamp") or raw_event.get("@timestamp")) or "unknown-ts"
        rule_id = self._safe_get_str(raw_event, "rule", "id") or "no-rule"
        agent_id = self._safe_get_str(raw_event, "agent", "id") or "no-agent"
        return f"wazuh-alert-{agent_id}-{rule_id}-{ts}"

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
        if "windows" in groups or "linux" in groups:
            return "system_activity"
        return "system_activity"

    def _infer_outcome_from_groups(self, groups: List[str]) -> Optional[str]:
        if "authentication_failed" in groups or "authentication_failures" in groups:
            return "failure"
        if "authentication_success" in groups:
            return "success"
        return None

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
        if status in {"disconnected", "never_connected", "pending"}:
            return "medium"
        if status in {"active"}:
            return "info"
        return "low"

    def _map_agent_status_risk(self, status: str) -> int:
        if status in {"disconnected", "never_connected", "pending"}:
            return 55
        if status == "active":
            return 10
        return 25

    def _detect_asset_type(self, name: Optional[str], platform: Optional[str]) -> str:
        lowered_name = (name or "").lower()
        lowered_platform = (platform or "").lower()

        if "manager" in lowered_name:
            return "manager"
        if "windows" in lowered_platform:
            return "workstation"
        if any(x in lowered_platform for x in ["linux", "amzn", "debian", "ubuntu", "centos", "rhel"]):
            return "server"
        return "server"

    @staticmethod
    def _detect_asset_type_static(name: Optional[str], platform: Optional[str]) -> str:
        lowered_name = (name or "").lower()
        lowered_platform = (platform or "").lower()

        if "manager" in lowered_name:
            return "manager"
        if "windows" in lowered_platform:
            return "workstation"
        if any(x in lowered_platform for x in ["linux", "amzn", "debian", "ubuntu", "centos", "rhel"]):
            return "server"
        return "server"

    def _normalize_groups(self, groups: Any) -> List[str]:
        if isinstance(groups, list):
            return [str(x).strip().lower() for x in groups if x is not None and str(x).strip()]

        if isinstance(groups, str):
            if "," in groups:
                return [part.strip().lower() for part in groups.split(",") if part.strip()]
            value = groups.strip().lower()
            return [value] if value else []

        return []

    @staticmethod
    def _normalize_groups_static(groups: Any) -> Optional[List[str]]:
        if isinstance(groups, list):
            result = [str(x).strip().lower() for x in groups if x is not None and str(x).strip()]
            return result or None

        if isinstance(groups, str):
            if "," in groups:
                result = [part.strip().lower() for part in groups.split(",") if part.strip()]
                return result or None
            value = groups.strip().lower()
            return [value] if value else None

        return None

    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            return str(value)

        raw = value.strip()
        if not raw:
            return None

        try:
            if raw.endswith("Z"):
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
            return datetime.fromisoformat(raw).isoformat()
        except ValueError:
            return raw

    def _normalize_ip(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        if isinstance(value, list):
            for item in value:
                normalized = self._normalize_ip(item)
                if normalized:
                    return normalized
            return None

        try:
            return str(ip_address(str(value).strip()))
        except ValueError:
            return self._normalize_str(value)

    def _normalize_protocol(self, value: Any) -> Optional[str]:
        normalized = self._normalize_str(value)
        return normalized.lower() if normalized else None

    def _normalize_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return str(value)

    def _to_int(self, value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _detect_network_type(self, src_ip: Optional[str], dest_ip: Optional[str]) -> Optional[str]:
        for candidate in (src_ip, dest_ip):
            if not candidate:
                continue
            try:
                return "ipv6" if ip_address(candidate).version == 6 else "ipv4"
            except ValueError:
                continue
        return None

    def _unique_list(self, values: List[Any]) -> Optional[List[Any]]:
        result = []
        for value in values:
            if value is None:
                continue
            if value not in result:
                result.append(value)
        return result or None

    def _safe_get_str(self, dct: Dict[str, Any], *keys: str) -> Optional[str]:
        current: Any = dct
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
            if current is None:
                return None
        return self._normalize_str(current)

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _drop_none(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for key, subvalue in value.items():
                cleaned_value = self._drop_none(subvalue)
                if cleaned_value is not None:
                    cleaned[key] = cleaned_value
            return cleaned or None

        if isinstance(value, list):
            cleaned_list = []
            for item in value:
                cleaned_item = self._drop_none(item)
                if cleaned_item is not None:
                    cleaned_list.append(cleaned_item)
            return cleaned_list or None

        return value