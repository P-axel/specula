from dataclasses import asdict
from typing import Any, Dict

from common.normalized_event import NormalizedEvent


class WazuhMapper:
    @staticmethod
    def _extract_source_event_id(alert: Dict[str, Any]) -> str:
        return str(
            alert.get("id")
            or alert.get("_id")
            or alert.get("timestamp")
            or alert.get("@timestamp")
            or "unknown-event"
        )

    @staticmethod
    def _extract_asset_id(alert: Dict[str, Any]) -> str:
        agent = alert.get("agent", {})
        manager = alert.get("manager", {})

        return str(
            agent.get("id")
            or agent.get("name")
            or manager.get("name")
            or "unknown-asset"
        )

    @staticmethod
    def _extract_asset_name(alert: Dict[str, Any]) -> str:
        agent = alert.get("agent", {})

        return str(
            agent.get("name")
            or agent.get("id")
            or "unknown-asset"
        )

    @staticmethod
    def _extract_severity(alert: Dict[str, Any]) -> int:
        rule = alert.get("rule", {})
        level = rule.get("level", 0)

        try:
            severity = int(level)
        except (TypeError, ValueError):
            severity = 0

        return max(0, min(severity, 15))

    @staticmethod
    def _extract_category(alert: Dict[str, Any]) -> str:
        rule = alert.get("rule", {})
        groups = rule.get("groups", [])

        if isinstance(groups, list) and groups:
            return str(groups[0])

        return "security_event"

    @staticmethod
    def _extract_title(alert: Dict[str, Any]) -> str:
        rule = alert.get("rule", {})
        return str(rule.get("description") or "Alerte Wazuh")

    @staticmethod
    def _extract_description(alert: Dict[str, Any]) -> str:
        rule = alert.get("rule", {})
        full_log = alert.get("full_log")

        if full_log:
            return str(full_log)

        return str(rule.get("description") or "Aucune description")

    @staticmethod
    def _extract_observed_at(alert: Dict[str, Any]) -> str:
        return str(
            alert.get("timestamp")
            or alert.get("@timestamp")
            or ""
        )

    @classmethod
    def to_normalized_event(cls, alert: Dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            source="wazuh",
            source_event_id=cls._extract_source_event_id(alert),
            event_type="alert",
            category=cls._extract_category(alert),
            severity=cls._extract_severity(alert),
            title=cls._extract_title(alert),
            description=cls._extract_description(alert),
            asset_id=cls._extract_asset_id(alert),
            asset_name=cls._extract_asset_name(alert),
            observed_at=cls._extract_observed_at(alert),
            raw_payload=alert if isinstance(alert, dict) else {"raw_value": str(alert)},
        )

    @classmethod
    def to_dict(cls, alert: Dict[str, Any]) -> Dict[str, Any]:
        return asdict(cls.to_normalized_event(alert))