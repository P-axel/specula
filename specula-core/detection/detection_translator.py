from common.detection import Detection
from detection.wazuh_rule_matcher import find_rule_mapping


class DetectionTranslator:
    @staticmethod
    def _extract_rule_id(alert: dict) -> str | None:
        rule = alert.get("rule") or {}
        rule_id = rule.get("id")
        return str(rule_id) if rule_id is not None else None

    @staticmethod
    def _extract_rule_level(alert: dict) -> int:
        rule = alert.get("rule") or {}
        try:
            return int(rule.get("level", 0))
        except Exception:
            return 0

    @staticmethod
    def _extract_asset_name(alert: dict) -> str | None:
        agent = alert.get("agent") or {}
        return agent.get("name")

    @staticmethod
    def _extract_asset_id(alert: dict) -> str | None:
        agent = alert.get("agent") or {}
        return agent.get("id")

    @staticmethod
    def _extract_hostname(alert: dict) -> str | None:
        agent = alert.get("agent") or {}
        return agent.get("name")

    @staticmethod
    def _extract_source_ip(alert: dict) -> str | None:
        data = alert.get("data") or {}
        return data.get("srcip") or alert.get("srcip")

    @staticmethod
    def _extract_username(alert: dict) -> str | None:
        data = alert.get("data") or {}
        return data.get("dstuser") or data.get("user") or data.get("username")

    @staticmethod
    def _extract_ip_address(alert: dict) -> str | None:
        agent = alert.get("agent") or {}
        return agent.get("ip")

    @staticmethod
    def _fallback_category(rule_groups: list[str]) -> str:
        groups = {str(group).lower() for group in rule_groups}

        if "authentication_failed" in groups or "sshd" in groups:
            return "authentication"
        if "syscheck" in groups:
            return "file_integrity"
        if "pci_dss" in groups or "configuration" in groups:
            return "misconfiguration"
        if "malware" in groups or "virus" in groups or "yara" in groups:
            return "malware"
        if "vulnerability" in groups or "cve" in groups:
            return "vulnerabilities"
        return "system_activity"

    @staticmethod
    def _fallback_severity(level: int) -> str:
        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 5:
            return "medium"
        return "low"

    @staticmethod
    def _fallback_confidence(level: int) -> float:
        if level >= 12:
            return 0.95
        if level >= 8:
            return 0.9
        if level >= 5:
            return 0.8
        return 0.6

    @classmethod
    def translate_wazuh_alert(cls, alert: dict) -> Detection | None:
        rule = alert.get("rule") or {}
        rule_id = cls._extract_rule_id(alert)
        rule_groups = rule.get("groups") or []
        rule_description = rule.get("description") or "Alerte Wazuh"
        rule_level = cls._extract_rule_level(alert)

        category_hint = None
        if "vulnerability" in {str(group).lower() for group in rule_groups}:
            category_hint = "VULN"

        mapping = find_rule_mapping(rule_id=rule_id, category_hint=category_hint)

        detection_id = str(alert.get("id") or alert.get("_id") or f"wazuh-{rule_id or 'unknown'}")
        asset_id = cls._extract_asset_id(alert)
        asset_name = cls._extract_asset_name(alert)
        hostname = cls._extract_hostname(alert)
        ip_address = cls._extract_ip_address(alert)
        username = cls._extract_username(alert)
        source_ip = cls._extract_source_ip(alert)
        occurred_at = alert.get("timestamp")

        if mapping is None:
            fallback_category = cls._fallback_category(rule_groups)

            return Detection(
                id=detection_id,
                type=fallback_category,
                title=rule_description,
                description=rule_description,
                severity=cls._fallback_severity(rule_level),
                confidence=cls._fallback_confidence(rule_level),
                source="wazuh",
                source_rule_id=rule_id,
                asset_id=asset_id,
                asset_name=asset_name,
                hostname=hostname,
                ip_address=ip_address,
                username=username,
                source_ip=source_ip,
                status="open",
                recommended_actions=[],
                tags=[str(group).lower() for group in rule_groups],
                metadata={
                    "occurred_at": occurred_at,
                    "rule_groups": [str(group).lower() for group in rule_groups],
                    "rule_level": rule_level,
                },
                raw_payload=alert,
            )

        return Detection(
            id=detection_id,
            type=mapping["category"],
            title=mapping["name"],
            description=mapping["summary"],
            severity=mapping["severity"],
            confidence=0.9,
            source="wazuh",
            source_rule_id=rule_id,
            asset_id=asset_id,
            asset_name=asset_name,
            hostname=hostname,
            ip_address=ip_address,
            username=username,
            source_ip=source_ip,
            status="open",
            recommended_actions=mapping.get("recommended_actions", []),
            tags=mapping.get("tags", []),
            metadata={
                "occurred_at": occurred_at,
                "rule_groups": [str(group).lower() for group in rule_groups],
                "rule_level": rule_level,
            },
            raw_payload=alert,
        )