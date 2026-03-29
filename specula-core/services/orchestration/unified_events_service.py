from __future__ import annotations

from typing import Any

from common.event import Event
from services.ingestion.alerts_service import AlertsService
from services.ingestion.assets_service import AssetsService
from services.ingestion.suricata_service import SuricataService
from services.ingestion.wazuh_events_service import WazuhEventsService


class UnifiedEventsService:
    """
    Agrège plusieurs sources brutes et les transforme en événements normalisés.

    Pipeline :
    - lecture brut source
    - normalisation légère -> Event
    - enrichissement léger avec le contexte actif
    """

    def __init__(self, eve_path: str) -> None:
        self.suricata_service = SuricataService(eve_path)
        self.alerts_service = AlertsService()
        self.assets_service = AssetsService()
        self.wazuh_events_service = WazuhEventsService()

    def list_events(self, limit: int = 200) -> list[Event]:
        items: list[Event] = []
        assets = self._load_assets_once()

        for payload in self._safe_call_suricata(limit=limit):
            try:
                event = self._from_suricata_payload(payload)
                items.append(self._enrich_event(event, assets))
            except Exception:
                continue

        for payload in self._safe_call_wazuh_alerts(limit=limit):
            try:
                event = self._from_wazuh_alert(payload)
                items.append(self._enrich_event(event, assets))
            except Exception:
                continue

        for agent in self._safe_call_wazuh_agents(limit=limit):
            try:
                event = self._from_wazuh_agent(agent)
                items.append(self._enrich_event(event, assets))
            except Exception:
                continue

        items.sort(key=lambda item: str(item.occurred_at or ""), reverse=True)

        if limit <= 0:
            return items

        return items[:limit]

    def list_event_dicts(self, limit: int = 200) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.list_events(limit=limit)]

    def _load_assets_once(self) -> list[dict[str, Any]]:
        try:
            return [asset.to_dict() for asset in self.assets_service.list_assets()]
        except Exception:
            return []

    def _from_suricata_payload(self, payload: dict[str, Any]) -> Event:
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
        dns = payload.get("dns") if isinstance(payload.get("dns"), dict) else {}
        tls = payload.get("tls") if isinstance(payload.get("tls"), dict) else {}

        event_type = str(payload.get("event_type") or "suricata_event").strip().lower()
        signature = (
            alert.get("signature")
            or payload.get("signature")
            or payload.get("title")
            or f"Suricata {event_type}"
        )

        category = self._infer_suricata_category(payload)
        severity = self._normalize_suricata_severity(
            alert.get("severity") if alert.get("severity") is not None else payload.get("severity")
        )

        occurred_at = payload.get("timestamp") or payload.get("created_at")
        hostname = http.get("hostname") or payload.get("host") or payload.get("hostname")
        src_ip = payload.get("src_ip") or payload.get("source_ip")
        dest_ip = payload.get("dest_ip") or payload.get("destination_ip")

        return Event(
            event_id=str(
                payload.get("flow_id")
                or payload.get("id")
                or f"suricata:{event_type}:{occurred_at}:{src_ip}:{dest_ip}"
            ),
            title=str(signature),
            description=str(alert.get("category") or signature),
            summary=str(signature),
            status="new",
            occurred_at=occurred_at,
            source="suricata",
            source_type="network",
            source_event_type=event_type,
            event_type=event_type,
            category=category,
            severity=severity,
            confidence=self._suricata_confidence(payload),
            asset_id=None,
            asset_name=dest_ip,
            hostname=hostname,
            src_ip=src_ip,
            src_port=payload.get("src_port"),
            dest_ip=dest_ip,
            dest_port=payload.get("dest_port"),
            protocol=payload.get("proto") or payload.get("protocol"),
            user_name=None,
            process_name=None,
            file_path=None,
            rule_id=alert.get("signature_id") or payload.get("signature_id"),
            signature=str(signature),
            tags=self._dedupe_tags(
                [
                    "suricata",
                    event_type,
                    payload.get("app_proto"),
                    category,
                ]
            ),
            metadata={
                "app_proto": payload.get("app_proto"),
                "alert_category": alert.get("category"),
                "http_url": http.get("url"),
                "dns_rrname": dns.get("rrname"),
                "tls_sni": tls.get("sni"),
            },
            raw_payload=payload,
        )

    def _from_wazuh_alert(self, payload: dict[str, Any]) -> Event:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}

        title = (
            rule.get("description")
            or payload.get("title")
            or payload.get("full_log")
            or "Wazuh alert"
        )

        category = self._infer_wazuh_alert_category(payload)
        severity = self._normalize_wazuh_severity(rule.get("level"))

        return Event(
            event_id=str(payload.get("id") or payload.get("_id") or f"wazuh:{title}"),
            title=str(title),
            description=str(payload.get("full_log") or title),
            summary=str(title),
            status="new",
            occurred_at=payload.get("timestamp") or payload.get("@timestamp"),
            source="wazuh",
            source_type="host",
            source_event_type="alert",
            event_type="alert",
            category=category,
            severity=severity,
            confidence=self._wazuh_confidence(rule.get("level")),
            asset_id=agent.get("id"),
            asset_name=agent.get("name"),
            hostname=agent.get("name"),
            src_ip=payload.get("srcip"),
            src_port=None,
            dest_ip=agent.get("ip"),
            dest_port=None,
            protocol=None,
            user_name=data.get("srcuser") or data.get("dstuser"),
            process_name=data.get("process") or data.get("program_name"),
            file_path=data.get("file"),
            rule_id=rule.get("id"),
            signature=str(title),
            tags=self._dedupe_tags(["wazuh", *(rule.get("groups") or [])]),
            metadata={
                "rule_level": rule.get("level"),
                "rule_groups": rule.get("groups") or [],
                "agent_ip": agent.get("ip"),
            },
            raw_payload=payload,
        )

    def _from_wazuh_agent(self, payload: dict[str, Any]) -> Event:
        title = payload.get("name") or payload.get("hostname") or "Wazuh agent"
        status = str(payload.get("status") or "").strip().lower()

        if status in {"disconnected", "never_connected"}:
            severity = "medium"
        elif status in {"pending"}:
            severity = "low"
        else:
            severity = "info"

        return Event(
            event_id=str(payload.get("id") or payload.get("agent_id") or f"agent:{title}"),
            title=f"État agent Wazuh: {title}",
            description=f"État agent {status or 'unknown'}",
            summary=f"Agent {title} ({status or 'unknown'})",
            status="new",
            occurred_at=payload.get("lastKeepAlive")
            or payload.get("last_seen")
            or payload.get("dateAdd"),
            source="wazuh",
            source_type="host",
            source_event_type="agent_status",
            event_type="agent_status",
            category="agent_status",
            severity=severity,
            confidence=0.6,
            asset_id=payload.get("id") or payload.get("agent_id"),
            asset_name=payload.get("name"),
            hostname=payload.get("name") or payload.get("hostname"),
            src_ip=None,
            src_port=None,
            dest_ip=payload.get("ip") or payload.get("last_ip"),
            dest_port=None,
            protocol=None,
            user_name=None,
            process_name=None,
            file_path=None,
            rule_id=None,
            signature=None,
            tags=self._dedupe_tags(["wazuh", "agent_status", status]),
            metadata={
                "agent_status": status,
                "version": payload.get("version"),
                "groups": payload.get("group") or payload.get("groups") or [],
                "os_name": payload.get("os", {}).get("name")
                if isinstance(payload.get("os"), dict)
                else payload.get("os_name"),
            },
            raw_payload=payload,
        )

    def _enrich_event(self, event: Event, assets: list[dict[str, Any]]) -> Event:
        asset = self._find_matching_asset(event, assets)
        if asset is None:
            return event

        if not event.asset_id:
            event.asset_id = self._safe_str(asset.get("asset_id")) or event.asset_id

        if not event.asset_name:
            event.asset_name = (
                self._safe_str(asset.get("name"))
                or self._safe_str(asset.get("asset_id"))
                or event.asset_name
            )

        if not event.hostname:
            event.hostname = (
                self._safe_str(asset.get("hostname"))
                or self._safe_str(asset.get("name"))
                or event.hostname
            )

        event.metadata["asset_criticality"] = asset.get("criticality")
        event.metadata["asset_platform"] = asset.get("platform") or asset.get("os_name")
        event.metadata["asset_health_state"] = asset.get("health_state")
        event.metadata["asset_status"] = asset.get("status")
        event.metadata["asset_groups"] = asset.get("groups") or []

        return event

    def _find_matching_asset(
        self,
        event: Event,
        assets: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        event_asset_id = self._safe_str(event.asset_id).lower()
        event_asset_name = self._safe_str(event.asset_name).lower()
        event_hostname = self._safe_str(event.hostname).lower()
        event_src_ip = self._safe_str(event.src_ip).lower()
        event_dest_ip = self._safe_str(event.dest_ip).lower()

        for asset in assets:
            asset_id = self._safe_str(asset.get("asset_id")).lower()
            asset_name = self._safe_str(asset.get("name")).lower()
            hostname = self._safe_str(asset.get("hostname")).lower()
            ip_address = self._safe_str(asset.get("ip")).lower()
            last_ip = self._safe_str(asset.get("last_ip")).lower()

            if event_asset_id and event_asset_id == asset_id:
                return asset

            if event_asset_name and event_asset_name == asset_name:
                return asset

            if event_hostname and event_hostname in {asset_name, hostname}:
                return asset

            if event_src_ip and event_src_ip in {ip_address, last_ip}:
                return asset

            if event_dest_ip and event_dest_ip in {ip_address, last_ip}:
                return asset

        return None

    def _safe_str(self, value: Any) -> str:
        return str(value or "").strip()

    def _safe_call_suricata(self, limit: int) -> list[dict[str, Any]]:
        candidates = [
            "list_alert_payloads",
            "list_alerts",
            "list_detection_payloads",
        ]

        for method_name in candidates:
            method = getattr(self.suricata_service, method_name, None)
            if callable(method):
                try:
                    result = method(limit=limit)
                except TypeError:
                    result = method()
                if isinstance(result, list):
                    return result

        return []

    def _safe_call_wazuh_alerts(self, limit: int) -> list[dict[str, Any]]:
        candidates = [
            "list_wazuh_alert_payloads",
            "list_alert_payloads",
            "list_alerts",
        ]

        for method_name in candidates:
            method = getattr(self.alerts_service, method_name, None)
            if callable(method):
                try:
                    result = method(limit=limit)
                except TypeError:
                    try:
                        result = method()
                    except TypeError:
                        continue
                if isinstance(result, list):
                    return result

        return []

    def _safe_call_wazuh_agents(self, limit: int) -> list[dict[str, Any]]:
        candidates = [
            "list_agents",
            "list_agent_status_payloads",
            "list_events",
        ]

        for method_name in candidates:
            method = getattr(self.wazuh_events_service, method_name, None)
            if callable(method):
                try:
                    result = method(limit=limit)
                except TypeError:
                    try:
                        result = method()
                    except TypeError:
                        continue
                if isinstance(result, list):
                    return result

        return []

    def _normalize_suricata_severity(self, value: Any) -> str:
        if isinstance(value, int):
            return {
                1: "critical",
                2: "high",
                3: "medium",
                4: "low",
            }.get(value, "low")

        normalized = str(value or "").strip().lower()
        if normalized in {"critical", "high", "medium", "low", "info"}:
            return normalized
        return "low"

    def _normalize_wazuh_severity(self, rule_level: Any) -> str:
        try:
            level = int(rule_level)
        except (TypeError, ValueError):
            return "low"

        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 5:
            return "medium"
        if level >= 3:
            return "low"
        return "info"

    def _suricata_confidence(self, payload: dict[str, Any]) -> float:
        event_type = str(payload.get("event_type") or "").strip().lower()
        if event_type == "alert":
            return 0.75
        if event_type in {"dns", "http", "tls", "anomaly"}:
            return 0.50
        return 0.30

    def _wazuh_confidence(self, rule_level: Any) -> float:
        try:
            level = int(rule_level)
        except (TypeError, ValueError):
            return 0.50

        if level >= 12:
            return 0.90
        if level >= 8:
            return 0.80
        if level >= 5:
            return 0.65
        return 0.50

    def _infer_suricata_category(self, payload: dict[str, Any]) -> str:
        event_type = str(payload.get("event_type") or "").strip().lower()
        app_proto = str(payload.get("app_proto") or "").strip().lower()

        if event_type == "dns" or app_proto == "dns":
            return "dns_activity"
        if event_type == "http" or app_proto == "http":
            return "web_activity"
        if event_type == "tls" or app_proto == "tls":
            return "tls_activity"
        if event_type == "alert":
            return "network_alert"
        return "network_event"

    def _infer_wazuh_alert_category(self, payload: dict[str, Any]) -> str:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        groups = [str(item).strip().lower() for item in (rule.get("groups") or [])]
        description = str(rule.get("description") or "").strip().lower()

        if "authentication" in groups or "auth" in description:
            return "identity_activity"
        if "syscheck" in groups or "fim" in groups:
            return "file_integrity"
        if "rootcheck" in groups:
            return "host_anomaly"
        if "process" in groups:
            return "process_activity"
        if "vulnerability" in groups:
            return "vulnerability"
        return "system_activity"

    def _dedupe_tags(self, values: list[Any]) -> list[str]:
        seen: set[str] = set()
        items: list[str] = []

        for value in values:
            normalized = str(value or "").strip().lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            items.append(normalized)

        return items