from __future__ import annotations

from typing import Any

from config.settings import settings
from common.event import Event
from services.ingestion.alerts_service import AlertsService
from services.ingestion.assets_service import AssetsService
from services.ingestion.suricata_service import SuricataService
from services.ingestion.wazuh_events_service import WazuhEventsService


class UnifiedEventsService:
    """
    Agrège plusieurs sources brutes et les transforme en événements normalisés.
    """

    def __init__(self, eve_path: str) -> None:
        self.suricata_service = SuricataService(eve_path)
        self.alerts_service = AlertsService()
        self.assets_service = AssetsService()

        self.wazuh_events_service: WazuhEventsService | None = None
        if settings.specula_enable_wazuh:
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

    def _safe_call_suricata(self, limit: int) -> list[dict[str, Any]]:
        for method_name in ("list_events", "list_event_payloads", "list_suricata_events"):
            method = getattr(self.suricata_service, method_name, None)
            if method is None:
                continue

            try:
                return method(limit=limit)
            except TypeError:
                try:
                    return method()
                except Exception:
                    continue
            except Exception:
                continue

        return []

    def _safe_call_wazuh_alerts(self, limit: int) -> list[dict[str, Any]]:
        if self.wazuh_events_service is None:
            return []

        method = getattr(self.wazuh_events_service, "list_wazuh_alert_payloads", None)
        if method is None:
            return []

        try:
            return method(limit=limit)
        except Exception:
            return []

    def _safe_call_wazuh_agents(self, limit: int) -> list[dict[str, Any]]:
        if self.wazuh_events_service is None:
            return []

        for method_name in ("list_agents", "list_wazuh_agents", "list_agent_payloads"):
            method = getattr(self.wazuh_events_service, method_name, None)
            if method is None:
                continue

            try:
                return method(limit=limit)
            except TypeError:
                try:
                    return method()
                except Exception:
                    continue
            except Exception:
                continue

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
            event.hostname = self._safe_str(asset.get("hostname")) or event.hostname

        return event

    def _find_matching_asset(
        self,
        event: Event,
        assets: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        event_asset_id = self._safe_str(event.asset_id)
        event_hostname = self._safe_str(event.hostname)
        event_asset_name = self._safe_str(event.asset_name)
        event_dest_ip = self._safe_str(event.dest_ip)

        for asset in assets:
            asset_id = self._safe_str(asset.get("asset_id"))
            hostname = self._safe_str(asset.get("hostname"))
            name = self._safe_str(asset.get("name"))
            ip_address = self._safe_str(asset.get("ip_address"))

            if event_asset_id and asset_id and event_asset_id == asset_id:
                return asset
            if event_hostname and hostname and event_hostname == hostname:
                return asset
            if event_asset_name and name and event_asset_name == name:
                return asset
            if event_dest_ip and ip_address and event_dest_ip == ip_address:
                return asset

        return None

    @staticmethod
    def _safe_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _dedupe_tags(values: list[Any]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        for value in values:
            if value is None:
                continue
            text = str(value).strip().lower()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)

        return result

    @staticmethod
    def _normalize_suricata_severity(value: Any) -> str:
        try:
            severity = int(value)
        except (TypeError, ValueError):
            return "info"

        if severity <= 1:
            return "critical"
        if severity == 2:
            return "high"
        if severity == 3:
            return "medium"
        return "info"

    @staticmethod
    def _suricata_confidence(payload: dict[str, Any]) -> float:
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        if alert.get("signature_id"):
            return 0.9
        return 0.6

    @staticmethod
    def _infer_suricata_category(payload: dict[str, Any]) -> str:
        alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
        category = str(alert.get("category") or payload.get("event_type") or "network").strip().lower()
        return category or "network"

    @staticmethod
    def _normalize_wazuh_severity(value: Any) -> str:
        try:
            level = int(value)
        except (TypeError, ValueError):
            return "info"

        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 4:
            return "medium"
        if level >= 1:
            return "low"
        return "info"

    @staticmethod
    def _wazuh_confidence(value: Any) -> float:
        try:
            level = int(value)
        except (TypeError, ValueError):
            return 0.5

        if level >= 12:
            return 0.95
        if level >= 8:
            return 0.85
        if level >= 4:
            return 0.7
        return 0.55

    @staticmethod
    def _infer_wazuh_alert_category(payload: dict[str, Any]) -> str:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        groups = rule.get("groups") or []
        if isinstance(groups, list) and groups:
            return str(groups[0]).strip().lower()
        return "host"
