from __future__ import annotations

from typing import Any

from common.event import Event
from normalization.event_normalizer import EventNormalizer
from services.alerts_service import AlertsService
from services.assets_service import AssetsService
from services.suricata_service import SuricataService


class UnifiedEventsService:
    """
    Agrège plusieurs sources brutes et les transforme en événements normalisés.

    Pipeline:
    - lecture brut source
    - normalisation -> Event
    - enrichissement léger avec le contexte actif
    """

    def __init__(self, eve_path: str) -> None:
        self.suricata_service = SuricataService(eve_path)
        self.alerts_service = AlertsService()
        self.assets_service = AssetsService()

    def list_events(self, limit: int = 200) -> list[Event]:
        items: list[Event] = []

        for payload in self._safe_call_suricata(limit=limit):
            try:
                event = EventNormalizer.from_suricata_alert(payload)
                items.append(self._enrich_event(event))
            except Exception:
                continue

        for payload in self._safe_call_wazuh_alerts():
            try:
                event = EventNormalizer.from_wazuh_alert(payload)
                items.append(self._enrich_event(event))
            except Exception:
                continue

        for agent in self._safe_call_wazuh_agents():
            try:
                event = EventNormalizer.from_wazuh_agent(agent)
                items.append(self._enrich_event(event))
            except Exception:
                continue

        items.sort(key=lambda item: str(item.occurred_at or ""), reverse=True)

        if limit <= 0:
            return items

        return items[:limit]

    def list_event_dicts(self, limit: int = 200) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.list_events(limit=limit)]

    def _enrich_event(self, event: Event) -> Event:
        asset = self._find_matching_asset(event)
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

    def _find_matching_asset(self, event: Event) -> dict[str, Any] | None:
        try:
            assets = [asset.to_dict() for asset in self.assets_service.list_assets()]
        except Exception:
            return None

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

    def _safe_call_wazuh_alerts(self) -> list[dict[str, Any]]:
        candidates = [
            "list_wazuh_alert_payloads",
            "list_alert_payloads",
            "list_alerts",
        ]

        for method_name in candidates:
            method = getattr(self.alerts_service, method_name, None)
            if callable(method):
                try:
                    result = method()
                except TypeError:
                    continue
                if isinstance(result, list):
                    return result

        return []

    def _safe_call_wazuh_agents(self) -> list[dict[str, Any]]:
        candidates = [
            "list_agents",
            "list_agent_status_payloads",
        ]

        for service in [self.alerts_service]:
            for method_name in candidates:
                method = getattr(service, method_name, None)
                if callable(method):
                    try:
                        result = method()
                    except TypeError:
                        continue
                    if isinstance(result, list):
                        return result

        return []