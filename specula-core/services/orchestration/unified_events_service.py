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