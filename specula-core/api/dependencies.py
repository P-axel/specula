import os
from pathlib import Path

from config.settings import settings
from detection.engine import DetectionEngine

from services.ingestion.alerts_service import AlertsService
from services.ingestion.assets_service import AssetsService
from services.ingestion.events_service import EventsService

from services.transformation.detections_aggregator import DetectionsAggregator
from services.transformation.detections_service import DetectionsService

from services.orchestration.unified_correlator import UnifiedCorrelator
from services.orchestration.unified_events_service import UnifiedEventsService
from services.orchestration.unified_incidents_service import UnifiedIncidentsService

from services.plugin_registry import PluginRegistry
from common.ttl_cache import TTLCache


DEFAULT_EVE_PATH = Path(
    settings.specula_suricata_eve_path or "/var/log/suricata/eve.json"
)

ENABLE_SURICATA = os.getenv("SPECULA_ENABLE_SURICATA", "true").lower() == "true"
ENABLE_WAZUH = settings.specula_enable_wazuh

_raw_assets_service      = AssetsService()
_raw_alerts_service      = AlertsService()
_raw_detections_service  = DetectionsService()
detection_engine         = DetectionEngine()

if ENABLE_WAZUH:
    from services.ingestion.wazuh_events_service import WazuhEventsService
    wazuh_events_service = WazuhEventsService()
else:
    wazuh_events_service = None

events_service = EventsService(
    event_repository=None,
    detection_engine=detection_engine,
    detections_service=_raw_detections_service,
)

unified_events_service = UnifiedEventsService(str(DEFAULT_EVE_PATH))

plugin_registry = PluginRegistry.build_default(
    eve_path=DEFAULT_EVE_PATH,
    enable_suricata=ENABLE_SURICATA,
    enable_wazuh=ENABLE_WAZUH,
    wazuh_base_url=settings.wazuh_base_url,
    wazuh_username=settings.wazuh_username,
    wazuh_password=settings.wazuh_password,
    wazuh_verify_ssl=settings.wazuh_verify_tls,
    wazuh_timeout=settings.wazuh_timeout,
    wazuh_auth_type=os.getenv("WAZUH_AUTH_TYPE", "token"),
)

detections_aggregator = DetectionsAggregator(
    providers=plugin_registry.get_detection_providers()
)

unified_correlator = UnifiedCorrelator(window_minutes=120)

_raw_incidents_service = UnifiedIncidentsService(
    aggregator=detections_aggregator,
    correlator=unified_correlator,
)

# ── Cache TTL partagé ─────────────────────────────────────────────
# Tous les endpoints lisent le même cache — un seul appel Wazuh/Suricata
# toutes les 30s quelle que soit la charge du frontend.
_cache = TTLCache(ttl=300.0, stale_ttl=3600.0)  # fraîches 5min, utilisables 1h


class _CachedAssets:
    def list_assets(self):
        return _cache.get_or_fetch("assets", _raw_assets_service.list_assets)

    def get_asset(self, asset_id):
        return _raw_assets_service.get_asset(asset_id)


class _CachedAlerts:
    def list_alerts(self, limit: int = 100):
        return _cache.get_or_fetch("alerts", lambda: _raw_alerts_service.list_alerts(limit))


class _CachedDetections:
    def list_detections(self, source=None):
        # Cache toujours source=None (tout), filtre ensuite si besoin
        all_dets = _cache.get_or_fetch(
            "detections",
            lambda: _raw_detections_service.list_detections(None),
        )
        if source is None:
            return all_dets
        return [d for d in all_dets if d.get("source", "").lower() == source.lower()]


class _CachedIncidents:
    def list_incidents(self, limit: int = 500):
        # Cache toujours le max (500), on tronque — évite les cache misses par limit
        all_items = _cache.get_or_fetch(
            "incidents",
            lambda: _raw_incidents_service.list_incidents(500),
        )
        return all_items[:limit] if limit < len(all_items) else all_items

    def __getattr__(self, name):
        return getattr(_raw_incidents_service, name)


assets_service           = _CachedAssets()
alerts_service           = _CachedAlerts()
detections_service       = _CachedDetections()
unified_incidents_service = _CachedIncidents()
