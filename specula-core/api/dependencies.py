import os
from pathlib import Path

from detection.engine import DetectionEngine
from services.alerts_service import AlertsService
from services.assets_service import AssetsService
from services.detections_service import DetectionsService
from services.detections_aggregator import DetectionsAggregator
from services.events_service import EventsService
from services.network_alerts_service import NetworkAlertsService
from services.network_incidents_service import NetworkIncidentsService
from services.plugin_registry import PluginRegistry
from services.themes_service import ThemesService
from services.translated_detections_service import TranslatedDetectionsService
from services.unified_correlator import UnifiedCorrelator
from services.unified_incidents_service import UnifiedIncidentsService
from services.wazuh_events_service import WazuhEventsService

assets_service = AssetsService()
wazuh_events_service = WazuhEventsService()
alerts_service = AlertsService()
detections_service = DetectionsService()
detection_engine = DetectionEngine()
translated_detections_service = TranslatedDetectionsService()

themes_service = ThemesService()
network_alerts_service = NetworkAlertsService()
network_incidents_service = NetworkIncidentsService()

events_service = EventsService(
    event_repository=None,
    detection_engine=detection_engine,
    detections_service=detections_service,
)

DEFAULT_EVE_PATH = Path(
    os.getenv("SPECULA_SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
)

DEFAULT_WAZUH_ALERTS_PATH = Path(
    os.getenv("SPECULA_WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
)

plugin_registry = PluginRegistry.build_default(
    eve_path=DEFAULT_EVE_PATH,
    wazuh_alerts_path=DEFAULT_WAZUH_ALERTS_PATH,
    enable_suricata=True,
    enable_wazuh=True,
)

detections_aggregator = DetectionsAggregator(
    providers=plugin_registry.get_detection_providers()
)

unified_correlator = UnifiedCorrelator(window_minutes=30)

unified_incidents_service = UnifiedIncidentsService(
    aggregator=detections_aggregator,
    correlator=unified_correlator,
)