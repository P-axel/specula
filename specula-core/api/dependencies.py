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


DEFAULT_EVE_PATH = Path(
    settings.specula_suricata_eve_path or "/var/log/suricata/eve.json"
)

ENABLE_SURICATA = os.getenv("SPECULA_ENABLE_SURICATA", "true").lower() == "true"
ENABLE_WAZUH = settings.specula_enable_wazuh

assets_service = AssetsService()
alerts_service = AlertsService()
detections_service = DetectionsService()
detection_engine = DetectionEngine()


if ENABLE_WAZUH:
    from services.ingestion.wazuh_events_service import WazuhEventsService
    wazuh_events_service = WazuhEventsService()
else:
    wazuh_events_service = None

events_service = EventsService(
    event_repository=None,
    detection_engine=detection_engine,
    detections_service=detections_service,
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

unified_correlator = UnifiedCorrelator(window_minutes=30)

unified_incidents_service = UnifiedIncidentsService(
    aggregator=detections_aggregator,
    correlator=unified_correlator,
)