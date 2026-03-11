from typing import List

from common.event import Event
from connectors.wazuh.agents import WazuhAgentsConnector
from connectors.wazuh.client import WazuhClient
from normalization.event_normalizer import EventNormalizer
from specula_logging.logger import get_logger


logger = get_logger(__name__)


class WazuhEventsService:
    def __init__(self) -> None:
        client = WazuhClient()
        self.connector = WazuhAgentsConnector(client)

    def list_agent_status_events(self) -> List[Event]:
        logger.info("Récupération des événements de statut agents depuis Wazuh")
        agents = self.connector.list_agents()
        events = [EventNormalizer.from_wazuh_agent(agent) for agent in agents]
        logger.info("%s event(s) normalisé(s)", len(events))
        return events