from __future__ import annotations

from typing import Any, Optional

from providers.wazuh_provider import WazuhProvider
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class WazuhEventsService:
    """
     expose les événements de statut des agents Wazuh.

    Il s'appuie sur le provider Wazuh:
    - connector
    - normalizer
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
        auth_type: str = "token",
    ) -> None:
        self.provider = WazuhProvider(
            base_url=base_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            auth_type=auth_type,
        )

    def list_agent_status_events(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        logger.info("Récupération des événements de statut agents depuis Wazuh")

        events = self.provider.list_agents(
            limit=limit,
            offset=offset,
            status=status,
        )

        agent_status_events = [
            event
            for event in events
            if str(event.get("event", {}).get("category", "")).lower() == "agent_status"
        ]

        logger.info("%s event(s) normalisé(s)", len(agent_status_events))
        return agent_status_events