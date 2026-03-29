from __future__ import annotations

from typing import Any, Optional

from connectors.wazuh.connector import WazuhConnector
from normalization.wazuh_normalizer import WazuhNormalizer
from providers.base_provider import DetectionProvider


class WazuhProvider(DetectionProvider):
    """
    Provider Wazuh.

    Rôle :
    - point d'entrée unique pour Wazuh
    - récupère les alertes via le connector
    - les normalise via le normalizer
    - retourne des détections prêtes pour Specula
    """

    name = "wazuh"

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
        auth_type: str = "token",
    ) -> None:
        self.connector = WazuhConnector(
            base_url=base_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            auth_type=auth_type,
        )
        self.normalizer = WazuhNormalizer()

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        raw_alerts = self.connector.fetch_alerts(limit=limit)
        return [self.normalizer.normalize(alert) for alert in raw_alerts]

    def list_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        raw_agents = self.connector.fetch_agents(
            limit=limit,
            offset=offset,
            status=status,
        )
        return [self.normalizer.normalize(agent) for agent in raw_agents]

    def get_status(self) -> dict[str, Any]:
        return self.connector.get_status()