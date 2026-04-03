from __future__ import annotations

import logging
from typing import Any, Optional, List, Dict

from connectors.wazuh.connector import WazuhConnector
from normalization.wazuh_normalizer import WazuhNormalizer
from providers.base_provider import DetectionProvider

logger = logging.getLogger(__name__)


class WazuhProvider(DetectionProvider):
    """
    Provider Wazuh (bas niveau).

    Rôle :
    - récupérer les données Wazuh via le connector
    - normaliser les événements
    - exposer des détections brutes prêtes pour le pipeline Specula

    ⚠️ Ne fait PAS d’enrichissement métier
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

    def list_detections(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            raw_alerts = self.connector.fetch_alerts(limit=limit)
        except Exception as e:
            logger.error("Failed to fetch Wazuh alerts: %s", e, exc_info=True)
            return []

        detections: List[Dict[str, Any]] = []

        for alert in raw_alerts:
            try:
                normalized = self.normalizer.normalize(alert)
                if normalized:
                    detections.append(normalized)
            except Exception as e:
                logger.warning("Failed to normalize alert: %s", e, exc_info=True)

        return detections

    def list_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        try:
            raw_agents = self.connector.fetch_agents(
                limit=limit,
                offset=offset,
                status=status,
            )
        except Exception as e:
            logger.error("Failed to fetch Wazuh agents: %s", e, exc_info=True)
            return []

        agents: List[Dict[str, Any]] = []

        for agent in raw_agents:
            try:
                normalized = self.normalizer.normalize(agent)
                if normalized:
                    agents.append(normalized)
            except Exception as e:
                logger.warning("Failed to normalize agent: %s", e, exc_info=True)

        return agents

    def get_status(self) -> Dict[str, Any]:
        try:
            return self.connector.get_status()
        except Exception as e:
            logger.error("Failed to get Wazuh status: %s", e, exc_info=True)
            return {
                "status": "error",
                "message": str(e),
            }