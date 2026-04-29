from __future__ import annotations

from typing import Any, Dict, List, Optional

from .agents import WazuhAgentsConnector
from .alerts import WazuhAlertsConnector
from .client import WazuhClient


class WazuhConnector:
    """
    Façade principale du module Wazuh.

    Responsabilités :
    - exposer un point d'entrée unique pour Specula
    - centraliser l'accès aux alertes et aux agents
    - fournir un statut simple du connecteur
    - retourner des objets bruts Wazuh

    Le connector ne fait pas la normalisation canonique Specula.
    Cette responsabilité reste au WazuhNormalizer.
    """

    SOURCE = "wazuh"

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
        auth_type: str = "token",
    ) -> None:
        self.client = WazuhClient(
            base_url=base_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
            auth_type=auth_type,
            max_retries=1,       # 1 retry max — Wazuh indispo = retour rapide
            retry_delay_seconds=1,
        )
        self.alerts = WazuhAlertsConnector(self.client)
        self.agents = WazuhAgentsConnector(self.client)

    def test_connection(self) -> bool:
        """
        Vérifie que l'API Wazuh est joignable.

        - en mode token : teste l'authentification
        - en mode basic : tente un appel simple
        """
        try:
            if self.client.auth_type == "token":
                self.client.authenticate()
            else:
                self.client.get("/")
            return True
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Retourne un état synthétique du connecteur.
        """
        available = self.test_connection()

        return {
            "source": self.SOURCE,
            "connector": "wazuh",
            "available": available,
            "base_url": self.client.base_url,
            "auth_type": self.client.auth_type,
            "verify_ssl": self.client.verify_ssl,
            "timeout": self.client.timeout,
        }

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def fetch_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        q: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les alertes Wazuh brutes.
        """
        return self.alerts.list_alerts(
            limit=limit,
            offset=offset,
            q=q,
            sort=sort,
        )

    def fetch_recent_high_alerts(self, limit: int = 25) -> List[Dict[str, Any]]:
        """
        Retourne les alertes Wazuh à niveau élevé.
        """
        return self.alerts.get_recent_high_alerts(limit=limit)

    def fetch_alert_events(
        self,
        limit: int = 50,
        offset: int = 0,
        q: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Alias métier pratique pour le pipeline Specula :
        retourne les événements d'alerte bruts destinés au normalizer.
        """
        return self.fetch_alerts(
            limit=limit,
            offset=offset,
            q=q,
            sort=sort,
        )

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def fetch_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les agents Wazuh bruts.
        """
        return self.agents.list_agents(
            limit=limit,
            offset=offset,
            status=status,
        )

    def fetch_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        Retourne un agent Wazuh brut par identifiant.
        """
        return self.agents.get_agent(agent_id)

    def fetch_agent_events(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Alias métier pratique pour le pipeline Specula :
        retourne les événements d'agents bruts destinés au normalizer.
        """
        return self.fetch_agents(
            limit=limit,
            offset=offset,
            status=status,
        )