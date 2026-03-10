from typing import Any, Dict, List, Optional

from .client import WazuhClient


class WazuhAlertsConnector:
    def __init__(self, client: WazuhClient) -> None:
        self.client = client

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        q: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les alertes Wazuh.
        Selon ton endpoint réel, tu ajusteras éventuellement le chemin.
        """
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }

        if q:
            params["q"] = q
        if sort:
            params["sort"] = sort

        data = self.client.get("/alerts", params=params)

        if "data" in data and "affected_items" in data["data"]:
            return data["data"]["affected_items"]

        if "affected_items" in data:
            return data["affected_items"]

        return []

    def get_recent_high_alerts(self, limit: int = 25) -> List[Dict[str, Any]]:
        """
        Exemple de filtre simple : alertes de niveau élevé.
        Ajuste la requête q selon ton API / backend indexé.
        """
        return self.list_alerts(limit=limit, q="rule.level>=10")