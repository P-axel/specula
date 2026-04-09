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
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """
        Récupère les alertes depuis le Wazuh Indexer via `_search`.
        Par défaut, seulement les 24 dernières heures.
        """
        must: List[Dict[str, Any]] = [
            {"range": {"@timestamp": {"gte": f"now-{hours}h/h", "lte": "now"}}}
        ]

        if q:
            if q.startswith("rule.level>="):
                try:
                    level = int(q.split(">=")[1].strip())
                    must.append({"range": {"rule.level": {"gte": level}}})
                except (IndexError, ValueError):
                    must.append({"query_string": {"query": q}})
            else:
                must.append({"query_string": {"query": q}})

        sort_clause: List[Dict[str, Any]] = [{"@timestamp": {"order": "desc"}}]

        if sort:
            try:
                field, order = sort.split(":", 1)
                field = field.strip()
                order = order.strip().lower()

                if field and order in {"asc", "desc"}:
                    sort_clause = [{field: {"order": order}}]
            except ValueError:
                pass

        body: Dict[str, Any] = {
            "from": offset,
            "size": limit,
            "sort": sort_clause,
            "query": {
                "bool": {
                    "must": must if must else [{"match_all": {}}]
                }
            },
        }

        data = self.client.post("/wazuh-alerts-*/_search", json=body)
        hits = data.get("hits", {}).get("hits", [])

        return [hit.get("_source", {}) for hit in hits]

    def get_recent_high_alerts(self, limit: int = 25) -> List[Dict[str, Any]]:
        return self.list_alerts(limit=limit, q="rule.level>=10")