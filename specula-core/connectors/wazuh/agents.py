from typing import Any, Dict, List, Optional

from .client import WazuhClient
from common.asset import Asset
from normalization.asset_normalizer import AssetNormalizer


class WazuhAgentsConnector:
    def __init__(self, client: WazuhClient) -> None:
        self.client = client

    def list_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }

        if status:
            params["status"] = status

        data = self.client.get("/agents", params=params)

        return data.get("data", {}).get("affected_items", [])

    def get_agent(self, agent_id: str) -> Dict[str, Any]:
        data = self.client.get(f"/agents/{agent_id}")
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    @staticmethod
    def to_asset(agent: Dict[str, Any]) -> Asset:
        return AssetNormalizer.from_wazuh_agent(agent)