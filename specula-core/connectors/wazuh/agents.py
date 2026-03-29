from typing import Any, Dict, List, Optional

from .client import WazuhClient
from common.asset import Asset
from normalization.wazuh_normalizer import WazuhNormalizer
from common.time_utils import relative_time
from common.asset_health import compute_health


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
    def _normalize_groups(agent: Dict[str, Any]) -> List[str]:
        raw_groups = agent.get("group") or agent.get("groups") or []

        if isinstance(raw_groups, list):
            return [str(group).strip() for group in raw_groups if str(group).strip()]

        if isinstance(raw_groups, str):
            if "," in raw_groups:
                return [part.strip() for part in raw_groups.split(",") if part.strip()]
            value = raw_groups.strip()
            return [value] if value else []

        return []

    @staticmethod
    def to_asset(agent: Dict[str, Any]) -> Asset:
        asset = WazuhNormalizer.from_wazuh_agent(agent)

        groups = WazuhAgentsConnector._normalize_groups(agent)
        last_seen = agent.get("lastKeepAlive") or asset.last_seen
        registered_at = (
            agent.get("dateAdd")
            or agent.get("registeredDate")
            or agent.get("register_date")
            or asset.registered_at
        )
        status = str(agent.get("status") or asset.status or "unknown").lower()

        asset.groups = groups
        asset.last_seen = last_seen
        asset.last_seen_relative = relative_time(last_seen)
        asset.registered_at = registered_at
        asset.health_state = compute_health(status, last_seen)
        asset.status = status
        asset.node_name = agent.get("node_name") or asset.node_name
        asset.manager = agent.get("manager") or asset.manager
        asset.version = agent.get("version") or asset.version
        asset.raw_payload = agent

        return asset