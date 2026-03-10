from typing import List, Optional

from connectors.wazuh.client import WazuhClient
from connectors.wazuh.agents import WazuhAgentsConnector
from common.asset import Asset
from storage.asset_repository import AssetRepository


class AssetsService:

    def __init__(self, repository: Optional[AssetRepository] = None) -> None:
        client = WazuhClient()
        self.connector = WazuhAgentsConnector(client)
        self.repository = repository or AssetRepository()

    def list_assets(self) -> List[Asset]:
        agents = self.connector.list_agents()
        return [self.connector.to_asset(agent) for agent in agents]

    def collect_and_save_assets(self) -> List[Asset]:
        assets = self.list_assets()
        self.repository.save_all(assets)
        return assets