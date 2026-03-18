from typing import List, Optional

from common.asset import Asset
from connectors.wazuh.agents import WazuhAgentsConnector
from connectors.wazuh.client import WazuhClient
from specula_logging.logger import get_logger
from storage.asset_repository import AssetRepository


logger = get_logger(__name__)


class AssetsService:
    def __init__(self, repository: Optional[AssetRepository] = None) -> None:
        client = WazuhClient()
        self.connector = WazuhAgentsConnector(client)
        self.repository = repository or AssetRepository()

    def list_assets(self) -> List[Asset]:
        logger.info("Récupération des assets depuis Wazuh")
        agents = self.connector.list_agents()
        assets = [self.connector.to_asset(agent) for agent in agents]

        assets.sort(
            key=lambda asset: (
                str(asset.health_state or ""),
                str(asset.status or ""),
                str(asset.name or "").lower(),
            )
        )

        logger.info("%s asset(s) normalisé(s)", len(assets))
        return assets

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        logger.info("Récupération de l'asset %s", asset_id)
        agent = self.connector.get_agent(asset_id)

        if not agent:
            return None

        return self.connector.to_asset(agent)

    def collect_and_save_assets(self) -> List[Asset]:
        assets = self.list_assets()
        logger.info("Sauvegarde de %s asset(s)", len(assets))
        self.repository.save_all(assets)
        return assets