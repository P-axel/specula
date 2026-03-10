from typing import List

from common.asset import Asset
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class AssetRepository:
    def save_all(self, assets: List[Asset]) -> None:
        for asset in assets:
            logger.info("STORE asset_id=%s name=%s", asset.asset_id, asset.name)

    def list_all(self) -> List[Asset]:
        logger.debug("Lecture de tous les assets")
        return []