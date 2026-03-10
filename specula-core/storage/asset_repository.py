from typing import List

from common.asset import Asset


class AssetRepository:

    def save_all(self, assets: List[Asset]) -> None:
        for asset in assets:
            print(f"[STORE] {asset.asset_id} - {asset.name}")

    def list_all(self) -> List[Asset]:
        return []