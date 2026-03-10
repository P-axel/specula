import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "specula-core"))

from services.assets_service import AssetsService


def main() -> None:
    service = AssetsService()

    assets = service.list_assets()

    print(f"{len(assets)} asset(s)\n")

    for index, asset in enumerate(assets, start=1):
        print(f"--- ASSET {index} ---")
        print(asset)
        print(asset.to_dict())
        print()


if __name__ == "__main__":
    main()