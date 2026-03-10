import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "specula-core"))

from connectors.wazuh.client import WazuhClient
from connectors.wazuh.agents import WazuhAgentsConnector


def main() -> None:
    client = WazuhClient()
    connector = WazuhAgentsConnector(client)

    agents = connector.list_agents(limit=10)

    print(f"{len(agents)} agent(s) récupéré(s)\n")

    for index, agent in enumerate(agents, start=1):
        asset = connector.to_asset(agent)
        print(f"--- ASSET {index} ---")
        print(asset)
        print(asset.to_dict())
        print()


if __name__ == "__main__":
    main()