from typing import Any, Dict

from common.asset import Asset


class AssetNormalizer:
    @staticmethod
    def from_wazuh_agent(agent: Dict[str, Any]) -> Asset:
        os_data = agent.get("os", {})

        asset_id = str(agent.get("id", "unknown"))
        name = str(agent.get("name", "unknown"))
        ip_address = str(agent.get("ip", "unknown"))
        platform = str(os_data.get("platform", "unknown"))
        os_name = str(os_data.get("name", "unknown"))
        os_version = str(os_data.get("version", "unknown"))
        architecture = str(os_data.get("arch", "unknown"))
        status = str(agent.get("status", "unknown"))
        manager = str(agent.get("manager", "unknown"))
        node_name = str(agent.get("node_name", "unknown"))
        version = str(agent.get("version", "unknown"))

        groups = agent.get("group")
        last_seen = agent.get("lastKeepAlive")
        registered_at = agent.get("dateAdd")

        asset_type = "server"
        lowered_name = name.lower()
        lowered_platform = platform.lower()

        if "manager" in lowered_name:
            asset_type = "manager"
        elif "windows" in lowered_platform:
            asset_type = "workstation"
        elif "linux" in lowered_platform or "amzn" in lowered_platform or "debian" in lowered_platform:
            asset_type = "server"

        return Asset(
            asset_id=asset_id,
            name=name,
            hostname=name,
            ip_address=ip_address,
            asset_type=asset_type,
            platform=platform,
            os_name=os_name,
            os_version=os_version,
            architecture=architecture,
            status=status,
            manager=manager,
            node_name=node_name,
            version=version,
            groups=groups,
            last_seen=last_seen,
            registered_at=registered_at,
            raw_payload=agent,
        )