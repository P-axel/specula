from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class Asset:
    asset_id: str
    name: str
    hostname: str
    ip_address: str
    asset_type: str
    platform: str
    os_name: str
    os_version: str
    architecture: str
    status: str
    manager: str
    node_name: str
    version: str
    site: Optional[str] = None
    criticality: str = "medium"
    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)