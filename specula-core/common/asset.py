from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


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

    groups: Optional[List[str]] = None

    last_seen: Optional[str] = None
    last_seen_relative: Optional[str] = None   
    registered_at: Optional[str] = None

    health_state: Optional[str] = None      

    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)