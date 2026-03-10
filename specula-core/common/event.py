from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class Event:
    event_id: str
    source: str
    source_event_type: str
    event_type: str
    title: str
    severity: str
    asset_id: Optional[str] = None
    status: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    occurred_at: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)