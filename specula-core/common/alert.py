from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class Alert:
    alert_id: str
    source: str
    rule_id: str
    title: str
    severity: str
    status: str
    asset_id: Optional[str] = None
    event_id: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)