from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass(slots=True)
class NormalizedEvent:
    source: str
    source_event_id: str
    event_type: str
    category: str
    severity: int
    title: str
    description: str
    asset_id: str
    asset_name: str
    observed_at: str
    raw_payload: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)