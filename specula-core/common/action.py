from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass(slots=True)
class Action:
    action_id: str
    action_type: str
    target_type: str
    target_id: str
    status: str
    description: str
    source_alert_id: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)