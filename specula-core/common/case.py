from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Case:
    id: str
    title: str
    status: str
    severity: str
    asset_id: Optional[str]
    detection_ids: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)