from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Detection:
    id: str
    type: str
    title: str
    description: str
    severity: str
    confidence: float
    source: str
    asset_id: Optional[str]
    event_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "asset_id": self.asset_id,
            "event_ids": self.event_ids,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }