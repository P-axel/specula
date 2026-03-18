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
    source_rule_id: Optional[str] = None

    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None

    username: Optional[str] = None
    source_ip: Optional[str] = None

    status: str = "open"

    event_ids: List[str] = field(default_factory=list)

    recommended_actions: List[str] = field(default_factory=list)

    tags: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    created_at: datetime = field(default_factory=datetime.utcnow)

    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "source_rule_id": self.source_rule_id,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "username": self.username,
            "source_ip": self.source_ip,
            "status": self.status,
            "event_ids": self.event_ids,
            "recommended_actions": self.recommended_actions,
            "tags": self.tags,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "raw_payload": self.raw_payload,
        }