from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class Event:
    # === IDENTITÉ ===
    event_id: str
    source: str                         # wazuh, suricata, etc.
    source_type: str                    # host, network, identity, vulnerability
    source_event_type: str              # agent_status, network_alert, auth_failure...
    event_type: str                     # status, alert, telemetry, anomaly

    # === CONTENU ===
    title: str
    description: Optional[str] = None
    summary: Optional[str] = None

    # === QUALIFICATION ===
    category: str = "uncategorized"     # auth_failure, malware, scan...
    severity: str = "info"              # critical, high, medium, low, info
    confidence: float = 0.0             # 0.0 → 1.0

    # === CONTEXTE ACTIF ===
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    hostname: Optional[str] = None

    # === CONTEXTE RÉSEAU ===
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None

    # === CONTEXTE UTILISATEUR / PROCESS ===
    user_name: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None

    # === SIGNATURE / RÈGLE ===
    rule_id: Optional[str] = None
    signature: Optional[str] = None

    # === TEMPS ===
    occurred_at: Optional[str] = None

    # === ÉTAT ===
    status: Optional[str] = None        # new, processed, ignored...

    # === MÉTADONNÉES ===
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # === PAYLOAD ORIGINAL ===
    raw_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)