from __future__ import annotations

from typing import Any

from common.event import Event
from services.orchestration.unified_events_service import UnifiedEventsService


class UnifiedDetectionsService:
    """
    Produit des détections homogènes à partir d'événements normalisés.
    """

    def __init__(self, eve_path: str) -> None:
        self.unified_events_service = UnifiedEventsService(eve_path)

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        events = self.unified_events_service.list_events(limit=max(limit * 2, 200))
        detections = [self._build_detection(event) for event in events]

        detections.sort(
            key=lambda item: (
                self._severity_rank(item.get("severity")),
                int(item.get("risk_score") or 0),
                str(item.get("timestamp") or ""),
            ),
            reverse=True,
        )

        if limit <= 0:
            return detections

        return detections[:limit]

    def _build_detection(self, event: Event) -> dict[str, Any]:
        risk_score = self._compute_risk_score(event)
        priority = self._priority_from_score(risk_score)

        return {
            "id": event.event_id,
            "title": event.title,
            "name": event.title,
            "description": event.description or event.title,
            "summary": event.summary or event.description or event.title,
            "type": "detection",
            "status": event.status or "new",
            "timestamp": event.occurred_at,
            "created_at": event.occurred_at,
            "updated_at": event.occurred_at,
            "source": event.source,
            "source_engine": event.source,
            "source_type": event.source_type,
            "source_event_type": event.source_event_type,
            "event_type": event.event_type,
            "category": event.category,
            "severity": event.severity,
            "priority": priority,
            "confidence": event.confidence,
            "risk_score": risk_score,
            "asset_id": event.asset_id,
            "asset_name": event.asset_name,
            "hostname": event.hostname,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "dest_ip": event.dest_ip,
            "dest_port": event.dest_port,
            "protocol": event.protocol,
            "user_name": event.user_name,
            "process_name": event.process_name,
            "file_path": event.file_path,
            "rule_id": event.rule_id,
            "signature": event.signature,
            "tags": sorted(set(event.tags or [])),
            "theme": self._theme_from_event(event),
            "metadata": dict(event.metadata or {}),
            "raw": event.raw_payload or {},
        }

    def _compute_risk_score(self, event: Event) -> int:
        score = 0

        severity_weights = {
            "critical": 80,
            "high": 60,
            "medium": 40,
            "low": 20,
            "info": 5,
        }
        score += severity_weights.get(str(event.severity).lower(), 0)

        category_bonus = {
            "malware": 20,
            "exploit_attempt": 18,
            "intrusion_detection": 18,
            "identity_activity": 12,
            "file_integrity": 14,
            "host_anomaly": 14,
            "process_activity": 12,
            "vulnerability": 10,
            "network_scan": 8,
            "dns_activity": 6,
            "tls_activity": 6,
            "web_activity": 6,
            "agent_status": 4,
            "network_alert": 5,
            "system_activity": 5,
        }
        score += category_bonus.get(str(event.category).lower(), 0)

        if event.source_type == "network":
            score += 5

        if event.source_type == "host":
            score += 4

        confidence_bonus = int(max(0.0, min(float(event.confidence or 0.0), 1.0)) * 10)
        score += confidence_bonus

        asset_criticality = str(event.metadata.get("asset_criticality") or "").lower()
        if asset_criticality == "critical":
            score += 15
        elif asset_criticality == "high":
            score += 10
        elif asset_criticality == "medium":
            score += 5

        asset_health_state = str(event.metadata.get("asset_health_state") or "").lower()
        if asset_health_state == "critical":
            score += 8
        elif asset_health_state == "warning":
            score += 4

        if event.user_name:
            score += 2

        if event.process_name:
            score += 2

        if event.file_path:
            score += 2

        return max(0, min(100, score))

    def _priority_from_score(self, risk_score: int) -> str:
        if risk_score >= 75:
            return "critical"
        if risk_score >= 55:
            return "high"
        if risk_score >= 30:
            return "medium"
        if risk_score >= 10:
            return "low"
        return "info"

    def _theme_from_event(self, event: Event) -> str:
        category = str(event.category or "").lower()
        source_type = str(event.source_type or "").lower()

        if category in {"network_scan", "dns_activity", "tls_activity", "web_activity", "network_alert"}:
            return "network"
        if category == "identity_activity":
            return "identity"
        if category in {"malware", "host_anomaly", "file_integrity", "process_activity"}:
            return "endpoint"
        if category == "vulnerability":
            return "vulnerability"
        if source_type:
            return source_type
        return "generic"

    def _severity_rank(self, value: Any) -> int:
        normalized = str(value or "").strip().lower()
        if normalized == "critical":
            return 5
        if normalized == "high":
            return 4
        if normalized == "medium":
            return 3
        if normalized == "low":
            return 2
        if normalized == "info":
            return 1
        return 0