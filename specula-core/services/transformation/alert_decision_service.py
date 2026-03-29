from __future__ import annotations

from typing import Any


class AlertDecisionService:
    """
    Décide si une détection doit devenir une alerte exploitable.
    """

    def should_create_alert(self, detection: dict[str, Any]) -> bool:
        severity = str(detection.get("severity") or "").strip().lower()
        priority = str(detection.get("priority") or "").strip().lower()

        try:
            risk_score = int(detection.get("risk_score") or 0)
        except (TypeError, ValueError):
            risk_score = 0

        category = str(detection.get("category") or "").strip().lower()
        confidence = float(detection.get("confidence") or 0.0)

        if severity in {"critical", "high"}:
            return True

        if priority in {"critical", "high"}:
            return True

        if risk_score >= 70:
            return True

        if category in {"malware", "exploit_attempt", "intrusion_detection"} and risk_score >= 50:
            return True

        if category == "identity_activity" and confidence >= 0.85 and risk_score >= 45:
            return True

        return False

    def alert_status(self, detection: dict[str, Any]) -> str:
        return "open" if self.should_create_alert(detection) else "suppressed"

    def alert_reason(self, detection: dict[str, Any]) -> str:
        severity = str(detection.get("severity") or "").strip().lower()

        try:
            risk_score = int(detection.get("risk_score") or 0)
        except (TypeError, ValueError):
            risk_score = 0

        category = str(detection.get("category") or "").strip().lower()

        if severity in {"critical", "high"}:
            return f"severity={severity}"

        if risk_score >= 70:
            return f"risk_score={risk_score}"

        if category in {"malware", "exploit_attempt", "intrusion_detection"}:
            return f"category={category}"

        return "below_threshold"