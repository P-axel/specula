from __future__ import annotations

from typing import Any, Dict


class RiskScoringService:
    """
    Calcule un score de risque simple sur 100
    à partir de la sévérité, de la confiance, de la catégorie
    et de la criticité de l'actif.

    Compatible avec :
    - détections Wazuh
    - détections Suricata
    """

    SEVERITY_SCORES = {
        "critical": 60,
        "high": 40,
        "medium": 25,
        "low": 10,
        "info": 5,
    }

    CATEGORY_BONUS = {
        # Wazuh / générique
        "host_compromise": 20,
        "privilege_abuse": 15,
        "network_sniffing": 15,
        "malware": 20,
        "identity_attack": 12,
        "integrity_change": 10,
        "service_failure": 8,
        "exposure_change": 8,
        "identity_activity": 5,
        "security_event": 5,
        "host_anomaly": 8,

        # Suricata / réseau
        "network_alert": 8,
        "network_reconnaissance": 12,
        "suspicious_http": 10,
        "dns_anomaly": 8,
        "tls_anomaly": 8,
        "anomaly_event": 10,
        "http_event": 4,
        "tls_event": 4,
        "network_flow": 1,
    }

    ASSET_CRITICALITY_BONUS = {
        "critical": 20,
        "high": 15,
        "medium": 10,
        "low": 5,
    }

    def score_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        severity = self._normalize_severity(detection.get("severity", "low"))
        category = str(detection.get("category", "security_event")).strip().lower()
        confidence = self._normalize_confidence(detection.get("confidence", 0.5))

        metadata = detection.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            detection["metadata"] = metadata

        asset_criticality = str(
            detection.get("asset_criticality")
            or metadata.get("asset_criticality")
            or "medium"
        ).strip().lower()

        severity_score = self.SEVERITY_SCORES.get(severity, 10)
        category_bonus = self.CATEGORY_BONUS.get(category, 5)
        asset_bonus = self.ASSET_CRITICALITY_BONUS.get(asset_criticality, 10)
        confidence_bonus = round(confidence * 15)

        # Ajustements réseau contextuels
        context_bonus = self._compute_context_bonus(detection)

        risk_score = (
            severity_score
            + category_bonus
            + asset_bonus
            + confidence_bonus
            + context_bonus
        )
        risk_score = max(0, min(100, risk_score))

        priority = self.score_to_priority(risk_score)

        detection["risk_score"] = risk_score
        detection["risk_level"] = priority
        detection["priority"] = priority

        metadata["risk_breakdown"] = {
            "severity_score": severity_score,
            "category_bonus": category_bonus,
            "asset_criticality_bonus": asset_bonus,
            "confidence_bonus": confidence_bonus,
            "context_bonus": context_bonus,
        }

        return detection

    def score_to_priority(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def _normalize_severity(self, severity: Any) -> str:
        if isinstance(severity, int):
            return {
                1: "critical",
                2: "high",
                3: "medium",
                4: "low",
            }.get(severity, "low")

        value = str(severity or "").strip().lower()
        if value in {"critical", "high", "medium", "low", "info"}:
            return value
        return "low"

    def _normalize_confidence(self, confidence: Any) -> float:
        try:
            value = float(confidence)
        except (TypeError, ValueError):
            return 0.5

        if value < 0:
            return 0.0
        if value > 1:
            return 1.0
        return value

    def _compute_context_bonus(self, detection: Dict[str, Any]) -> int:
        category = str(detection.get("category") or "").strip().lower()
        metadata = detection.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        bonus = 0

        # Signatures ou marqueurs réseau plus sensibles
        signature = str(
            metadata.get("suricata_signature")
            or detection.get("title")
            or ""
        ).strip().lower()

        if any(token in signature for token in ["c2", "command and control", "beacon", "callback"]):
            bonus += 10
        elif any(token in signature for token in ["malware", "trojan", "worm", "backdoor"]):
            bonus += 8
        elif any(token in signature for token in ["exploit", "shellcode", "overflow", "injection"]):
            bonus += 8
        elif any(token in signature for token in ["scan", "nmap", "recon", "enumeration"]):
            bonus += 4

        # HTTP sensible
        if category == "suspicious_http":
            url = str(metadata.get("url") or "").strip().lower()
            user_agent = str(metadata.get("user_agent") or "").strip().lower()

            if url and any(token in url for token in ["/admin", "/login", "/wp-login", "/.env", "/phpmyadmin"]):
                bonus += 4

            if user_agent and any(token in user_agent for token in ["sqlmap", "nikto", "nmap", "curl", "python-requests"]):
                bonus += 4

        # DNS sensible
        if category == "dns_anomaly":
            rrname = str(metadata.get("rrname") or "").strip().lower()
            if rrname and any(token in rrname for token in ["dyn", "ddns", "no-ip", "duckdns"]):
                bonus += 3

        # TLS sensible
        if category == "tls_anomaly":
            sni = str(metadata.get("sni") or "").strip().lower()
            if sni and any(token in sni for token in ["ddns", "duckdns", "no-ip"]):
                bonus += 3

        # Les flows ne doivent pas monter trop haut
        if category == "network_flow":
            bonus -= 5

        return max(-5, min(15, bonus))