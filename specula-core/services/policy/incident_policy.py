from __future__ import annotations

from typing import Any


SENSITIVE_CATEGORIES = {
    "malware",
    "host_compromise",
    "intrusion",
    "intrusion_detection",
    "privilege_escalation",
    "privilege_abuse",
    "auth_failure",
    "bruteforce",
    "identity_attack",
    "network_scan",
    "network_reconnaissance",
    "exploit_attempt",
    "suspicious_http",
    "dns_anomaly",
    "tls_anomaly",
    "host_anomaly",
    "file_integrity",
    "process_activity",
    "vulnerability",
}


NOISE_CATEGORIES = {
    "network_flow",
    "network_dns",
    "network_tls",
    "network_event",
    "dns",
    "tls",
    "http",
    "http_event",
    "dns_event",
    "tls_event",
    "agent_status",
}


SUSPICIOUS_PROTOCOL_CATEGORIES = {
    "suspicious_http",
    "dns_anomaly",
    "tls_anomaly",
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except Exception:
        return default


def _has_context(item: dict[str, Any]) -> bool:
    return any(
        item.get(key) not in (None, "", [], {})
        for key in [
            "asset_name",
            "hostname",
            "src_ip",
            "dest_ip",
            "user_name",
            "process_name",
            "rule_id",
        ]
    )


def _is_noisy_info(item: dict[str, Any]) -> bool:
    severity = str(item.get("severity") or "").strip().lower()
    category = str(item.get("category") or "").strip().lower()
    title = str(item.get("title") or item.get("name") or "").strip().lower()

    if severity in {"info", ""} and category in NOISE_CATEGORIES:
        return True

    if title in {"event", "flow", "dns", "tls", "http"} and severity in {"info", "low", ""}:
        return True

    return False


def is_incident_candidate(item: dict[str, Any]) -> bool:
    severity = str(item.get("severity") or "").strip().lower()
    category = str(item.get("category") or "").strip().lower()
    risk_score = _safe_int(item.get("risk_score"), 0)
    confidence = _safe_float(item.get("confidence"), 0.0)
    source_engine = str(
        item.get("source_engine") or item.get("engine") or item.get("source") or ""
    ).strip().lower()

    if _is_noisy_info(item):
        return False

    if not _has_context(item):
        return False

    # Signaux forts quasi toujours éligibles
    if severity == "critical":
        return True

    if severity == "high" and risk_score >= 50:
        return True

    if risk_score >= 75:
        return True

    # Catégories sensibles avec un minimum de crédibilité
    if category in SENSITIVE_CATEGORIES:
        if severity in {"high", "critical"}:
            return True
        if risk_score >= 50:
            return True
        if confidence >= 0.75 and severity == "medium":
            return True

    # Cas réseau : on veut éviter de remonter tout Suricata
    if source_engine == "suricata":
        if category in SUSPICIOUS_PROTOCOL_CATEGORIES:
            return risk_score >= 55 or confidence >= 0.8
        if category in {"network_scan", "network_reconnaissance", "identity_attack", "exploit_attempt"}:
            return risk_score >= 45 or severity in {"medium", "high", "critical"}

    # Cas système / hôte : medium acceptable si bien scoré
    if source_engine == "wazuh":
        if category in {"host_anomaly", "file_integrity", "process_activity", "privilege_abuse"}:
            return risk_score >= 45 or confidence >= 0.8

    # Medium générique uniquement si contexte solide
    if severity == "medium" and risk_score >= 55:
        return True

    return False