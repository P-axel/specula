from __future__ import annotations

from typing import Any


def map_suricata_severity(severity: int | None) -> str:
    if severity == 1:
        return "critical"
    if severity == 2:
        return "high"
    if severity == 3:
        return "medium"
    if severity is None:
        return "info"
    return "low"


def normalize_suricata_event(parsed_event: dict[str, Any]) -> dict[str, Any]:
    event_type = parsed_event.get("event_type")
    alert = parsed_event.get("alert", {}) or {}
    dns = parsed_event.get("dns", {}) or {}
    http = parsed_event.get("http", {}) or {}
    tls = parsed_event.get("tls", {}) or {}
    anomaly = parsed_event.get("anomaly", {}) or {}

    title = f"Suricata {event_type}"
    severity_num = None
    priority = "info"
    category = "network_event"

    if event_type == "alert":
        title = alert.get("signature") or "Suricata alert"
        severity_num = alert.get("severity")
        priority = map_suricata_severity(severity_num)
        category = "network_alert"
    elif event_type == "dns":
        category = "dns_event"
        title = dns.get("rrname") or "DNS event"
        priority = "low"
    elif event_type == "http":
        category = "http_event"
        title = http.get("url") or "HTTP event"
        priority = "low"
    elif event_type == "tls":
        category = "tls_event"
        title = tls.get("sni") or "TLS event"
        priority = "low"
    elif event_type == "flow":
        category = "network_flow"
        title = "Network flow"
        priority = "info"
    elif event_type == "anomaly":
        category = "anomaly_event"
        title = anomaly.get("event") or "Network anomaly"
        priority = "medium"

    src_ip = parsed_event.get("src_ip")
    src_port = parsed_event.get("src_port")
    dest_ip = parsed_event.get("dest_ip")
    dest_port = parsed_event.get("dest_port")
    proto = parsed_event.get("proto")

    app_proto = parsed_event.get("app_proto")
    flow_id = parsed_event.get("flow_id")
    direction = parsed_event.get("flow", {}).get("state") if isinstance(parsed_event.get("flow"), dict) else None

    signature_id = alert.get("signature_id")
    confidence = alert.get("confidence")

    description = f"{src_ip or 'unknown'}:{src_port or 'unknown'} → {dest_ip or 'unknown'}:{dest_port or 'unknown'}"

    return {
        "source": "suricata",
        "source_engine": "suricata",
        "theme": "network",
        "category": category,
        "timestamp": parsed_event.get("timestamp"),
        "title": title,
        "summary": description,
        "description": description,
        "priority": priority,
        "severity": severity_num,
        "risk_score": None,
        "confidence": confidence,
        "src_ip": src_ip,
        "src_port": src_port,
        "src_label": src_ip or "unknown",
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "dest_label": dest_ip or "unknown",
        "protocol": proto,
        "protocol_label": proto or "unknown",
        "app_proto": app_proto,
        "direction": direction,
        "flow_id": flow_id,
        "rule_id": signature_id,
        "status": "open",
        "asset_name": dest_ip or "unknown",
        "recommended_actions": [],
        "evidence": {
            "timestamp": parsed_event.get("timestamp"),
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "app_proto": app_proto,
            "alert": alert,
            "dns": dns,
            "http": http,
            "tls": tls,
            "anomaly": anomaly,
        },
        "raw_event": parsed_event,
    }