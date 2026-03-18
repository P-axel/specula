from __future__ import annotations

from typing import Any

from services.themes_service import ThemesService


class NetworkAlertsService:
    """
    Transforme les détections réseau en alertes réseau lisibles par Specula.
    """

    def __init__(self) -> None:
        self.themes_service = ThemesService()

    def list_network_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        detections = self.themes_service.list_network_detections(limit=limit)

        alerts: list[dict[str, Any]] = []
        for item in detections:
            severity = self._normalize_severity(item.get("severity"))
            priority = item.get("priority") or item.get("risk_level") or severity

            src_ip = item.get("src_ip") or item.get("source_ip")
            src_port = item.get("src_port")
            dest_ip = item.get("dest_ip") or item.get("destination_ip")
            dest_port = item.get("dest_port")

            protocol = item.get("protocol") or item.get("proto")
            app_proto = item.get("app_proto")
            direction = item.get("direction")

            title = self._build_title(item)
            summary = self._build_summary(
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=protocol,
                app_proto=app_proto,
            )

            alerts.append(
                {
                    "id": self._build_alert_id(item),
                    "timestamp": item.get("timestamp"),
                    "title": title,
                    "summary": summary,
                    "description": item.get("description") or summary,
                    "status": item.get("status") or "open",
                    "source_engine": item.get("engine") or item.get("source") or "suricata",
                    "theme": "network",
                    "severity": severity,
                    "priority": priority,
                    "risk_score": item.get("risk_score"),
                    "confidence": item.get("confidence"),
                    "category": item.get("category"),
                    "asset_name": (
                        item.get("asset_name")
                        or item.get("hostname")
                        or dest_ip
                        or src_ip
                        or "unknown"
                    ),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "src_label": self._format_endpoint(src_ip, src_port),
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "dest_label": self._format_endpoint(dest_ip, dest_port),
                    "protocol": protocol,
                    "protocol_label": self._format_protocol(protocol, app_proto),
                    "app_proto": app_proto,
                    "direction": direction,
                    "flow_id": item.get("flow_id") or item.get("metadata", {}).get("flow_id"),
                    "rule_id": (
                        item.get("rule_id")
                        or item.get("source_rule_id")
                        or item.get("metadata", {}).get("suricata_signature_id")
                    ),
                    "recommended_actions": item.get("recommended_actions", []),
                    "evidence": item,
                }
            )

        return alerts

    def _build_alert_id(self, item: dict[str, Any]) -> str:
        flow_id = item.get("flow_id") or item.get("metadata", {}).get("flow_id") or "unknown"
        rule_id = (
            item.get("rule_id")
            or item.get("source_rule_id")
            or item.get("metadata", {}).get("suricata_signature_id")
            or "unknown"
        )
        direction = item.get("direction", "na")

        return f"network:{flow_id}:{rule_id}:{direction}"

    def _build_title(self, item: dict[str, Any]) -> str:
        title = str(item.get("title") or "").strip()
        if title:
            return title

        app_proto = str(item.get("app_proto") or "").lower()
        category = str(item.get("category") or "").lower()

        if category == "network_reconnaissance":
            return "Reconnaissance réseau détectée"
        if category == "suspicious_http":
            return "Trafic HTTP suspect détecté"
        if category == "dns_anomaly":
            return "Anomalie DNS détectée"
        if category == "tls_anomaly":
            return "Anomalie TLS détectée"
        if app_proto == "http":
            return "Événement HTTP à surveiller"
        if app_proto == "dns":
            return "Événement DNS à surveiller"
        if app_proto == "tls":
            return "Événement TLS à surveiller"

        return "Détection réseau"

    def _build_summary(
        self,
        src_ip: Any,
        src_port: Any,
        dest_ip: Any,
        dest_port: Any,
        protocol: Any,
        app_proto: Any,
    ) -> str:
        proto_label = self._format_protocol(protocol, app_proto)
        src_label = self._format_endpoint(src_ip, src_port)
        dest_label = self._format_endpoint(dest_ip, dest_port)
        return f"{proto_label} {src_label} → {dest_label}"

    def _format_protocol(self, protocol: Any, app_proto: Any) -> str:
        proto = str(protocol or "").strip().upper()
        app = str(app_proto or "").strip().lower()

        if proto and app:
            return f"{proto}/{app}"
        if proto:
            return proto
        if app:
            return app
        return "unknown"

    def _format_endpoint(self, ip: Any, port: Any) -> str:
        ip_str = str(ip or "").strip()
        if not ip_str:
            return "unknown"

        port_str = str(port or "").strip()
        if not port_str:
            return ip_str

        if ":" in ip_str:
            return f"[{ip_str}]:{port_str}"
        return f"{ip_str}:{port_str}"

    def _normalize_severity(self, severity: Any) -> str:
        if isinstance(severity, str):
            value = severity.lower().strip()
            if value in {"critical", "high", "medium", "low", "info"}:
                return value

        try:
            value = int(severity)
        except (TypeError, ValueError):
            return "info"

        if value <= 1:
            return "critical"
        if value == 2:
            return "high"
        if value == 3:
            return "medium"
        if value == 4:
            return "low"
        return "info"