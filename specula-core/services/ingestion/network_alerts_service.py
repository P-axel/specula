from __future__ import annotations

from typing import Any

from services.themes_service import ThemesService


class NetworkAlertsService:
    """
    Transforme les détections réseau normalisées en alertes réseau lisibles.
    """

    def __init__(self) -> None:
        self.themes_service = ThemesService()

    def list_network_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        detections = self.themes_service.list_network_detections(limit=limit)

        alerts: list[dict[str, Any]] = []
        for item in detections:
            event = item.get("event", {}) or {}
            source = item.get("source", {}) or {}
            destination = item.get("destination", {}) or {}
            network = item.get("network", {}) or {}
            risk = item.get("risk", {}) or {}
            rule = item.get("rule", {}) or {}
            detection = item.get("detection", {}) or {}
            suricata = item.get("suricata", {}) or {}

            severity = self._normalize_severity(
                event.get("severity")
                or detection.get("severity_label")
                or detection.get("severity")
            )

            priority = risk.get("level") or severity

            src_ip = source.get("ip") or item.get("src_ip") or item.get("source_ip")
            src_port = source.get("port") or item.get("src_port")
            dest_ip = destination.get("ip") or item.get("dest_ip") or item.get("destination_ip")
            dest_port = destination.get("port") or item.get("dest_port")

            protocol = network.get("transport") or item.get("protocol") or item.get("proto")
            app_proto = network.get("application") or network.get("protocol") or item.get("app_proto")
            direction = network.get("direction") or item.get("direction")

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
                    "description": detection.get("title") or item.get("description") or summary,
                    "status": detection.get("status") or "open",
                    "source_engine": item.get("source_context", {}).get("source")
                    or event.get("provider")
                    or detection.get("provider")
                    or "suricata",
                    "theme": "network",
                    "severity": severity,
                    "priority": priority,
                    "risk_score": risk.get("score") or item.get("risk_score"),
                    "confidence": risk.get("confidence") or item.get("confidence"),
                    "category": event.get("category") or detection.get("category") or item.get("category"),
                    "asset_name": dest_ip or src_ip or "unknown",
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
                    "flow_id": suricata.get("flow_id") or item.get("flow_id"),
                    "rule_id": rule.get("id") or detection.get("rule_id") or item.get("rule_id"),
                    "recommended_actions": item.get("recommended_actions", []),
                    "evidence": item,
                }
            )

        return alerts

    def _build_alert_id(self, item: dict[str, Any]) -> str:
        suricata = item.get("suricata", {}) or {}
        rule = item.get("rule", {}) or {}
        network = item.get("network", {}) or {}
        event = item.get("event", {}) or {}

        flow_id = suricata.get("flow_id") or item.get("flow_id") or "unknown"
        rule_id = rule.get("id") or item.get("rule_id") or "unknown"
        direction = network.get("direction") or item.get("direction") or "na"
        event_id = event.get("id") or "no-event"

        return f"network:{flow_id}:{rule_id}:{direction}:{event_id}"

    def _build_title(self, item: dict[str, Any]) -> str:
        detection = item.get("detection", {}) or {}
        rule = item.get("rule", {}) or {}
        event = item.get("event", {}) or {}
        network = item.get("network", {}) or {}

        title = str(
            detection.get("title")
            or rule.get("name")
            or item.get("title")
            or ""
        ).strip()
        if title:
            return title

        app_proto = str(
            network.get("application")
            or network.get("protocol")
            or item.get("app_proto")
            or ""
        ).lower()
        category = str(event.get("category") or item.get("category") or "").lower()

        if category == "network_scan":
            return "Reconnaissance réseau détectée"
        if category == "network_http":
            return "Trafic HTTP suspect détecté"
        if category == "network_dns":
            return "Anomalie DNS détectée"
        if category == "network_tls":
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