from __future__ import annotations

from typing import Any


from services.orchestration.unified_correlator import UnifiedCorrelator
from services.themes_service import ThemesService


class NetworkIncidentsService:
    """
    Transforme les détections réseau en incidents lisibles pour la console Specula.
    """

    def __init__(self) -> None:
        self.themes_service = ThemesService()
        self.incident_correlator = UnifiedCorrelator()
        
    def list_network_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        detections = self.themes_service.list_network_detections(limit=max(limit * 10, 100))
        incidents = self.incident_correlator.correlate(detections)

        items: list[dict[str, Any]] = []
        for item in incidents[:limit]:
            signals = item.get("signals")
            if not isinstance(signals, list):
                signals = []
            severity = self._normalize_severity(item.get("severity"))
            priority = item.get("priority") or item.get("risk_level") or severity
            

            ip_pairs = self._build_ip_pairs(signals)
            engines = self._build_engines(item, signals)

            title = self._build_title(item)
            first_seen = item.get("created_at") or item.get("timestamp")
            last_seen = item.get("updated_at") or item.get("timestamp")

            items.append(
                {
                    "id": item.get("id"),
                    "title": title,
                    "name": title,
                    "description": item.get("description") or title,
                    "status": item.get("status") or "open",
                    "severity": severity,
                    "priority": priority,
                    "risk_score": item.get("risk_score"),
                    "confidence": item.get("confidence"),
                    "category": item.get("category"),
                    "source_engine": "specula",
                    "theme": "network",
                    "asset_name": item.get("asset_name") or item.get("hostname") or "unknown",
                    "asset_id": item.get("asset_id"),
                    "hostname": item.get("hostname"),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "detections_count": item.get("signals_count") or len(signals),
                    "signals_count": item.get("signals_count") or len(signals),
                    "ip_pairs": ip_pairs,
                    "peer_ips": ip_pairs,
                    "engines": engines,
                    "signals": self._format_signals(signals),
                    "tags": item.get("tags", []),
                    "metadata": item.get("metadata", {}),
                    "evidence": item,
                }
            )

        return items

    def _build_title(self, item: dict[str, Any]) -> str:
        title = str(item.get("title") or item.get("name") or "").strip()
        if title and title.lower() != "network detection":
            return title

        category = str(item.get("category") or "").lower()

        if category == "network_incident":
            return "Activité réseau sensible"
        if category == "configuration_incident":
            return "Changement réseau à surveiller"
        if category == "security_incident":
            return "Incident réseau corrélé"
        if category == "host_incident":
            return "Suspicion de compromission liée au réseau"
        if category == "identity_incident":
            return "Activité d’authentification à surveiller"
        if category == "availability_incident":
            return "Dégradation de service impactant le réseau"

        return "Incident réseau"

    def _build_ip_pairs(self, signals: list[dict[str, Any]]) -> list[str]:
        pairs: list[str] = []
        seen: set[str] = set()

        for signal in signals:
            left = self._extract_endpoint(signal, side="src")
            right = self._extract_endpoint(signal, side="dest")
            pair = f"{left} → {right}"

            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)

        return pairs

    def _build_engines(
        self,
        incident: dict[str, Any],
        signals: list[dict[str, Any]],
    ) -> list[str]:
        engines: list[str] = []
        seen: set[str] = set()

        incident_source = str(incident.get("source") or "").strip().lower()
        if incident_source and incident_source != "specula":
            seen.add(incident_source)
            engines.append(incident_source)

        for signal in signals:
            raw_engine = signal.get("source_engine") or signal.get("engine") or ""
            engine = str(raw_engine).strip().lower()

            if not engine:
                continue

            if engine not in seen:
                seen.add(engine)
                engines.append(engine)

        if not engines:
            return ["suricata"]

        return engines

    def _format_signals(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        formatted: list[dict[str, Any]] = []

        for signal in signals:
            protocol = signal.get("protocol") or signal.get("proto")
            app_proto = signal.get("app_proto")

            formatted.append(
                {
                    "id": signal.get("id"),
                    "title": signal.get("title") or signal.get("name") or "Détection réseau",
                    "severity": self._normalize_severity(signal.get("severity")),
                    "priority": signal.get("priority") or signal.get("risk_level"),
                    "risk_score": signal.get("risk_score"),
                    "timestamp": signal.get("timestamp") or signal.get("created_at"),
                    "category": signal.get("category"),
                    "source_engine": signal.get("source_engine") or signal.get("engine") or "suricata",
                    "src_label": self._extract_endpoint(signal, side="src"),
                    "dest_label": self._extract_endpoint(signal, side="dest"),
                    "protocol_label": self._format_protocol(protocol, app_proto),
                }
            )

        return formatted

    def _extract_endpoint(self, signal: dict[str, Any], side: str) -> str:
        if side == "src":
            ip = signal.get("src_ip") or signal.get("source_ip")
            port = signal.get("src_port")
            label = signal.get("src_label")
        else:
            ip = signal.get("dest_ip") or signal.get("destination_ip")
            port = signal.get("dest_port")
            label = signal.get("dest_label")

        if ip:
            return self._format_endpoint(ip, port)

        label_str = str(label or "").strip()
        if label_str:
            return label_str

        return "unknown"

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