from __future__ import annotations

from pathlib import Path
from typing import Any

from connectors.suricata.eve_connector import SuricataEveConnector
from normalization.suricata_normalizer import SuricataNormalizer
from services.suricata_detection_engine import SuricataDetectionEngine


class SuricataService:
    """
    Service métier Suricata.

    Responsabilités :
    - lire les événements bruts via le connecteur
    - normaliser les événements
    - dédupliquer les alertes
    - exposer des vues simples pour l'API
    """

    def __init__(self, eve_path: str | Path) -> None:
        self.connector = SuricataEveConnector(eve_path)
        self.normalizer = SuricataNormalizer()
        self.detection_engine = SuricataDetectionEngine()

    def get_status(self) -> dict[str, Any]:
        return self.connector.get_status()

    def list_raw_events(
        self,
        limit: int = 50,
        event_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        return self.connector.read_events(limit=limit, event_types=event_types)

    def list_events(
        self,
        limit: int = 50,
        event_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        raw_items = self.list_raw_events(limit=limit, event_types=event_types)

        items: list[dict[str, Any]] = []
        for item in raw_items:
            normalized = self.normalizer.normalize(item)
            if normalized:
                items.append(normalized)

        return items

    def list_raw_alerts(self, limit: int = 5000) -> list[dict[str, Any]]:
        return self.connector.read_events(limit=limit, event_types=["alert"])

    def list_detections(self, limit: int = 50) -> list[dict[str, Any]]:
        raw_alerts = self.list_raw_alerts(limit=5000)
        deduped_alerts = self._deduplicate_alerts(raw_alerts)

        detections: list[dict[str, Any]] = []

        for item in deduped_alerts:
            normalized = self.normalizer.normalize(item)
            if not normalized:
                continue

            try:
                event_detections = self.detection_engine.from_suricata_event(normalized)
            except Exception:
                event_detections = []

            if event_detections:
                detections.extend(event_detections)
                continue

            # Fallback pour ne pas casser la console si le moteur Suricata
            # n'est pas encore aligné avec le normalizer.
            detections.append(normalized)

        if limit <= 0:
            return detections

        return detections[-limit:]

    def list_detection_summaries(self, limit: int = 50) -> list[dict[str, Any]]:
        detections = self.list_detections(limit=limit)

        items: list[dict[str, Any]] = []
        for item in detections:
            metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}

            detection = item.get("detection", {}) if isinstance(item.get("detection"), dict) else {}
            source = item.get("source", {}) if isinstance(item.get("source"), dict) else {}
            destination = item.get("destination", {}) if isinstance(item.get("destination"), dict) else {}
            network = item.get("network", {}) if isinstance(item.get("network"), dict) else {}
            suricata = item.get("suricata", {}) if isinstance(item.get("suricata"), dict) else {}
            suricata_alert = suricata.get("alert", {}) if isinstance(suricata.get("alert"), dict) else {}

            src_ip = item.get("src_ip") or item.get("source_ip") or source.get("ip")
            src_port = item.get("src_port") or source.get("port")
            dest_ip = item.get("dest_ip") or item.get("destination_ip") or destination.get("ip")
            dest_port = item.get("dest_port") or destination.get("port")

            protocol = item.get("protocol") or item.get("proto") or network.get("transport")
            app_proto = item.get("app_proto") or network.get("application")
            direction = item.get("direction") or network.get("direction")

            engine = (
                item.get("engine")
                or item.get("source_engine")
                or detection.get("engine")
                or "suricata"
            )

            title = (
                item.get("title")
                or detection.get("title")
                or suricata_alert.get("signature")
                or "Network detection"
            )

            rule_id = (
                item.get("source_rule_id")
                or item.get("rule_id")
                or detection.get("rule_id")
                or suricata_alert.get("signature_id")
                or metadata.get("suricata_signature_id")
            )

            severity = item.get("severity") or detection.get("severity")
            priority = item.get("priority") or item.get("risk_level")
            category = item.get("category") or detection.get("category") or item.get("event", {}).get("category")

            description = item.get("description")
            if not description:
                description = (
                    f"{src_ip or 'unknown'}:{src_port or 'unknown'} → "
                    f"{dest_ip or 'unknown'}:{dest_port or 'unknown'}"
                )

            items.append(
                {
                    "timestamp": item.get("timestamp"),
                    "engine": engine,
                    "source_engine": engine,
                    "theme": "network",
                    "title": title,
                    "rule_id": rule_id,
                    "severity": severity,
                    "priority": priority,
                    "risk_score": item.get("risk_score"),
                    "confidence": item.get("confidence"),
                    "action": metadata.get("suricata_action") or detection.get("action") or item.get("action"),
                    "category": category,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "src_label": src_ip or "unknown",
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "dest_label": dest_ip or "unknown",
                    "protocol": protocol,
                    "protocol_label": protocol or "unknown",
                    "app_proto": app_proto,
                    "direction": direction,
                    "flow_id": item.get("flow_id") or suricata.get("flow_id") or metadata.get("flow_id"),
                    "in_iface": item.get("in_iface") or suricata.get("in_iface") or metadata.get("in_iface"),
                    "description": description,
                    "summary": description,
                    "recommended_actions": item.get("recommended_actions", []),
                    "status": item.get("status") or detection.get("status") or "observed",
                    "asset_name": item.get("asset_name") or dest_ip or "unknown",
                }
            )

        return items

    def _deduplicate_alerts(self, raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Déduplication simple des alertes Suricata.

        Clé retenue :
        - flow_id
        - signature_id
        - direction

        On garde la dernière occurrence rencontrée.
        """
        deduped: dict[tuple[Any, Any, Any], dict[str, Any]] = {}

        for item in raw_alerts:
            alert = item.get("alert", {}) if isinstance(item.get("alert"), dict) else {}

            key = (
                item.get("flow_id"),
                alert.get("signature_id"),
                item.get("direction"),
            )
            deduped[key] = item

        return list(deduped.values())