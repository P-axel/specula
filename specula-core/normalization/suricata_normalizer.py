from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _safe_get(dct: Dict[str, Any], *keys: str) -> Optional[Any]:
    current: Any = dct
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


class SuricataNormalizer:
    """
    Transforme un événement brut Suricata en schéma Specula minimal.

    Cette version reste volontairement simple pour sécuriser l’intégration.
    """

    DATASET = "suricata"

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event_type = raw_event.get("event_type")
        alert = raw_event.get("alert", {}) if isinstance(raw_event.get("alert"), dict) else {}
        dns = raw_event.get("dns", {}) if isinstance(raw_event.get("dns"), dict) else {}
        flow = raw_event.get("flow", {}) if isinstance(raw_event.get("flow"), dict) else {}

        logger.debug(
            "SURICATA RAW EVENT | event_type=%s | timestamp=%s | src=%s:%s | dest=%s:%s | proto=%s | app_proto=%s | alert_signature=%s | alert_severity=%s",
            event_type,
            raw_event.get("timestamp"),
            raw_event.get("src_ip"),
            raw_event.get("src_port"),
            raw_event.get("dest_ip"),
            raw_event.get("dest_port"),
            raw_event.get("proto"),
            raw_event.get("app_proto"),
            alert.get("signature"),
            alert.get("severity"),
        )

        normalized = {
            "timestamp": raw_event.get("timestamp"),
            "event": {
                "kind": self._map_event_kind(event_type),
                "category": self._map_event_category(event_type),
                "type": event_type,
                "dataset": self.DATASET,
            },
            "source": {
                "ip": raw_event.get("src_ip"),
                "port": raw_event.get("src_port"),
            },
            "destination": {
                "ip": raw_event.get("dest_ip"),
                "port": raw_event.get("dest_port"),
            },
            "network": {
                "transport": raw_event.get("proto"),
                "application": raw_event.get("app_proto"),
                "direction": raw_event.get("direction"),
                "community_id": raw_event.get("community_id"),
            },
            "suricata": {
                "event_type": event_type,
                "flow_id": raw_event.get("flow_id"),
                "in_iface": raw_event.get("in_iface"),
                "alert": {
                    "action": alert.get("action"),
                    "gid": alert.get("gid"),
                    "signature_id": alert.get("signature_id"),
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                } if alert else None,
                "dns": {
                    "type": dns.get("type"),
                    "rcode": dns.get("rcode"),
                    "queries": dns.get("queries"),
                    "answers": dns.get("answers"),
                    "grouped": dns.get("grouped"),
                } if dns else None,
                "flow": {
                    "pkts_toserver": flow.get("pkts_toserver"),
                    "pkts_toclient": flow.get("pkts_toclient"),
                    "bytes_toserver": flow.get("bytes_toserver"),
                    "bytes_toclient": flow.get("bytes_toclient"),
                    "start": flow.get("start"),
                    "end": flow.get("end"),
                    "state": flow.get("state"),
                    "alerted": flow.get("alerted"),
                } if flow else None,
            },
            "detection": self._build_detection(raw_event),
            "raw": raw_event,
        }

        logger.debug(
            "SURICATA NORMALIZED | timestamp=%s | source=%s | destination=%s | network=%s | detection=%s",
            normalized.get("timestamp"),
            normalized.get("source"),
            normalized.get("destination"),
            normalized.get("network"),
            normalized.get("detection"),
        )

        return normalized

    def _build_detection(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = raw_event.get("event_type")
        alert = raw_event.get("alert")

        if event_type != "alert" or not isinstance(alert, dict):
            logger.debug(
                "SURICATA DETECTION SKIPPED | event_type=%s | has_alert=%s",
                event_type,
                isinstance(alert, dict),
            )
            return None

        severity = alert.get("severity")
        signature = alert.get("signature")
        signature_id = alert.get("signature_id")

        detection = {
            "engine": "suricata",
            "title": signature,
            "rule_id": signature_id,
            "severity": severity,
            "action": alert.get("action"),
            "category": alert.get("category"),
            "status": "observed",
        }

        logger.debug(
            "SURICATA DETECTION BUILT | engine=%s | title=%s | rule_id=%s | severity=%s | category=%s",
            detection.get("engine"),
            detection.get("title"),
            detection.get("rule_id"),
            detection.get("severity"),
            detection.get("category"),
        )

        return detection

    def _map_event_kind(self, event_type: Optional[str]) -> str:
        if event_type == "alert":
            return "alert"
        return "event"

    def _map_event_category(self, event_type: Optional[str]) -> str:
        mapping = {
            "alert": "intrusion_detection",
            "dns": "network_dns",
            "http": "network_http",
            "tls": "network_tls",
            "flow": "network_flow",
        }
        return mapping.get(event_type, "network")