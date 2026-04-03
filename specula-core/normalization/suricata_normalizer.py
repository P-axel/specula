from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SuricataNormalizer:
    SOURCE = "suricata"
    DATASET = "suricata"
    OBSERVER_VENDOR = "OISF"
    OBSERVER_PRODUCT = "Suricata"
    OBSERVER_TYPE = "ids"

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw_event, dict):
            raise TypeError("raw_event must be a dict")

        event_type = self._normalize_str(raw_event.get("event_type"))
        alert = self._as_dict(raw_event.get("alert"))
        dns = self._as_dict(raw_event.get("dns"))
        flow = self._as_dict(raw_event.get("flow"))
        http = self._as_dict(raw_event.get("http"))
        tls = self._as_dict(raw_event.get("tls"))
        fileinfo = self._as_dict(raw_event.get("fileinfo"))
        anomaly = self._as_dict(raw_event.get("anomaly"))
        ssh = self._as_dict(raw_event.get("ssh"))

        src_ip = self._normalize_ip(raw_event.get("src_ip"))
        dest_ip = self._normalize_ip(raw_event.get("dest_ip"))
        src_port = self._to_int(raw_event.get("src_port"))
        dest_port = self._to_int(raw_event.get("dest_port"))
        proto = self._normalize_protocol(raw_event.get("proto"))
        app_proto = self._normalize_protocol(raw_event.get("app_proto"))
        timestamp = self._normalize_timestamp(raw_event.get("timestamp"))

        confidence = self._normalize_float(alert.get("confidence"))
        if event_type == "alert" and confidence is None:
            confidence = 0.80

        normalized = {
            "timestamp": timestamp,
            "event": {
                "id": self._build_event_id(raw_event),
                "kind": self._map_event_kind(event_type),
                "category": self._map_event_category(event_type, alert, anomaly),
                "type": self._map_event_type(event_type, app_proto),
                "action": self._normalize_str(alert.get("action")),
                "dataset": self.DATASET,
                "module": self.SOURCE,
                "provider": self.SOURCE,
                "outcome": self._infer_outcome_from_alert(alert),
                "severity": self._normalize_severity(alert.get("severity")),
                "severity_code": self._to_int(alert.get("severity")),
            },
            "observer": {
                "vendor": self.OBSERVER_VENDOR,
                "product": self.OBSERVER_PRODUCT,
                "type": self.OBSERVER_TYPE,
                "name": self._normalize_str(raw_event.get("host"))
                or self._normalize_str(raw_event.get("sensor_name")),
                "ingress": {
                    "interface": self._normalize_str(raw_event.get("in_iface")),
                },
            },
            "source": {
                "ip": src_ip,
                "port": src_port,
            },
            "destination": {
                "ip": dest_ip,
                "port": dest_port,
            },
            "client": self._build_client(raw_event),
            "server": self._build_server(raw_event),
            "network": {
                "transport": proto,
                "protocol": app_proto,
                "application": app_proto,
                "direction": self._normalize_str(raw_event.get("direction")),
                "community_id": self._normalize_str(raw_event.get("community_id")),
                "type": self._detect_network_type(src_ip, dest_ip),
            },
            "file": self._build_file(fileinfo),
            "url": self._build_url(http),
            "dns": self._build_dns(dns),
            "http": self._build_http(http),
            "tls": self._build_tls(tls),
            "rule": self._build_rule(alert),
            "detection": self._build_detection(alert),
            "risk": {
                "score": self._map_risk_score_from_suricata(alert.get("severity")),
                "level": self._normalize_severity(alert.get("severity")),
                "confidence": confidence,
            },
            "related": {
                "ip": self._unique_list([src_ip, dest_ip]),
                "hosts": self._unique_list([
                    self._normalize_str(dns.get("rrname")),
                    self._normalize_str(http.get("hostname")),
                    self._normalize_str(tls.get("sni")),
                ]),
                "hash": self._unique_list([
                    self._normalize_str(fileinfo.get("md5")),
                    self._normalize_str(fileinfo.get("sha1")),
                    self._normalize_str(fileinfo.get("sha256")),
                ]),
                "rule_ids": self._unique_list([
                    self._normalize_str(alert.get("signature_id")),
                ]),
            },
            "tags": self._build_tags(event_type, alert, app_proto),
            "source_context": {
                "source": self.SOURCE,
                "source_type": "network",
                "ingest_type": "telemetry",
            },
            "suricata": {
                "event_type": event_type,
                "flow_id": self._normalize_str(raw_event.get("flow_id")),
            },
            "raw": raw_event,
        }

        return self._drop_none(normalized) or {}

    def _map_event_type(self, event_type: Optional[str], app_proto: Optional[str]) -> Optional[str]:
        if event_type == "alert":
            return "network_alert"
        if app_proto:
            return f"{app_proto}_event"
        return event_type

    def _build_event_id(self, raw_event: Dict[str, Any]) -> str:
        ts = self._normalize_str(raw_event.get("timestamp")) or "unknown"
        flow_id = self._normalize_str(raw_event.get("flow_id")) or "no-flow"
        event_type = self._normalize_str(raw_event.get("event_type")) or "event"
        sig_id = self._normalize_str(self._safe_get(raw_event, "alert", "signature_id")) or "no-sig"
        return f"suricata-{event_type}-{flow_id}-{sig_id}-{ts}"

    def _build_client(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        direction = self._normalize_str(raw_event.get("direction"))
        src_ip = self._normalize_ip(raw_event.get("src_ip"))
        src_port = self._to_int(raw_event.get("src_port"))
        dest_ip = self._normalize_ip(raw_event.get("dest_ip"))
        dest_port = self._to_int(raw_event.get("dest_port"))

        if direction == "to_server":
            return {"ip": src_ip, "port": src_port}
        if direction == "to_client":
            return {"ip": dest_ip, "port": dest_port}
        return None

    def _build_server(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        direction = self._normalize_str(raw_event.get("direction"))
        src_ip = self._normalize_ip(raw_event.get("src_ip"))
        src_port = self._to_int(raw_event.get("src_port"))
        dest_ip = self._normalize_ip(raw_event.get("dest_ip"))
        dest_port = self._to_int(raw_event.get("dest_port"))

        if direction == "to_server":
            return {"ip": dest_ip, "port": dest_port}
        if direction == "to_client":
            return {"ip": src_ip, "port": src_port}
        return None

    def _build_rule(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not alert:
            return None
        return {
            "id": self._to_int(alert.get("signature_id")),
            "name": self._normalize_str(alert.get("signature")),
            "category": self._normalize_str(alert.get("category")),
            "severity": self._normalize_severity(alert.get("severity")),
        }

    def _build_detection(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not alert:
            return None
        severity_code = self._to_int(alert.get("severity"))
        return {
            "engine": "suricata",
            "title": self._normalize_str(alert.get("signature")),
            "rule_id": self._to_int(alert.get("signature_id")),
            "severity": severity_code,
            "severity_label": self._normalize_severity(severity_code),
            "status": "observed",
        }

    def _build_dns(self, dns: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not dns:
            return None
        return {
            "name": self._normalize_str(dns.get("rrname")),
            "type": self._normalize_str(dns.get("rrtype")),
        }

    def _build_http(self, http: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not http:
            return None
        return {
            "method": self._normalize_str(http.get("http_method")),
            "status": self._to_int(http.get("status")),
        }

    def _build_url(self, http: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not http:
            return None
        return {
            "domain": self._normalize_str(http.get("hostname")),
            "path": self._normalize_str(http.get("url")),
        }

    def _build_tls(self, tls: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tls:
            return None
        return {
            "sni": self._normalize_str(tls.get("sni")),
        }

    def _build_file(self, fileinfo: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not fileinfo:
            return None
        return {
            "name": self._normalize_str(fileinfo.get("filename")),
            "size": self._to_int(fileinfo.get("size")),
        }

    def _build_tags(self, event_type: Optional[str], alert: Dict[str, Any], app_proto: Optional[str]) -> Optional[List[str]]:
        return self._unique_list(["suricata", event_type, app_proto])

    def _map_event_kind(self, event_type: Optional[str]) -> str:
        return "alert" if event_type == "alert" else "event"

    def _map_event_category(self, event_type: Optional[str], alert: Dict[str, Any], anomaly: Dict[str, Any]) -> str:
        if event_type == "alert":
            return "network_alert"
        return event_type or "network"

    def _infer_outcome_from_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        action = self._normalize_str(alert.get("action"))
        if action == "allowed":
            return "success"
        if action in {"blocked", "drop"}:
            return "failure"
        return None

    def _normalize_severity(self, severity: Any) -> str:
        sev = self._to_int(severity)
        return {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(sev, "info")

    def _map_risk_score_from_suricata(self, severity: Any) -> Optional[int]:
        sev = self._to_int(severity)
        return {1: 90, 2: 75, 3: 55, 4: 30}.get(sev)

    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except Exception:
            return None

    def _normalize_ip(self, value: Any) -> Optional[str]:
        try:
            return str(ip_address(str(value)))
        except Exception:
            return None

    def _normalize_protocol(self, value: Any) -> Optional[str]:
        return self._normalize_str(value)

    def _normalize_str(self, value: Any) -> Optional[str]:
        return str(value).strip() if value else None

    def _normalize_float(self, value: Any) -> Optional[float]:
        try:
            return float(value)
        except Exception:
            return None

    def _to_int(self, value: Any) -> Optional[int]:
        try:
            return int(value)
        except Exception:
            return None

    def _detect_network_type(self, src_ip: Optional[str], dest_ip: Optional[str]) -> Optional[str]:
        for ip in (src_ip, dest_ip):
            try:
                return "ipv6" if ip_address(ip).version == 6 else "ipv4"
            except Exception:
                continue
        return None

    def _unique_list(self, values: List[Any]) -> Optional[List[Any]]:
        return list(dict.fromkeys([v for v in values if v]))

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _safe_get(self, dct: Dict[str, Any], *keys: str) -> Optional[Any]:
        for key in keys:
            if not isinstance(dct, dict):
                return None
            dct = dct.get(key)
        return dct

    def _drop_none(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self._drop_none(v) for k, v in value.items() if v is not None}
        if isinstance(value, list):
            return [self._drop_none(v) for v in value if v is not None]
        return value