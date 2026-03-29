from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SuricataNormalizer:
    """
    Normalizeur canonique Suricata -> schéma commun Specula.

    Schéma cible :
    - timestamp
    - event
    - observer
    - host
    - source / destination
    - client / server
    - network
    - user / process / file / url / dns / http / tls
    - rule / detection / risk / related / tags
    - source_context
    - suricata (namespace natif)
    - raw
    """

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

        logger.debug(
            "SURICATA RAW | event_type=%s timestamp=%s src=%s:%s dst=%s:%s proto=%s app_proto=%s",
            event_type,
            timestamp,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            proto,
            app_proto,
        )

        normalized = {
            "timestamp": timestamp,
            "event": {
                "id": self._build_event_id(raw_event),
                "kind": self._map_event_kind(event_type),
                "category": self._map_event_category(event_type, alert, anomaly),
                "type": event_type,
                "action": self._normalize_str(alert.get("action")),
                "dataset": self.DATASET,
                "module": app_proto or event_type,
                "provider": self.SOURCE,
                "outcome": self._infer_outcome_from_alert(alert),
                "severity": self._normalize_severity(alert.get("severity")),
                "severity_code": self._to_int(alert.get("severity")),
            },
            "observer": {
                "vendor": self.OBSERVER_VENDOR,
                "product": self.OBSERVER_PRODUCT,
                "type": self.OBSERVER_TYPE,
                "name": self._normalize_str(raw_event.get("host")) or self._normalize_str(raw_event.get("sensor_name")),
                "ingress": {
                    "interface": self._normalize_str(raw_event.get("in_iface")),
                },
            },
            "host": {
                "hostname": self._normalize_str(raw_event.get("host")),
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
            "user": None,
            "process": None,
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
                "confidence": self._normalize_float(alert.get("confidence")) or 0.80 if event_type == "alert" else None,
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
                "usernames": None,
                "process_names": None,
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
                "pcap_cnt": self._to_int(raw_event.get("pcap_cnt")),
                "in_iface": self._normalize_str(raw_event.get("in_iface")),
                "host": self._normalize_str(raw_event.get("host")),
                "alert": {
                    "action": self._normalize_str(alert.get("action")),
                    "gid": self._to_int(alert.get("gid")),
                    "signature_id": self._to_int(alert.get("signature_id")),
                    "rev": self._to_int(alert.get("rev")),
                    "signature": self._normalize_str(alert.get("signature")),
                    "category": self._normalize_str(alert.get("category")),
                    "severity": self._to_int(alert.get("severity")),
                    "metadata": alert.get("metadata") if isinstance(alert.get("metadata"), dict) else None,
                } if alert else None,
                "dns": {
                    "type": self._normalize_str(dns.get("type")),
                    "id": self._to_int(dns.get("id")),
                    "rcode": self._normalize_str(dns.get("rcode")),
                    "rrname": self._normalize_str(dns.get("rrname")),
                    "rrtype": self._normalize_str(dns.get("rrtype")),
                    "tx_id": self._to_int(dns.get("tx_id")),
                    "queries": dns.get("queries") if isinstance(dns.get("queries"), list) else None,
                    "answers": dns.get("answers") if isinstance(dns.get("answers"), list) else None,
                    "grouped": dns.get("grouped") if isinstance(dns.get("grouped"), dict) else None,
                } if dns else None,
                "http": {
                    "hostname": self._normalize_str(http.get("hostname")),
                    "url": self._normalize_str(http.get("url")),
                    "http_method": self._normalize_str(http.get("http_method")),
                    "protocol": self._normalize_str(http.get("protocol")),
                    "status": self._to_int(http.get("status")),
                    "length": self._to_int(http.get("length")),
                    "user_agent": self._normalize_str(http.get("http_user_agent")),
                    "content_type": self._normalize_str(http.get("content_type")),
                    "referer": self._normalize_str(http.get("http_refer")),
                } if http else None,
                "tls": {
                    "version": self._normalize_str(tls.get("version")),
                    "subject": self._normalize_str(tls.get("subject")),
                    "issuerdn": self._normalize_str(tls.get("issuerdn")),
                    "sni": self._normalize_str(tls.get("sni")),
                    "serial": self._normalize_str(tls.get("serial")),
                    "fingerprint": self._normalize_str(tls.get("fingerprint")),
                    "ja3": self._normalize_str(tls.get("ja3")),
                    "ja3s": self._normalize_str(tls.get("ja3s")),
                    "notbefore": self._normalize_str(tls.get("notbefore")),
                    "notafter": self._normalize_str(tls.get("notafter")),
                } if tls else None,
                "fileinfo": {
                    "filename": self._normalize_str(fileinfo.get("filename")),
                    "size": self._to_int(fileinfo.get("size")),
                    "magic": self._normalize_str(fileinfo.get("magic")),
                    "md5": self._normalize_str(fileinfo.get("md5")),
                    "sha1": self._normalize_str(fileinfo.get("sha1")),
                    "sha256": self._normalize_str(fileinfo.get("sha256")),
                    "stored": fileinfo.get("stored"),
                } if fileinfo else None,
                "flow": {
                    "pkts_toserver": self._to_int(flow.get("pkts_toserver")),
                    "pkts_toclient": self._to_int(flow.get("pkts_toclient")),
                    "bytes_toserver": self._to_int(flow.get("bytes_toserver")),
                    "bytes_toclient": self._to_int(flow.get("bytes_toclient")),
                    "start": self._normalize_timestamp(flow.get("start")),
                    "end": self._normalize_timestamp(flow.get("end")),
                    "state": self._normalize_str(flow.get("state")),
                    "alerted": flow.get("alerted"),
                } if flow else None,
                "anomaly": anomaly or None,
                "ssh": ssh or None,
            },
            "raw": raw_event,
        }

        cleaned = self._drop_none(normalized) or {}

        logger.debug(
            "SURICATA NORMALIZED | event_id=%s category=%s severity=%s",
            cleaned.get("event", {}).get("id"),
            cleaned.get("event", {}).get("category"),
            cleaned.get("event", {}).get("severity"),
        )

        return cleaned

    def _build_event_id(self, raw_event: Dict[str, Any]) -> str:
        ts = self._normalize_str(raw_event.get("timestamp")) or "unknown-ts"
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
            "version": self._to_int(alert.get("rev")),
            "gid": self._to_int(alert.get("gid")),
        }

    def _build_detection(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not alert:
            return None

        severity_code = self._to_int(alert.get("severity"))

        return {
            "engine": "suricata",
            "provider": "suricata",
            "title": self._normalize_str(alert.get("signature")),
            "rule_id": self._to_int(alert.get("signature_id")),
            "severity": severity_code,
            "severity_label": self._normalize_severity(severity_code),
            "action": self._normalize_str(alert.get("action")),
            "category": self._normalize_str(alert.get("category")),
            "status": "observed",
            "gid": self._to_int(alert.get("gid")),
            "rev": self._to_int(alert.get("rev")),
        }

    def _build_dns(self, dns: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not dns:
            return None

        return {
            "id": self._to_int(dns.get("id")) or self._to_int(dns.get("tx_id")),
            "type": self._normalize_str(dns.get("type")),
            "rcode": self._normalize_str(dns.get("rcode")),
            "question": {
                "name": self._normalize_str(dns.get("rrname")),
                "type": self._normalize_str(dns.get("rrtype")),
            },
            "answers": dns.get("answers") if isinstance(dns.get("answers"), list) else None,
        }

    def _build_http(self, http: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not http:
            return None

        return {
            "request": {
                "method": self._normalize_str(http.get("http_method")),
                "referrer": self._normalize_str(http.get("http_refer")),
            },
            "response": {
                "status_code": self._to_int(http.get("status")),
                "mime_type": self._normalize_str(http.get("content_type")),
                "bytes": self._to_int(http.get("length")),
            },
            "user_agent": self._normalize_str(http.get("http_user_agent")),
            "protocol": self._normalize_str(http.get("protocol")),
        }

    def _build_url(self, http: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not http:
            return None

        hostname = self._normalize_str(http.get("hostname"))
        url = self._normalize_str(http.get("url"))

        full_url = None
        if hostname and url:
            full_url = url if url.startswith(("http://", "https://")) else f"http://{hostname}{url}"

        return {
            "original": full_url or url,
            "path": url if url and not url.startswith(("http://", "https://")) else None,
            "domain": hostname,
        }

    def _build_tls(self, tls: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tls:
            return None

        return {
            "version": self._normalize_str(tls.get("version")),
            "server": {
                "name": self._normalize_str(tls.get("sni")),
            },
            "certificate": {
                "subject": self._normalize_str(tls.get("subject")),
                "issuer": self._normalize_str(tls.get("issuerdn")),
                "serial_number": self._normalize_str(tls.get("serial")),
                "not_before": self._normalize_str(tls.get("notbefore")),
                "not_after": self._normalize_str(tls.get("notafter")),
                "fingerprint": self._normalize_str(tls.get("fingerprint")),
            },
            "ja3": self._normalize_str(tls.get("ja3")),
            "ja3s": self._normalize_str(tls.get("ja3s")),
        }

    def _build_file(self, fileinfo: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not fileinfo:
            return None

        return {
            "name": self._normalize_str(fileinfo.get("filename")),
            "size": self._to_int(fileinfo.get("size")),
            "mime_type": self._normalize_str(fileinfo.get("magic")),
            "hash": self._drop_none({
                "md5": self._normalize_str(fileinfo.get("md5")),
                "sha1": self._normalize_str(fileinfo.get("sha1")),
                "sha256": self._normalize_str(fileinfo.get("sha256")),
            }),
            "stored": fileinfo.get("stored"),
        }

    def _build_tags(self, event_type: Optional[str], alert: Dict[str, Any], app_proto: Optional[str]) -> Optional[List[str]]:
        tags = [
            "suricata",
            "network",
            event_type,
            app_proto,
            self._normalize_str(alert.get("category")),
        ]
        return self._unique_list(tags)

    def _map_event_kind(self, event_type: Optional[str]) -> str:
        return "alert" if event_type == "alert" else "event"

    def _map_event_category(self, event_type: Optional[str], alert: Dict[str, Any], anomaly: Dict[str, Any]) -> str:
        if event_type == "alert":
            category_raw = self._normalize_str(alert.get("category")) or ""
            signature = self._normalize_str(alert.get("signature")) or ""
            return self._map_alert_category(signature, category_raw)

        mapping = {
            "dns": "network_dns",
            "http": "network_http",
            "tls": "network_tls",
            "flow": "network_flow",
            "fileinfo": "network_file",
            "ssh": "network_ssh",
            "smtp": "network_email",
            "ftp": "network_file_transfer",
            "rdp": "network_remote_access",
            "dhcp": "network_dhcp",
            "ike": "network_vpn",
            "smb": "network_file_sharing",
            "mqtt": "network_messaging",
            "netflow": "network_flow",
            "stats": "telemetry",
            "anomaly": "network_anomaly",
        }
        if event_type == "anomaly" and anomaly:
            return "network_anomaly"
        return mapping.get(event_type, "network")

    def _map_alert_category(self, signature: str, category_raw: str) -> str:
        haystack = f"{signature} {category_raw}".lower()

        if "scan" in haystack:
            return "network_scan"
        if "dns" in haystack:
            return "network_dns"
        if "tls" in haystack or "ssl" in haystack:
            return "network_tls"
        if "http" in haystack or "web" in haystack:
            return "network_http"
        if "malware" in haystack:
            return "malware"
        if "exploit" in haystack:
            return "exploit_attempt"
        if "intrusion" in haystack:
            return "intrusion_detection"
        return "network_alert"

    def _infer_outcome_from_alert(self, alert: Dict[str, Any]) -> Optional[str]:
        action = self._normalize_str(alert.get("action"))
        if action == "allowed":
            return "success"
        if action in {"blocked", "drop", "rejected"}:
            return "failure"
        return None

    def _normalize_severity(self, severity: Any) -> str:
        sev = self._to_int(severity)
        mapping = {
            1: "critical",
            2: "high",
            3: "medium",
            4: "low",
        }
        return mapping.get(sev, "info")

    def _map_risk_score_from_suricata(self, severity: Any) -> Optional[int]:
        sev = self._to_int(severity)
        mapping = {
            1: 90,
            2: 75,
            3: 55,
            4: 30,
        }
        return mapping.get(sev)

    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            return str(value)

        raw = value.strip()
        if not raw:
            return None

        try:
            if raw.endswith("Z"):
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
            return datetime.fromisoformat(raw).isoformat()
        except ValueError:
            return raw

    def _normalize_ip(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        try:
            return str(ip_address(str(value).strip()))
        except ValueError:
            return self._normalize_str(value)

    def _normalize_protocol(self, value: Any) -> Optional[str]:
        normalized = self._normalize_str(value)
        return normalized.lower() if normalized else None

    def _normalize_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return str(value)

    def _normalize_float(self, value: Any) -> Optional[float]:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _to_int(self, value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _detect_network_type(self, src_ip: Optional[str], dest_ip: Optional[str]) -> Optional[str]:
        for candidate in (src_ip, dest_ip):
            if not candidate:
                continue
            try:
                return "ipv6" if ip_address(candidate).version == 6 else "ipv4"
            except ValueError:
                continue
        return None

    def _unique_list(self, values: List[Any]) -> Optional[List[Any]]:
        result = []
        for value in values:
            if value is None:
                continue
            if value not in result:
                result.append(value)
        return result or None

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _safe_get(self, dct: Dict[str, Any], *keys: str) -> Optional[Any]:
        current: Any = dct
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
            if current is None:
                return None
        return current

    def _drop_none(self, value: Any) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for key, subvalue in value.items():
                cleaned_value = self._drop_none(subvalue)
                if cleaned_value is not None:
                    cleaned[key] = cleaned_value
            return cleaned or None

        if isinstance(value, list):
            cleaned_list = []
            for item in value:
                cleaned_item = self._drop_none(item)
                if cleaned_item is not None:
                    cleaned_list.append(cleaned_item)
            return cleaned_list or None

        return value