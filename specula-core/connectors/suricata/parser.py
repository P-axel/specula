from __future__ import annotations

from typing import Any


class SuricataParser:
    SUPPORTED_TYPES = {
        "alert",
        "flow",
        "dns",
        "http",
        "tls",
        "anomaly",
    }

    @classmethod
    def parse(cls, raw_event: dict[str, Any]) -> dict[str, Any] | None:
        event_type = raw_event.get("event_type")
        if event_type not in cls.SUPPORTED_TYPES:
            return None

        parsed = {
            "timestamp": raw_event.get("timestamp"),
            "event_type": event_type,
            "src_ip": raw_event.get("src_ip"),
            "dest_ip": raw_event.get("dest_ip"),
            "src_port": raw_event.get("src_port"),
            "dest_port": raw_event.get("dest_port"),
            "proto": raw_event.get("proto"),
            "app_proto": raw_event.get("app_proto"),
            "flow_id": raw_event.get("flow_id"),
            "in_iface": raw_event.get("in_iface"),
            "host": raw_event.get("host"),
            "raw": raw_event,
        }

        if event_type == "alert":
            alert = raw_event.get("alert", {}) or {}
            parsed["alert"] = {
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
            }

        elif event_type == "dns":
            dns = raw_event.get("dns", {}) or {}
            parsed["dns"] = {
                "type": dns.get("type"),
                "rrname": dns.get("rrname"),
                "rcode": dns.get("rcode"),
            }

        elif event_type == "http":
            http = raw_event.get("http", {}) or {}
            parsed["http"] = {
                "hostname": http.get("hostname"),
                "url": http.get("url"),
                "http_method": http.get("http_method"),
                "status": http.get("status"),
                "user_agent": http.get("http_user_agent"),
            }

        elif event_type == "tls":
            tls = raw_event.get("tls", {}) or {}
            parsed["tls"] = {
                "subject": tls.get("subject"),
                "issuerdn": tls.get("issuerdn"),
                "sni": tls.get("sni"),
                "version": tls.get("version"),
            }

        elif event_type == "flow":
            flow = raw_event.get("flow", {}) or {}
            parsed["flow"] = {
                "pkts_toserver": flow.get("pkts_toserver"),
                "pkts_toclient": flow.get("pkts_toclient"),
                "bytes_toserver": flow.get("bytes_toserver"),
                "bytes_toclient": flow.get("bytes_toclient"),
                "state": flow.get("state"),
            }

        elif event_type == "anomaly":
            anomaly = raw_event.get("anomaly", {}) or {}
            parsed["anomaly"] = {
                "type": anomaly.get("type"),
                "event": anomaly.get("event"),
                "layer": anomaly.get("layer"),
            }

        return parsed