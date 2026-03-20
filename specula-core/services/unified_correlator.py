from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class UnifiedCorrelator:
    """
    Corrèle des détections multi-sources sur une fenêtre temporelle.

    Pivot principal :
    - asset / hostname / dest_ip
    Puis rapprochement par temps, utilisateur, IP, process.

    Objectifs supplémentaires :
    - choisir un signal dominant
    - générer un titre d'incident compréhensible
    - enrichir les incidents avec catégories, engines, CVE éventuelles
    """

    def __init__(self, window_minutes: int = 30) -> None:
        self.window_minutes = window_minutes

    def _parse_dt(self, value: str | None) -> datetime | None:
        if not value:
            return None

        try:
            if value.endswith("Z"):
                value = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            if value is None or value == "":
                return default
            return int(value)
        except Exception:
            return default

    def _normalize_text(self, value: Any) -> str:
        return str(value or "").strip()

    def _normalize_text_lower(self, value: Any) -> str:
        return self._normalize_text(value).lower()

    def _asset_key(self, item: dict[str, Any]) -> str:
        return str(
            item.get("asset_id")
            or item.get("asset_name")
            or item.get("hostname")
            or item.get("dest_ip")
            or item.get("src_ip")
            or "unknown"
        ).strip().lower()

    def _compact_signal(self, item: dict[str, Any]) -> dict[str, Any]:
        cve_ids = item.get("cve_ids") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        mitre_techniques = item.get("mitre_techniques") or []
        if isinstance(mitre_techniques, str):
            mitre_techniques = [mitre_techniques]

        return {
            "id": item.get("id"),
            "timestamp": item.get("timestamp"),
            "title": item.get("title"),
            "theme": item.get("theme"),
            "category": item.get("category"),
            "severity": item.get("severity"),
            "priority": item.get("priority"),
            "risk_score": item.get("risk_score"),
            "source_engine": item.get("source_engine") or item.get("engine"),
            "asset_name": item.get("asset_name"),
            "hostname": item.get("hostname"),
            "src_ip": item.get("src_ip"),
            "src_port": item.get("src_port"),
            "dest_ip": item.get("dest_ip"),
            "dest_port": item.get("dest_port"),
            "user_name": item.get("user_name"),
            "process_name": item.get("process_name"),
            "rule_id": item.get("rule_id"),
            "description": item.get("description"),
            "summary": item.get("summary"),
            "cve_ids": cve_ids,
            "mitre_techniques": mitre_techniques,
            "file_path": item.get("file_path"),
            "package_name": item.get("package_name"),
            "package_version": item.get("package_version"),
            "cvss_score": item.get("cvss_score"),
        }

    def _signal_rank(self, item: dict[str, Any]) -> tuple[int, int, str]:
        risk_score = self._safe_int(item.get("risk_score"), 0)
        severity_value = self._severity_rank(item.get("priority") or item.get("severity"))
        timestamp = self._normalize_text(item.get("timestamp"))
        return (risk_score, severity_value, timestamp)

    def _severity_rank(self, value: Any) -> int:
        normalized = self._normalize_text_lower(value)

        if normalized in {"critical", "critique"}:
            return 5
        if normalized in {"high", "haute"}:
            return 4
        if normalized in {"medium", "moyenne"}:
            return 3
        if normalized in {"low", "basse"}:
            return 2
        if normalized in {"info", "informational"}:
            return 1

        numeric = self._safe_int(value, -1)
        if numeric >= 14:
            return 5
        if numeric >= 10:
            return 4
        if numeric >= 7:
            return 3
        if numeric >= 4:
            return 2
        if numeric >= 0:
            return 1

        return 0

    def _dominant_signal(self, bucket: list[dict[str, Any]]) -> dict[str, Any]:
        return max(bucket, key=self._signal_rank)

    def _incident_kind(self, bucket: list[dict[str, Any]]) -> str:
        themes = {
            self._normalize_text_lower(item.get("theme"))
            for item in bucket
            if item.get("theme")
        }
        engines = {
            self._normalize_text_lower(item.get("source_engine") or item.get("engine"))
            for item in bucket
            if item.get("source_engine") or item.get("engine")
        }
        categories = {
            self._normalize_text_lower(item.get("category"))
            for item in bucket
            if item.get("category")
        }

        haystack = " ".join(sorted(themes | engines | categories))

        if "vulnerability" in haystack or "cve" in haystack:
            return "vulnerability"
        if "network" in haystack or "suricata" in haystack:
            return "network"
        if any(
            token in haystack
            for token in [
                "wazuh",
                "authentication",
                "auth",
                "rootcheck",
                "file_integrity",
                "fim",
                "process",
                "sysmon",
                "malware",
                "system",
                "ossec",
            ]
        ):
            return "system"

        return "generic"

    def _extract_cve_ids(self, bucket: list[dict[str, Any]]) -> list[str]:
        cves: set[str] = set()

        for item in bucket:
            item_cves = item.get("cve_ids") or []
            if isinstance(item_cves, str):
                item_cves = [item_cves]

            for cve in item_cves:
                normalized = self._normalize_text(cve).upper()
                if normalized:
                    cves.add(normalized)

            raw = item.get("raw") or {}
            if isinstance(raw, dict):
                raw_cves = (
                    raw.get("cve_ids")
                    or raw.get("cves")
                    or raw.get("vulnerability", {}).get("cve")
                    if isinstance(raw.get("vulnerability"), dict)
                    else None
                )

                if isinstance(raw_cves, str):
                    raw_cves = [raw_cves]

                if isinstance(raw_cves, list):
                    for cve in raw_cves:
                        normalized = self._normalize_text(cve).upper()
                        if normalized:
                            cves.add(normalized)

        return sorted(cves)

    def _main_user(self, bucket: list[dict[str, Any]]) -> str | None:
        counter: dict[str, int] = {}

        for item in bucket:
            user_name = self._normalize_text(item.get("user_name"))
            if not user_name:
                continue
            counter[user_name] = counter.get(user_name, 0) + 1

        if not counter:
            return None

        return max(counter.items(), key=lambda entry: entry[1])[0]

    def _main_process(self, bucket: list[dict[str, Any]]) -> str | None:
        counter: dict[str, int] = {}

        for item in bucket:
            process_name = self._normalize_text(item.get("process_name"))
            if not process_name:
                continue
            counter[process_name] = counter.get(process_name, 0) + 1

        if not counter:
            return None

        return max(counter.items(), key=lambda entry: entry[1])[0]

    def _main_file_path(self, bucket: list[dict[str, Any]]) -> str | None:
        counter: dict[str, int] = {}

        for item in bucket:
            file_path = self._normalize_text(item.get("file_path"))
            if not file_path:
                continue
            counter[file_path] = counter.get(file_path, 0) + 1

        if not counter:
            return None

        return max(counter.items(), key=lambda entry: entry[1])[0]

    def _main_package(self, bucket: list[dict[str, Any]]) -> str | None:
        counter: dict[str, int] = {}

        for item in bucket:
            package_name = self._normalize_text(item.get("package_name"))
            if not package_name:
                continue
            counter[package_name] = counter.get(package_name, 0) + 1

        if not counter:
            return None

        return max(counter.items(), key=lambda entry: entry[1])[0]

    def _build_incident_title(
        self,
        bucket: list[dict[str, Any]],
        dominant: dict[str, Any],
        asset_name: str,
        incident_kind: str,
        cve_ids: list[str],
    ) -> str:
        category = self._normalize_text_lower(dominant.get("category"))
        title = self._normalize_text(dominant.get("title"))
        engine = self._normalize_text_lower(
            dominant.get("source_engine") or dominant.get("engine")
        )
        main_user = self._main_user(bucket)
        main_process = self._main_process(bucket)
        main_file = self._main_file_path(bucket)
        main_package = self._main_package(bucket)

        if cve_ids:
            if len(cve_ids) == 1:
                return f"Vulnérabilité {cve_ids[0]} détectée sur {asset_name}"
            return f"Vulnérabilités détectées sur {asset_name}"

        if "authentication" in category or "auth" in category:
            if main_user:
                return f"Échecs d’authentification pour {main_user} sur {asset_name}"
            return f"Échecs d’authentification sur {asset_name}"

        if "rootcheck" in category:
            if main_file:
                return f"Anomalie rootcheck sur {main_file} ({asset_name})"
            return f"Anomalie rootcheck sur {asset_name}"

        if "file_integrity" in category or "fim" in category:
            if main_file:
                return f"Modification de fichier sensible sur {asset_name}"
            return f"Activité FIM sur {asset_name}"

        if "process" in category or "process_activity" in category or "sysmon" in category:
            if main_process:
                return f"Activité processus suspecte sur {asset_name}"
            return f"Activité processus sur {asset_name}"

        if "malware" in category:
            return f"Suspicion de malware sur {asset_name}"

        if "vulnerability" in category:
            if main_package:
                return f"Paquet vulnérable détecté sur {asset_name}"
            return f"Vulnérabilité détectée sur {asset_name}"

        if incident_kind == "network":
            if title:
                lowered = title.lower()
                if "http" in lowered:
                    return f"Trafic HTTP suspect vers {asset_name}"
                if "dns" in lowered:
                    return f"Activité DNS suspecte sur {asset_name}"
                if "tls" in lowered or "ssl" in lowered:
                    return f"Activité TLS suspecte sur {asset_name}"
                if "scan" in lowered:
                    return f"Scan réseau détecté sur {asset_name}"
                if "intrusion" in lowered:
                    return f"Détection intrusion réseau sur {asset_name}"
            return f"Activité réseau suspecte sur {asset_name}"

        if engine == "wazuh":
            if title:
                return f"{title} ({asset_name})"
            return f"Incident système sur {asset_name}"

        if title:
            return f"{title} sur {asset_name}"

        return f"Incident corrélé sur {asset_name}"

    def _build_incident_description(
        self,
        bucket: list[dict[str, Any]],
        asset_name: str,
        first_ts: str | None,
        last_ts: str | None,
        incident_kind: str,
        dominant: dict[str, Any],
        cve_ids: list[str],
    ) -> str:
        count = len(bucket)
        category = self._normalize_text(dominant.get("category")) or "unknown"

        if cve_ids:
            if len(cve_ids) == 1:
                return (
                    f"{count} signal(s) corrélés sur {asset_name} autour de la vulnérabilité "
                    f"{cve_ids[0]} entre {first_ts} et {last_ts}."
                )
            return (
                f"{count} signal(s) corrélés sur {asset_name} liés à plusieurs vulnérabilités "
                f"entre {first_ts} et {last_ts}."
            )

        if incident_kind == "network":
            return (
                f"{count} signal(s) réseau corrélés sur {asset_name} "
                f"({category}) entre {first_ts} et {last_ts}."
            )

        if incident_kind == "system":
            return (
                f"{count} signal(s) système corrélés sur {asset_name} "
                f"({category}) entre {first_ts} et {last_ts}."
            )

        return (
            f"{count} signal(s) corrélés sur {asset_name} "
            f"entre {first_ts} et {last_ts}."
        )

    def _compute_risk_score(self, bucket: list[dict[str, Any]]) -> int:
        max_signal_score = max(self._safe_int(item.get("risk_score"), 0) for item in bucket)
        max_severity_score = max(self._severity_rank(item.get("priority") or item.get("severity")) for item in bucket)

        severity_bonus = {
            5: 35,
            4: 25,
            3: 15,
            2: 8,
            1: 3,
            0: 0,
        }.get(max_severity_score, 0)

        volume_bonus = min(max(len(bucket) - 1, 0) * 3, 24)

        return min(100, max(max_signal_score, severity_bonus) + volume_bonus)

    def _priority_from_score(self, risk_score: int) -> str:
        if risk_score >= 75:
            return "critical"
        if risk_score >= 50:
            return "high"
        if risk_score >= 20:
            return "medium"
        if risk_score >= 5:
            return "low"
        return "info"

    def correlate(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sorted_items = sorted(
            detections,
            key=lambda item: self._parse_dt(item.get("timestamp"))
            or datetime.min.replace(tzinfo=timezone.utc),
        )

        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in sorted_items:
            grouped.setdefault(self._asset_key(item), []).append(item)

        incidents: list[dict[str, Any]] = []

        for asset_key, asset_items in grouped.items():
            buckets: list[list[dict[str, Any]]] = []

            for item in asset_items:
                item_dt = self._parse_dt(item.get("timestamp")) or datetime.min.replace(
                    tzinfo=timezone.utc
                )

                placed = False
                for bucket in buckets:
                    last_dt = self._parse_dt(bucket[-1].get("timestamp")) or datetime.min.replace(
                        tzinfo=timezone.utc
                    )

                    same_user = (
                        self._normalize_text_lower(item.get("user_name"))
                        and self._normalize_text_lower(item.get("user_name"))
                        == self._normalize_text_lower(bucket[-1].get("user_name"))
                    )

                    same_process = (
                        self._normalize_text_lower(item.get("process_name"))
                        and self._normalize_text_lower(item.get("process_name"))
                        == self._normalize_text_lower(bucket[-1].get("process_name"))
                    )

                    same_category = (
                        self._normalize_text_lower(item.get("category"))
                        == self._normalize_text_lower(bucket[-1].get("category"))
                    )

                    close_in_time = abs(item_dt - last_dt) <= timedelta(minutes=self.window_minutes)

                    if close_in_time and (same_category or same_user or same_process or not bucket):
                        bucket.append(item)
                        placed = True
                        break

                if not placed:
                    buckets.append([item])

            for bucket in buckets:
                dominant = self._dominant_signal(bucket)
                signals = [self._compact_signal(x) for x in bucket]

                first_ts = bucket[0].get("timestamp")
                last_ts = bucket[-1].get("timestamp")

                themes = sorted(
                    {self._normalize_text(x.get("theme") or "unknown") for x in bucket}
                )
                engines = sorted(
                    {
                        self._normalize_text(
                            x.get("source_engine") or x.get("engine") or "unknown"
                        )
                        for x in bucket
                    }
                )
                categories = sorted(
                    {self._normalize_text(x.get("category") or "unknown") for x in bucket}
                )

                cve_ids = self._extract_cve_ids(bucket)
                incident_kind = self._incident_kind(bucket)

                risk_score = self._compute_risk_score(bucket)
                priority = self._priority_from_score(risk_score)

                asset_name = self._normalize_text(bucket[0].get("asset_name")) or asset_key

                title = self._build_incident_title(
                    bucket=bucket,
                    dominant=dominant,
                    asset_name=asset_name,
                    incident_kind=incident_kind,
                    cve_ids=cve_ids,
                )

                description = self._build_incident_description(
                    bucket=bucket,
                    asset_name=asset_name,
                    first_ts=first_ts,
                    last_ts=last_ts,
                    incident_kind=incident_kind,
                    dominant=dominant,
                    cve_ids=cve_ids,
                )

                incidents.append(
                    {
                        "id": f"incident:{asset_key}:{first_ts}:{len(bucket)}",
                        "title": title,
                        "description": description,
                        "type": "incident",
                        "incident_kind": incident_kind,
                        "status": "open",
                        "asset_name": asset_name,
                        "hostname": bucket[0].get("hostname"),
                        "timestamp": first_ts,
                        "created_at": first_ts,
                        "updated_at": last_ts,
                        "first_seen": first_ts,
                        "last_seen": last_ts,
                        "risk_score": risk_score,
                        "priority": priority,
                        "severity": priority,
                        "themes": themes,
                        "engines": engines,
                        "categories": categories,
                        "signals_count": len(bucket),
                        "signals": signals,
                        "source": "specula",
                        "dominant_signal_title": dominant.get("title"),
                        "dominant_category": dominant.get("category"),
                        "dominant_engine": dominant.get("source_engine") or dominant.get("engine"),
                        "user_name": self._main_user(bucket),
                        "process_name": self._main_process(bucket),
                        "cve_ids": cve_ids,
                    }
                )

        incidents.sort(
            key=lambda x: (
                self._safe_int(x.get("risk_score"), 0),
                self._normalize_text(x.get("updated_at")),
            ),
            reverse=True,
        )

        return incidents