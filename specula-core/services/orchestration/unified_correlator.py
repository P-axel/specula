from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.policy.incident_policy import is_incident_candidate


class UnifiedCorrelator:
    """
    Corrèle des détections multi-sources sur une fenêtre temporelle.

    Objectif :
    - ne garder que les signaux éligibles à un incident SOC
    - regrouper les signaux proches selon plusieurs dimensions
    - produire des incidents lisibles, priorisés et exploitables
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
            if value in (None, ""):
                return default
            return int(value)
        except Exception:
            return default

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        try:
            if value in (None, ""):
                return default
            return float(value)
        except Exception:
            return default

    def _normalize_text(self, value: Any) -> str:
        return str(value or "").strip()

    def _normalize_text_lower(self, value: Any) -> str:
        return self._normalize_text(value).lower()

    def _dedupe_list(self, values: list[Any]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        for value in values:
            normalized = self._normalize_text(value)
            if not normalized:
                continue
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            result.append(normalized)

        return result

    def _first_non_empty(self, bucket: list[dict[str, Any]], *fields: str) -> str | None:
        for item in bucket:
            for field in fields:
                value = self._normalize_text(item.get(field))
                if value:
                    return value
        return None

    def _asset_key(self, item: dict[str, Any]) -> str:
        return self._normalize_text_lower(
            item.get("asset_id")
            or item.get("asset_name")
            or item.get("hostname")
            or item.get("agent_name")
            or item.get("host")
            or item.get("dest_ip")
            or item.get("src_ip")
            or "unknown"
        )

    def _primary_asset_name(self, bucket: list[dict[str, Any]], fallback: str) -> str:
        return (
            self._first_non_empty(
                bucket,
                "asset_name",
                "hostname",
                "agent_name",
                "host",
                "asset_id",
            )
            or fallback
        )

    def _primary_hostname(self, bucket: list[dict[str, Any]], fallback: str | None = None) -> str | None:
        return self._first_non_empty(
            bucket,
            "hostname",
            "host",
            "asset_name",
            "agent_name",
            "asset_id",
        ) or fallback

    def _primary_agent_name(self, bucket: list[dict[str, Any]], fallback: str | None = None) -> str | None:
        return self._first_non_empty(
            bucket,
            "agent_name",
            "hostname",
            "host",
            "asset_name",
            "asset_id",
        ) or fallback

    def _primary_agent_id(self, bucket: list[dict[str, Any]]) -> str | None:
        return self._first_non_empty(bucket, "agent_id", "asset_id")

    def _primary_ip(self, bucket: list[dict[str, Any]], field: str) -> str | None:
        return self._first_non_empty(bucket, field)

    def _severity_rank(self, value: Any) -> int:
        normalized = self._normalize_text_lower(value)
        mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        if normalized in mapping:
            return mapping[normalized]

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

    def _signal_rank(self, item: dict[str, Any]) -> tuple[int, int, str]:
        return (
            self._safe_int(item.get("risk_score"), 0),
            self._severity_rank(item.get("priority") or item.get("severity")),
            self._normalize_text(item.get("timestamp") or item.get("created_at")),
        )

    def _dominant_signal(self, bucket: list[dict[str, Any]]) -> dict[str, Any]:
        return max(bucket, key=self._signal_rank)

    def _incident_domain(self, bucket: list[dict[str, Any]]) -> str:
        categories = {
            self._normalize_text_lower(item.get("category"))
            for item in bucket
            if item.get("category")
        }
        themes = {
            self._normalize_text_lower(item.get("theme"))
            for item in bucket
            if item.get("theme")
        }
        engines = {
            self._normalize_text_lower(
                item.get("source_engine") or item.get("engine") or item.get("provider")
            )
            for item in bucket
            if item.get("source_engine") or item.get("engine") or item.get("provider")
        }

        haystack = " ".join(sorted(categories | themes | engines))

        if any(token in haystack for token in ["network", "dns", "tls", "http", "scan", "suricata"]):
            return "network"
        if any(token in haystack for token in ["identity", "auth", "login", "bruteforce"]):
            return "identity"
        if "vulnerability" in haystack or "cve" in haystack:
            return "vulnerability"
        if any(
            token in haystack
            for token in ["malware", "rootcheck", "process", "host", "system", "fim", "wazuh"]
        ):
            return "system"

        return "generic"

    def _compute_risk_score(self, bucket: list[dict[str, Any]]) -> int:
        max_score = max(self._safe_int(item.get("risk_score"), 0) for item in bucket)
        max_severity = max(
            self._severity_rank(item.get("priority") or item.get("severity"))
            for item in bucket
        )

        severity_bonus = {
            5: 20,
            4: 15,
            3: 8,
            2: 3,
            1: 0,
            0: 0,
        }.get(max_severity, 0)

        volume_bonus = min(max(len(bucket) - 1, 0) * 4, 20)

        diversity_sources = len(
            {
                self._normalize_text_lower(
                    item.get("source_engine") or item.get("engine") or item.get("provider")
                )
                for item in bucket
                if item.get("source_engine") or item.get("engine") or item.get("provider")
            }
        )
        diversity_bonus = min(max(diversity_sources - 1, 0) * 5, 10)

        return min(100, max_score + severity_bonus + volume_bonus + diversity_bonus)

    def _priority_from_score(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 10:
            return "low"
        return "info"

    def _compute_confidence(self, bucket: list[dict[str, Any]]) -> float:
        values = [
            self._safe_float(item.get("confidence"), 0.0)
            for item in bucket
            if item.get("confidence") is not None
        ]
        if not values:
            return 0.5
        return round(sum(values) / len(values), 2)

    def _main_user(self, bucket: list[dict[str, Any]]) -> str | None:
        counts: dict[str, int] = {}

        for item in bucket:
            user_name = self._normalize_text(
                item.get("user_name") or item.get("user") or item.get("username")
            )
            if not user_name:
                continue
            counts[user_name] = counts.get(user_name, 0) + 1

        if not counts:
            return None

        return max(counts.items(), key=lambda x: x[1])[0]

    def _normalize_process_display(self, value: Any) -> str | None:
        process_name = self._normalize_text(value)
        if not process_name:
            return None

        lowered = process_name.lower()

        aliases = {
            "nc": "NC",
            "cmd": "CMD",
            "sh": "SH",
            "bash": "BASH",
            "pwsh": "PWSH",
            "powershell": "PowerShell",
        }

        if lowered in aliases:
            return aliases[lowered]

        return process_name

    def _main_process(self, bucket: list[dict[str, Any]]) -> str | None:
        counts: dict[str, int] = {}

        for item in bucket:
            process_name = self._normalize_process_display(
                item.get("process_name") or item.get("process")
            )
            if not process_name:
                continue
            counts[process_name] = counts.get(process_name, 0) + 1

        if not counts:
            return None

        return max(counts.items(), key=lambda x: x[1])[0]

    def _main_category(self, bucket: list[dict[str, Any]]) -> str | None:
        counts: dict[str, int] = {}

        for item in bucket:
            category = self._normalize_text(item.get("category"))
            if not category:
                continue
            counts[category] = counts.get(category, 0) + 1

        if not counts:
            return None

        return max(counts.items(), key=lambda x: x[1])[0]

    def _main_kind(self, bucket: list[dict[str, Any]], domain: str) -> str:
        for item in bucket:
            kind = self._normalize_text_lower(item.get("kind"))
            if kind:
                return kind
        return domain if domain != "generic" else "correlated"

    def _build_title(
        self,
        bucket: list[dict[str, Any]],
        dominant: dict[str, Any],
        asset_name: str,
        domain: str,
    ) -> str:
        title = self._normalize_text(dominant.get("title") or dominant.get("name"))
        category = self._normalize_text_lower(dominant.get("category"))

        if domain == "network":
            if "scan" in category:
                return f"Reconnaissance réseau sur {asset_name}"
            if "dns" in category:
                return f"Activité DNS suspecte sur {asset_name}"
            if "tls" in category:
                return f"Activité TLS suspecte sur {asset_name}"
            if title:
                return f"{title} ({asset_name})"
            return f"Incident réseau sur {asset_name}"

        if domain == "identity":
            user_name = self._main_user(bucket)
            if user_name:
                return f"Activité d’identité suspecte pour {user_name} sur {asset_name}"
            return f"Activité d’identité suspecte sur {asset_name}"

        if domain == "vulnerability":
            return f"Vulnérabilité à investiguer sur {asset_name}"

        if domain == "system":
            process_name = self._main_process(bucket)
            if process_name:
                return f"Activité système suspecte ({process_name}) sur {asset_name}"
            if title:
                return f"{title} ({asset_name})"
            return f"Incident système sur {asset_name}"

        if title:
            return f"{title} ({asset_name})"

        return f"Incident de sécurité sur {asset_name}"

    def _build_description(
        self,
        bucket: list[dict[str, Any]],
        asset_name: str,
        first_ts: str | None,
        last_ts: str | None,
        domain: str,
    ) -> str:
        count = len(bucket)

        if domain == "network":
            return f"{count} signal(s) réseau corrélés sur {asset_name} entre {first_ts} et {last_ts}."

        if domain == "system":
            return f"{count} signal(s) système corrélés sur {asset_name} entre {first_ts} et {last_ts}."

        if domain == "identity":
            return f"{count} signal(s) liés à l’identité corrélés sur {asset_name} entre {first_ts} et {last_ts}."

        if domain == "vulnerability":
            return f"{count} signal(s) de vulnérabilité corrélés sur {asset_name} entre {first_ts} et {last_ts}."

        return f"{count} signal(s) corrélés sur {asset_name} entre {first_ts} et {last_ts}."

    def _build_why_it_matters(self, bucket: list[dict[str, Any]], domain: str) -> str:
        categories = {
            self._normalize_text_lower(item.get("category"))
            for item in bucket
            if item.get("category")
        }

        if domain == "network":
            if any("scan" in category for category in categories):
                return "L’activité observée évoque une reconnaissance réseau pouvant précéder une attaque."
            if any("dns" in category for category in categories):
                return "Le trafic DNS corrélé peut refléter un comportement anormal ou préparatoire."
            if any("tls" in category for category in categories):
                return "Le trafic TLS corrélé peut cacher une communication anormale ou malveillante."
            return "La corrélation réseau met en évidence une activité à qualifier rapidement."

        if domain == "system":
            return "Plusieurs signaux système convergent vers un risque de compromission, d’abus ou de dégradation."

        if domain == "identity":
            return "Les signaux d’identité peuvent indiquer une tentative d’accès non légitime ou un abus de privilèges."

        if domain == "vulnerability":
            return "Le contexte suggère une exposition vulnérable nécessitant validation et priorisation."

        return "La corrélation de plusieurs signaux justifie une investigation analyste."

    def _build_recommended_actions(
        self, bucket: list[dict[str, Any]], domain: str
    ) -> list[str]:
        if domain == "network":
            return [
                "Vérifier la légitimité de la source et de la destination",
                "Contrôler les journaux firewall, DNS ou proxy associés",
                "Qualifier si l’activité est attendue ou malveillante",
            ]

        if domain == "system":
            return [
                "Analyser les journaux système et les processus associés",
                "Vérifier l’intégrité de l’hôte et les changements récents",
                "Isoler l’actif si des signes de compromission se confirment",
            ]

        if domain == "identity":
            return [
                "Vérifier les journaux d’authentification et les comptes impliqués",
                "Confirmer la légitimité de l’utilisateur et du contexte d’accès",
                "Réinitialiser ou protéger le compte si nécessaire",
            ]

        if domain == "vulnerability":
            return [
                "Valider la vulnérabilité et son périmètre réel",
                "Prioriser le correctif selon l’exposition et la criticité",
                "Rechercher des signes d’exploitation associée",
            ]

        return [
            "Analyser les événements corrélés",
            "Qualifier le niveau de risque réel",
            "Documenter la suite d’investigation",
        ]

    def _compact_signal(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": item.get("id"),
            "timestamp": item.get("timestamp"),
            "title": item.get("title") or item.get("name"),
            "category": item.get("category"),
            "theme": item.get("theme"),
            "severity": item.get("severity"),
            "priority": item.get("priority"),
            "risk_score": item.get("risk_score"),
            "source_engine": item.get("source_engine") or item.get("engine") or item.get("provider"),
            "asset_name": item.get("asset_name"),
            "hostname": item.get("hostname"),
            "agent_name": item.get("agent_name"),
            "agent_id": item.get("agent_id"),
            "src_ip": item.get("src_ip"),
            "dest_ip": item.get("dest_ip"),
            "user_name": item.get("user_name") or item.get("user"),
            "process_name": self._normalize_process_display(
                item.get("process_name") or item.get("process")
            ),
            "rule_id": item.get("rule_id"),
            "description": item.get("description"),
            "summary": item.get("summary"),
        }

    def _timeline_entry(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": item.get("timestamp"),
            "title": item.get("title") or item.get("name") or "Signal",
            "category": item.get("category"),
            "severity": item.get("severity") or item.get("priority"),
            "source_engine": item.get("source_engine") or item.get("engine") or item.get("provider"),
            "user_name": item.get("user_name") or item.get("user"),
            "process_name": self._normalize_process_display(
                item.get("process_name") or item.get("process")
            ),
            "src_ip": item.get("src_ip"),
            "dest_ip": item.get("dest_ip"),
        }

    def _collect_engines(self, bucket: list[dict[str, Any]]) -> list[str]:
        return self._dedupe_list(
            [
                item.get("source_engine") or item.get("engine") or item.get("provider")
                for item in bucket
            ]
        )

    def _collect_themes(self, bucket: list[dict[str, Any]]) -> list[str]:
        return self._dedupe_list([item.get("theme") for item in bucket])

    def _collect_categories(self, bucket: list[dict[str, Any]]) -> list[str]:
        return self._dedupe_list([item.get("category") for item in bucket])

    def _collect_cves(self, bucket: list[dict[str, Any]]) -> list[str]:
        cves: list[str] = []

        for item in bucket:
            value = item.get("cves") or item.get("cve") or []
            if isinstance(value, list):
                cves.extend([self._normalize_text(x) for x in value if self._normalize_text(x)])
            else:
                single = self._normalize_text(value)
                if single:
                    cves.append(single)

        return self._dedupe_list(cves)

    def _collect_mitre(self, bucket: list[dict[str, Any]]) -> list[str]:
        techniques: list[str] = []

        for item in bucket:
            value = item.get("mitre_techniques") or item.get("mitre") or []
            if isinstance(value, list):
                techniques.extend([self._normalize_text(x) for x in value if self._normalize_text(x)])
            else:
                single = self._normalize_text(value)
                if single:
                    techniques.append(single)

        return self._dedupe_list(techniques)

    def _same_context(self, current: dict[str, Any], reference: dict[str, Any]) -> bool:
        strong_pairs = [
            (
                self._normalize_text_lower(current.get("user_name") or current.get("user")),
                self._normalize_text_lower(reference.get("user_name") or reference.get("user")),
            ),
            (
                self._normalize_text_lower(current.get("process_name") or current.get("process")),
                self._normalize_text_lower(reference.get("process_name") or reference.get("process")),
            ),
            (
                self._normalize_text_lower(current.get("rule_id")),
                self._normalize_text_lower(reference.get("rule_id")),
            ),
            (
                self._normalize_text_lower(current.get("src_ip")),
                self._normalize_text_lower(reference.get("src_ip")),
            ),
            (
                self._normalize_text_lower(current.get("dest_ip")),
                self._normalize_text_lower(reference.get("dest_ip")),
            ),
        ]

        weak_pairs = [
            (
                self._normalize_text_lower(current.get("category")),
                self._normalize_text_lower(reference.get("category")),
            ),
            (
                self._normalize_text_lower(current.get("theme")),
                self._normalize_text_lower(reference.get("theme")),
            ),
            (
                self._normalize_text_lower(
                    current.get("source_engine") or current.get("engine") or current.get("provider")
                ),
                self._normalize_text_lower(
                    reference.get("source_engine") or reference.get("engine") or reference.get("provider")
                ),
            ),
        ]

        strong_matches = sum(1 for left, right in strong_pairs if left and left == right)
        weak_matches = sum(1 for left, right in weak_pairs if left and left == right)

        return strong_matches >= 1 or (strong_matches + weak_matches) >= 2

    def _dedupe_timeline(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str, str, str, str]] = set()
        result: list[dict[str, Any]] = []

        for entry in entries:
            key = (
                self._normalize_text(entry.get("timestamp")),
                self._normalize_text_lower(entry.get("title")),
                self._normalize_text_lower(entry.get("category")),
                self._normalize_text_lower(entry.get("source_engine")),
                self._normalize_text_lower(entry.get("user_name")),
                self._normalize_text_lower(entry.get("process_name")),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(entry)

        return result

    def _dedupe_signals(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str, str, str, str]] = set()
        result: list[dict[str, Any]] = []

        for signal in signals:
            key = (
                self._normalize_text(signal.get("id")),
                self._normalize_text(signal.get("timestamp")),
                self._normalize_text_lower(signal.get("title")),
                self._normalize_text_lower(signal.get("category")),
                self._normalize_text_lower(signal.get("user_name")),
                self._normalize_text_lower(signal.get("process_name")),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(signal)

        return result

    def correlate(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []

        for item in detections:
            if not isinstance(item, dict):
                continue

            timestamp = item.get("timestamp") or item.get("created_at")
            if not timestamp:
                continue

            if not is_incident_candidate(item):
                continue

            if not any(
                [
                    item.get("title"),
                    item.get("name"),
                    item.get("category"),
                    item.get("severity"),
                    item.get("asset_name"),
                    item.get("src_ip"),
                    item.get("dest_ip"),
                ]
            ):
                continue

            normalized = dict(item)
            normalized["timestamp"] = timestamp
            filtered.append(normalized)

        sorted_items = sorted(
            filtered,
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
                    reference = bucket[-1]
                    last_dt = self._parse_dt(reference.get("timestamp")) or datetime.min.replace(
                        tzinfo=timezone.utc
                    )

                    close_in_time = abs(item_dt - last_dt) <= timedelta(minutes=self.window_minutes)
                    same_context = self._same_context(item, reference)

                    if close_in_time and same_context:
                        bucket.append(item)
                        placed = True
                        break

                if not placed:
                    buckets.append([item])

            for bucket in buckets:
                dominant = self._dominant_signal(bucket)
                first_ts = bucket[0].get("timestamp")
                last_ts = bucket[-1].get("timestamp")
                asset_name = self._primary_asset_name(bucket, fallback=asset_key)
                hostname = self._primary_hostname(bucket, fallback=asset_name)
                agent_name = self._primary_agent_name(bucket, fallback=hostname or asset_name)
                agent_id = self._primary_agent_id(bucket)
                domain = self._incident_domain(bucket)
                risk_score = self._compute_risk_score(bucket)
                priority = self._priority_from_score(risk_score)
                confidence = self._compute_confidence(bucket)
                engines = self._collect_engines(bucket)
                themes = self._collect_themes(bucket)
                categories = self._collect_categories(bucket)
                cves = self._collect_cves(bucket)
                mitre = self._collect_mitre(bucket)
                user_name = self._main_user(bucket)
                process_name = self._main_process(bucket)
                dominant_engine = (
                    dominant.get("source_engine")
                    or dominant.get("engine")
                    or dominant.get("provider")
                    or (engines[0] if engines else None)
                )
                src_ip = dominant.get("src_ip") or self._primary_ip(bucket, "src_ip")
                dest_ip = dominant.get("dest_ip") or self._primary_ip(bucket, "dest_ip")

                signals = self._dedupe_signals([self._compact_signal(x) for x in bucket])
                timeline = self._dedupe_timeline([self._timeline_entry(x) for x in bucket])

                incidents.append(
                    {
                        "id": f"incident:{asset_key}:{first_ts}:{len(bucket)}",
                        "title": self._build_title(
                            bucket=bucket,
                            dominant=dominant,
                            asset_name=asset_name,
                            domain=domain,
                        ),
                        "name": self._build_title(
                            bucket=bucket,
                            dominant=dominant,
                            asset_name=asset_name,
                            domain=domain,
                        ),
                        "description": self._build_description(
                            bucket=bucket,
                            asset_name=asset_name,
                            first_ts=first_ts,
                            last_ts=last_ts,
                            domain=domain,
                        ),
                        "incident_domain": domain,
                        "kind": self._main_kind(bucket, domain),
                        "type": "incident",
                        "status": "open",
                        "asset_name": asset_name,
                        "hostname": hostname,
                        "agent_name": agent_name,
                        "agent_id": agent_id,
                        "timestamp": first_ts,
                        "created_at": first_ts,
                        "updated_at": last_ts,
                        "first_seen": first_ts,
                        "last_seen": last_ts,
                        "risk_score": risk_score,
                        "priority": priority,
                        "severity": priority,
                        "confidence": confidence,
                        "detections_count": len(signals),
                        "signals_count": len(signals),
                        "signals": signals,
                        "timeline": timeline,
                        "source": "correlated",
                        "why_it_matters": self._build_why_it_matters(bucket, domain),
                        "recommended_actions": self._build_recommended_actions(bucket, domain),
                        "dominant_signal_title": dominant.get("title") or dominant.get("name"),
                        "dominant_category": dominant.get("category"),
                        "dominant_engine": dominant_engine,
                        "engines": [x.lower() for x in engines],
                        "themes": [x.lower() for x in themes],
                        "categories": [x.lower() for x in categories],
                        "category": self._main_category(bucket),
                        "user_name": user_name,
                        "process_name": process_name,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "cves": cves,
                        "mitre_techniques": mitre,
                    }
                )

        incidents.sort(
            key=lambda item: (
                self._safe_int(item.get("risk_score"), 0),
                self._normalize_text(item.get("updated_at")),
            ),
            reverse=True,
        )

        return incidents