from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.policy.incident_policy import is_incident_candidate


class UnifiedCorrelator:
    """
    Corrèle des détections multi-sources sur une fenêtre temporelle.

    Objectif :
    - ne garder que les signaux éligibles à un incident SOC
    - regrouper les signaux proches sur le même actif
    - produire des incidents lisibles et exploitables
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

    def _asset_key(self, item: dict[str, Any]) -> str:
        return str(
            item.get("asset_id")
            or item.get("asset_name")
            or item.get("hostname")
            or item.get("dest_ip")
            or item.get("src_ip")
            or "unknown"
        ).strip().lower()

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

        haystack = " ".join(sorted(categories | themes))

        if any(token in haystack for token in ["network", "dns", "tls", "http", "scan", "suricata"]):
            return "network"
        if any(token in haystack for token in ["identity", "auth", "login", "bruteforce"]):
            return "identity"
        if "vulnerability" in haystack or "cve" in haystack:
            return "vulnerability"
        if any(token in haystack for token in ["malware", "rootcheck", "process", "host", "system", "fim"]):
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

        volume_bonus = min(max(len(bucket) - 1, 0) * 3, 15)

        return min(100, max_score + severity_bonus + volume_bonus)

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
            user_name = self._normalize_text(item.get("user_name"))
            if not user_name:
                continue
            counts[user_name] = counts.get(user_name, 0) + 1

        if not counts:
            return None

        return max(counts.items(), key=lambda x: x[1])[0]

    def _main_process(self, bucket: list[dict[str, Any]]) -> str | None:
        counts: dict[str, int] = {}

        for item in bucket:
            process_name = self._normalize_text(item.get("process_name"))
            if not process_name:
                continue
            counts[process_name] = counts.get(process_name, 0) + 1

        if not counts:
            return None

        return max(counts.items(), key=lambda x: x[1])[0]

    def _build_title(
        self,
        bucket: list[dict[str, Any]],
        dominant: dict[str, Any],
        asset_name: str,
        domain: str,
    ) -> str:
        title = self._normalize_text(dominant.get("title"))
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
            return (
                f"{count} signal(s) réseau corrélés sur {asset_name} "
                f"entre {first_ts} et {last_ts}."
            )

        if domain == "system":
            return (
                f"{count} signal(s) système corrélés sur {asset_name} "
                f"entre {first_ts} et {last_ts}."
            )

        if domain == "identity":
            return (
                f"{count} signal(s) liés à l’identité corrélés sur {asset_name} "
                f"entre {first_ts} et {last_ts}."
            )

        if domain == "vulnerability":
            return (
                f"{count} signal(s) de vulnérabilité corrélés sur {asset_name} "
                f"entre {first_ts} et {last_ts}."
            )

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

    def _build_recommended_actions(self, bucket: list[dict[str, Any]], domain: str) -> list[str]:
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
            "title": item.get("title"),
            "category": item.get("category"),
            "severity": item.get("severity"),
            "priority": item.get("priority"),
            "risk_score": item.get("risk_score"),
            "source_engine": item.get("source_engine") or item.get("engine"),
            "asset_name": item.get("asset_name"),
            "hostname": item.get("hostname"),
            "src_ip": item.get("src_ip"),
            "dest_ip": item.get("dest_ip"),
            "user_name": item.get("user_name"),
            "process_name": item.get("process_name"),
            "rule_id": item.get("rule_id"),
            "description": item.get("description"),
            "summary": item.get("summary"),
        }

    def correlate(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []

        for item in detections:
            if not isinstance(item, dict):
                continue

            timestamp = item.get("timestamp") or item.get("created_at")
            if not timestamp:
                continue

            # Filtre métier SOC
            if not is_incident_candidate(item):
                continue

            # garde-fou minimal
            if not any(
                [
                    item.get("title"),
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
                    last_dt = self._parse_dt(bucket[-1].get("timestamp")) or datetime.min.replace(
                        tzinfo=timezone.utc
                    )

                    same_category = (
                        self._normalize_text_lower(item.get("category"))
                        == self._normalize_text_lower(bucket[-1].get("category"))
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

                    close_in_time = abs(item_dt - last_dt) <= timedelta(minutes=self.window_minutes)

                    if close_in_time and (same_category or same_user or same_process):
                        bucket.append(item)
                        placed = True
                        break

                if not placed:
                    buckets.append([item])

            for bucket in buckets:
                dominant = self._dominant_signal(bucket)
                first_ts = bucket[0].get("timestamp")
                last_ts = bucket[-1].get("timestamp")
                asset_name = self._normalize_text(bucket[0].get("asset_name")) or asset_key
                domain = self._incident_domain(bucket)
                risk_score = self._compute_risk_score(bucket)
                priority = self._priority_from_score(risk_score)
                confidence = self._compute_confidence(bucket)

                incidents.append(
                    {
                        "id": f"incident:{asset_key}:{first_ts}:{len(bucket)}",
                        "title": self._build_title(
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
                        "type": "incident",
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
                        "confidence": confidence,
                        "signals_count": len(bucket),
                        "signals": [self._compact_signal(x) for x in bucket],
                        "source": "specula",
                        "why_it_matters": self._build_why_it_matters(bucket, domain),
                        "recommended_actions": self._build_recommended_actions(bucket, domain),
                        "dominant_signal_title": dominant.get("title"),
                        "dominant_category": dominant.get("category"),
                        "dominant_engine": dominant.get("source_engine") or dominant.get("engine"),
                        "user_name": self._main_user(bucket),
                        "process_name": self._main_process(bucket),
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