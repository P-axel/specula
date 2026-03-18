from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple


class IncidentCorrelator:
    """
    Regroupe plusieurs détections proches dans le temps pour produire
    un incident unique plus exploitable.

    Corrélation utilisée :
    - actif / destination
    - catégorie
    - moteur
    - fenêtre temporelle

    Règle métier :
    - plusieurs signaux corrélés => incident
    - un seul signal => incident seulement si high/critical
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

    def _risk_score_to_level(self, risk_score: int) -> str:
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        if risk_score >= 35:
            return "medium"
        return "low"

    def _compute_incident_risk_score(self, bucket: List[Dict[str, Any]]) -> int:
        """
        Garde la compatibilité avec ton comportement actuel :
        - base = score max des signaux
        Puis ajoute de petits bonus de corrélation sans exploser le score.
        """
        max_signal_score = max(int(item.get("risk_score", 0) or 0) for item in bucket)
        signals_count = len(bucket)

        distinct_categories = {
            str(item.get("category") or "").lower()
            for item in bucket
            if item.get("category")
        }
        distinct_titles = {
            str(item.get("title") or item.get("name") or "").strip().lower()
            for item in bucket
            if item.get("title") or item.get("name")
        }

        count_bonus = min(max(signals_count - 1, 0) * 2, 10)
        category_bonus = min(max(len(distinct_categories) - 1, 0) * 3, 9)
        title_bonus = min(max(len(distinct_titles) - 1, 0) * 2, 6)

        risk_score = max_signal_score + count_bonus + category_bonus + title_bonus
        return max(0, min(100, risk_score))

    def _incident_title_and_category(
        self,
        categories: set[str],
        severities: set[str],
    ) -> Tuple[str, str, str]:
        has_host_compromise = "host_compromise" in categories
        has_host_anomaly = "host_anomaly" in categories
        has_privilege = "privilege_abuse" in categories
        has_sniffing = "network_sniffing" in categories
        has_identity = "identity_activity" in categories
        has_exposure = "exposure_change" in categories
        has_service_failure = "service_failure" in categories
        has_intrusion = "intrusion_detection" in categories
        has_network = any("network" in category for category in categories)

        if has_host_compromise or (has_host_anomaly and has_privilege and has_sniffing):
            return (
                "Suspicion de compromission hôte",
                "host_incident",
                "critical" if "critical" in severities else "high",
            )

        if has_privilege and (has_identity or has_exposure):
            return (
                "Activité privilégiée à surveiller",
                "privileged_activity_incident",
                "high" if "high" in severities else "medium",
            )

        if has_sniffing:
            return (
                "Suspicion de capture réseau",
                "network_incident",
                "high" if "high" in severities or "critical" in severities else "medium",
            )

        if has_intrusion or has_network:
            return (
                "Incident réseau corrélé",
                "network_incident",
                "high" if "critical" in severities else "medium",
            )

        if has_exposure and has_service_failure:
            return (
                "Changement système ou réseau à surveiller",
                "configuration_incident",
                "medium",
            )

        if has_exposure:
            return (
                "Changement d’exposition réseau",
                "configuration_incident",
                "low" if severities == {"low"} else "medium",
            )

        if has_service_failure:
            return (
                "Dégradation de service",
                "availability_incident",
                "low" if severities == {"low"} else "medium",
            )

        if has_identity:
            return (
                "Activité d’authentification à surveiller",
                "identity_incident",
                "low" if severities == {"low"} else "medium",
            )

        return (
            "Incident de sécurité corrélé",
            "security_incident",
            "high" if "critical" in severities else "medium",
        )

    def _compact_signal(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Conserve les champs utiles à l'affichage des incidents.
        """
        return {
            "id": signal.get("id"),
            "title": signal.get("title") or signal.get("name"),
            "name": signal.get("name"),
            "severity": signal.get("severity"),
            "risk_score": signal.get("risk_score"),
            "risk_level": signal.get("risk_level"),
            "priority": signal.get("priority"),
            "timestamp": signal.get("timestamp"),
            "created_at": signal.get("created_at"),
            "category": signal.get("category"),
            "description": signal.get("description"),
            "summary": signal.get("summary"),
            "asset_name": signal.get("asset_name"),
            "asset_id": signal.get("asset_id"),
            "hostname": signal.get("hostname"),
            "source_engine": signal.get("source_engine") or signal.get("engine"),
            "engine": signal.get("engine"),
            "src_ip": signal.get("src_ip"),
            "src_port": signal.get("src_port"),
            "src_label": signal.get("src_label"),
            "source_ip": signal.get("source_ip"),
            "dest_ip": signal.get("dest_ip"),
            "dest_port": signal.get("dest_port"),
            "dest_label": signal.get("dest_label"),
            "destination_ip": signal.get("destination_ip"),
            "protocol": signal.get("protocol"),
            "proto": signal.get("proto"),
            "app_proto": signal.get("app_proto"),
            "flow_id": signal.get("flow_id"),
            "rule_id": signal.get("rule_id"),
            "source_rule_id": signal.get("source_rule_id"),
            "direction": signal.get("direction"),
            "confidence": signal.get("confidence"),
            "status": signal.get("status"),
            "type": signal.get("type"),
        }

    def _normalize_severity_label(self, value: Any) -> str:
        if isinstance(value, str):
            v = value.strip().lower()
            if v in {"critical", "high", "medium", "low", "info"}:
                return v

        try:
            numeric = int(value)
        except (TypeError, ValueError):
            return "info"

        if numeric <= 1:
            return "critical"
        if numeric == 2:
            return "high"
        if numeric == 3:
            return "medium"
        if numeric == 4:
            return "low"
        return "info"

    def _should_create_incident(self, bucket: List[Dict[str, Any]]) -> bool:
        """
        Règle métier anti-bruit :
        - 2 signaux ou plus => incident
        - 1 seul signal => seulement si high/critical ou score élevé
        """
        if not bucket:
            return False

        if len(bucket) >= 2:
            return True

        item = bucket[0]
        severity = self._normalize_severity_label(item.get("severity"))
        risk_score = int(item.get("risk_score", 0) or 0)

        return severity in {"high", "critical"} or risk_score >= 60

    def _correlation_key(self, detection: Dict[str, Any]) -> str:
        """
        Clé plus large et plus métier que l'ancienne version.

        Ancienne version :
        - dest_ip + rule + direction
        Trop fine => 1 signal ~= 1 incident

        Nouvelle version :
        - asset/destination + catégorie + moteur
        """
        asset = (
            detection.get("asset_name")
            or detection.get("dest_ip")
            or detection.get("destination_ip")
            or detection.get("hostname")
            or detection.get("dest_label")
            or "unknown"
        )

        category = detection.get("category") or "uncategorized"
        engine = (
            detection.get("source_engine")
            or detection.get("engine")
            or detection.get("source")
            or "unknown"
        )

        return (
            f"{str(asset).strip().lower()}|"
            f"{str(category).strip().lower()}|"
            f"{str(engine).strip().lower()}"
        )

    def correlate(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sorted_detections = sorted(
            detections,
            key=lambda item: self._parse_dt(
                item.get("created_at") or item.get("timestamp")
            ) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=False,
        )

        grouped_by_key: dict[str, List[Dict[str, Any]]] = {}

        for detection in sorted_detections:
            correlation_key = self._correlation_key(detection)
            grouped_by_key.setdefault(correlation_key, []).append(detection)

        incidents: List[Dict[str, Any]] = []

        for correlation_key, grouped_detections in grouped_by_key.items():
            buckets: List[List[Dict[str, Any]]] = []

            for detection in grouped_detections:
                detection_dt = self._parse_dt(
                    detection.get("created_at") or detection.get("timestamp")
                )
                if detection_dt is None:
                    detection_dt = datetime.min.replace(tzinfo=timezone.utc)

                placed = False

                for bucket in buckets:
                    last_dt = self._parse_dt(
                        bucket[-1].get("created_at") or bucket[-1].get("timestamp")
                    )
                    if last_dt is None:
                        last_dt = datetime.min.replace(tzinfo=timezone.utc)

                    if abs(detection_dt - last_dt) <= timedelta(minutes=self.window_minutes):
                        bucket.append(detection)
                        placed = True
                        break

                if not placed:
                    buckets.append([detection])

            for bucket in buckets:
                if not self._should_create_incident(bucket):
                    continue

                categories = {
                    str(item.get("category") or "").lower()
                    for item in bucket
                    if item.get("category")
                }
                severities = {
                    self._normalize_severity_label(item.get("severity"))
                    for item in bucket
                }

                title, incident_category, incident_severity = self._incident_title_and_category(
                    categories,
                    severities,
                )

                first_ts = bucket[0].get("created_at") or bucket[0].get("timestamp")
                last_ts = bucket[-1].get("created_at") or bucket[-1].get("timestamp")

                max_signal_score = max(int(item.get("risk_score", 0) or 0) for item in bucket)
                risk_score = self._compute_incident_risk_score(bucket)
                avg_confidence = round(
                    sum(float(item.get("confidence", 0.0) or 0.0) for item in bucket) / max(len(bucket), 1),
                    2,
                )

                signals = [self._compact_signal(signal) for signal in bucket]

                distinct_titles = sorted(
                    {
                        str(item.get("title") or item.get("name") or "").strip()
                        for item in bucket
                        if item.get("title") or item.get("name")
                    }
                )

                primary_signal = bucket[0]

                asset_name = (
                    primary_signal.get("asset_name")
                    or primary_signal.get("asset")
                    or primary_signal.get("hostname")
                    or primary_signal.get("dest_ip")
                    or primary_signal.get("dest_label")
                    or "unknown"
                )

                if incident_category == "host_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"suggèrent une possible compromission entre {first_ts} et {last_ts}."
                    )
                elif incident_category == "privileged_activity_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"montrent une activité privilégiée à surveiller entre {first_ts} et {last_ts}."
                    )
                elif incident_category == "network_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"évoquent une activité réseau sensible entre {first_ts} et {last_ts}."
                    )
                elif incident_category == "configuration_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"montrent un changement système ou réseau à surveiller entre {first_ts} et {last_ts}."
                    )
                elif incident_category == "availability_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"indiquent une dégradation de service entre {first_ts} et {last_ts}."
                    )
                elif incident_category == "identity_incident":
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"indiquent une activité d’authentification à surveiller entre {first_ts} et {last_ts}."
                    )
                else:
                    description = (
                        f"{len(bucket)} signal(s) corrélés sur l’actif {asset_name} "
                        f"entre {first_ts} et {last_ts}."
                    )

                risk_level = self._risk_score_to_level(risk_score)

                incidents.append(
                    {
                        "id": f"incident:{correlation_key}:{first_ts}:{len(bucket)}",
                        "title": title,
                        "name": title,
                        "description": description,
                        "severity": incident_severity,
                        "confidence": avg_confidence,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "priority": risk_level,
                        "category": incident_category,
                        "type": "incident",
                        "status": "open",
                        "asset_name": asset_name,
                        "asset_id": primary_signal.get("asset_id"),
                        "hostname": primary_signal.get("hostname"),
                        "source": "specula",
                        "timestamp": first_ts,
                        "created_at": first_ts,
                        "updated_at": last_ts,
                        "signals_count": len(bucket),
                        "signals": signals,
                        "tags": sorted(categories),
                        "metadata": {
                            "distinct_signal_titles": distinct_titles,
                            "primary_signature": distinct_titles[0] if distinct_titles else None,
                            "window_minutes": self.window_minutes,
                            "max_signal_score": max_signal_score,
                            "correlation_risk_bonus": max(0, risk_score - max_signal_score),
                            "correlation_key": correlation_key,
                        },
                    }
                )

        incidents.sort(
            key=lambda item: (
                int(item.get("risk_score", 0)),
                str(item.get("updated_at") or item.get("created_at") or ""),
            ),
            reverse=True,
        )

        return incidents