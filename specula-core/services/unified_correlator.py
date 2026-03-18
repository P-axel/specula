from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class UnifiedCorrelator:
    """
    Corrèle des détections multi-sources sur une fenêtre temporelle.

    Pivot principal :
    - asset / hostname / dest_ip
    Puis rapprochement par temps, utilisateur, IP, process.
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
        }

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
                    if abs(item_dt - last_dt) <= timedelta(minutes=self.window_minutes):
                        bucket.append(item)
                        placed = True
                        break

                if not placed:
                    buckets.append([item])

            for bucket in buckets:
                signals = [self._compact_signal(x) for x in bucket]

                first_ts = bucket[0].get("timestamp")
                last_ts = bucket[-1].get("timestamp")

                themes = sorted({str(x.get("theme") or "unknown") for x in bucket})
                engines = sorted(
                    {
                        str(x.get("source_engine") or x.get("engine") or "unknown")
                        for x in bucket
                    }
                )
                categories = sorted(
                    {str(x.get("category") or "unknown") for x in bucket}
                )

                risk_score = min(
                    100,
                    max(int(x.get("risk_score") or 0) for x in bucket) + max(len(bucket) - 1, 0) * 3,
                )

                incidents.append(
                    {
                        "id": f"incident:{asset_key}:{first_ts}:{len(bucket)}",
                        "title": "Incident multi-source corrélé",
                        "description": (
                            f"{len(bucket)} signal(s) corrélés sur {asset_key} "
                            f"entre {first_ts} et {last_ts}."
                        ),
                        "type": "incident",
                        "status": "open",
                        "asset_name": bucket[0].get("asset_name") or asset_key,
                        "hostname": bucket[0].get("hostname"),
                        "timestamp": first_ts,
                        "created_at": first_ts,
                        "updated_at": last_ts,
                        "risk_score": risk_score,
                        "priority": "medium" if risk_score < 60 else "high",
                        "severity": "medium" if risk_score < 60 else "high",
                        "themes": themes,
                        "engines": engines,
                        "categories": categories,
                        "signals_count": len(bucket),
                        "signals": signals,
                        "source": "specula",
                    }
                )

        incidents.sort(
            key=lambda x: (int(x.get("risk_score", 0)), str(x.get("updated_at") or "")),
            reverse=True,
        )

        return incidents