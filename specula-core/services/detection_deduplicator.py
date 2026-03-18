from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple


class DetectionDeduplicator:
    """
    Regroupe les détections quasi identiques sur une fenêtre temporelle.
    Garde la plus récente et incrémente un compteur d'occurrences.
    """

    def __init__(self, window_minutes: int = 15) -> None:
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

    def _make_key(self, detection: Dict[str, Any]) -> Tuple[str, str, str]:
        title = str(detection.get("title") or detection.get("name") or "").strip().lower()
        asset = str(
            detection.get("asset_name")
            or detection.get("asset")
            or detection.get("hostname")
            or detection.get("asset_id")
            or "unknown"
        ).strip().lower()
        category = str(detection.get("category") or detection.get("type") or "").strip().lower()

        return (title, asset, category)

    def deduplicate(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sorted_items = sorted(
            detections,
            key=lambda item: self._parse_dt(
                item.get("created_at") or item.get("timestamp")
            ) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        groups: dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}

        for detection in sorted_items:
            key = self._make_key(detection)
            groups.setdefault(key, []).append(detection)

        deduped: List[Dict[str, Any]] = []

        for _, items in groups.items():
            kept: List[Dict[str, Any]] = []

            for item in items:
                item_dt = self._parse_dt(item.get("created_at") or item.get("timestamp"))
                if item_dt is None:
                    item_dt = datetime.min.replace(tzinfo=timezone.utc)

                matched = False

                for existing in kept:
                    existing_dt = self._parse_dt(
                        existing.get("created_at") or existing.get("timestamp")
                    )
                    if existing_dt is None:
                        existing_dt = datetime.min.replace(tzinfo=timezone.utc)

                    if abs(existing_dt - item_dt) <= timedelta(minutes=self.window_minutes):
                        existing["occurrences"] = int(existing.get("occurrences", 1)) + 1

                        existing.setdefault("metadata", {})
                        existing["metadata"]["last_seen"] = (
                            existing.get("created_at") or existing.get("timestamp")
                        )
                        matched = True
                        break

                if not matched:
                    cloned = dict(item)
                    cloned["occurrences"] = 1
                    cloned.setdefault("metadata", {})
                    cloned["metadata"]["first_seen"] = cloned.get("created_at") or cloned.get("timestamp")
                    cloned["metadata"]["last_seen"] = cloned.get("created_at") or cloned.get("timestamp")
                    kept.append(cloned)

            deduped.extend(kept)

        deduped.sort(
            key=lambda item: self._parse_dt(
                item.get("created_at") or item.get("timestamp")
            ) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        return deduped