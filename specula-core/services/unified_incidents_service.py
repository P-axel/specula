from __future__ import annotations

from typing import Any

from services.detections_aggregator import DetectionsAggregator
from services.unified_correlator import UnifiedCorrelator


class UnifiedIncidentsService:
    """
    Orchestre la génération d'incidents multi-sources à partir
    d'un agrégat de providers de détections.

    Ce service ne remplace pas le pipeline réseau spécialisé :
    - NetworkIncidentsService reste dédié à la page Réseau
    - UnifiedIncidentsService sert aux incidents SOC globaux
    """

    def __init__(
        self,
        aggregator: DetectionsAggregator,
        correlator: UnifiedCorrelator | None = None,
    ) -> None:
        self.aggregator = aggregator
        self.correlator = correlator or UnifiedCorrelator(window_minutes=30)

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        detections = self.aggregator.list_detections(limit=max(limit * 20, 200))
        incidents = self.correlator.correlate(detections)

        if limit <= 0:
            return incidents

        return incidents[:limit]

    def get_overview(self, limit: int = 50) -> dict[str, Any]:
        incidents = self.list_incidents(limit=limit)

        open_count = sum(
            1
            for item in incidents
            if str(item.get("status") or "").strip().lower() in {"open", "new", "investigating"}
        )

        high_count = sum(
            1
            for item in incidents
            if str(item.get("priority") or item.get("severity") or "").strip().lower()
            in {"high", "critical"}
        )

        engines: set[str] = set()
        themes: set[str] = set()
        categories: set[str] = set()
        assets: set[str] = set()

        max_risk_score = 0

        for item in incidents:
            try:
                max_risk_score = max(max_risk_score, int(item.get("risk_score") or 0))
            except (TypeError, ValueError):
                pass

            asset_name = str(item.get("asset_name") or "").strip()
            if asset_name:
                assets.add(asset_name)

            for engine in item.get("engines", []) or []:
                if engine:
                    engines.add(str(engine).strip().lower())

            for theme in item.get("themes", []) or []:
                if theme:
                    themes.add(str(theme).strip().lower())

            for category in item.get("categories", []) or []:
                if category:
                    categories.add(str(category).strip().lower())

        return {
            "total_incidents": len(incidents),
            "open_incidents": open_count,
            "high_priority_incidents": high_count,
            "max_risk_score": max_risk_score,
            "engines": sorted(engines),
            "themes": sorted(themes),
            "categories": sorted(categories),
            "assets": sorted(assets),
            "items": incidents,
        }