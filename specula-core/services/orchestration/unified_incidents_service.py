from __future__ import annotations

import os
import time
from threading import Lock
from typing import Any

from services.transformation.detections_aggregator import DetectionsAggregator
from services.orchestration.unified_correlator import UnifiedCorrelator

_CACHE_TTL = int(os.getenv("SPECULA_CACHE_TTL", "30"))  # secondes

_incident_cache: dict[str, Any] = {"incidents": [], "ts": 0.0, "overview": None}
_cache_lock = Lock()


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

        # Le fallback est activé explicitement via env, ou automatiquement hors prod.
        mode = str(os.getenv("SPECULA_MODE", "prod")).strip().lower()
        env_flag = os.getenv("SPECULA_ENABLE_DETECTIONS_FALLBACK", "").strip().lower()
        if env_flag in ("true", "1", "yes"):
            self.enable_detections_fallback = True
        elif env_flag in ("false", "0", "no"):
            self.enable_detections_fallback = False
        else:
            # Par défaut : toujours actif (les incidents corrélés restent prioritaires)
            self.enable_detections_fallback = True

    def _detection_to_incident(self, detection: dict[str, Any]) -> dict[str, Any]:
        """
        Normalisation d'une détection pour en faire un incident exploitable.
        """
        severity = str(detection.get("severity") or "medium").strip().lower()
        status = str(detection.get("status") or "open").strip().lower()

        title = (
            detection.get("title")
            or detection.get("name")
            or detection.get("rule_description")
            or detection.get("description")
            or "Incident SOC"
        )

        description = (
            detection.get("description")
            or detection.get("summary")
            or detection.get("message")
            or title
        )

        asset_name = (
            detection.get("asset_name")
            or detection.get("asset")
            or detection.get("host")
            or detection.get("agent_name")
            or ""
        )

        provider = str(
            detection.get("provider")
            or detection.get("engine")
            or detection.get("source")
            or "unknown"
        ).strip().lower()

        kind = (
            detection.get("kind")
            or detection.get("category")
            or detection.get("theme")
            or "correlated"
        )

        risk_score = detection.get("risk_score")
        if risk_score in (None, ""):
            mapping = {
                "critical": 90,
                "high": 75,
                "medium": 50,
                "low": 25,
                "info": 10,
            }
            risk_score = mapping.get(severity, 50)

        return {
            "id": detection.get("id") or detection.get("detection_id") or title,
            "title": title,
            "name": title,
            "description": description,
            "severity": severity,
            "priority": severity,
            "status": status,
            "risk_score": risk_score,
            "kind": kind,
            "asset_name": asset_name,
            "source": "detection_fallback",
            "engines": [provider] if provider else [],
            "themes": (
                [str(detection.get("theme")).strip().lower()]
                if detection.get("theme")
                else []
            ),
            "categories": [str(kind).strip().lower()] if kind else [],
            "signals": [detection],
            "detections_count": 1,
            "first_seen": detection.get("first_seen") or detection.get("timestamp"),
            "last_seen": detection.get("last_seen") or detection.get("timestamp"),
            "timestamp": detection.get("timestamp"),
            "provider": provider,
            "raw_detection": detection,
        }

    def _compute_incidents(self, fetch_limit: int) -> list[dict[str, Any]]:
        detections = self.aggregator.list_detections(limit=fetch_limit)
        incidents = self.correlator.correlate(detections)
        if not incidents and detections and self.enable_detections_fallback:
            incidents = [self._detection_to_incident(item) for item in detections]
        return incidents

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Récupère la liste des incidents avec cache TTL.
        """
        fetch_limit = max(limit * 20, 200) if limit > 0 else 200
        now = time.monotonic()

        with _cache_lock:
            if now - _incident_cache["ts"] < _CACHE_TTL and _incident_cache["incidents"]:
                incidents = _incident_cache["incidents"]
            else:
                incidents = self._compute_incidents(fetch_limit)
                _incident_cache["incidents"] = incidents
                _incident_cache["overview"] = None  # invalide l'overview aussi
                _incident_cache["ts"] = now

        return incidents[:limit] if limit > 0 else incidents

    def invalidate_cache(self) -> None:
        with _cache_lock:
            _incident_cache["ts"] = 0.0
            _incident_cache["incidents"] = []
            _incident_cache["overview"] = None

    def get_overview(self, limit: int = 50) -> dict[str, Any]:
        """
        Récupère un résumé des incidents, incluant les incidents ouverts et à haute priorité.
        """
        incidents = self.list_incidents(limit=limit)

        open_count = sum(
            1
            for item in incidents
            if str(item.get("status") or "").strip().lower()
            in {"open", "new", "investigating"}
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