from __future__ import annotations

import hashlib
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

    @staticmethod
    def _compute_signature(incident: dict[str, Any]) -> str:
        """Signature stable d'un incident : hash(asset + titre canonique + moteur)."""
        asset = str(incident.get("asset_name") or incident.get("hostname") or "").strip().lower()
        title = str(incident.get("title") or incident.get("name") or "").strip().lower()
        # Retire le suffixe " (asset)" généré par le correlator
        title = title.replace(f" ({asset})", "").strip()
        engine = str(incident.get("dominant_engine") or "").strip().lower()
        raw = f"{asset}|{title}|{engine}"
        return hashlib.sha1(raw.encode()).hexdigest()[:20]

    def _apply_lifecycle(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Fusionne les incidents live avec le cycle de vie persisted en SQLite :
        - stabilise l'ID (même incident = même ID entre les redémarrages)
        - restaure le statut (resolved, false_positive restent tels quels)
        - préserve first_seen et cumule signals_count
        """
        try:
            from storage.incident_store_repository import (
                get_incident_lifecycle,
                upsert_incident_lifecycle,
            )
        except Exception:
            return incidents

        result = []
        for incident in incidents:
            sig = self._compute_signature(incident)
            incident["signature"] = sig

            try:
                persisted = get_incident_lifecycle(sig)
            except Exception:
                persisted = None

            if persisted:
                # Stabiliser l'ID : l'incident garde son ID d'origine
                incident["id"] = persisted["incident_id"]
                # Restaurer le statut persisted
                incident["status"] = persisted.get("status") or "open"
                # Préserver first_seen historique
                if persisted.get("first_seen"):
                    incident["first_seen"] = persisted["first_seen"]
                # Cumuler les signaux
                live_count = incident.get("signals_count") or 1
                db_count = persisted.get("signals_count") or 1
                incident["signals_count"] = max(live_count, db_count)
                incident["detections_count"] = incident["signals_count"]

            try:
                upsert_incident_lifecycle(
                    signature=sig,
                    incident_id=incident["id"],
                    title=incident.get("title"),
                    asset_name=incident.get("asset_name"),
                    dominant_engine=incident.get("dominant_engine"),
                    incident_domain=incident.get("incident_domain"),
                    severity=incident.get("severity"),
                    risk_score=incident.get("risk_score"),
                    status=incident.get("status", "open"),
                    signals_count=incident.get("signals_count") or 1,
                    first_seen=incident.get("first_seen"),
                    last_seen=incident.get("last_seen"),
                )
            except Exception:
                pass

            result.append(incident)
        return result

    def _dedupe_incidents(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Fusionne les incidents ayant le même titre canonique et le même actif.
        Conserve l'incident avec le risk_score le plus élevé, cumule les signaux.
        """
        seen: dict[tuple[str, str], int] = {}  # (title_key, asset_key) -> index
        result: list[dict[str, Any]] = []

        for incident in incidents:
            title_raw = str(incident.get("title") or incident.get("name") or "").strip()
            asset_raw = str(incident.get("asset_name") or incident.get("hostname") or "").strip()
            # Titre canonique : on retire la partie " (asset)" en fin de titre si présente
            title_key = title_raw.replace(f" ({asset_raw})", "").strip().lower()
            asset_key = asset_raw.lower()
            key = (title_key, asset_key)

            if key in seen:
                existing = result[seen[key]]
                # Garder le risk_score maximal
                if (incident.get("risk_score") or 0) > (existing.get("risk_score") or 0):
                    result[seen[key]] = incident
                else:
                    # Cumuler le nombre de signaux dans l'incident conservé
                    existing["signals_count"] = (
                        (existing.get("signals_count") or 1)
                        + (incident.get("signals_count") or 1)
                    )
                    existing["detections_count"] = existing["signals_count"]
            else:
                seen[key] = len(result)
                result.append(incident)

        return result

    def _enrich_incidents(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrichit les incidents avec la threat intelligence abuse.ch (ThreatFox + URLhaus)."""
        try:
            from enrichment.ioc_enricher import enrich_incident
        except ImportError:
            return incidents

        for incident in incidents:
            try:
                ti = enrich_incident(incident)
                if ti:
                    incident["threat_intel"] = ti
                    # Booster le risk_score si l'IP est connue malveillante
                    if ti.get("is_known_bad"):
                        current = int(incident.get("risk_score") or 0)
                        bonus = int(ti.get("reputation_score", 0) * 0.3)
                        incident["risk_score"] = min(100, current + bonus)
            except Exception:
                pass
        return incidents

    def _compute_incidents(self, fetch_limit: int) -> list[dict[str, Any]]:
        detections = self.aggregator.list_detections(limit=fetch_limit)
        incidents = self.correlator.correlate(detections)
        if not incidents and detections and self.enable_detections_fallback:
            incidents = [self._detection_to_incident(item) for item in detections]
        incidents = self._dedupe_incidents(incidents)
        incidents = self._apply_lifecycle(incidents)
        incidents = self._enrich_incidents(incidents)
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