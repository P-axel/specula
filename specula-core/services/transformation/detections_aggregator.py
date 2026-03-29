from __future__ import annotations

from typing import Any, Iterable
from providers.base_provider import DetectionProvider
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class DetectionsAggregator:
    """
    Agrège les détections issues de plusieurs providers.

    RESPONSABILITÉ :
    - normaliser
    - filtrer le bruit technique
    - garantir des détections exploitables

    NE DOIT PAS :
    - décider ce qu’est un incident (fait ailleurs)
    """

    def __init__(self, providers: Iterable[DetectionProvider] | None = None) -> None:
        self.providers: list[DetectionProvider] = list(providers or [])

    def register_provider(self, provider: DetectionProvider) -> None:
        self.providers.append(provider)

    def clear_providers(self) -> None:
        self.providers.clear()

    def list_providers(self) -> list[str]:
        return [getattr(provider, "name", provider.__class__.__name__) for provider in self.providers]

    # ==========================================================
    # NORMALISATION
    # ==========================================================

    def _normalize_item(self, item: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None

        # Déjà normalisé
        if any(
            key in item
            for key in [
                "title",
                "category",
                "severity",
                "asset_name",
                "src_ip",
                "dest_ip",
            ]
        ):
            return item

        event = item.get("event")
        if not isinstance(event, dict):
            return None

        source = item.get("source") or {}
        destination = item.get("destination") or {}
        network = item.get("network") or {}
        risk = item.get("risk") or {}
        observer = item.get("observer") or {}
        raw = item.get("raw") or {}

        raw_alert = raw.get("alert") or {}

        title = (
            event.get("signature")
            or raw_alert.get("signature")
            or event.get("title")
            or event.get("category")
            or event.get("type")
            or "event"
        )

        severity = str(event.get("severity") or risk.get("level") or "info").lower()
        source_engine = str(event.get("provider") or observer.get("product") or "unknown").lower()

        return {
            "id": event.get("id") or item.get("id"),
            "timestamp": item.get("timestamp"),
            "created_at": item.get("timestamp"),
            "title": title,
            "name": title,
            "category": str(event.get("category") or event.get("type") or "unknown").lower(),
            "severity": severity,
            "priority": severity,
            "risk_score": item.get("risk_score") or risk.get("score") or 0,
            "source": source_engine,
            "source_engine": source_engine,
            "engine": source_engine,
            "asset_name": destination.get("ip") or source.get("ip") or "unknown",
            "hostname": destination.get("ip") or source.get("ip"),
            "src_ip": source.get("ip"),
            "src_port": source.get("port"),
            "dest_ip": destination.get("ip"),
            "dest_port": destination.get("port"),
            "protocol": network.get("transport") or network.get("protocol"),
            "rule_id": event.get("id"),
            "description": title,
            "summary": title,
            "theme": "network" if "network" in str(event.get("category")).lower() else "generic",
            "raw": raw,
        }

    # ==========================================================
    # FILTRE BRUIT TECHNIQUE
    # ==========================================================

    def _is_valid_detection(self, item: dict[str, Any]) -> bool:
        timestamp = item.get("timestamp") or item.get("created_at") or item.get("updated_at")
        if not timestamp:
            return False

        severity = str(item.get("severity") or "").lower()
        category = str(item.get("category") or "").lower()
        title = str(item.get("title") or "").lower()
        source_engine = str(item.get("source_engine") or "").lower()

        # ❌ bruit Suricata pur
        if source_engine == "suricata":
            if severity in {"info", ""} and category in {
                "network_flow",
                "network_dns",
                "network_tls",
                "dns",
                "tls",
                "http",
            }:
                return False

            if title in {"event", "flow", "dns", "tls", "http"}:
                return False

        # ❌ détection vide
        if not any([
            item.get("title"),
            item.get("category"),
            item.get("severity"),
            item.get("asset_name"),
        ]):
            return False

        return True

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        for provider in self.providers:
            provider_name = getattr(provider, "name", provider.__class__.__name__)

            try:
                provider_items = provider.list_detections(limit=limit)
            except Exception as exc:
                logger.warning("Provider %s en erreur: %s", provider_name, exc)
                continue

            if not isinstance(provider_items, list):
                logger.warning("Provider %s a retourné un type invalide", provider_name)
                continue

            valid_count = 0
            dropped_count = 0

            for raw_item in provider_items:
                item = self._normalize_item(raw_item)

                if item is None or not self._is_valid_detection(item):
                    dropped_count += 1
                    continue

                items.append(item)
                valid_count += 1

            logger.info(
                "Provider %s -> %s détection(s) valide(s), %s ignorée(s)",
                provider_name,
                valid_count,
                dropped_count,
            )

        # tri temporel
        items.sort(
            key=lambda x: str(
                x.get("timestamp")
                or x.get("created_at")
                or x.get("updated_at")
                or ""
            ),
            reverse=True,
        )

        return items[:limit] if limit > 0 else items