from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from providers.base_provider import DetectionProvider
from specula_logging.logger import get_logger

logger = get_logger(__name__)

USE_TEST_DETECTIONS = (
    os.getenv("SPECULA_USE_TEST_DETECTIONS", "false").strip().lower() == "true"
)

ALLOW_LOW_VALUE_SURICATA = (
    os.getenv("SPECULA_ALLOW_LOW_VALUE_SURICATA", "false").strip().lower() == "true"
)


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
        return [
            getattr(provider, "name", provider.__class__.__name__)
            for provider in self.providers
        ]

    # ==========================================================
    # HELPERS
    # ==========================================================

    def _now_iso(self, minutes_ago: int = 0) -> str:
        return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            if value in (None, ""):
                return default
            return int(value)
        except Exception:
            return default

    def _sort_key(self, item: dict[str, Any]) -> datetime:
        raw_value = (
            item.get("timestamp")
            or item.get("created_at")
            or item.get("updated_at")
            or ""
        )

        if not isinstance(raw_value, str) or not raw_value.strip():
            return datetime.min.replace(tzinfo=timezone.utc)

        value = raw_value.strip()

        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)

    # ==========================================================
    # TEST DATA
    # ==========================================================

    def _get_test_detections(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "test-auth-1",
                "title": "Échecs répétés d’authentification",
                "name": "Échecs répétés d’authentification",
                "message": "Échecs répétés d’authentification",
                "timestamp": self._now_iso(8),
                "created_at": self._now_iso(8),
                "category": "auth",
                "theme": "identity",
                "severity": "high",
                "priority": "high",
                "risk_score": 72,
                "source": "wazuh",
                "source_engine": "wazuh",
                "engine": "wazuh",
                "asset_name": "srv-auth-01",
                "hostname": "srv-auth-01",
                "user_name": "admin",
                "status": "open",
                "description": "Plusieurs échecs d’authentification détectés pour le compte admin.",
                "summary": "Échecs répétés sur compte admin",
                "confidence": 0.82,
                "rule_id": "AUTH-1001",
            },
            {
                "id": "test-auth-2",
                "title": "Échecs répétés d’authentification",
                "name": "Échecs répétés d’authentification",
                "message": "Échecs répétés d’authentification",
                "timestamp": self._now_iso(6),
                "created_at": self._now_iso(6),
                "category": "auth",
                "theme": "identity",
                "severity": "high",
                "priority": "high",
                "risk_score": 78,
                "source": "wazuh",
                "source_engine": "wazuh",
                "engine": "wazuh",
                "asset_name": "srv-auth-01",
                "hostname": "srv-auth-01",
                "user_name": "admin",
                "status": "open",
                "description": "Nouvelle série d’échecs d’authentification sur le même actif.",
                "summary": "Nouvelle série d’échecs admin",
                "confidence": 0.86,
                "rule_id": "AUTH-1001",
            },
            {
                "id": "test-net-1",
                "title": "Scan réseau détecté",
                "name": "Scan réseau détecté",
                "message": "Scan réseau détecté",
                "timestamp": self._now_iso(12),
                "created_at": self._now_iso(12),
                "category": "network_scan",
                "theme": "network",
                "severity": "medium",
                "priority": "medium",
                "risk_score": 45,
                "source": "suricata",
                "source_engine": "suricata",
                "engine": "suricata",
                "asset_name": "web-frontend-01",
                "hostname": "web-frontend-01",
                "src_ip": "192.168.1.50",
                "dest_ip": "10.0.10.20",
                "status": "open",
                "description": "Activité de scan réseau détectée vers le frontal web.",
                "summary": "Scan sur frontal web",
                "confidence": 0.74,
                "rule_id": "NET-2001",
            },
            {
                "id": "test-net-2",
                "title": "Scan réseau détecté",
                "name": "Scan réseau détecté",
                "message": "Scan réseau détecté",
                "timestamp": self._now_iso(11),
                "created_at": self._now_iso(11),
                "category": "network_scan",
                "theme": "network",
                "severity": "medium",
                "priority": "medium",
                "risk_score": 48,
                "source": "suricata",
                "source_engine": "suricata",
                "engine": "suricata",
                "asset_name": "web-frontend-01",
                "hostname": "web-frontend-01",
                "src_ip": "192.168.1.50",
                "dest_ip": "10.0.10.20",
                "status": "open",
                "description": "Répétition du comportement de scan sur le même actif.",
                "summary": "Scan récurrent",
                "confidence": 0.77,
                "rule_id": "NET-2001",
            },
            {
                "id": "test-sys-1",
                "title": "Processus suspect observé",
                "name": "Processus suspect observé",
                "message": "Processus suspect observé",
                "timestamp": self._now_iso(15),
                "created_at": self._now_iso(15),
                "category": "process",
                "theme": "system",
                "severity": "high",
                "priority": "high",
                "risk_score": 66,
                "source": "wazuh",
                "source_engine": "wazuh",
                "engine": "wazuh",
                "asset_name": "db-server-01",
                "hostname": "db-server-01",
                "process_name": "nc",
                "status": "open",
                "description": "Présence du processus nc sur un serveur critique.",
                "summary": "Processus nc détecté",
                "confidence": 0.79,
                "rule_id": "PROC-3001",
            },
            {
                "id": "test-sys-2",
                "title": "Processus suspect observé",
                "name": "Processus suspect observé",
                "message": "Processus suspect observé",
                "timestamp": self._now_iso(13),
                "created_at": self._now_iso(13),
                "category": "process",
                "theme": "system",
                "severity": "high",
                "priority": "high",
                "risk_score": 69,
                "source": "wazuh",
                "source_engine": "wazuh",
                "engine": "wazuh",
                "asset_name": "db-server-01",
                "hostname": "db-server-01",
                "process_name": "nc",
                "status": "open",
                "description": "Deuxième occurrence du processus suspect sur le même serveur.",
                "summary": "Processus nc récurrent",
                "confidence": 0.83,
                "rule_id": "PROC-3001",
            },
        ]

    # ==========================================================
    # NORMALISATION
    # ==========================================================

    def _normalize_item(self, item: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None

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
            normalized = dict(item)

            source_engine = str(
                normalized.get("source_engine")
                or normalized.get("engine")
                or normalized.get("source")
                or "unknown"
            ).strip().lower()

            severity = str(
                normalized.get("severity")
                or normalized.get("priority")
                or "info"
            ).strip().lower()

            normalized.setdefault("name", normalized.get("title"))
            normalized.setdefault("message", normalized.get("title") or normalized.get("name")) # Fix 500
            normalized.setdefault("created_at", normalized.get("timestamp"))
            normalized["priority"] = normalized.get("priority") or severity
            normalized["severity"] = normalized.get("severity") or severity
            normalized["source_engine"] = normalized.get("source_engine") or source_engine
            normalized["engine"] = normalized.get("engine") or source_engine
            normalized["source"] = normalized.get("source") or source_engine
            normalized["risk_score"] = self._safe_int(normalized.get("risk_score"), 0)
            normalized.setdefault("status", "open")

            return normalized

        event = item.get("event")
        if not isinstance(event, dict):
            return None

        source = item.get("source")
        if not isinstance(source, dict):
            source = {}

        destination = item.get("destination")
        if not isinstance(destination, dict):
            destination = {}

        network = item.get("network")
        if not isinstance(network, dict):
            network = {}

        risk = item.get("risk")
        if not isinstance(risk, dict):
            risk = {}

        observer = item.get("observer")
        if not isinstance(observer, dict):
            observer = {}

        raw = item.get("raw")
        if not isinstance(raw, dict):
            raw = {}

        raw_alert = raw.get("alert")
        if not isinstance(raw_alert, dict):
            raw_alert = {}

        title = (
            event.get("signature")
            or raw_alert.get("signature")
            or event.get("title")
            or event.get("category")
            or event.get("type")
            or "event"
        )

        severity = str(
            event.get("severity")
            or risk.get("level")
            or "info"
        ).strip().lower()

        source_engine = str(
            event.get("provider")
            or observer.get("product")
            or "unknown"
        ).strip().lower()

        category = str(
            event.get("category")
            or event.get("type")
            or "unknown"
        ).strip().lower()

        theme = "network" if any(
            token in category for token in ["network", "dns", "tls", "http", "flow", "scan"]
        ) else "generic"

        return {
            "id": event.get("id") or item.get("id"),
            "timestamp": item.get("timestamp"),
            "created_at": item.get("timestamp"),
            "title": title,
            "name": title,
            "message": title, # Fix 500
            "category": category,
            "severity": severity,
            "priority": severity,
            "risk_score": self._safe_int(item.get("risk_score") or risk.get("score"), 0),
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
            "theme": theme,
            "status": "open",
            "raw": raw,
        }

    # ==========================================================
    # FILTRE BRUIT TECHNIQUE
    # ==========================================================

    def _is_valid_detection(self, item: dict[str, Any]) -> bool:
        timestamp = item.get("timestamp") or item.get("created_at") or item.get("updated_at")
        if not timestamp:
            return False

        severity = str(item.get("severity") or "").strip().lower()
        category = str(item.get("category") or "").strip().lower()
        title = str(item.get("title") or "").strip().lower()
        source_engine = str(
            item.get("source_engine") or item.get("engine") or item.get("source") or ""
        ).strip().lower()

        if source_engine == "suricata":
            if ALLOW_LOW_VALUE_SURICATA:
                return True

            if severity in {"info", ""} and category in {
                "network_flow",
                "network_dns",
                "network_tls",
                "dns",
                "tls",
                "http",
                "flow",
            }:
                return False

            if title in {"event", "flow", "dns", "tls", "http"}:
                return False

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
            return False

        return True

    # ==========================================================
    # PROVIDER EXECUTION
    # ==========================================================

    def _collect_provider_items(
        self,
        provider: DetectionProvider,
        limit: int,
    ) -> tuple[str, list[dict[str, Any]]]:
        provider_name = getattr(provider, "name", provider.__class__.__name__)
        provider_items = provider.list_detections(limit=limit)

        if not isinstance(provider_items, list):
            logger.warning("Provider %s a retourné un type invalide", provider_name)
            return provider_name, []

        valid_items: list[dict[str, Any]] = []
        dropped_count = 0

        for raw_item in provider_items:
            item = self._normalize_item(raw_item)

            if item is None or not self._is_valid_detection(item):
                dropped_count += 1
                continue

            valid_items.append(item)

        logger.info(
            "Provider %s -> %s détection(s) valide(s), %s ignorée(s)",
            provider_name,
            len(valid_items),
            dropped_count,
        )
        return provider_name, valid_items

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def list_detections(self, limit: int = 50) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        if self.providers:
            max_workers = min(len(self.providers), 4)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self._collect_provider_items, provider, limit)
                    for provider in self.providers
                ]

                for future in as_completed(futures):
                    try:
                        _, provider_items = future.result()
                        items.extend(provider_items)
                    except Exception as exc:
                        logger.exception(
                            "Erreur lors de la récupération des détections d'un provider: %s",
                            exc,
                        )

        if USE_TEST_DETECTIONS:
            valid_test_items: list[dict[str, Any]] = []

            for item in self._get_test_detections():
                normalized = self._normalize_item(item)
                if normalized is not None and self._is_valid_detection(normalized):
                    valid_test_items.append(normalized)

            items.extend(valid_test_items)
            logger.info(
                "Mode test activé -> %s détection(s) de test injectée(s)",
                len(valid_test_items),
            )

        items.sort(key=self._sort_key, reverse=True)

        return items[:limit] if limit > 0 else items