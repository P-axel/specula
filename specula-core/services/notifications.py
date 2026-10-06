"""
Notifications push via ntfy auto-hébergé.
Utilise uniquement urllib (stdlib Python) — aucune dépendance externe.
"""
from __future__ import annotations

import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

NTFY_BASE_URL = os.getenv("NTFY_BASE_URL", "http://specula-ntfy:80")
NTFY_TOPIC    = os.getenv("NTFY_TOPIC", "")

_PRIORITY_MAP = {
    "critical": "urgent",
    "high":     "high",
    "medium":   "default",
    "low":      "low",
}


def is_configured() -> bool:
    return bool(NTFY_TOPIC and NTFY_BASE_URL)


def send(title: str, message: str, severity: str = "high", tags: list[str] | None = None) -> bool:
    """Envoie une notification push ntfy. Retourne True si envoyé, False sinon."""
    if not is_configured():
        return False

    priority = _PRIORITY_MAP.get(severity.lower(), "default")
    tag_header = ",".join(tags or ["shield", "specula"])
    url = f"{NTFY_BASE_URL.rstrip('/')}/{NTFY_TOPIC}"

    try:
        req = urllib.request.Request(
            url,
            data=message.encode(),
            headers={
                "Title":    title,
                "Priority": priority,
                "Tags":     tag_header,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
        logger.debug("Notification envoyée : %s", title)
        return True
    except urllib.error.URLError as e:
        logger.warning("ntfy indisponible (%s) — notification ignorée", e)
        return False
    except Exception as e:
        logger.warning("Erreur notification : %s", e)
        return False


def notify_incident(incident: dict) -> bool:
    """Formatte et envoie une notification pour un incident."""
    severity  = str(incident.get("severity") or incident.get("priority") or "high").lower()
    title_raw = incident.get("title") or incident.get("name") or incident.get("category") or "Incident détecté"
    engine    = incident.get("dominant_engine") or incident.get("engine") or incident.get("source_engine") or ""
    asset     = incident.get("asset_name") or incident.get("src_ip") or ""

    title = f"[Specula] {severity.upper()} — {title_raw[:60]}"
    parts = [title_raw]
    if engine:
        parts.append(f"Source : {engine}")
    if asset:
        parts.append(f"Actif : {asset}")
    message = "\n".join(parts)

    tags = ["warning" if severity in ("high", "critical") else "information", engine or "specula"]
    return send(title, message, severity=severity, tags=tags)
