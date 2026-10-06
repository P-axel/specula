import os
from fastapi import APIRouter

router = APIRouter(prefix="/notifications", tags=["notifications"])

NTFY_BASE_URL    = os.getenv("NTFY_BASE_URL", "http://specula-ntfy:80")
NTFY_TOPIC       = os.getenv("NTFY_TOPIC", "")
NTFY_PUBLIC_URL  = os.getenv("NTFY_PUBLIC_URL", "")  # URL accessible depuis le LAN (pour le QR)


@router.post("/test")
def send_test() -> dict:
    """Envoie une notification de test ntfy."""
    from services.notifications import send, is_configured
    if not is_configured():
        return {"sent": False, "reason": "NTFY_TOPIC non configuré"}
    ok = send(
        title="[Specula] Notification de test",
        message="La connexion ntfy fonctionne correctement.",
        severity="high",
        tags=["shield", "white_check_mark"],
    )
    return {"sent": ok}


@router.get("/config")
def get_config() -> dict:
    """Retourne la configuration ntfy pour le QR code de souscription."""
    base = (NTFY_PUBLIC_URL or NTFY_BASE_URL).rstrip("/")
    subscribe_url = f"{base}/{NTFY_TOPIC}" if NTFY_TOPIC else ""
    return {
        "configured": bool(NTFY_TOPIC),
        "topic":      NTFY_TOPIC,
        "server_url": base,
        "subscribe_url": subscribe_url,
    }
