from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load .env files
ENV_FILE = BASE_DIR / ".env"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)

ENV_LOCAL_FILE = BASE_DIR / ".env.local"
if ENV_LOCAL_FILE.exists():
    load_dotenv(ENV_LOCAL_FILE, override=True)


# -------------------------
# Utils
# -------------------------

def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _to_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid integer value: {value!r}") from exc


def _get_optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return None
    return value.strip()


def _get_required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        raise ValueError(f"{name} is missing")
    return value.strip()


# -------------------------
# Settings
# -------------------------

@dataclass(slots=True, frozen=True)
class Settings:
    # App
    app_env: str
    app_debug: bool
    log_level: str
    use_test_fixtures: bool

    # Specula runtime
    specula_mode: str
    specula_enable_detections_fallback: bool
    specula_use_test_detections: bool
    specula_enable_wazuh: bool

    # Wazuh (optionnel)
    wazuh_base_url: str | None
    wazuh_username: str | None
    wazuh_password: str | None

    wazuh_indexer_url: str | None
    wazuh_indexer_username: str | None
    wazuh_indexer_password: str | None

    # Suricata
    specula_suricata_eve_path: str | None

    # Common
    wazuh_verify_tls: bool
    wazuh_timeout: int
    wazuh_default_limit: int


# -------------------------
# Loader
# -------------------------

def load_settings() -> Settings:
    suricata_eve_path = os.getenv("SPECULA_SURICATA_EVE_PATH", "").strip() or None

    enable_wazuh = _to_bool(os.getenv("SPECULA_ENABLE_WAZUH"), False)

    return Settings(
        # App
        app_env=os.getenv("SPECULA_ENV", "dev").strip(),
        app_debug=_to_bool(os.getenv("SPECULA_DEBUG"), False),
        log_level=os.getenv("SPECULA_LOG_LEVEL", "INFO").strip(),
        use_test_fixtures=_to_bool(os.getenv("USE_TEST_FIXTURES"), False),

        # Specula runtime
        specula_mode=os.getenv("SPECULA_MODE", "prod").strip(),
        specula_enable_detections_fallback=_to_bool(
            os.getenv("SPECULA_ENABLE_DETECTIONS_FALLBACK"), False
        ),
        specula_use_test_detections=_to_bool(
            os.getenv("SPECULA_USE_TEST_DETECTIONS"), False
        ),
        specula_enable_wazuh=enable_wazuh,

        # Wazuh (chargé uniquement si activé)
        wazuh_base_url=_get_required_env("WAZUH_BASE_URL") if enable_wazuh else None,
        wazuh_username=os.getenv("WAZUH_USERNAME", "wazuh-wui").strip() if enable_wazuh else None,
        wazuh_password=_get_required_env("WAZUH_PASSWORD") if enable_wazuh else None,

        wazuh_indexer_url=_get_required_env("WAZUH_INDEXER_URL") if enable_wazuh else None,
        wazuh_indexer_username=_get_required_env("WAZUH_INDEXER_USERNAME") if enable_wazuh else None,
        wazuh_indexer_password=_get_required_env("WAZUH_INDEXER_PASSWORD") if enable_wazuh else None,

        # Suricata
        specula_suricata_eve_path=suricata_eve_path,

        # Common
        wazuh_verify_tls=_to_bool(os.getenv("WAZUH_VERIFY_TLS"), False),
        wazuh_timeout=_to_int(os.getenv("WAZUH_TIMEOUT"), 10),
        wazuh_default_limit=_to_int(os.getenv("WAZUH_DEFAULT_LIMIT"), 50),
    )


# Singleton
settings = load_settings()