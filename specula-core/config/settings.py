import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent.parent

env_file = BASE_DIR / ".env"
if env_file.exists():
    load_dotenv(env_file)

env_local_file = BASE_DIR / ".env.local"
if env_local_file.exists():
    load_dotenv(env_local_file, override=True)


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    app_env: str
    app_debug: bool
    log_level: str

    # Wazuh Manager API
    wazuh_base_url: str
    wazuh_username: str
    wazuh_password: str

    # Wazuh Indexer API
    wazuh_indexer_url: str
    wazuh_indexer_username: str
    wazuh_indexer_password: str

    # Commun
    wazuh_verify_tls: bool
    wazuh_timeout: int
    wazuh_default_limit: int


def load_settings() -> Settings:
    settings = Settings(
        app_env=os.getenv("SPECULA_ENV", "dev"),
        app_debug=_to_bool(os.getenv("SPECULA_DEBUG", "false")),
        log_level=os.getenv("SPECULA_LOG_LEVEL", "INFO"),

        # Manager API
        wazuh_base_url=os.getenv("WAZUH_BASE_URL", "https://localhost:55000"),
        wazuh_username=os.getenv("WAZUH_USERNAME", "wazuh-wui"),
        wazuh_password=os.getenv("WAZUH_PASSWORD", ""),

        # Indexer API
        wazuh_indexer_url=os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200"),
        wazuh_indexer_username=os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
        wazuh_indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),

        # Commun
        wazuh_verify_tls=_to_bool(os.getenv("WAZUH_VERIFY_TLS", "false")),
        wazuh_timeout=int(os.getenv("WAZUH_TIMEOUT", "10")),
        wazuh_default_limit=int(os.getenv("WAZUH_DEFAULT_LIMIT", "50")),
    )

    if not settings.wazuh_password:
        raise ValueError("WAZUH_PASSWORD is missing")

    if not settings.wazuh_base_url:
        raise ValueError("WAZUH_BASE_URL is missing")

    if not settings.wazuh_indexer_url:
        raise ValueError("WAZUH_INDEXER_URL is missing")

    if not settings.wazuh_indexer_username:
        raise ValueError("WAZUH_INDEXER_USERNAME is missing")

    if not settings.wazuh_indexer_password:
        raise ValueError("WAZUH_INDEXER_PASSWORD is missing")

    return settings


settings = load_settings()