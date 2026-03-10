import os
from dataclasses import dataclass


def _to_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    app_env: str
    app_debug: bool
    wazuh_base_url: str
    wazuh_username: str
    wazuh_password: str
    wazuh_verify_tls: bool
    wazuh_timeout: int
    wazuh_default_limit: int


def load_settings() -> Settings:
    settings = Settings(
        app_env=os.getenv("SPECULA_ENV", "dev"),
        app_debug=_to_bool(os.getenv("SPECULA_DEBUG", "false")),
        wazuh_base_url=os.getenv("WAZUH_BASE_URL", "https://localhost:55000"),
        wazuh_username=os.getenv("WAZUH_USERNAME", "wazuh-wui"),
        wazuh_password=os.getenv("WAZUH_PASSWORD", ""),
        wazuh_verify_tls=_to_bool(os.getenv("WAZUH_VERIFY_TLS", "false")),
        wazuh_timeout=int(os.getenv("WAZUH_TIMEOUT", "10")),
        wazuh_default_limit=int(os.getenv("WAZUH_DEFAULT_LIMIT", "50")),
    )

    if not settings.wazuh_password:
        raise ValueError("WAZUH_PASSWORD is missing")

    return settings


settings = load_settings()