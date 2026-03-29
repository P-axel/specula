from __future__ import annotations

from pathlib import Path
from typing import Optional

from providers.base_provider import DetectionProvider
from providers.suricata_provider import SuricataProvider
from providers.wazuh_business_provider import WazuhBusinessProvider


class PluginRegistry:
    """
    Registre simple des providers actifs.

    Objectif :
    - centraliser les providers activés
    - garder le noyau découplé des sources
    - préparer l'évolution vers une config dynamique plus tard

    Important :
    - pour le SOC global, on enregistre des providers métier
    - on évite ici d'injecter le provider Wazuh "brut" pour ne pas
      corréler des centaines d'événements techniques non filtrés
    """

    def __init__(self) -> None:
        self._providers: list[DetectionProvider] = []

    def register(self, provider: DetectionProvider) -> None:
        self._providers.append(provider)

    def get_detection_providers(self) -> list[DetectionProvider]:
        return list(self._providers)

    def clear(self) -> None:
        self._providers.clear()

    @classmethod
    def build_default(
        cls,
        *,
        eve_path: str | Path | None = None,
        enable_suricata: bool = True,
        enable_wazuh: bool = True,
        wazuh_base_url: Optional[str] = None,
        wazuh_username: Optional[str] = None,
        wazuh_password: Optional[str] = None,
        wazuh_verify_ssl: Optional[bool] = None,
        wazuh_timeout: Optional[int] = None,
        wazuh_auth_type: str = "token",
    ) -> "PluginRegistry":
        registry = cls()

        # Provider Suricata existant
        if enable_suricata and eve_path:
            registry.register(SuricataProvider(eve_path))

        # Provider métier Wazuh pour aligner /soc/detections et /incidents/soc
        # avec le pipeline métier utilisé par /detections
        if enable_wazuh:
            registry.register(WazuhBusinessProvider())

        return registry