from __future__ import annotations

from pathlib import Path

from providers.base_provider import DetectionProvider
from providers.suricata_provider import SuricataProvider
from providers.wazuh_provider import WazuhProvider


class PluginRegistry:
    """
    Registre simple des providers actifs.

    Objectif :
    - centraliser les providers activés
    - garder le noyau découplé des sources
    - préparer l'évolution vers une config dynamique plus tard
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
        wazuh_alerts_path: str | Path | None = None,
        enable_suricata: bool = True,
        enable_wazuh: bool = True,
    ) -> "PluginRegistry":
        registry = cls()

        if enable_suricata and eve_path:
            registry.register(SuricataProvider(eve_path))

        if enable_wazuh and wazuh_alerts_path:
            registry.register(WazuhProvider(wazuh_alerts_path))

        return registry