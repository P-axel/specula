from __future__ import annotations

from typing import Any, Iterable

from providers.base_provider import DetectionProvider


class DetectionsAggregator:
    """
    Agrège les détections issues de plusieurs providers sans connaître
    leurs implémentations concrètes.
    """

    def __init__(self, providers: Iterable[DetectionProvider] | None = None) -> None:
        self.providers: list[DetectionProvider] = list(providers or [])

    def register_provider(self, provider: DetectionProvider) -> None:
        self.providers.append(provider)

    def clear_providers(self) -> None:
        self.providers.clear()

    def list_providers(self) -> list[str]:
        return [getattr(provider, "name", provider.__class__.__name__) for provider in self.providers]

    def list_detections(self, limit: int = 200) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        for provider in self.providers:
            try:
                provider_items = provider.list_detections(limit=limit)
            except Exception:
                continue

            if not isinstance(provider_items, list):
                continue

            for item in provider_items:
                if isinstance(item, dict):
                    items.append(item)

        items.sort(
            key=lambda x: str(
                x.get("timestamp")
                or x.get("created_at")
                or x.get("updated_at")
                or ""
            ),
            reverse=True,
        )

        if limit <= 0:
            return items

        return items[:limit]