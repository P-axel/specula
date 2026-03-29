from __future__ import annotations

from typing import Any, Protocol


class DetectionProvider(Protocol):
    """
    Contrat minimal pour toute source branchable dans Specula.
    """

    name: str

    def list_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        ...

    def get_status(self) -> dict[str, Any]:
        ...