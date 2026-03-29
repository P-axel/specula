from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .eve_connector import SuricataEveConnector


class SuricataConnector:
    """
    Façade principale du module Suricata.

    Responsabilités :
    - exposer un point d'entrée unique pour Specula
    - lire les événements bruts depuis eve.json
    - fournir un statut simple du connecteur

    Le connector ne normalise pas dans le schéma canonique Specula.
    Cette responsabilité reste au SuricataNormalizer.
    """

    SOURCE = "suricata"
    DEFAULT_EVENT_TYPES = ["alert", "flow", "dns", "http", "tls", "anomaly"]

    def __init__(self, eve_path: str | Path) -> None:
        self.eve_path = Path(eve_path)
        self.eve = SuricataEveConnector(self.eve_path)

    def test_connection(self) -> bool:
        """
        Vérifie simplement que le fichier eve.json existe et est lisible.
        """
        return self.eve.exists()

    def get_status(self) -> Dict[str, Any]:
        """
        Retourne un état synthétique du connecteur.
        """
        status = self.eve.get_status()
        status["connector"] = "suricata"
        return status

    def fetch_events(
        self,
        limit: int = 100,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les événements bruts Suricata destinés au normalizer.
        """
        return self.eve.read_events(
            limit=limit,
            event_types=event_types or self.DEFAULT_EVENT_TYPES,
        )

    def iter_events(
        self,
        event_types: Optional[List[str]] = None,
    ) -> Iterable[Dict[str, Any]]:
        """
        Itère sur les événements bruts Suricata.
        """
        yield from self.eve.iter_events(
            event_types=event_types or self.DEFAULT_EVENT_TYPES,
        )