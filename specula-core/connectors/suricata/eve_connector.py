from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class SuricataEveConnector:
    """
    Connector simple pour lire eve.json de Suricata en JSON lines.

    Objectifs:
    - lecture robuste ligne par ligne
    - filtrage par event_type
    - limitation du nombre de résultats
    - retour des événements bruts
    """

    def __init__(self, eve_path: str | Path) -> None:
        self.eve_path = Path(eve_path)

    def exists(self) -> bool:
        return self.eve_path.exists() and self.eve_path.is_file()

    def read_events(
        self,
        limit: int = 100,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lit les derniers événements du fichier eve.json.

        Note:
        Pour rester simple et robuste, on charge les lignes valides
        puis on tronque à la fin. Pour un gros volume, on pourra
        ensuite remplacer par une lecture inversée optimisée.
        """
        if limit <= 0:
            return []

        events: List[Dict[str, Any]] = []

        for event in self.iter_events(event_types=event_types):
            events.append(event)

        if len(events) <= limit:
            return events

        return events[-limit:]

    def iter_events(
        self,
        event_types: Optional[List[str]] = None,
    ) -> Iterable[Dict[str, Any]]:
        """
        Itère sur tous les événements valides de eve.json.
        Ignore les lignes vides ou corrompues.
        """
        if not self.exists():
            return

        normalized_event_types = set(event_types or [])

        with self.eve_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(payload, dict):
                    continue

                event_type = payload.get("event_type")
                if normalized_event_types and event_type not in normalized_event_types:
                    continue

                yield payload

    def get_status(self) -> Dict[str, Any]:
        """
        Retourne un état simple du connecteur.
        """
        if not self.exists():
            return {
                "source": "suricata",
                "available": False,
                "path": str(self.eve_path),
                "size_bytes": 0,
            }

        stat = self.eve_path.stat()
        return {
            "source": "suricata",
            "available": True,
            "path": str(self.eve_path),
            "size_bytes": stat.st_size,
        }