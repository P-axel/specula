from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class SuricataEveConnector:
    """
    Connector simple pour lire eve.json de Suricata en JSON lines.

    Lecture incrémentale : on mémorise le dernier offset lu pour
    ne relire que les nouvelles lignes à chaque appel.
    """
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
        self._offset: int = 0          # dernier octet lu
        self._inode: int = -1          # détecte rotation du fichier

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

        # incremental=False : les API on-demand lisent tout le fichier.
        # L'incrémental est réservé à un éventuel background poller.
        for event in self.iter_events(event_types=event_types, incremental=False):
            events.append(event)

        if len(events) <= limit:
            return events

        return events[-limit:]

    def iter_events(
        self,
        event_types: Optional[List[str]] = None,
        incremental: bool = True,
    ) -> Iterable[Dict[str, Any]]:
        """
        Itère sur les événements de eve.json.

        Si incremental=True (défaut), ne lit que les nouvelles lignes
        depuis le dernier appel. Détecte aussi la rotation du fichier.
        """
        if not self.exists():
            return

        normalized_event_types = set(event_types or [])
        stat = self.eve_path.stat()
        current_inode = stat.st_ino

        # Rotation détectée ou premier appel
        if current_inode != self._inode:
            self._inode = current_inode
            self._offset = 0

        # Si le fichier a rétréci (truncate), on repart du début
        if incremental and self._offset > stat.st_size:
            self._offset = 0

        with self.eve_path.open("rb") as handle:
            if incremental:
                handle.seek(self._offset)

            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line)
                except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                    continue

                if not isinstance(payload, dict):
                    continue

                event_type = payload.get("event_type")
                if normalized_event_types and event_type not in normalized_event_types:
                    continue

                yield payload

            if incremental:
                self._offset = handle.tell()

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