from __future__ import annotations

import json
from pathlib import Path
from typing import Generator, Any


class SuricataReader:
    def __init__(self, eve_path: str | Path) -> None:
        self.eve_path = Path(eve_path)

    def exists(self) -> bool:
        return self.eve_path.exists() and self.eve_path.is_file()

    def read_events(self) -> Generator[dict[str, Any], None, None]:
        if not self.exists():
            raise FileNotFoundError(f"Suricata eve.json introuvable: {self.eve_path}")

        with self.eve_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        yield payload
                except json.JSONDecodeError:
                    # On ignore les lignes corrompues pour ne pas casser l’ingestion entière
                    continue