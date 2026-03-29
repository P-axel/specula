from __future__ import annotations

import json
from pathlib import Path
from typing import Any


BASE_FIXTURES_DIR = Path("/app/tests/fixtures")


def load_json_fixture_list(name: str) -> list[dict[str, Any]]:
    target = BASE_FIXTURES_DIR / name
    items: list[dict[str, Any]] = []

    if not target.exists():
        return items

    if target.is_file():
        return _load_fixture_file(target)

    for file_path in sorted(target.glob("*.json")):
        items.extend(_load_fixture_file(file_path))

    return items


def _load_fixture_file(file_path: Path) -> list[dict[str, Any]]:
    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    if isinstance(data, dict):
        return [data]

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    return []