import json

from config.settings import BASE_DIR

FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"


def load_json_fixture(relative_path: str):
    file_path = FIXTURES_DIR / relative_path
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_json_fixture_list(relative_dir: str):
    dir_path = FIXTURES_DIR / relative_dir
    items = []

    for file_path in sorted(dir_path.glob("*.json")):
        with file_path.open("r", encoding="utf-8") as f:
            items.append(json.load(f))

    return items