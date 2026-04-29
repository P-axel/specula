"""
Client HTTP léger vers l'API Ollama.
Pas de dépendance externe — urllib uniquement.
"""

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://specula-ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA_TIMEOUT  = int(os.getenv("OLLAMA_TIMEOUT", "300"))


class OllamaUnavailableError(Exception):
    pass


def _post(endpoint: str, payload: dict) -> dict:
    url  = f"{OLLAMA_BASE_URL}{endpoint}"
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        raise OllamaUnavailableError(f"Ollama inaccessible ({OLLAMA_BASE_URL}): {e}") from e


def is_available() -> bool:
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5):
            return True
    except Exception:
        return False


def chat(system: str, user: str, model: str = OLLAMA_MODEL) -> dict[str, Any]:
    """
    Appel chat avec sortie JSON forcée.
    Retourne le dict parsé ou lève OllamaUnavailableError / ValueError.
    """
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 400, "num_ctx": 2048},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }
    resp = _post("/api/chat", payload)
    raw = resp.get("message", {}).get("content", "").strip()

    # Tentative directe
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Extraction du bloc JSON entre { } ou [ ]
    import re
    for pattern in (r'\{[\s\S]*\}', r'\[[\s\S]*\]'):
        m = re.search(pattern, raw)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass

    logger.warning("Réponse Ollama non-JSON : %s", raw[:300])
    raise ValueError(f"Réponse non-JSON après extraction: {raw[:200]}")
