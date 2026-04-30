#!/usr/bin/env python3
"""
Worker IA — subprocess indépendant.
Lit l'incident depuis stdin (JSON), exécute l'analyse IA, persiste en SQLite.
Survit au reload uvicorn.
"""
import json
import logging
import os
import sys

# Ajoute le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("ai.worker")

# Force le modèle léger et le bon timeout, indépendamment de l'env du container
os.environ.setdefault("OLLAMA_MODEL",   "qwen2.5:1.5b")
os.environ.setdefault("OLLAMA_TIMEOUT", "300")
os.environ["OLLAMA_MODEL"]   = "qwen2.5:1.5b"
os.environ["OLLAMA_TIMEOUT"] = "300"


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception as e:
        logger.error("Impossible de lire le payload: %s", e)
        sys.exit(1)

    incident_id = payload["incident_id"]
    incident    = payload["incident"]
    related     = payload.get("related", [])

    # Garantit que incident["id"] est correct pour analysis_service
    incident["id"] = incident_id

    from storage.ai_analysis_repository import save, set_error
    from ai.analysis_service import run_analysis
    from ai.ollama_client import OllamaUnavailableError

    try:
        logger.info("Worker démarré pour %s", incident_id)
        report = run_analysis(incident, related)
        save(report)
        logger.info("Worker terminé pour %s (%.1fs)", incident_id, report.get("duration_s", 0))
    except OllamaUnavailableError as e:
        set_error(incident_id, str(e))
        logger.warning("Ollama indisponible: %s", e)
    except Exception as e:
        set_error(incident_id, f"Erreur analyse: {e}")
        logger.exception("Erreur worker pour %s", incident_id)


if __name__ == "__main__":
    main()
