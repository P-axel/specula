"""
Logging structuré Specula.

En mode JSON (SPECULA_LOG_FORMAT=json), chaque ligne de log est un objet JSON
exploitable par n'importe quel SIEM ou agrégateur de logs (ELK, Loki, Datadog...).
En mode texte (défaut), format lisible pour le développement.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Formateur JSON structuré — une ligne JSON par log."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Champs extra passés via logger.info("msg", extra={"req_id": "..."})
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            }:
                payload[key] = value

        try:
            return json.dumps(payload, default=str)
        except Exception:
            return json.dumps({"ts": payload["ts"], "level": "ERROR", "msg": "log serialization failed"})


def _resolve_level() -> int:
    level_name = os.getenv("SPECULA_LOG_LEVEL", "INFO").strip().upper()
    return getattr(logging, level_name, logging.INFO)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    level = _resolve_level()
    logger.setLevel(level)
    logger.propagate = False

    use_json = os.getenv("SPECULA_LOG_FORMAT", "text").strip().lower() == "json"

    handler = logging.StreamHandler()
    handler.setLevel(level)

    if use_json:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

    logger.addHandler(handler)
    return logger
