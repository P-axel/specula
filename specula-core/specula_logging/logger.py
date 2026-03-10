import logging
import os


def _resolve_level() -> int:
    level_name = os.getenv("SPECULA_LOG_LEVEL", "INFO").strip().upper()

    levels = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }

    return levels.get(level_name, logging.INFO)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(_resolve_level())
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler()
    handler.setLevel(_resolve_level())
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger