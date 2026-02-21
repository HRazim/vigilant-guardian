"""
Vigilant Guardian — Structured JSON logging.

Utilise *structlog* pour produire des logs JSON lisibles par un
agrégateur centralisé (Loki / ELK — cf. section 9.3, Semaine 10).
"""

from __future__ import annotations

import logging
import sys

import structlog

from src.config.settings import settings


def setup_logging() -> None:
    """Configure le logging structuré pour toute l'application."""

    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Processeurs structlog
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.debug:
        # Dev : sortie colorée lisible
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        # Prod : JSON pour agrégation
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Réduire le bruit des librairies tierces
    for noisy in ("uvicorn.access", "httpx", "httpcore", "celery.worker"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Renvoie un logger structuré nommé."""
    return structlog.get_logger(name)
