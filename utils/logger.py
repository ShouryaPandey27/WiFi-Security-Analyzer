"""
Centralised logging configuration for Secure Wave Analyzer.

Never logs passwords or other secrets. All modules should obtain a
logger via ``get_logger(__name__)``.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config.settings import settings

_CONFIGURED = False


def configure_logging() -> None:
    """Configure the root logger once for the whole application."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    settings.ensure_directories()
    log_file: Path = settings.logs_dir / "secure_wave.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(settings.logging_level.upper())

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)

    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    _CONFIGURED = True
    root_logger.info("Logging initialized for %s", settings.app_name)


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger, configuring logging on first use."""
    configure_logging()
    return logging.getLogger(name)
