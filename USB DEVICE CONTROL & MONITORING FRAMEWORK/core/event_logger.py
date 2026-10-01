"""Centralized rotating logging for application, USB, and security activity."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from config import LOG_DIR, ensure_directories


def configure_logging() -> None:
    ensure_directories()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if root.handlers:
        return

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    for name, filename in (
        (None, "application.log"),
        ("usb_events", "usb_events.log"),
        ("security_events", "security_events.log"),
    ):
        handler = RotatingFileHandler(LOG_DIR / filename, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(formatter)
        (root if name is None else logging.getLogger(name)).addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
