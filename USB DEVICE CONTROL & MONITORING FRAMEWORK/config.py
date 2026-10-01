"""Application configuration for the USB security framework."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / os.getenv("DATA_DIR", "data")
LOG_DIR = PROJECT_ROOT / os.getenv("LOG_DIR", "logs")
REPORT_DIR = DATA_DIR / "reports"
EXPORT_DIR = DATA_DIR / "exports"
DATABASE_PATH = DATA_DIR / "usb_monitor.db"

APP_NAME = "USB Device Control & Monitoring Framework"
APP_VERSION = "1.0.0"
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-local-development-secret")
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "SIMULATION").upper()
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
MONITOR_INTERVAL_SECONDS = float(os.getenv("MONITOR_INTERVAL_SECONDS", "5"))
MAX_SINGLE_FILE_SIZE = int(os.getenv("MAX_SINGLE_FILE_SIZE", str(100 * 1024 * 1024)))
MAX_TOTAL_TRANSFER_SIZE = int(os.getenv("MAX_TOTAL_TRANSFER_SIZE", str(500 * 1024 * 1024)))
MAX_FILES_PER_SESSION = int(os.getenv("MAX_FILES_PER_SESSION", "100"))


def ensure_directories() -> None:
    """Create application data and log directories if they are absent."""
    for directory in (DATA_DIR, LOG_DIR, REPORT_DIR, EXPORT_DIR):
        directory.mkdir(parents=True, exist_ok=True)
