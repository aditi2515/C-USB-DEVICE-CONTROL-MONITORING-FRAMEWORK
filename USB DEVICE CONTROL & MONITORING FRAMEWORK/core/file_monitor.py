"""Watchdog-based removable-drive file auditing with honest direction attribution."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("usb_events")


def calculate_sha256(file_path: str | Path, chunk_size: int = 1024 * 1024) -> str | None:
    try:
        digest = hashlib.sha256()
        with Path(file_path).open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


class USBFileEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback("CREATE", Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self.callback("MODIFY", Path(event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback("DELETE", Path(event.src_path))


class FileMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.observer = Observer()
        self.watched_paths: set[str] = set()

    def watch_drive(self, drive_path: str) -> bool:
        path = Path(drive_path)
        if not path.exists():
            return False
        self.observer.schedule(USBFileEventHandler(self.callback), str(path), recursive=True)
        self.watched_paths.add(str(path))
        return True

    def start(self) -> None:
        if not self.observer.is_alive():
            self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=2)
