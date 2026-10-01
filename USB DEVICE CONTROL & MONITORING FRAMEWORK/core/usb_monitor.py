"""Background USB polling service with a callback boundary for Flask integration."""
from __future__ import annotations

import threading
import time
from typing import Callable

from config import MONITOR_INTERVAL_SECONDS
from core.device_identifier import DeviceInfo, scan_windows_devices


class USBMonitor:
    def __init__(self, on_connect: Callable[[DeviceInfo], None] | None = None, on_remove: Callable[[DeviceInfo], None] | None = None):
        self.on_connect = on_connect
        self.on_remove = on_remove
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._connected: dict[str, DeviceInfo] = {}
        self.last_scan_time = None

    def scan_devices(self) -> list[DeviceInfo]:
        devices = scan_windows_devices()
        self.last_scan_time = time.time()
        return devices

    def get_connected_devices(self) -> list[DeviceInfo]:
        return list(self._connected.values())

    def _run(self) -> None:
        while not self._stop_event.is_set():
            current = {device.fingerprint: device for device in self.scan_devices()}
            for fingerprint, device in current.items():
                if fingerprint not in self._connected and self.on_connect:
                    self.on_connect(device)
            for fingerprint, device in list(self._connected.items()):
                if fingerprint not in current and self.on_remove:
                    self.on_remove(device)
            self._connected = current
            self._stop_event.wait(MONITOR_INTERVAL_SECONDS)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="usb-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
