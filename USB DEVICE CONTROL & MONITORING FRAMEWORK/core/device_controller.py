"""Safe enforcement boundary. Simulation is the default and never changes Windows state."""
from __future__ import annotations

import ctypes
import platform
from dataclasses import dataclass

from config import ENFORCEMENT_MODE


@dataclass(slots=True)
class ControlResult:
    success: bool
    action: str
    detail: str


def is_administrator() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class DeviceController:
    def block_device(self, device) -> ControlResult:
        if ENFORCEMENT_MODE != "REAL":
            return ControlResult(True, "SIMULATED BLOCK", "Simulation mode: no operating-system change was made")
        if not is_administrator():
            return ControlResult(False, "BLOCK_FAILED", "Administrator privileges are required")
        return ControlResult(False, "BLOCK_FAILED", "Real enforcement adapter is unavailable; device was not reported as blocked")

    def unblock_device(self, device) -> ControlResult:
        if ENFORCEMENT_MODE != "REAL":
            return ControlResult(True, "SIMULATED UNBLOCK", "Simulation mode: no operating-system change was made")
        return ControlResult(False, "UNBLOCK_FAILED", "Real enforcement adapter is unavailable")

    def simulate_block(self, device) -> ControlResult:
        return ControlResult(True, "SIMULATED BLOCK", "No operating-system change was made")
