"""USB identity normalization, fingerprinting, and Windows discovery helpers."""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import subprocess
from dataclasses import asdict, dataclass

logger = logging.getLogger("usb_events")


@dataclass(slots=True)
class DeviceInfo:
    vendor_id: str = "UNKNOWN"
    product_id: str = "UNKNOWN"
    serial_number: str = "UNKNOWN"
    device_name: str = "UNKNOWN USB device"
    manufacturer: str = "UNKNOWN"
    device_type: str = "UNKNOWN"
    filesystem: str = "UNKNOWN"
    drive_letter: str = "UNKNOWN"

    @property
    def fingerprint(self) -> str:
        """Return a stable identifier, useful for policy matching but not spoof-proof."""
        identity = "|".join(
            f"{key.upper()}:{getattr(self, key).strip().upper()}"
            for key in ("vendor_id", "product_id", "serial_number")
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, str]:
        values = asdict(self)
        values["fingerprint"] = self.fingerprint
        return values


def _clean(value: object) -> str:
    text = str(value or "").strip()
    return text if text else "UNKNOWN"


def normalize_device(raw: dict) -> DeviceInfo:
    return DeviceInfo(
        vendor_id=_clean(raw.get("VendorId") or raw.get("vendor_id")),
        product_id=_clean(raw.get("ProductId") or raw.get("product_id")),
        serial_number=_clean(raw.get("SerialNumber") or raw.get("serial_number")),
        device_name=_clean(raw.get("Name") or raw.get("device_name")),
        manufacturer=_clean(raw.get("Manufacturer") or raw.get("manufacturer")),
        device_type=_clean(raw.get("DeviceType") or raw.get("device_type")),
        filesystem=_clean(raw.get("FileSystem") or raw.get("filesystem")),
        drive_letter=_clean(raw.get("DriveLetter") or raw.get("drive_letter")),
    )


def scan_windows_devices() -> list[DeviceInfo]:
    """Scan USB devices with PowerShell; return an empty list on unavailable systems."""
    if platform.system() != "Windows":
        return []
    command = (
        "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB*' } | "
        "Select-Object FriendlyName,Manufacturer,Class,InstanceId | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        payload = json.loads(result.stdout)
        records = payload if isinstance(payload, list) else [payload]
        devices = []
        for record in records:
            instance_id = str(record.get("InstanceId", ""))
            parts = instance_id.split("\\")
            ids = parts[1].split("&") if len(parts) > 1 else []
            values = {
                "Name": record.get("FriendlyName"),
                "Manufacturer": record.get("Manufacturer"),
                "DeviceType": record.get("Class"),
                "VendorId": next((part[4:] for part in ids if part.upper().startswith("VID_")), None),
                "ProductId": next((part[4:] for part in ids if part.upper().startswith("PID_")), None),
                "SerialNumber": parts[-1] if parts else None,
            }
            devices.append(normalize_device(values))
        return devices
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("Windows USB scan unavailable: %s", exc)
        return []
