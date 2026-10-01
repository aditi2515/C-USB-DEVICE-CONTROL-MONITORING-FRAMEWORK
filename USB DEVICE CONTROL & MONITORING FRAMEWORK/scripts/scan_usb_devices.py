"""Scan currently visible USB devices without inventing unavailable information."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.device_identifier import scan_windows_devices

print("=" * 52)
print("USB DEVICE SECURITY SCAN")
print("=" * 52)
devices = scan_windows_devices()
if not devices:
    print("No USB devices returned by the Windows scan, or the scan is unavailable.")
for device in devices:
    print(f"Device: {device.device_name}")
    print(f"Vendor ID: {device.vendor_id}")
    print(f"Product ID: {device.product_id}")
    print(f"Serial: {device.serial_number}")
    print(f"Manufacturer: {device.manufacturer}")
    print(f"Drive: {device.drive_letter}")
    print(f"Device Type: {device.device_type}")
    print(f"Fingerprint: {device.fingerprint}")
    print("Authorization: UNKNOWN (not evaluated by CLI)")
    print("Risk Score: UNKNOWN (not evaluated by CLI)")
    print("Status: CONNECTED")
    print("=" * 52)
