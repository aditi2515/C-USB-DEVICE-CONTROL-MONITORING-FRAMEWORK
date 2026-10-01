"""Generate clearly marked records for presentations without a physical USB device."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from database.database import db
from database.models import Device, FileEvent, SecurityAlert, USBEvent, utc_now

app = create_app()
with app.app_context():
    demo_fingerprint = "demo-" + "0" * 59
    demo_device = Device.query.filter_by(fingerprint=demo_fingerprint).first()
    if demo_device is None:
        demo_device = Device(
            fingerprint=demo_fingerprint, vendor_id="0781", product_id="5567", serial_number="DEMO-001",
            device_name="SanDisk Demo Storage", manufacturer="Demo Manufacturer", device_type="USB Storage",
            drive_letter="E:", status="CONNECTED", authorization_status="AUTHORIZED", risk_score=10,
            connection_count=4, is_demo=True,
        )
        db.session.add(demo_device)
        db.session.flush()
    else:
        print("Demo device already exists; skipping duplicate demo records.")
        raise SystemExit(0)
    db.session.add_all([
        USBEvent(device_id=demo_device.id, event_type="CONNECT", vendor_id=demo_device.vendor_id, product_id=demo_device.product_id, serial_number=demo_device.serial_number, authorization_result="AUTHORIZED", action_taken="ALLOW", risk_score=10, description="DEMO DATA: authorized device connected", is_demo=True),
        FileEvent(device_id=demo_device.id, event_type="CREATE", file_path="E:/demo-report.xlsx", file_name="demo-report.xlsx", file_extension=".xlsx", file_size=24000, direction="SYSTEM_TO_USB", risk_level="MEDIUM", description="DEMO DATA: sensitive extension indicator", is_demo=True),
        FileEvent(device_id=demo_device.id, event_type="CREATE", file_path="E:/demo-tool.exe", file_name="demo-tool.exe", file_extension=".exe", file_size=120000, direction="SYSTEM_TO_USB", risk_level="HIGH", description="DEMO DATA: potentially risky executable/script file", is_demo=True),
        SecurityAlert(device_id=demo_device.id, severity="HIGH", alert_type="EXECUTABLE_TRANSFER", description="DEMO DATA: Potentially risky executable/script file copied to USB", evidence="demo-tool.exe", status="OPEN", is_demo=True),
        SecurityAlert(device_id=demo_device.id, severity="HIGH", alert_type="LARGE_FILE_TRANSFER", description="DEMO DATA: Potential Data Exfiltration Indicator", evidence="Transfer exceeded configured threshold", status="OPEN", is_demo=True),
    ])
    db.session.commit()
    print("Demo data generated. All records are marked DEMO DATA.")
