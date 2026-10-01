"""Application entry point and Flask application factory."""
from __future__ import annotations

import logging
import platform
import socket
import getpass

from flask import Flask, jsonify, render_template

from config import APP_NAME, APP_VERSION, DEMO_MODE, ENFORCEMENT_MODE, SECRET_KEY
from core.authorization import authorize_device
from core.device_controller import DeviceController
from core.device_identifier import DeviceInfo
from core.risk_engine import assess_device
from core.usb_monitor import USBMonitor
from core.event_logger import configure_logging
from database.database import db, init_database
from database.models import Device, Policy, SecurityAlert, USBEvent, utc_now
from routes.api import api


def create_app() -> Flask:
    configure_logging()
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    init_database(app)
    app.register_blueprint(api)

    def handle_connect(info: DeviceInfo) -> None:
        with app.app_context():
            device = Device.query.filter_by(fingerprint=info.fingerprint).first()
            previously_seen = device is not None
            if device is None:
                device = Device(fingerprint=info.fingerprint, device_name=info.device_name)
                db.session.add(device)
            device.vendor_id = info.vendor_id
            device.product_id = info.product_id
            device.serial_number = info.serial_number
            device.device_name = info.device_name
            device.manufacturer = info.manufacturer
            device.device_type = info.device_type
            device.filesystem = info.filesystem
            device.drive_letter = info.drive_letter
            device.last_seen = utc_now()
            device.connection_count = (device.connection_count or 0) + 1
            decision = authorize_device(device, Policy.query.all())
            assessment = assess_device(
                unknown=decision.status == "UNKNOWN",
                blocked=decision.status == "BLOCKED",
                missing_serial=info.serial_number == "UNKNOWN",
                anomaly=False,
                previously_seen=previously_seen,
            )
            device.status = "CONNECTED"
            device.authorization_status = decision.status
            device.risk_score = assessment.score
            device.is_blocked = decision.status == "BLOCKED"
            event = USBEvent(
                device=device, event_type="CONNECT", vendor_id=info.vendor_id,
                product_id=info.product_id, serial_number=info.serial_number,
                drive_letter=info.drive_letter, user_name=getpass.getuser(),
                hostname=socket.gethostname(), authorization_result=decision.status,
                action_taken=decision.action, risk_score=assessment.score,
                description=decision.reason,
            )
            db.session.add(event)
            if decision.status in {"BLOCKED", "UNAUTHORIZED"}:
                db.session.add(SecurityAlert(
                    device=device, severity="HIGH", alert_type="UNAUTHORIZED_DEVICE",
                    description=decision.reason or "Unauthorized USB device detected",
                    evidence=info.fingerprint,
                ))
                DeviceController().block_device(device)
            db.session.commit()

    def handle_remove(info: DeviceInfo) -> None:
        with app.app_context():
            device = Device.query.filter_by(fingerprint=info.fingerprint).first()
            if device is None:
                return
            device.status = "BLOCKED" if device.is_blocked else "DISCONNECTED"
            db.session.add(USBEvent(device=device, event_type="DISCONNECT", vendor_id=info.vendor_id, product_id=info.product_id, serial_number=info.serial_number, drive_letter=info.drive_letter, user_name=getpass.getuser(), hostname=socket.gethostname(), action_taken="RECORDED", risk_score=device.risk_score, description="USB device disconnected"))
            db.session.commit()

    app.extensions["usb_monitor"] = USBMonitor(on_connect=handle_connect, on_remove=handle_remove)

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", app_name=APP_NAME, version=APP_VERSION)

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "application": APP_NAME,
                "version": APP_VERSION,
                "platform": platform.system(),
                "database": "CONNECTED",
                "enforcement_mode": ENFORCEMENT_MODE,
                "demo_mode": DEMO_MODE,
            }
        )

    return app


app = create_app()

if __name__ == "__main__":
    logging.getLogger(__name__).info("Starting %s %s", APP_NAME, APP_VERSION)
    app.extensions["usb_monitor"].start()
    app.run(host="127.0.0.1", port=5000, debug=False)
