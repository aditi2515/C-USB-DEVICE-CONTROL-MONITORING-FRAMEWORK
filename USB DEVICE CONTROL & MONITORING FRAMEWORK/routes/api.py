"""JSON API for dashboard data and policy actions."""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from core.device_identifier import DeviceInfo
from core.risk_engine import assess_device
from database.database import db
from database.models import AuditLog, Device, FileEvent, Policy, SecurityAlert, USBEvent

api = Blueprint("api", __name__, url_prefix="/api")


def _device_json(device: Device) -> dict:
    return {
        "id": device.id, "name": device.device_name, "fingerprint": device.fingerprint,
        "vendor_id": device.vendor_id, "product_id": device.product_id, "serial_number": device.serial_number,
        "status": device.status, "authorization_status": device.authorization_status,
        "risk_score": device.risk_score, "is_blocked": device.is_blocked, "is_demo": device.is_demo,
    }


@api.get("/devices")
def devices():
    return jsonify([_device_json(device) for device in Device.query.order_by(Device.last_seen.desc()).all()])


@api.get("/events")
def events():
    rows = USBEvent.query.order_by(USBEvent.timestamp.desc()).limit(100).all()
    return jsonify([{"id": row.id, "event_type": row.event_type, "timestamp": row.timestamp.isoformat(), "device": row.device.device_name if row.device else "UNKNOWN", "risk_score": row.risk_score, "action_taken": row.action_taken, "is_demo": row.is_demo} for row in rows])


@api.get("/file-events")
def file_events():
    rows = FileEvent.query.order_by(FileEvent.timestamp.desc()).limit(100).all()
    return jsonify([{"id": row.id, "event_type": row.event_type, "timestamp": row.timestamp.isoformat(), "file_name": row.file_name, "direction": row.direction, "risk_level": row.risk_level, "is_demo": row.is_demo} for row in rows])


@api.get("/alerts")
def alerts():
    rows = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(100).all()
    return jsonify([{"id": row.id, "severity": row.severity, "alert_type": row.alert_type, "description": row.description, "status": row.status, "timestamp": row.timestamp.isoformat(), "is_demo": row.is_demo} for row in rows])


@api.get("/policies")
def policies():
    return jsonify([{"id": row.id, "name": row.policy_name, "type": row.policy_type, "value": row.value, "enabled": row.enabled} for row in Policy.query.order_by(Policy.policy_type).all()])


@api.post("/policies/allow")
def add_allow_policy():
    payload = request.get_json(silent=True) or {}
    value = str(payload.get("value", "")).strip()
    if not value:
        return jsonify({"error": "value is required"}), 400
    policy = Policy(policy_name=payload.get("name", f"Allow {value}"), policy_type="ALLOW_DEVICE", value=value)
    db.session.add(policy)
    db.session.commit()
    return jsonify({"id": policy.id, "message": "Allow policy created"}), 201


@api.post("/policies/block")
def add_block_policy():
    payload = request.get_json(silent=True) or {}
    value = str(payload.get("value", "")).strip()
    if not value:
        return jsonify({"error": "value is required"}), 400
    policy = Policy(policy_name=payload.get("name", f"Block {value}"), policy_type="BLOCK_DEVICE", value=value)
    db.session.add(policy)
    db.session.commit()
    return jsonify({"id": policy.id, "message": "Block policy created"}), 201


@api.get("/statistics")
def statistics():
    return jsonify({
        "total_devices": Device.query.count(),
        "authorized_devices": Device.query.filter_by(authorization_status="AUTHORIZED").count(),
        "unauthorized_devices": Device.query.filter(Device.authorization_status.in_(["UNKNOWN", "UNAUTHORIZED"])).count(),
        "blocked_devices": Device.query.filter_by(is_blocked=True).count(),
        "security_alerts": SecurityAlert.query.filter_by(status="OPEN").count(),
        "files_audited": FileEvent.query.count(),
    })
