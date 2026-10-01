"""Database entities for devices, activity, policies, alerts, and audit history."""
from __future__ import annotations

from datetime import datetime, timezone

from database.database import db


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class Device(TimestampMixin, db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(64), unique=True, index=True, nullable=False)
    vendor_id = db.Column(db.String(32), index=True)
    product_id = db.Column(db.String(32), index=True)
    serial_number = db.Column(db.String(255), index=True)
    device_name = db.Column(db.String(255), nullable=False)
    manufacturer = db.Column(db.String(255))
    device_type = db.Column(db.String(100))
    filesystem = db.Column(db.String(64))
    drive_letter = db.Column(db.String(8))
    first_seen = db.Column(db.DateTime, default=utc_now, nullable=False)
    last_seen = db.Column(db.DateTime, default=utc_now, nullable=False)
    connection_count = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(32), default="UNKNOWN", nullable=False)
    authorization_status = db.Column(db.String(32), default="UNKNOWN", nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    is_demo = db.Column(db.Boolean, default=False, nullable=False)

    events = db.relationship("USBEvent", back_populates="device", cascade="all, delete-orphan")
    file_events = db.relationship("FileEvent", back_populates="device")
    alerts = db.relationship("SecurityAlert", back_populates="device")


class USBEvent(db.Model):
    __tablename__ = "usb_events"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True, index=True)
    event_type = db.Column(db.String(32), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    vendor_id = db.Column(db.String(32))
    product_id = db.Column(db.String(32))
    serial_number = db.Column(db.String(255))
    drive_letter = db.Column(db.String(8))
    user_name = db.Column(db.String(255))
    hostname = db.Column(db.String(255))
    authorization_result = db.Column(db.String(64))
    action_taken = db.Column(db.String(64))
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    description = db.Column(db.Text)
    is_demo = db.Column(db.Boolean, default=False, nullable=False)

    device = db.relationship("Device", back_populates="events")


class FileEvent(db.Model):
    __tablename__ = "file_events"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    event_type = db.Column(db.String(32), nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    file_name = db.Column(db.String(255))
    file_extension = db.Column(db.String(32))
    file_size = db.Column(db.Integer)
    source_location = db.Column(db.Text)
    destination_location = db.Column(db.Text)
    direction = db.Column(db.String(32), default="DIRECTION_UNCERTAIN")
    sha256_hash = db.Column(db.String(64))
    username = db.Column(db.String(255))
    risk_level = db.Column(db.String(32), default="LOW")
    description = db.Column(db.Text)
    is_demo = db.Column(db.Boolean, default=False, nullable=False)

    device = db.relationship("Device", back_populates="file_events")


class Policy(TimestampMixin, db.Model):
    __tablename__ = "policies"

    id = db.Column(db.Integer, primary_key=True)
    policy_name = db.Column(db.String(255), nullable=False)
    policy_type = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    severity = db.Column(db.String(32), nullable=False, index=True)
    alert_type = db.Column(db.String(64), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text)
    status = db.Column(db.String(32), default="OPEN", nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    is_demo = db.Column(db.Boolean, default=False, nullable=False)

    device = db.relationship("Device", back_populates="alerts")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False)
    username = db.Column(db.String(255))
    action = db.Column(db.String(128), nullable=False)
    resource = db.Column(db.String(128))
    resource_id = db.Column(db.String(128))
    result = db.Column(db.String(64), nullable=False)
    details = db.Column(db.Text)
