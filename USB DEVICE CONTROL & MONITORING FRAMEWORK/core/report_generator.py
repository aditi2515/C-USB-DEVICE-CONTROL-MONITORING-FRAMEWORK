"""Generate lightweight CSV, JSON, and HTML security reports."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from config import EXPORT_DIR, REPORT_DIR, ensure_directories
from database.models import Device, FileEvent, SecurityAlert, USBEvent


def build_report() -> dict:
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "executive_summary": {
            "devices": Device.query.count(),
            "usb_events": USBEvent.query.count(),
            "file_events": FileEvent.query.count(),
            "open_alerts": SecurityAlert.query.filter_by(status="OPEN").count(),
        },
        "devices": [{"name": d.device_name, "fingerprint": d.fingerprint, "authorization": d.authorization_status, "risk_score": d.risk_score, "demo": d.is_demo} for d in Device.query.all()],
        "alerts": [{"severity": a.severity, "type": a.alert_type, "description": a.description, "status": a.status, "demo": a.is_demo} for a in SecurityAlert.query.all()],
        "limitations": [
            "Filesystem events cannot always establish exact Windows copy direction; uncertain cases are labeled DIRECTION_UNCERTAIN.",
            "Executable and large-transfer indicators are not proof of malware or data theft.",
            "Simulation mode records intended actions without changing operating-system device state.",
        ],
    }


def generate_report(format_name: str = "json") -> Path:
    ensure_directories()
    report = build_report()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if format_name == "json":
        path = EXPORT_DIR / f"security-report-{timestamp}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif format_name == "html":
        path = REPORT_DIR / f"security-report-{timestamp}.html"
        summary = report["executive_summary"]
        rows = "".join(f"<tr><td>{a['severity']}</td><td>{a['type']}</td><td>{a['description']}</td></tr>" for a in report["alerts"])
        path.write_text(f"<html><head><title>USB Security Report</title></head><body><h1>USB Security Report</h1><p>Generated: {report['generated_at']}</p><h2>Executive Summary</h2><pre>{json.dumps(summary, indent=2)}</pre><h2>Alerts</h2><table border='1'><tr><th>Severity</th><th>Type</th><th>Description</th></tr>{rows}</table><h2>Limitations</h2><ul>{''.join(f'<li>{item}</li>' for item in report['limitations'])}</ul></body></html>", encoding="utf-8")
    elif format_name == "csv":
        path = EXPORT_DIR / f"security-alerts-{timestamp}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["severity", "type", "description", "status", "demo"])
            writer.writeheader()
            writer.writerows(report["alerts"])
    else:
        raise ValueError("format_name must be json, html, or csv")
    return path
