"""Transparent rule-based risk scoring; this module intentionally uses no machine learning."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RiskAssessment:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def assess_device(*, unknown: bool, blocked: bool, missing_serial: bool, anomaly: bool, previously_seen: bool, repeated_unauthorized: bool = False) -> RiskAssessment:
    rules = [
        (unknown, 30, "Unknown USB device +30"),
        (blocked, 50, "Device is blocklisted +50"),
        (missing_serial, 15, "Missing serial number +15"),
        (anomaly, 25, "Potential Device Identity Anomaly +25"),
        (previously_seen is False, 20, "Previously unseen device +20"),
        (repeated_unauthorized, 25, "Repeated unauthorized attempts +25"),
    ]
    score = 0
    reasons = []
    for condition, points, reason in rules:
        if condition:
            score += points
            reasons.append(reason)
    score = min(score, 100)
    return RiskAssessment(score, risk_level(score), reasons)


def assess_file(*, file_extension: str, file_size: int = 0, file_count: int = 1, max_single_size: int = 100 * 1024 * 1024) -> RiskAssessment:
    extension = file_extension.lower()
    score = 0
    reasons: list[str] = []
    if extension in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi", ".dll"}:
        score += 20
        reasons.append("Potentially risky executable/script file +20")
    if extension in {".docx", ".xlsx", ".pdf", ".csv", ".sql", ".zip"}:
        score += 15
        reasons.append("Sensitive file extension indicator +15")
    if file_size > max_single_size:
        score += 20
        reasons.append("Large file transfer +20")
    if file_count > 100:
        score += 15
        reasons.append("Large number of files transferred +15")
    score = min(score, 100)
    return RiskAssessment(score, risk_level(score), reasons)
