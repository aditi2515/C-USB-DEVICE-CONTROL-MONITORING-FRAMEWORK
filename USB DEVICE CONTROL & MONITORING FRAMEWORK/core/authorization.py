"""Allowlist and blocklist policy evaluation."""
from __future__ import annotations

from dataclasses import dataclass

from database.models import Device, Policy


@dataclass(slots=True)
class AuthorizationDecision:
    status: str
    action: str
    matched_rule: str | None = None
    reason: str = ""


def _matches(policy: Policy, device: Device) -> bool:
    if not policy.enabled:
        return False
    value = policy.value.strip().upper()
    candidates = {
        device.fingerprint.upper(),
        (device.vendor_id or "").upper(),
        (device.product_id or "").upper(),
        (device.serial_number or "").upper(),
    }
    return value in candidates


def authorize_device(device: Device, policies: list[Policy]) -> AuthorizationDecision:
    blocks = [policy for policy in policies if policy.policy_type in {"BLOCK_DEVICE", "BLOCK_VENDOR", "BLOCK_PRODUCT"}]
    allows = [policy for policy in policies if policy.policy_type in {"ALLOW_DEVICE", "ALLOW_VENDOR", "ALLOW_PRODUCT"}]
    for policy in blocks:
        if _matches(policy, device):
            return AuthorizationDecision("BLOCKED", "SIMULATED BLOCK", policy.policy_name, f"Matched block rule: {policy.policy_name}")
    for policy in allows:
        if _matches(policy, device):
            return AuthorizationDecision("AUTHORIZED", "ALLOW", policy.policy_name, f"Matched allow rule: {policy.policy_name}")
    unknown_policy = next((policy for policy in policies if policy.policy_type == "BLOCK_UNKNOWN" and policy.enabled), None)
    if unknown_policy:
        return AuthorizationDecision("UNAUTHORIZED", "SIMULATED BLOCK", unknown_policy.policy_name, "Unknown devices are restricted by policy")
    return AuthorizationDecision("UNKNOWN", "REVIEW", reason="No allowlist or blocklist rule matched")
