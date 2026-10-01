from core.device_controller import DeviceController
from core.device_identifier import DeviceInfo
from core.file_monitor import calculate_sha256
from core.risk_engine import assess_device, assess_file, risk_level


def test_fingerprint_is_stable_sha256():
    device = DeviceInfo(vendor_id="1234", product_id="5678", serial_number="ABC")
    assert device.fingerprint == DeviceInfo(vendor_id="1234", product_id="5678", serial_number="ABC").fingerprint
    assert len(device.fingerprint) == 64


def test_risk_score_is_explainable_and_capped():
    assessment = assess_device(unknown=True, blocked=True, missing_serial=True, anomaly=True, previously_seen=False, repeated_unauthorized=True)
    assert assessment.score == 100
    assert "Missing serial number +15" in assessment.reasons
    assert risk_level(75) == "CRITICAL"


def test_executable_file_is_indicator_not_malware_claim():
    assessment = assess_file(file_extension=".exe")
    assert assessment.score == 20
    assert "Potentially risky executable/script file +20" in assessment.reasons


def test_hashing_streams_file(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"usb security")
    assert calculate_sha256(path) == "e8cd7906481b5013afb5da9d577e428fde756a66f94eceddcce95c7510f69690"


def test_simulated_controller_never_claims_real_block():
    result = DeviceController().simulate_block(object())
    assert result.action == "SIMULATED BLOCK"
    assert "operating-system change" in result.detail
