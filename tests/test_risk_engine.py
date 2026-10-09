from core.risk_engine import calculate_device_risk, calculate_network_risk, classify_level  # noqa: F401


def test_open_network_is_high_risk():
    result = calculate_network_risk(authentication="Open", encryption="None")
    assert result.score >= 50
    assert result.level in {"MEDIUM", "HIGH"}


def test_wep_network_is_high_risk_contribution():
    result = calculate_network_risk(authentication="WEP", encryption="WEP")
    assert result.score >= 40


def test_wpa2_ccmp_is_not_automatically_100_high():
    # Explicit spec requirement: WPA2 + CCMP must NOT become 100/100 HIGH.
    result = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    assert result.score < 100
    assert result.level in {"LOW", "MEDIUM"}


def test_wpa3_is_low_risk():
    result = calculate_network_risk(authentication="WPA3", encryption="CCMP")
    assert result.level == "LOW"
    assert result.score == 0


def test_wps_adds_points():
    baseline = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    with_wps = calculate_network_risk(authentication="WPA2", encryption="CCMP", wps_enabled=True)
    assert with_wps.score == baseline.score + 20


def test_score_never_exceeds_max():
    result = calculate_network_risk(
        authentication="Open",
        encryption="TKIP",
        wps_enabled=True,
        weak_configuration=True,
        suspicious_condition=True,
    )
    assert result.score <= 100


def test_classify_level_boundaries():
    assert classify_level(0) == "LOW"
    assert classify_level(30) == "LOW"
    assert classify_level(31) == "MEDIUM"
    assert classify_level(70) == "MEDIUM"
    assert classify_level(71) == "HIGH"
    assert classify_level(100) == "HIGH"


def test_device_risk_trusted_reduces_score():
    untrusted = calculate_device_risk(vendor_unknown=True)
    trusted = calculate_device_risk(vendor_unknown=True, trusted=True)
    assert trusted.score < untrusted.score


def test_device_risk_duplicate_ip_is_high():
    result = calculate_device_risk(duplicate_ip=True)
    assert result.score >= 40


def test_device_risk_score_never_negative():
    result = calculate_device_risk(trusted=True)
    assert result.score >= 0


def test_network_risk_unaffected_by_devices_when_not_provided():
    # A network must never become riskier just because device info exists —
    # only unknown/suspicious devices (explicitly passed) add points.
    baseline = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    assert baseline.score == 5


def test_network_risk_single_unknown_device_adds_ten():
    baseline = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    with_unknown = calculate_network_risk(
        authentication="WPA2", encryption="CCMP", unknown_device_count=1
    )
    assert with_unknown.score == baseline.score + 10


def test_network_risk_multiple_unknown_devices_adds_fifteen_flat():
    baseline = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    with_many = calculate_network_risk(
        authentication="WPA2", encryption="CCMP", unknown_device_count=5
    )
    # Flat +15 regardless of exactly how many, per spec (not per-device).
    assert with_many.score == baseline.score + 15


def test_network_risk_suspicious_device_adds_twenty():
    baseline = calculate_network_risk(authentication="WPA2", encryption="CCMP")
    with_suspicious = calculate_network_risk(
        authentication="WPA2", encryption="CCMP", suspicious_device_detected=True
    )
    assert with_suspicious.score == baseline.score + 20


def test_network_risk_many_known_devices_does_not_raise_risk():
    # Explicit spec requirement: many *known* (non-unknown, non-suspicious)
    # devices must never push a network toward HIGH risk on their own.
    result = calculate_network_risk(
        authentication="WPA2",
        encryption="CCMP",
        unknown_device_count=0,
        suspicious_device_detected=False,
    )
    assert result.level == "LOW"
