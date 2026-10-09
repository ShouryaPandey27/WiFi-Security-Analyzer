from core.security_analyzer import analyze_network


def test_open_network_flags_vulnerability():
    assessment = analyze_network(
        ssid="FreeWiFi", bssid="AA:BB:CC:DD:EE:FF", authentication="Open", encryption="None"
    )
    assert any("unprotected" in v.lower() for v in assessment.vulnerabilities)
    assert "Enable WPA2 or WPA3 security." in assessment.recommendations


def test_wep_network_flags_vulnerability():
    assessment = analyze_network(
        ssid="OldRouter", bssid="11:22:33:44:55:66", authentication="WEP", encryption="WEP"
    )
    assert any("wep" in v.lower() for v in assessment.vulnerabilities)
    assert "Upgrade from WEP to WPA2/WPA3." in assessment.recommendations


def test_wpa2_network_has_no_vulnerabilities_by_default():
    assessment = analyze_network(
        ssid="HomeNet", bssid="AA:AA:AA:AA:AA:AA", authentication="WPA2", encryption="CCMP"
    )
    assert assessment.vulnerabilities == ["None detected"]


def test_wps_enabled_flags_vulnerability_and_recommendation():
    assessment = analyze_network(
        ssid="HomeNet", bssid="BB:BB:BB:BB:BB:BB", authentication="WPA2", encryption="CCMP",
        wps_enabled=True,
    )
    assert any("wps" in v.lower() for v in assessment.vulnerabilities)
    assert "Disable WPS if not required." in assessment.recommendations


def test_status_label_matches_risk_level():
    assessment = analyze_network(
        ssid="Test", bssid="CC:CC:CC:CC:CC:CC", authentication="WPA3", encryption="CCMP"
    )
    assert assessment.status_label == f"{assessment.risk.level} RISK"
