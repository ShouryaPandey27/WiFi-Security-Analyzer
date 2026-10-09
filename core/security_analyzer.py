"""
WiFi security analysis: classifies authentication/encryption, flags
weaknesses, and drives the risk engine + recommendation engine to produce
a fully explained security assessment per network (Sections 9 & 11).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.recommendation_engine import build_network_recommendations
from core.risk_engine import RiskResult, calculate_network_risk
from database.models import NetworkRecord
from utils.logger import get_logger

logger = get_logger(__name__)

KNOWN_AUTH_TYPES = {"OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3"}


@dataclass
class SecurityAssessment:
    authentication: str
    encryption: str
    risk: RiskResult
    vulnerabilities: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def status_label(self) -> str:
        return f"{self.risk.level} RISK"


# Stable identifiers for every vulnerability the analyzer can report, mapped to
# the exact message shown to users. Identifiers let the evaluator
# (core/vulnerability_evaluator.py) check detections without matching free text.
VULN_OPEN_NETWORK = "OPEN_NETWORK"
VULN_WEP = "WEP"
VULN_LEGACY_WPA = "LEGACY_WPA"
VULN_TKIP = "TKIP_CIPHER"
VULN_WPS = "WPS_ENABLED"
VULN_SUSPICIOUS_DEVICE = "SUSPICIOUS_DEVICE"

VULNERABILITY_MESSAGES: dict[str, str] = {
    VULN_OPEN_NETWORK: "No authentication required — traffic and access are unprotected.",
    VULN_WEP: "WEP encryption is cryptographically broken and trivially crackable.",
    VULN_LEGACY_WPA: "Legacy WPA is deprecated and vulnerable to known attacks.",
    VULN_TKIP: "TKIP cipher is weaker than AES/CCMP and considered legacy.",
    VULN_WPS: "WPS is enabled, which is susceptible to PIN brute-force attacks.",
    VULN_SUSPICIOUS_DEVICE: "A connected device shows suspicious characteristics.",
}
NO_VULNERABILITY_MESSAGE = "None detected"


def _detect_vulnerabilities(
    auth: str, encryption: str, wps_enabled: bool, suspicious_device_detected: bool
) -> list[str]:
    vulns: list[str] = []
    auth_u = (auth or "").upper()
    enc_u = (encryption or "").upper()

    if auth_u in {"OPEN", "NONE", ""}:
        vulns.append(VULNERABILITY_MESSAGES[VULN_OPEN_NETWORK])
    if "WEP" in auth_u:
        vulns.append(VULNERABILITY_MESSAGES[VULN_WEP])
    if auth_u == "WPA":
        vulns.append(VULNERABILITY_MESSAGES[VULN_LEGACY_WPA])
    if "TKIP" in enc_u:
        vulns.append(VULNERABILITY_MESSAGES[VULN_TKIP])
    if wps_enabled:
        vulns.append(VULNERABILITY_MESSAGES[VULN_WPS])
    if suspicious_device_detected:
        vulns.append(VULNERABILITY_MESSAGES[VULN_SUSPICIOUS_DEVICE])
    if not vulns:
        vulns.append(NO_VULNERABILITY_MESSAGE)
    return vulns


def analyze_network(
    *,
    ssid: str,
    bssid: str,
    authentication: str,
    encryption: str,
    wps_enabled: bool = False,
    weak_configuration: bool = False,
    suspicious_condition: bool = False,
    unknown_device_count: int = 0,
    suspicious_device_detected: bool = False,
) -> SecurityAssessment:
    """
    Produce a full, explainable security assessment for one network.

    ``unknown_device_count``/``suspicious_device_detected`` should only be
    passed for networks where connected-device information was actually
    determined (see database.models.NetworkRecord.device_info_available).
    """
    risk = calculate_network_risk(
        authentication=authentication,
        encryption=encryption,
        wps_enabled=wps_enabled,
        weak_configuration=weak_configuration,
        suspicious_condition=suspicious_condition,
        unknown_device_count=unknown_device_count,
        suspicious_device_detected=suspicious_device_detected,
    )
    vulnerabilities = _detect_vulnerabilities(
        authentication, encryption, wps_enabled, suspicious_device_detected
    )
    recommendations = build_network_recommendations(
        authentication=authentication,
        encryption=encryption,
        wps_enabled=wps_enabled,
        unknown_device_count=unknown_device_count,
        suspicious_device_detected=suspicious_device_detected,
    )

    logger.debug("Analyzed %s (%s): %s/100 %s", ssid, bssid, risk.score, risk.level)
    return SecurityAssessment(
        authentication=authentication or "Unknown",
        encryption=encryption or "Unknown",
        risk=risk,
        vulnerabilities=vulnerabilities,
        recommendations=recommendations,
    )


def apply_assessment(network: NetworkRecord, assessment: SecurityAssessment) -> NetworkRecord:
    """Mutate a NetworkRecord in place with the results of an assessment."""
    network.risk_score = assessment.risk.score
    network.risk_level = assessment.risk.level
    network.reasons = assessment.risk.reasons
    network.recommendations = assessment.recommendations
    return network
