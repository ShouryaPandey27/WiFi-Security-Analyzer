"""
Transparent, explainable risk scoring engine for WiFi networks.

Every score is built from named, additive factors so the GUI can always
show *why* a network received its score (Section 10 of the spec).
"""

from __future__ import annotations

from dataclasses import dataclass

from utils.logger import get_logger

logger = get_logger(__name__)

MAX_SCORE = 100

# Risk level thresholds (inclusive lower bound).
LOW_MAX = 30
MEDIUM_MAX = 70


@dataclass
class RiskFactor:
    label: str
    points: int


@dataclass
class RiskResult:
    score: int
    level: str
    factors: list[RiskFactor]

    @property
    def reasons(self) -> list[str]:
        return [f"{f.label} ({'+' if f.points >= 0 else ''}{f.points})" for f in self.factors]


def classify_level(score: int) -> str:
    if score <= LOW_MAX:
        return "LOW"
    if score <= MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


def calculate_network_risk(
    *,
    authentication: str,
    encryption: str,
    wps_enabled: bool = False,
    weak_configuration: bool = False,
    suspicious_condition: bool = False,
    unknown_device_count: int = 0,
    suspicious_device_detected: bool = False,
) -> RiskResult:
    """
    Compute an explainable 0-100 risk score for a WiFi network.

    Base points come from the authentication protocol; encryption cipher
    and optional heuristics add on top. The result is capped at 100 and
    never negative. WPA2 + CCMP intentionally lands LOW/MEDIUM, not a
    reflexive 100/100 HIGH.

    ``unknown_device_count`` and ``suspicious_device_detected`` should
    only be passed when connected-device information was actually
    determined for this network (see database.models.NetworkRecord.
    device_info_available) — a network must never be marked riskier
    based on device data that couldn't be reliably discovered. Having
    many connected devices alone never forces HIGH risk; only unknown
    or suspicious devices contribute points.
    """
    factors: list[RiskFactor] = []
    auth = (authentication or "").strip().upper()
    enc = (encryption or "").strip().upper()

    # --- Authentication protocol -------------------------------------------------
    if auth in {"OPEN", "NONE", ""}:
        factors.append(RiskFactor("Open network (no authentication)", 50))
    elif "WEP" in auth:
        factors.append(RiskFactor("WEP authentication", 40))
    elif auth == "WPA" or (auth.startswith("WPA") and "WPA2" not in auth and "WPA3" not in auth):
        factors.append(RiskFactor("WPA (legacy) authentication", 20))
    elif "WPA2" in auth and "WPA3" in auth:
        factors.append(RiskFactor("WPA2/WPA3 mixed mode", 3))
    elif "WPA3" in auth:
        factors.append(RiskFactor("WPA3 authentication", 0))
    elif "WPA2" in auth:
        factors.append(RiskFactor("WPA2 authentication", 5))
    else:
        factors.append(RiskFactor(f"Unrecognized authentication ({authentication})", 15))

    # --- Encryption cipher --------------------------------------------------------
    if "TKIP" in enc:
        factors.append(RiskFactor("TKIP encryption (weaker cipher)", 20))
    elif enc in {"UNKNOWN", ""}:
        factors.append(RiskFactor("Unknown encryption cipher", 5))
    elif "CCMP" in enc or "AES" in enc:
        pass  # CCMP/AES is the modern, expected cipher — no penalty.

    # --- Optional heuristics --------------------------------------------------------
    if wps_enabled:
        factors.append(RiskFactor("WPS enabled", 20))
    if weak_configuration:
        factors.append(RiskFactor("Weak configuration detected", 15))
    if suspicious_condition:
        factors.append(RiskFactor("Suspicious condition detected", 10))

    # --- Connected device context (only when reliably determined) --------------
    device_factors: list[RiskFactor] = []
    if unknown_device_count == 1:
        device_factors.append(RiskFactor("1 unknown device detected", 10))
    elif unknown_device_count > 1:
        device_factors.append(
            RiskFactor(f"Multiple unknown devices detected ({unknown_device_count})", 15)
        )
    if suspicious_device_detected:
        device_factors.append(RiskFactor("Suspicious device condition detected", 20))

    config_score = sum(f.points for f in factors)
    device_points = sum(f.points for f in device_factors)
    factors.extend(device_factors)

    if config_score <= LOW_MAX:
        # The network's OWN configuration (authentication, encryption,
        # WPS, etc.) is already secure enough to be LOW on its own —
        # unidentified/suspicious devices are a signal worth
        # investigating, but they should not by themselves push a
        # securely-configured network into MEDIUM or HIGH. If the
        # configuration itself is already risky (config_score > LOW_MAX),
        # device factors continue to add normally below.
        raw_score = min(config_score + device_points, LOW_MAX)
    else:
        raw_score = config_score + device_points

    score = max(0, min(MAX_SCORE, raw_score))
    level = classify_level(score)

    logger.debug("Risk computed: score=%d level=%s factors=%s", score, level, factors)
    return RiskResult(score=score, level=level, factors=factors)


# ===========================================================================
# Device risk (Section 14 of the spec)
# ===========================================================================
def calculate_device_risk(
    *,
    vendor_unknown: bool = False,
    randomized_mac: bool = False,
    long_offline: bool = False,
    duplicate_ip: bool = False,
    suspicious_hostname: bool = False,
    trusted: bool = False,
) -> RiskResult:
    """Compute an explainable 0-100 risk score for a connected device."""
    factors: list[RiskFactor] = []

    if vendor_unknown:
        factors.append(RiskFactor("Unknown vendor", 20))
    if randomized_mac:
        factors.append(RiskFactor("Randomized MAC address", 20))
    if long_offline:
        factors.append(RiskFactor("Long offline period", 5))
    if duplicate_ip:
        factors.append(RiskFactor("Duplicate IP address on network", 40))
    if suspicious_hostname:
        factors.append(RiskFactor("Suspicious hostname pattern", 20))
    if trusted:
        factors.append(RiskFactor("Marked as trusted device", -20))

    raw_score = sum(f.points for f in factors)
    score = max(0, min(MAX_SCORE, raw_score))
    level = classify_level(score)

    return RiskResult(score=score, level=level, factors=factors)