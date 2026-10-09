"""
Dynamic, specific security recommendations (Section 12).

Recommendations are always chosen to match the concrete condition
detected — a generic fallback is only used when nothing specific applies.
"""

from __future__ import annotations


def build_network_recommendations(
    *,
    authentication: str,
    encryption: str,
    wps_enabled: bool = False,
    unknown_device_count: int = 0,
    suspicious_device_detected: bool = False,
) -> list[str]:
    auth_u = (authentication or "").upper()
    enc_u = (encryption or "").upper()
    recs: list[str] = []

    if auth_u in {"OPEN", "NONE", ""}:
        recs.append("Enable WPA2 or WPA3 security.")
    elif "WEP" in auth_u:
        recs.append("Upgrade from WEP to WPA2/WPA3.")
    elif auth_u == "WPA":
        recs.append("Upgrade from legacy WPA to WPA2 or WPA3.")
    elif "WPA2" in auth_u and "WPA3" not in auth_u:
        recs.append("Consider WPA3 if your router and devices support it.")
    elif "WPA3" in auth_u:
        recs.append("WPA3 is the current best practice — no authentication upgrade needed.")

    if "TKIP" in enc_u:
        recs.append("Use AES/CCMP instead of TKIP.")

    if wps_enabled:
        recs.append("Disable WPS if not required.")

    if unknown_device_count == 1:
        recs.append("Verify the unknown device if it does not belong to an authorized user.")
    elif unknown_device_count > 1:
        recs.append(
            f"Verify the {unknown_device_count} unknown devices if they do not belong to "
            "authorized users."
        )
    if suspicious_device_detected:
        recs.append("Investigate the device flagged with suspicious characteristics.")

    # Always-applicable good hygiene, appended after anything specific.
    recs.append("Keep router firmware updated.")
    recs.append("Use a strong, unique WiFi password.")

    return recs
