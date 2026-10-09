"""Validation helpers for network identifiers and user input."""

from __future__ import annotations

import re

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_valid_mac(mac: str | None) -> bool:
    """Return True if ``mac`` looks like a valid MAC address."""
    if not mac:
        return False
    return bool(_MAC_RE.match(mac.strip()))


def is_valid_ipv4(ip: str | None) -> bool:
    """Return True if ``ip`` looks like a valid dotted-quad IPv4 address."""
    if not ip or not _IPV4_RE.match(ip.strip()):
        return False
    return all(0 <= int(part) <= 255 for part in ip.strip().split("."))


def normalize_mac(mac: str | None) -> str:
    """Normalize a MAC address to upper-case colon-separated form, or 'Unknown'."""
    if not is_valid_mac(mac):
        return "Unknown"
    return mac.strip().upper().replace("-", ":")


def is_randomized_mac(mac: str | None) -> bool:
    """
    Heuristic: a MAC is 'locally administered' (often randomized by mobile
    OSes for privacy) when the second least-significant bit of the first
    octet is set.
    """
    if not is_valid_mac(mac):
        return False
    first_octet = int(mac.split(":")[0].split("-")[0], 16)
    return bool(first_octet & 0b00000010)


def safe_str(value, default: str = "Unknown") -> str:
    """Coerce a possibly-missing value to a display-safe string."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default
