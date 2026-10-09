"""
WiFi network discovery (Section 8).

Uses native OS tooling to enumerate nearby access points:
  - Windows: `netsh wlan show networks mode=bssid`
  - Linux:   `nmcli -f ... dev wifi list`, falling back to `iwlist scan`
  - macOS:   the `airport` utility

This module performs discovery only — no cracking, injection, or
deauthentication. If no adapter/tooling is available, it returns an
empty, clearly-flagged result rather than fabricating data.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from config.settings import settings
from database.models import NetworkRecord
from utils.logger import get_logger
from utils.network_utils import current_platform, run_command
from utils.time_utils import now_iso

logger = get_logger(__name__)


@dataclass
class ScanOutcome:
    networks: list[NetworkRecord] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None
    adapter_available: bool = True


# ---------------------------------------------------------------------------
# Windows: netsh
# ---------------------------------------------------------------------------
def _scan_windows() -> tuple[list[NetworkRecord], str | None]:
    output = run_command(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        timeout=settings.scan_timeout_seconds,
    )
    if not output:
        return [], "No output from netsh (adapter unavailable or WiFi off)."

    networks: list[NetworkRecord] = []
    current: dict = {}

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("SSID") and ":" in line and "BSSID" not in line:
            ssid = line.split(":", 1)[1].strip() or "Hidden Network"
            current = {"ssid": ssid}
        elif line.startswith("Authentication"):
            current["authentication"] = line.split(":", 1)[1].strip()
        elif line.startswith("Encryption"):
            current["encryption"] = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[1].strip()
            # netsh splits the BSSID's colons across the "BSSID N :" prefix oddly
            # only in some locales; guard by re-detecting a MAC pattern below.
            mac_match = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", line)
            bssid = mac_match.group(0) if mac_match else bssid
            record = NetworkRecord(
                ssid=current.get("ssid", "Hidden Network"),
                bssid=bssid,
                authentication=current.get("authentication", "Unknown"),
                encryption=current.get("encryption", "Unknown"),
                last_seen=now_iso(),
            )
            networks.append(record)
        elif line.startswith("Signal"):
            if networks:
                pct_match = re.search(r"(\d+)%", line)
                if pct_match:
                    # Convert 0-100% signal quality to an approximate dBm scale.
                    pct = int(pct_match.group(1))
                    networks[-1].signal_strength = -100 + int(pct * 0.5)
        elif line.startswith("Channel"):
            if networks:
                chan_match = re.search(r"(\d+)", line)
                if chan_match:
                    networks[-1].channel = int(chan_match.group(1))

    return networks, None


# ---------------------------------------------------------------------------
# Linux: nmcli (preferred), fallback to iwlist
# ---------------------------------------------------------------------------
def _scan_linux() -> tuple[list[NetworkRecord], str | None]:
    output = run_command(
        [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,SIGNAL,CHAN,SECURITY",
            "dev",
            "wifi",
            "list",
        ],
        timeout=settings.scan_timeout_seconds,
    )
    networks: list[NetworkRecord] = []

    if output:
        for line in output.splitlines():
            # nmcli terse output escapes ':' inside BSSID with '\:'
            parts = re.split(r"(?<!\\):", line)
            if len(parts) < 5:
                continue
            ssid, bssid, signal, channel, security = [p.replace("\\:", ":") for p in parts[:5]]
            auth, enc = _split_nmcli_security(security)
            networks.append(
                NetworkRecord(
                    ssid=ssid or "Hidden Network",
                    bssid=bssid or "Unknown",
                    signal_strength=_percent_to_dbm(signal),
                    channel=int(channel) if channel.isdigit() else None,
                    authentication=auth,
                    encryption=enc,
                    last_seen=now_iso(),
                )
            )
        return networks, None

    # Fallback: iwlist
    iwlist_output = run_command(["iwlist", "scan"], timeout=settings.scan_timeout_seconds)
    if not iwlist_output:
        return [], "No WiFi adapter/tooling detected (nmcli and iwlist unavailable)."

    current: dict = {}
    for raw in iwlist_output.splitlines():
        line = raw.strip()
        if line.startswith("Cell"):
            if current.get("bssid"):
                networks.append(_record_from_iwlist(current))
            mac_match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
            current = {"bssid": mac_match.group(0) if mac_match else "Unknown"}
        elif line.startswith("ESSID"):
            current["ssid"] = line.split(":", 1)[1].strip('"') or "Hidden Network"
        elif line.startswith("Channel"):
            chan_match = re.search(r"(\d+)", line)
            if chan_match:
                current["channel"] = int(chan_match.group(1))
        elif "Encryption key" in line:
            current["encrypted"] = "on" in line.lower()
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["authentication"] = "WPA2"
        elif "WPA Version 1" in line:
            current["authentication"] = "WPA"
    if current.get("bssid"):
        networks.append(_record_from_iwlist(current))

    return networks, None


def _record_from_iwlist(current: dict) -> NetworkRecord:
    encrypted = current.get("encrypted", False)
    auth = current.get("authentication") or ("Unknown" if encrypted else "Open")
    return NetworkRecord(
        ssid=current.get("ssid", "Hidden Network"),
        bssid=current.get("bssid", "Unknown"),
        channel=current.get("channel"),
        authentication=auth,
        encryption="CCMP" if "WPA" in auth else "Unknown",
        last_seen=now_iso(),
    )


def _split_nmcli_security(security: str) -> tuple[str, str]:
    security = security or ""
    if not security:
        return "Open", "None"
    auth = "Unknown"
    if "WPA3" in security and "WPA2" in security:
        auth = "WPA2/WPA3"
    elif "WPA3" in security:
        auth = "WPA3"
    elif "WPA2" in security:
        auth = "WPA2"
    elif "WPA" in security:
        auth = "WPA"
    elif "WEP" in security:
        auth = "WEP"
    enc = "CCMP" if "WPA" in security else ("WEP" if "WEP" in security else "Unknown")
    return auth, enc


def _percent_to_dbm(signal: str) -> int | None:
    if not signal or not signal.isdigit():
        return None
    pct = int(signal)
    return -100 + int(pct * 0.5)


# ---------------------------------------------------------------------------
# macOS: airport
# ---------------------------------------------------------------------------
_AIRPORT_PATH = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)


def _scan_macos() -> tuple[list[NetworkRecord], str | None]:
    output = run_command([_AIRPORT_PATH, "-s"], timeout=settings.scan_timeout_seconds)
    if not output:
        return [], "airport utility unavailable or WiFi adapter off."

    networks: list[NetworkRecord] = []
    lines = output.splitlines()[1:]  # skip header
    for line in lines:
        parts = line.split()
        if len(parts) < 7:
            continue
        ssid = parts[0]
        bssid = parts[1]
        rssi = parts[2]
        channel = parts[3]
        security = " ".join(parts[6:])
        auth = "WPA2" if "WPA2" in security else ("WPA3" if "WPA3" in security else "Open")
        networks.append(
            NetworkRecord(
                ssid=ssid or "Hidden Network",
                bssid=bssid,
                signal_strength=int(rssi) if rssi.lstrip("-").isdigit() else None,
                channel=int(channel) if channel.isdigit() else None,
                authentication=auth,
                encryption="CCMP" if "WPA" in security else "Unknown",
                last_seen=now_iso(),
            )
        )
    return networks, None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def scan_networks() -> ScanOutcome:
    """Discover nearby WiFi networks using the best available OS backend."""
    start = time.monotonic()
    plat = current_platform()

    try:
        if plat == "windows":
            networks, error = _scan_windows()
        elif plat == "linux":
            networks, error = _scan_linux()
        elif plat == "darwin":
            networks, error = _scan_macos()
        else:
            networks, error = [], f"Unsupported platform: {plat}"
    except Exception as exc:  # noqa: BLE001 - never let a scan crash the app
        logger.error("Unexpected error during WiFi scan: %s", exc)
        networks, error = [], f"Unexpected scan error: {exc}"

    # De-duplicate by BSSID (some backends can double-report).
    deduped: dict[str, NetworkRecord] = {}
    for net in networks:
        deduped[net.bssid] = net

    duration = time.monotonic() - start
    adapter_available = error is None or bool(deduped)

    if not deduped and error is None:
        error = "No networks detected."

    logger.info(
        "WiFi scan complete: %d networks in %.2fs (platform=%s)",
        len(deduped),
        duration,
        plat,
    )
    return ScanOutcome(
        networks=list(deduped.values()),
        duration_seconds=duration,
        error=error,
        adapter_available=adapter_available,
    )
