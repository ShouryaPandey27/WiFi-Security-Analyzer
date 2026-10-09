"""
Local network host discovery for the authorized subnet (Section 13).

Prefers Scapy-based ARP requests when Scapy (and sufficient privileges)
are available; falls back to the system ARP cache (`arp -a`) otherwise.
This module only ever probes hosts already present on the user's own
local subnet — it performs no scanning of remote/external networks.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field

from config.settings import settings
from utils.logger import get_logger
from utils.network_utils import (
    current_platform,
    get_local_ip,
    get_local_mac,
    guess_subnet_cidr,
    ping_sweep,
    run_command,
)
from utils.validators import is_valid_ipv4, normalize_mac


def is_real_host_mac(mac: str | None) -> bool:
    """Return True only for a plausible unicast host MAC address."""
    if not mac:
        return False
    try:
        normalized = normalize_mac(mac)
    except Exception:  # pragma: no cover - validation is best-effort
        return False

    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", normalized):
        return False

    octets = [int(part, 16) for part in normalized.split(":")]
    if not octets or all(value == 0 for value in octets):
        return False

    # Exclude multicast/broadcast addresses (LSB of first octet set),
    # which are not valid host MACs for this discovery use case.
    return (octets[0] & 1) == 0


logger = get_logger(__name__)

try:
    from scapy.all import ARP, Ether, srp  # type: ignore

    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - environment-dependent
    _SCAPY_AVAILABLE = False

DEFAULT_SSID_FALLBACK = "Unknown Network"


@dataclass
class DiscoveredHost:
    ip_address: str
    mac_address: str
    hostname: str = "Unknown"
    response_time: float | None = None


@dataclass
class DiscoveryOutcome:
    hosts: list[DiscoveredHost] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None
    method: str = "unavailable"


# ---------------------------------------------------------------------------
# Current connection detection — identifies which nearby network (if any)
# this host is actually, authorizedly associated with. Device discovery is
# only ever attempted for that one network; every other nearby network's
# device count is reported as unavailable rather than guessed.
# ---------------------------------------------------------------------------
def get_current_connection_bssid() -> str | None:
    """Best-effort detection of the BSSID this host is currently connected to."""
    plat = current_platform()
    try:
        if plat == "windows":
            return _current_bssid_windows()
        if plat == "linux":
            return _current_bssid_linux()
        if plat == "darwin":
            return _current_bssid_macos()
    except Exception as exc:  # noqa: BLE001 - detection must never crash the app
        logger.warning("Could not determine current WiFi connection: %s", exc)
    return None


def _current_bssid_windows() -> str | None:
    output = run_command(["netsh", "wlan", "show", "interfaces"])
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("BSSID"):
            match = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", line)
            if match:
                return normalize_mac(match.group(0))
    return None


def _current_bssid_linux() -> str | None:
    output = run_command(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"])
    for line in output.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 2 and parts[0].strip().lower() == "yes":
            return normalize_mac(parts[1].replace("\\:", ":"))
    # Fallback: iwgetid reports the AP's BSSID for the active connection.
    output = run_command(["iwgetid", "-a"])
    match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", output)
    return normalize_mac(match.group(0)) if match else None


def _current_bssid_macos() -> str | None:
    output = run_command([_AIRPORT_PATH_FOR_STATUS, "-I"])
    for line in output.splitlines():
        if "BSSID" in line and ":" in line:
            match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line)
            if match:
                return normalize_mac(match.group(0))
    return None


_AIRPORT_PATH_FOR_STATUS = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)


# ---------------------------------------------------------------------------
# Current network info — SSID / local IP / netmask / subnet / gateway for
# whichever network the host is presently connected to. Best-effort only:
# each field is resolved independently, and a failure on one field never
# prevents the others from being returned. Nothing here is invented; an
# unresolved field is None (or, for SSID only, a safe fallback string).
# ---------------------------------------------------------------------------
def get_current_ssid() -> str | None:
    """Best-effort detection of the SSID this host is currently connected to."""
    plat = current_platform()
    try:
        if plat == "windows":
            return _current_ssid_windows()
        if plat == "linux":
            return _current_ssid_linux()
        if plat == "darwin":
            return _current_ssid_macos()
    except Exception as exc:  # noqa: BLE001 - detection must never crash the app
        logger.warning("Could not determine current SSID: %s", exc)
    return None


def _current_ssid_windows() -> str | None:
    output = run_command(["netsh", "wlan", "show", "interfaces"])
    for line in output.splitlines():
        stripped = line.strip()
        # Must exclude "BSSID" lines, which also contain the substring
        # "SSID" but should never be reported as the network name.
        if stripped.startswith("SSID") and not stripped.startswith("BSSID"):
            _, _, value = stripped.partition(":")
            value = value.strip()
            return value or None
    return None


def _current_ssid_linux() -> str | None:
    output = run_command(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])
    for line in output.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 2 and parts[0].strip().lower() == "yes":
            ssid = parts[1].replace("\\:", ":").strip()
            return ssid or None
    # Fallback: iwgetid reports the SSID of the active connection directly.
    output = run_command(["iwgetid", "-r"])
    ssid = output.strip()
    return ssid or None


def _current_ssid_macos() -> str | None:
    output = run_command([_AIRPORT_PATH_FOR_STATUS, "-I"])
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSID:"):
            _, _, value = stripped.partition(":")
            value = value.strip()
            return value or None
    return None


def is_current_connection(ssid: str, bssid: str) -> bool:
    """
    Best-effort determination of whether the given (ssid, bssid) pair is
    the ONE network this host is currently, authorizedly connected to.

    Prefers BSSID matching (unique per access point, so it is reliable
    even when two nearby networks share an SSID). Falls back to SSID
    comparison only if the current BSSID could not be determined.
    """
    current_bssid = get_current_connection_bssid()
    if current_bssid and bssid:
        return normalize_mac(current_bssid) == normalize_mac(bssid)

    current_ssid = get_current_ssid()
    if current_ssid and current_ssid != DEFAULT_SSID_FALLBACK:
        return current_ssid == ssid

    return False


def get_current_gateway() -> str | None:
    """Best-effort detection of the default gateway for the active connection."""
    plat = current_platform()
    try:
        if plat == "windows":
            return _current_gateway_windows()
        if plat == "linux":
            return _current_gateway_linux()
        if plat == "darwin":
            return _current_gateway_macos()
    except Exception as exc:  # noqa: BLE001 - detection must never crash the app
        logger.warning("Could not determine default gateway: %s", exc)
    return None


def _current_gateway_windows() -> str | None:
    output = run_command(["ipconfig"])
    for line in output.splitlines():
        if "Default Gateway" in line:
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match:
                return match.group(1)
    return None


def _current_gateway_linux() -> str | None:
    output = run_command(["ip", "route", "show", "default"])
    match = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", output)
    return match.group(1) if match else None


def _current_gateway_macos() -> str | None:
    output = run_command(["route", "-n", "get", "default"])
    for line in output.splitlines():
        if "gateway:" in line:
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match:
                return match.group(1)
    return None


def _netmask_from_cidr(subnet_cidr: str) -> str | None:
    """Derive a dotted-decimal netmask from a CIDR string, e.g. '192.168.1.0/24'."""
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return str(network.netmask)
    except (ValueError, TypeError):
        return None


def get_current_network_info() -> dict[str, str | None]:
    """
    Best-effort snapshot of the currently connected local network.

    Returns a dict shaped like:
        {
            "ssid": "MyHomeWiFi",
            "local_ip": "192.168.1.10",
            "netmask": "255.255.255.0",
            "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1",
        }

    Every field is resolved independently and best-effort. Nothing is
    invented: unresolved fields are None, except SSID, which uses the
    safe fallback ``DEFAULT_SSID_FALLBACK`` when it cannot be determined.
    This function performs no ARP scanning — see discover_hosts() for
    that, which lives separately in this module and is unaffected by
    this function.
    """
    local_ip = get_local_ip()
    subnet_cidr = guess_subnet_cidr(local_ip) if local_ip else None
    netmask = _netmask_from_cidr(subnet_cidr) if subnet_cidr else None
    ssid = get_current_ssid() or DEFAULT_SSID_FALLBACK
    gateway = get_current_gateway()

    return {
        "ssid": ssid,
        "local_ip": local_ip,
        "netmask": netmask,
        "subnet": subnet_cidr,
        "gateway": gateway,
    }


def _resolve_hostname(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def _discover_with_scapy(subnet_cidr: str, timeout: int) -> list[DiscoveredHost]:
    hosts: list[DiscoveredHost] = []
    # Import Scapy symbols locally to avoid "possibly unbound" warnings
    # when Scapy isn't available in the static analysis environment.
    try:
        from scapy.all import Ether, ARP, srp  # type: ignore
    except Exception:  # pragma: no cover - runtime/import dependent
        raise
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_cidr)
    start = time.monotonic()
    answered, _ = srp(request, timeout=timeout, verbose=False)
    for _, received in answered:
        response_time = time.monotonic() - start
        ip_address = received.psrc
        mac_address = normalize_mac(received.hwsrc)
        if not is_real_host_mac(mac_address):
            continue
        hosts.append(
            DiscoveredHost(
                ip_address=ip_address,
                mac_address=mac_address,
                hostname=_resolve_hostname(ip_address),
                response_time=round(response_time, 4),
            )
        )
    return hosts


def _discover_with_arp_cache() -> list[DiscoveredHost]:
    """Fallback: read the OS ARP cache instead of actively probing."""
    plat = current_platform()
    if plat == "windows":
        output = run_command(["arp", "-a"])
        pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f\-]{17})\s+\w+"
        )
    else:
        output = run_command(["arp", "-a"])
        pattern = re.compile(
            r"\(( \d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:]{17})".replace(" ", "")
        )

    hosts: list[DiscoveredHost] = []
    for ip_address, mac_address in pattern.findall(output):
        if not is_valid_ipv4(ip_address):
            continue
        if not is_real_host_mac(mac_address):
            # Skip broadcast/multicast/all-zero ARP-cache entries — these
            # are not devices, and Windows repeats them under every
            # network adapter section (WiFi, Ethernet, VPN, virtual
            # adapters), which would otherwise show up as duplicates.
            continue
        hosts.append(
            DiscoveredHost(
                ip_address=ip_address,
                mac_address=normalize_mac(mac_address),
                hostname=_resolve_hostname(ip_address),
            )
        )
    return hosts


def _deduplicate_hosts(hosts: list[DiscoveredHost]) -> list[DiscoveredHost]:
    """
    Merge duplicate entries for the same physical device. Windows lists a
    separate ARP table per network adapter, so a machine with multiple
    adapters (WiFi + Ethernet + VPN + virtual adapters such as Hyper-V or
    Docker) can report the SAME device's MAC more than once. Keep the
    first occurrence (first-seen order preserved) per MAC address.
    """
    seen: dict[str, DiscoveredHost] = {}
    for host in hosts:
        key = host.mac_address or host.ip_address
        if key not in seen:
            seen[key] = host
    return list(seen.values())


def discover_hosts() -> DiscoveryOutcome:
    """Discover live hosts on the authorized local subnet."""
    start = time.monotonic()
    local_ip = get_local_ip()
    subnet_cidr = guess_subnet_cidr(local_ip)

    if not subnet_cidr:
        return DiscoveryOutcome(
            error="Could not determine local subnet (no active network connection).",
        )

    # Warm the OS ARP cache with a fast, concurrent ping sweep BEFORE
    # reading it. This needs no admin/root privileges or Npcap (unlike
    # raw ARP via Scapy), takes ~1-2 seconds for a /24, and is what makes
    # `arp -a`-based discovery actually find devices without the user
    # ever needing to run `arp -a` by hand first.
    if settings.device_ping_sweep_enabled:
        try:
            ping_sweep(
                subnet_cidr,
                timeout_ms=settings.device_ping_sweep_timeout_ms,
                max_workers=settings.device_ping_sweep_max_workers,
            )
        except Exception:  # noqa: BLE001 - sweep is best-effort only
            logger.exception("Ping sweep failed; continuing with ARP-cache read anyway.")

    try:
        scapy_hosts: list[DiscoveredHost] = []
        if _SCAPY_AVAILABLE:
            try:
                scapy_hosts = _discover_with_scapy(subnet_cidr, settings.device_scan_timeout_seconds)
            except PermissionError:
                logger.warning("Insufficient privileges for raw ARP scanning (Scapy skipped).")
            except Exception:  # noqa: BLE001 - Scapy failing must not skip the ARP-cache read
                logger.exception("Scapy ARP scan failed; continuing with ARP-cache read anyway.")

        # Always also read the (now ping-warmed) ARP cache and MERGE it
        # with any Scapy results, rather than treating them as
        # either/or. Some devices answer a raw ARP request but silently
        # drop ICMP pings (or vice versa, depending on OS/firewall), so
        # combining both methods finds more real devices than either
        # alone — this is what actually surfaces phones/tablets/etc.
        # alongside this machine on the same WiFi network.
        arp_cache_hosts = _discover_with_arp_cache()
        hosts = scapy_hosts + arp_cache_hosts
        if scapy_hosts and arp_cache_hosts:
            method = "scapy_arp+arp_cache"
        elif scapy_hosts:
            method = "scapy_arp"
        elif arp_cache_hosts:
            method = "arp_cache"
        else:
            method = "unavailable"
        error = None
        if not hosts:
            error = "No devices found on the local network."
    except Exception as exc:  # noqa: BLE001 - never let discovery crash the app
        logger.error("Unexpected error during device discovery: %s", exc)
        hosts, method, error = [], "error", f"Unexpected discovery error: {exc}"

    # Exclude this machine's own interface (by IP AND by MAC, since a
    # multi-adapter machine — WiFi + Ethernet + VPN — can otherwise have
    # its own entry survive an IP-only filter) and merge duplicate
    # ARP-table entries reported under different network adapters (see
    # _deduplicate_hosts docstring) so every OTHER real device on the
    # network is shown exactly once.
    local_mac = get_local_mac()
    hosts = [
        h for h in hosts
        if h.ip_address != local_ip and (not local_mac or h.mac_address != local_mac)
    ]
    hosts = _deduplicate_hosts(hosts)
    if not hosts and error is None:
        error = "No devices found on the local network."

    duration = time.monotonic() - start
    logger.info(
        "Device discovery complete: %d hosts in %.2fs (method=%s)",
        len(hosts),
        duration,
        method,
    )
    return DiscoveryOutcome(hosts=hosts, duration_seconds=duration, error=error, method=method)