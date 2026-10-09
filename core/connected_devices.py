"""
Per-network connected device association.

IMPORTANT: nearby WiFi scanning only reveals information about each
access point — never its connected clients. This module only attempts
device discovery for the ONE network the host is currently, authorizedly
associated with. Every other nearby network's device information is
reported as unavailable rather than fabricated.

This is intentionally NOT a standalone "connected devices scanner" with
its own GUI page — call :func:`associate_devices_for_network` from the
WiFi scan workflow only, for the single matching network.

DISCOVERY STRATEGY:
This module prefers the project's primary discovery path,
``core.network_discovery.discover_hosts()``, when it is importable and
runs without raising. If that module is unavailable (import error) or
raises unexpectedly, this module falls back to a fully self-contained
Windows-safe implementation (local IP detection, subnet detection,
Scapy ARP scan, ``arp -a`` cache fallback, hostname resolution) defined
below, so this module can function on its own if needed. In normal
operation with a healthy ``network_discovery`` module, only the primary
path runs — the fallback exists for resilience, not as a second scanner
running in parallel.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field

from config.settings import settings
from core.device_classifier import classify_device
from core.risk_engine import calculate_device_risk
from core.vendor_lookup import lookup_vendor
from database.models import DeviceRecord
from utils.logger import get_logger
from utils.network_utils import (
    current_platform,
    get_local_ip,
    get_local_mac,
    guess_subnet_cidr,
    ping_sweep,
    run_command,
)
from utils.time_utils import now_iso
from utils.validators import is_randomized_mac, is_valid_ipv4, normalize_mac

logger = get_logger(__name__)

try:
    from database.repositories import DeviceRepository as _DeviceRepository
except Exception:  # noqa: BLE001 - trust lookup is a nice-to-have, never fatal
    _DeviceRepository = None


def _lookup_trusted(mac_address: str) -> bool:
    """
    Best-effort lookup of a previously-saved "trusted" flag for this MAC.

    A live device scan builds brand-new DeviceRecord objects every time,
    so without this, marking a device "Trusted" in the GUI would appear
    to be forgotten the next time the user clicks Rescan.
    """
    if _DeviceRepository is None:
        return False
    try:
        existing = _DeviceRepository().get_by_mac(mac_address)
        return bool(existing.trusted) if existing else False
    except Exception:  # noqa: BLE001 - never let this abort a device scan
        return False


FALLBACK_DEVICE_NAME = "Unknown Device"

_SUSPICIOUS_HOSTNAME_PATTERNS = [
    re.compile(r"^unknown$", re.IGNORECASE),
    re.compile(r"^\s*$"),
    re.compile(r"^android-[0-9a-f]{16}$", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Primary discovery path: reuse the project's existing, verified module.
# Imported defensively — this module must remain usable even if
# core.network_discovery is missing or fails to import.
# ---------------------------------------------------------------------------
try:
    from core.network_discovery import discover_hosts as _primary_discover_hosts
    from core.network_discovery import get_current_gateway as _get_current_gateway

    _PRIMARY_DISCOVERY_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import-time failure must not break this module
    _primary_discover_hosts = None
    _get_current_gateway = None
    _PRIMARY_DISCOVERY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Fallback discovery path: fully self-contained, Windows-safe. Used only
# when the primary path above is unavailable or raises.
# ---------------------------------------------------------------------------
ARP = Ether = srp = None
try:
    from scapy.all import ARP, Ether, srp  # type: ignore

    _SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - environment-dependent
    _SCAPY_AVAILABLE = False


@dataclass
class _LocalHost:
    """Duck-type compatible with core.network_discovery.DiscoveredHost."""

    ip_address: str
    mac_address: str
    hostname: str = "Unknown"
    response_time: float | None = None


@dataclass
class _LocalDiscoveryResult:
    hosts: list[_LocalHost] = field(default_factory=list)
    error: str | None = None
    method: str = "unavailable"


def _resolve_via_netbios(ip_address: str) -> str | None:
    """Windows-only NetBIOS name query — see core.network_discovery for details."""
    output = run_command(["nbtstat", "-A", ip_address], timeout=3)
    match = re.search(r"^\s*(\S+)\s*<00>\s*UNIQUE", output, re.MULTILINE)
    if match:
        name = match.group(1).strip()
        if name and name.upper() != "WORKGROUP":
            return name
    return None


def _resolve_via_mdns(ip_address: str) -> str | None:
    """Best-effort mDNS/Bonjour reverse lookup — see core.network_discovery for details."""
    plat = current_platform()
    if plat == "linux":
        output = run_command(["avahi-resolve-address", ip_address], timeout=2)
        parts = output.strip().split()
        if len(parts) >= 2:
            return parts[1].rstrip(".")
    elif plat == "darwin":
        output = run_command(["dscacheutil", "-q", "host", "-a", "ip_address", ip_address], timeout=2)
        match = re.search(r"^name:\s*(\S+)", output, re.MULTILINE)
        if match:
            return match.group(1).rstrip(".")
    return None


def _resolve_hostname(ip_address: str) -> str:
    """
    Best-effort device name resolution: reverse DNS, then NetBIOS
    (Windows), then mDNS/Bonjour. See core.network_discovery's version
    of this function for the full rationale. Returns "Unknown" only when
    none of the three actually resolve anything.
    """
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    netbios_name = _resolve_via_netbios(ip_address) if current_platform() == "windows" else None
    if netbios_name:
        return netbios_name

    mdns_name = _resolve_via_mdns(ip_address)
    if mdns_name:
        return mdns_name

    return "Unknown"


def _local_arp_scan(subnet_cidr: str, timeout: int) -> list[_LocalHost]:
    if not _SCAPY_AVAILABLE or Ether is None or ARP is None or srp is None:
        return []

    hosts: list[_LocalHost] = []
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_cidr)
    start = time.monotonic()
    answered, _ = srp(request, timeout=timeout, verbose=False)
    for _, received in answered:
        response_time = time.monotonic() - start
        ip_address = received.psrc
        mac_address = normalize_mac(received.hwsrc)
        hosts.append(
            _LocalHost(
                ip_address=ip_address,
                mac_address=mac_address,
                hostname=_resolve_hostname(ip_address),
                response_time=round(response_time, 4),
            )
        )
    return hosts


def _local_arp_cache_scan() -> list[_LocalHost]:
    """Passive fallback: read the OS ARP cache instead of actively probing."""
    output = run_command(["arp", "-a"])
    if current_platform() == "windows":
        pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f\-]{17})\s+\w+")
    else:
        pattern = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:]{17})")

    hosts: list[_LocalHost] = []
    for ip_address, mac_address in pattern.findall(output):
        if not is_valid_ipv4(ip_address):
            continue
        hosts.append(
            _LocalHost(
                ip_address=ip_address,
                mac_address=normalize_mac(mac_address),
                hostname=_resolve_hostname(ip_address),
            )
        )
    return hosts


def _local_discover_hosts(timeout: int) -> _LocalDiscoveryResult:
    """
    Fully self-contained device discovery for the authorized local subnet.

    Used only when core.network_discovery is unavailable or fails. Never
    raises — every failure mode (no active IPv4, no Scapy, no Npcap,
    insufficient privileges, no responses) is reported via the ``error``
    field on the returned result instead.
    """
    local_ip = get_local_ip()
    if not local_ip:
        return _LocalDiscoveryResult(
            error="No active IPv4 address found (Wi-Fi may be disconnected)."
        )

    subnet_cidr = guess_subnet_cidr(local_ip)
    if not subnet_cidr:
        return _LocalDiscoveryResult(error="Could not determine local subnet.")

    # Same fast-warm-then-read strategy as core.network_discovery: ping
    # every host first (no admin/root needed) so the ARP cache read
    # below actually finds them, instead of relying on the user (or a
    # prior unrelated app) having already talked to those hosts.
    if settings.device_ping_sweep_enabled:
        try:
            ping_sweep(
                subnet_cidr,
                timeout_ms=settings.device_ping_sweep_timeout_ms,
                max_workers=settings.device_ping_sweep_max_workers,
            )
        except Exception:  # noqa: BLE001 - sweep is best-effort only
            logger.exception("Ping sweep failed; continuing with ARP-cache read anyway.")

    hosts: list[_LocalHost] = []
    method = "unavailable"
    try:
        scapy_hosts: list[_LocalHost] = []
        if _SCAPY_AVAILABLE:
            try:
                scapy_hosts = _local_arp_scan(subnet_cidr, timeout)
            except PermissionError:
                logger.warning("Insufficient privileges for raw ARP scanning (Scapy skipped).")
            except Exception:  # noqa: BLE001 - Scapy failing must not skip the ARP-cache read
                logger.exception("Scapy ARP scan failed; continuing with ARP-cache read anyway.")

        # Merge Scapy results with an ARP-cache read rather than treating
        # them as either/or — see core.network_discovery.discover_hosts
        # for why (some devices answer one probe type but not the other).
        arp_cache_hosts = _local_arp_cache_scan()
        hosts = scapy_hosts + arp_cache_hosts
        if scapy_hosts and arp_cache_hosts:
            method = "scapy_arp+arp_cache"
        elif scapy_hosts:
            method = "scapy_arp"
        elif arp_cache_hosts:
            method = "arp_cache"
    except Exception as exc:  # noqa: BLE001 - discovery must never crash the app
        logger.exception("Unexpected error during local device discovery")
        return _LocalDiscoveryResult(error=f"Local device discovery failed: {exc}")

    # Do not count the local machine itself, or the router/access point
    # itself, as a "connected device". Match self by IP AND by MAC (a
    # multi-adapter machine can otherwise slip past an IP-only filter)
    # and merge duplicate MAC entries.
    local_mac = get_local_mac()
    gateway_ip = _get_current_gateway() if _get_current_gateway else None
    hosts = [
        h for h in hosts
        if h.ip_address != local_ip
        and h.ip_address != gateway_ip
        and (not local_mac or h.mac_address != local_mac)
    ]
    seen: dict[str, _LocalHost] = {}
    for host in hosts:
        key = host.mac_address or host.ip_address
        if key not in seen:
            seen[key] = host
    hosts = list(seen.values())

    error = None if hosts else "No devices found on the local network."
    return _LocalDiscoveryResult(hosts=hosts, error=error, method=method)


def _get_hosts() -> tuple[list, str | None, float]:
    """
    Obtain discovered hosts for the current connection: prefer the
    project's primary discovery path, fall back to the local
    implementation above only if the primary path is unavailable or
    raises unexpectedly. Returns (hosts, error, duration_seconds).
    """
    start = time.monotonic()

    if _PRIMARY_DISCOVERY_AVAILABLE and _primary_discover_hosts is not None:
        try:
            outcome = _primary_discover_hosts()
            return outcome.hosts, outcome.error, outcome.duration_seconds
        except Exception:  # noqa: BLE001 - never let a primary-path failure crash the app
            logger.exception(
                "core.network_discovery.discover_hosts() raised; using local fallback discovery."
            )
    else:
        logger.debug(
            "core.network_discovery unavailable; using self-contained local fallback discovery."
        )

    local_result = _local_discover_hosts(timeout=settings.device_scan_timeout_seconds)
    return local_result.hosts, local_result.error, time.monotonic() - start


@dataclass
class DeviceAssociationOutcome:
    """Result of attempting to associate devices with one WiFi network."""

    devices: list[DeviceRecord] = field(default_factory=list)
    available: bool = False
    error: str | None = None
    unknown_device_count: int = 0
    suspicious_device_detected: bool = False
    duration_seconds: float = 0.0
    device_count: int = 0
    skipped_host_count: int = 0


def is_suspicious_hostname(hostname: str) -> bool:
    """Public wrapper so callers outside this module (e.g. the GUI, when
    recomputing a device's risk after a trust toggle) can reuse the same
    hostname heuristic used during discovery."""
    return any(pattern.match(hostname) for pattern in _SUSPICIOUS_HOSTNAME_PATTERNS)


def _build_device_record(host) -> tuple[DeviceRecord, bool, bool]:
    """
    Build a DeviceRecord from a single discovered host.

    ``host`` may come from either the primary discovery path
    (core.network_discovery.DiscoveredHost) or the local fallback above
    (_LocalHost) — both expose the same attributes (ip_address,
    mac_address, hostname, response_time), so this function works with
    either via duck typing.

    Returns (record, is_unknown_vendor, is_suspicious). Raises on
    unrecoverable per-host errors; callers should catch broadly so a
    single bad host does not abort the whole scan.
    """
    vendor = lookup_vendor(host.mac_address)
    device_type = classify_device(hostname=host.hostname, vendor=vendor)
    vendor_unknown = vendor == "Unknown"
    suspicious_hostname = is_suspicious_hostname(host.hostname or "")
    randomized = is_randomized_mac(host.mac_address)
    is_suspicious = suspicious_hostname or randomized
    trusted = _lookup_trusted(host.mac_address)

    device_risk = calculate_device_risk(
        vendor_unknown=vendor_unknown,
        randomized_mac=randomized,
        suspicious_hostname=suspicious_hostname,
        trusted=trusted,
    )

    record = DeviceRecord(
        hostname=host.hostname or FALLBACK_DEVICE_NAME,
        ip_address=host.ip_address,
        mac_address=host.mac_address,
        vendor=vendor,
        device_type=device_type,
        operating_system="Unknown",  # best-effort only; no active OS fingerprinting
        first_seen=now_iso(),
        last_seen=now_iso(),
        status="Online",
        response_time=host.response_time,
        risk_level=device_risk.level,
        risk_score=device_risk.score,
        reasons=device_risk.reasons,
        trusted=trusted,
    )
    return record, vendor_unknown, is_suspicious


def associate_devices_for_network(*, is_current_connection: bool) -> DeviceAssociationOutcome:
    """
    Attempt to discover and associate devices for ONE WiFi network.

    Only call this with ``is_current_connection=True`` — i.e. for the
    network whose BSSID matches the current connection. For every other
    nearby network, skip this call entirely and mark
    ``device_info_available=False`` on the NetworkRecord; do not call
    this function speculatively for networks the host isn't authorized
    to inspect.
    """
    start = time.monotonic()

    if not is_current_connection:
        return DeviceAssociationOutcome(
            available=False,
            error="Not detectable with current scan method — host is not connected to this network.",
        )

    hosts, discovery_error, discovery_duration = _get_hosts()

    if discovery_error and not hosts:
        return DeviceAssociationOutcome(
            available=False,
            error=discovery_error,
            duration_seconds=discovery_duration,
        )

    devices: list[DeviceRecord] = []
    unknown_count = 0
    any_suspicious = False
    skipped = 0

    for host in hosts:
        try:
            record, is_unknown, is_suspicious = _build_device_record(host)
        except Exception:  # noqa: BLE001 - one bad host must not abort the scan
            logger.exception(
                "Skipping host %s: failed to build device record",
                getattr(host, "ip_address", "<unknown ip>"),
            )
            skipped += 1
            continue

        devices.append(record)
        if is_unknown:
            unknown_count += 1
        if is_suspicious:
            any_suspicious = True

    duration = time.monotonic() - start
    logger.info(
        "Associated %d device(s) with the current network in %.2fs "
        "(%d unknown vendor, %d skipped)",
        len(devices),
        duration,
        unknown_count,
        skipped,
    )

    # Surface a partial-failure note even though devices/available reflect
    # what we *did* get, so the UI can optionally show a warning badge.
    partial_error = discovery_error if (discovery_error and devices) else None

    return DeviceAssociationOutcome(
        devices=devices,
        available=True,
        error=partial_error,
        unknown_device_count=unknown_count,
        suspicious_device_detected=any_suspicious,
        duration_seconds=duration,
        device_count=len(devices),
        skipped_host_count=skipped,
    )