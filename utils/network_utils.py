"""
Cross-platform helpers for discovering local network context (host IP,
subnet, gateway) needed for authorized local device discovery.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import socket
import subprocess
import uuid

from utils.logger import get_logger

logger = get_logger(__name__)


def get_local_ip() -> str | None:
    """Best-effort discovery of this machine's primary local IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError as exc:
        logger.warning("Could not determine local IP: %s", exc)
        return None


def get_local_mac() -> str | None:
    """
    Best-effort discovery of this machine's own MAC address, in the same
    upper-case colon-separated form used everywhere else in the app.

    Used as a second, independent signal (alongside local IP) to exclude
    this machine's own entry from a "connected devices" list. IP-only
    matching can miss the local host if ``get_local_ip()`` picks a
    different active interface than the one that answered the ARP/ping
    sweep (e.g. a machine with WiFi + Ethernet + a VPN adapter all up at
    once) — matching on MAC too closes that gap.
    """
    try:
        node = uuid.getnode()
    except Exception:  # noqa: BLE001 - never let this crash discovery
        return None
    # uuid.getnode() sets bit 40 (the multicast bit) as a sentinel when it
    # had to fall back to a random 48-bit value instead of a real NIC MAC.
    if (node >> 40) % 2 == 1:
        return None
    mac = ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -8, -8))
    return mac


def guess_subnet_cidr(local_ip: str | None, prefix_len: int = 24) -> str | None:
    """Guess a /24 (by default) CIDR range for the local network."""
    if not local_ip:
        return None
    try:
        network = ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)
        return str(network)
    except ValueError as exc:
        logger.warning("Could not derive subnet for %s: %s", local_ip, exc)
        return None


def run_command(command: list[str], timeout: int = 10) -> str:
    """
    Run a system command and return its stdout, or an empty string on any
    failure. Never raises — callers should treat empty output as 'no data'.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout or ""
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        logger.debug("Command %s failed: %s", command, exc)
        return ""


def current_platform() -> str:
    """Return 'windows', 'linux', 'darwin', or the raw system name."""
    return platform.system().lower()


def _ping_once(ip: str, timeout_ms: int, attempts: int = 2) -> None:
    """
    Fire up to ``attempts`` best-effort ICMP pings at one host. Result is
    intentionally discarded by callers — the point is only to make the OS
    resolve the host's MAC address and cache it, so a subsequent `arp -a`
    read finds it. Never raises.

    A single WiFi client can drop one probe packet to ordinary radio
    interference; trying twice materially reduces "device didn't answer
    in time" false negatives without meaningfully slowing the sweep down.
    """
    plat = current_platform()
    for _ in range(max(1, attempts)):
        if plat == "windows":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            # Linux/BSD/macOS ping's -W flag takes whole seconds, not ms.
            timeout_seconds = max(1, round(timeout_ms / 1000))
            command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=(timeout_ms / 1000) + 1,
                check=False,
            )
            if result.returncode == 0:
                return  # host answered — no need for a second attempt
        except (subprocess.SubprocessError, OSError):
            pass  # a single unreachable/blocked host must never abort the sweep


def ping_sweep(subnet_cidr: str, timeout_ms: int = 400, max_workers: int = 120) -> None:
    """
    Concurrently ping every host in ``subnet_cidr`` to warm the OS ARP
    cache, without requiring admin/root privileges or a raw-packet driver
    (unlike Scapy). This is fire-and-forget: callers should read the ARP
    cache (`arp -a`) immediately afterward to see which hosts answered.

    Skipped entirely for networks larger than /24 (more than 256
    addresses) to avoid pinging thousands of hosts.
    """
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError:
        logger.debug("Skipping ping sweep: invalid subnet %s", subnet_cidr)
        return

    if network.num_addresses > 256:
        logger.debug("Skipping ping sweep for %s: network too large.", subnet_cidr)
        return

    host_ips = [str(ip) for ip in network.hosts()]
    if not host_ips:
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(lambda ip: _ping_once(ip, timeout_ms), host_ips))