"""
Scan history service (Sections 17 & 19 of the base spec; Section 13 of
the per-network device addendum).

Wraps ScanHistoryRepository with the business logic for saving a
completed WiFi scan as a session, and for comparing two sessions —
including, for networks where device info was available in BOTH
sessions, the connected-device count and identity change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from database.models import NetworkRecord, ScanSession
from database.repositories import ScanHistoryRepository
from utils.logger import get_logger
from utils.time_utils import now_iso

logger = get_logger(__name__)


def build_session_from_networks(
    networks: list[NetworkRecord], *, duration_seconds: float
) -> ScanSession:
    """Summarize a list of assessed networks into a ScanSession."""
    high = sum(1 for n in networks if n.risk_level == "HIGH")
    medium = sum(1 for n in networks if n.risk_level == "MEDIUM")
    low = sum(1 for n in networks if n.risk_level == "LOW")
    avg_score = round(sum(n.risk_score for n in networks) / len(networks), 1) if networks else 0.0
    # Overall "security score" — higher is safer, so invert average risk.
    overall_security_score = round(100 - avg_score, 1)

    return ScanSession(
        scan_time=now_iso(),
        total_networks=len(networks),
        high_risk=high,
        medium_risk=medium,
        low_risk=low,
        overall_security_score=overall_security_score,
        scan_duration=round(duration_seconds, 2),
    )


def save_scan(
    networks: list[NetworkRecord],
    *,
    duration_seconds: float,
    network_ids: dict[str, int] | None = None,
) -> int | None:
    """
    Persist a completed scan as a new history session.

    ``network_ids`` (BSSID -> live networks.id) links each historical
    scan_networks row back to the live networks table. Devices are
    snapshotted into scan_network_devices for any network whose device
    info was actually available (never fabricated for the rest).
    """
    session = build_session_from_networks(networks, duration_seconds=duration_seconds)
    devices_by_bssid = {
        net.bssid: net.devices for net in networks if net.device_info_available and net.devices
    }
    repo = ScanHistoryRepository()
    session_id = repo.save_session(
        session, networks, network_ids=network_ids, devices_by_bssid=devices_by_bssid
    )
    if session_id:
        logger.info("Scan history saved as session #%s", session_id)
    return session_id


@dataclass
class DeviceChange:
    change_type: str  # NEW or REMOVED
    identifier: str  # IP address (or hostname if IP unavailable)


@dataclass
class NetworkDiff:
    bssid: str
    ssid: str
    change_type: str  # NEW, REMOVED, CHANGED, UNCHANGED
    details: list[str] = field(default_factory=list)
    device_count_before: int | None = None
    device_count_after: int | None = None
    device_count_available: bool = False
    device_changes: list[DeviceChange] = field(default_factory=list)


def _device_diff(old_net: NetworkRecord, new_net: NetworkRecord) -> tuple[list[str], list[DeviceChange]]:
    """Compare device counts/identities for one network across two scans."""
    details: list[str] = []
    changes: list[DeviceChange] = []

    both_available = old_net.device_info_available and new_net.device_info_available
    if not both_available:
        return details, changes

    before, after = old_net.connected_devices or 0, new_net.connected_devices or 0
    if before != after:
        delta = after - before
        sign = "+" if delta > 0 else ""
        details.append(f"Connected devices: {before} -> {after} ({sign}{delta})")

    old_macs = {d.mac_address: d for d in old_net.devices}
    new_macs = {d.mac_address: d for d in new_net.devices}

    for mac, device in new_macs.items():
        if mac not in old_macs:
            changes.append(DeviceChange(change_type="NEW", identifier=device.ip_address or device.hostname))
    for mac, device in old_macs.items():
        if mac not in new_macs:
            changes.append(
                DeviceChange(change_type="REMOVED", identifier=device.ip_address or device.hostname)
            )

    return details, changes


def compare_sessions(old_id: int, new_id: int) -> list[NetworkDiff]:
    """Compare two scan sessions by BSSID and describe what changed."""
    repo = ScanHistoryRepository()
    old_networks = {n.bssid: n for n in repo.get_session_networks(old_id)}
    new_networks = {n.bssid: n for n in repo.get_session_networks(new_id)}

    diffs: list[NetworkDiff] = []

    for bssid, new_net in new_networks.items():
        if bssid not in old_networks:
            diffs.append(
                NetworkDiff(
                    bssid=bssid,
                    ssid=new_net.ssid,
                    change_type="NEW",
                    device_count_after=new_net.connected_devices,
                    device_count_available=new_net.device_info_available,
                )
            )
            continue

        old_net = old_networks[bssid]
        details: list[str] = []
        if old_net.encryption != new_net.encryption or old_net.authentication != new_net.authentication:
            details.append(
                f"{old_net.authentication}/{old_net.encryption} -> "
                f"{new_net.authentication}/{new_net.encryption}"
            )
        if old_net.risk_score != new_net.risk_score:
            details.append(f"Risk: {old_net.risk_score} -> {new_net.risk_score}")
        if old_net.signal_strength != new_net.signal_strength:
            details.append(
                f"Signal: {old_net.signal_strength} dBm -> {new_net.signal_strength} dBm"
            )

        device_details, device_changes = _device_diff(old_net, new_net)
        details.extend(device_details)

        change_type = "CHANGED" if (details or device_changes) else "UNCHANGED"
        diffs.append(
            NetworkDiff(
                bssid=bssid,
                ssid=new_net.ssid,
                change_type=change_type,
                details=details,
                device_count_before=old_net.connected_devices,
                device_count_after=new_net.connected_devices,
                device_count_available=old_net.device_info_available and new_net.device_info_available,
                device_changes=device_changes,
            )
        )

    for bssid, old_net in old_networks.items():
        if bssid not in new_networks:
            diffs.append(
                NetworkDiff(
                    bssid=bssid,
                    ssid=old_net.ssid,
                    change_type="REMOVED",
                    device_count_before=old_net.connected_devices,
                    device_count_available=old_net.device_info_available,
                )
            )

    return diffs
