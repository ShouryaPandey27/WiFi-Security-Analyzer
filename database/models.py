"""Dataclass models mirroring the SQLite schema, used across core/gui layers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NetworkRecord:
    """A single detected WiFi network (current/live state).

    ``connected_devices`` is ``None`` when the device count for this
    network could not be reliably determined (the normal case for any
    network the host is not actively connected to). It is an ``int``
    only when a real, non-fabricated count was discovered — in which
    case ``device_info_available`` is True and ``devices`` may hold the
    individual DeviceRecord entries associated with this network.
    """

    ssid: str = "Hidden Network"
    bssid: str = ""
    signal_strength: int | None = None
    channel: int | None = None
    frequency: float | None = None
    authentication: str = "Unknown"
    encryption: str = "Unknown"
    connected_devices: int | None = None
    device_info_available: bool = False
    devices: list["DeviceRecord"] = field(default_factory=list)
    risk_level: str = "LOW"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    last_seen: str = ""
    id: int | None = None

    def devices_display(self) -> str:
        """Human-friendly value for the 'Connected Devices' table column."""
        if self.connected_devices is not None:
            return str(self.connected_devices)
        return "Unavailable"


@dataclass
class DeviceRecord:
    """A single device discovered on the authorized local network."""

    hostname: str = "Unknown"
    ip_address: str = ""
    mac_address: str = ""
    vendor: str = "Unknown"
    device_type: str = "Unknown"
    operating_system: str = "Unknown"
    first_seen: str = ""
    last_seen: str = ""
    status: str = "Offline"
    response_time: float | None = None
    risk_level: str = "LOW"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    trusted: bool = False
    id: int | None = None


@dataclass
class ScanSession:
    """Summary of one completed WiFi scan."""

    scan_time: str = ""
    total_networks: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    overall_security_score: float = 0.0
    scan_duration: float = 0.0
    id: int | None = None