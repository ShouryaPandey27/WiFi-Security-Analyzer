"""
PDF/CSV report generation (Section 21 of the base spec).

PDF reports use ReportLab; if ReportLab is not installed the caller gets
a clear error instead of a crash. CSV export always works (stdlib only).

Connected-device reporting is network-scoped: each row identifies which
WiFi network a device was associated with, and the network report's
"Connected Devices" column shows "Unavailable" rather than a fabricated
number when device info wasn't determinable for that network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from config.settings import settings
from database.models import NetworkRecord, ScanSession
from utils.export_utils import export_rows_to_csv
from utils.logger import get_logger
from utils.time_utils import now_iso

logger = get_logger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _REPORTLAB_AVAILABLE = True
except ImportError:  # pragma: no cover - environment-dependent
    colors: Any = None
    letter: Any = None # pyright: ignore[reportGeneralTypeIssues]
    getSampleStyleSheet: Any = None
    inch: Any = None # type: ignore
    Paragraph: Any = None
    SimpleDocTemplate: Any = None
    Spacer: Any = None
    Table: Any = None
    TableStyle: Any = None
    _REPORTLAB_AVAILABLE = False


class ReportGenerationError(Exception):
    """Raised when a report cannot be produced."""


def _timestamped_path(prefix: str, extension: str) -> Path:
    settings.ensure_directories()
    stamp = now_iso().replace(":", "-")
    return settings.reports_dir / f"{prefix}_{stamp}.{extension}"


def _devices_display(network: NetworkRecord) -> str:
    if not network.device_info_available or network.connected_devices is None:
        return "Unavailable"
    return str(network.connected_devices)


def _cell(value) -> str:
    """Render a table cell value safely — never hand ReportLab a bare None."""
    return "" if value is None else str(value)


# ===========================================================================
# CSV exports
# ===========================================================================
def export_networks_csv(networks: list[NetworkRecord], file_path: Path | None = None) -> Path:
    file_path = file_path or _timestamped_path("network_report", "csv")
    headers = [
        "ssid",
        "bssid",
        "signal_strength",
        "channel",
        "authentication",
        "encryption",
        "connected_devices",
        "risk_level",
        "risk_score",
    ]
    rows = [
        {
            "ssid": n.ssid,
            "bssid": n.bssid,
            "signal_strength": n.signal_strength,
            "channel": n.channel,
            "authentication": n.authentication,
            "encryption": n.encryption,
            "connected_devices": _devices_display(n),
            "risk_level": n.risk_level,
            "risk_score": n.risk_score,
        }
        for n in networks
    ]
    return export_rows_to_csv(rows, headers, file_path)


def export_network_devices_csv(networks: list[NetworkRecord], file_path: Path | None = None) -> Path:
    """Export the per-network connected-device associations only (Section 8)."""
    file_path = file_path or _timestamped_path("connected_devices_report", "csv")
    headers = [
        "network_ssid",
        "network_bssid",
        "hostname",
        "ip_address",
        "mac_address",
        "vendor",
        "device_type",
        "status",
    ]
    rows = []
    for network in networks:
        if not network.device_info_available:
            continue
        for device in network.devices:
            rows.append(
                {
                    "network_ssid": network.ssid,
                    "network_bssid": network.bssid,
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "vendor": device.vendor,
                    "device_type": device.device_type,
                    "status": device.status,
                }
            )
    return export_rows_to_csv(rows, headers, file_path)


def export_history_csv(sessions: list[ScanSession], file_path: Path | None = None) -> Path:
    file_path = file_path or _timestamped_path("history_report", "csv")
    headers = [
        "scan_time",
        "scan_duration",
        "total_networks",
        "high_risk",
        "medium_risk",
        "low_risk",
        "overall_security_score",
    ]
    rows = [
        {
            "scan_time": s.scan_time,
            "scan_duration": s.scan_duration,
            "total_networks": s.total_networks,
            "high_risk": s.high_risk,
            "medium_risk": s.medium_risk,
            "low_risk": s.low_risk,
            "overall_security_score": s.overall_security_score,
        }
        for s in sessions
    ]
    return export_rows_to_csv(rows, headers, file_path)


# ===========================================================================
# PDF exports
# ===========================================================================
def _require_reportlab() -> None:
    if not _REPORTLAB_AVAILABLE:
        raise ReportGenerationError(
            "ReportLab is not installed. Run 'pip install reportlab' to enable PDF export."
        )


# Keyed on the *normalized* (upper-cased, stripped) risk label so it matches
# regardless of how risk_level happens to be cased upstream ("High",
# "HIGH", " High " all resolve the same way). Covers the full band used by
# the risk engine, including CRITICAL and VERY SECURE.
_RISK_COLOR_MAP = {
    "CRITICAL": colors.HexColor("#F85149") if _REPORTLAB_AVAILABLE else None,
    "HIGH": colors.HexColor("#F85149") if _REPORTLAB_AVAILABLE else None,
    "MEDIUM": colors.HexColor("#D29922") if _REPORTLAB_AVAILABLE else None,
    "LOW": colors.HexColor("#3FB950") if _REPORTLAB_AVAILABLE else None,
    "VERY SECURE": colors.HexColor("#3FB950") if _REPORTLAB_AVAILABLE else None,
}


def _risk_color(level: str | None):
    if not level:
        return colors.grey # type: ignore
    normalized = level.strip().upper()
    return _RISK_COLOR_MAP.get(normalized, colors.grey) # type: ignore


def export_networks_pdf(networks: list[NetworkRecord], file_path: Path | None = None) -> Path:
    _require_reportlab()
    file_path = file_path or _timestamped_path("network_report", "pdf")

    doc = SimpleDocTemplate(str(file_path), pagesize=letter) # pyright: ignore[reportPossiblyUnboundVariable]
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"{settings.app_name} — WiFi Network Security Report", styles["Title"]),
        Paragraph(f"Generated: {now_iso()}", styles["Normal"]),
        Spacer(1, 0.25 * inch),
    ]

    table_data = [["SSID", "BSSID", "Auth", "Encryption", "Devices", "Risk", "Score"]]
    for n in networks:
        table_data.append(
            [
                _cell(n.ssid),
                _cell(n.bssid),
                _cell(n.authentication),
                _cell(n.encryption),
                _devices_display(n),
                _cell(n.risk_level),
                _cell(n.risk_score),
            ]
        )

    table = Table(table_data, repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161B22")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]
    for row_idx, n in enumerate(networks, start=1):
        style_commands.append(
            ("TEXTCOLOR", (5, row_idx), (5, row_idx), _risk_color(n.risk_level))
        )
    table.setStyle(TableStyle(style_commands))
    story.append(table)

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        logger.error("PDF generation failed: %s", exc)
        raise ReportGenerationError(f"Failed to generate PDF: {exc}") from exc

    logger.info("Generated network PDF report at %s", file_path)
    return file_path


def export_network_devices_pdf(networks: list[NetworkRecord], file_path: Path | None = None) -> Path:
    """PDF of per-network connected-device associations only (Section 8)."""
    _require_reportlab()
    file_path = file_path or _timestamped_path("connected_devices_report", "pdf")

    doc = SimpleDocTemplate(str(file_path), pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"{settings.app_name} — Connected Devices Report", styles["Title"]),
        Paragraph(f"Generated: {now_iso()}", styles["Normal"]),
        Paragraph(
            "Only networks with reliably determined device information are listed.",
            styles["Italic"],
        ),
        Spacer(1, 0.25 * inch),
    ]

    any_section = False
    for network in networks:
        if not network.device_info_available:
            continue
        any_section = True
        story.append(Paragraph(f"{network.ssid} ({network.bssid})", styles["Heading3"]))

        if not network.devices:
            # Device info WAS available for this network — it's just that
            # zero devices were found. That's a distinct, meaningful state
            # from "unavailable" and should say so, not vanish silently.
            story.append(Paragraph("No devices detected on this network.", styles["Normal"]))
            story.append(Spacer(1, 0.2 * inch))
            continue

        table_data = [["Hostname", "IP", "MAC", "Vendor", "Type", "Status"]]
        for d in network.devices:
            table_data.append(
                [
                    _cell(d.hostname),
                    _cell(d.ip_address),
                    _cell(d.mac_address),
                    _cell(d.vendor),
                    _cell(d.device_type),
                    _cell(d.status),
                ]
            )
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#161B22")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.2 * inch))

    if not any_section:
        story.append(Paragraph("No networks currently have available device information.", styles["Normal"]))

    try:
        doc.build(story)
    except Exception as exc:  # noqa: BLE001
        logger.error("PDF generation failed: %s", exc)
        raise ReportGenerationError(f"Failed to generate PDF: {exc}") from exc

    logger.info("Generated connected devices PDF report at %s", file_path)
    return file_path