"""
Network Details dialog (Sections 2, 8 & 14 of the per-network device spec).

Consolidates: Network Information, Security Analysis, Connected Devices,
Risk Assessment, and Recommendations for ONE WiFi network — there is no
separate "Connected Devices Scanner" page or dashboard widget; this
dialog IS how connected devices are surfaced, always scoped to the
network the user selected.

Connected Devices behaviour:
- For every OTHER nearby network, device info is genuinely undeterminable
  from a passive WiFi scan, so an "unavailable" explanation is shown.
- For the ONE network this host is currently, authorizedly connected to,
  this dialog always attempts a live device discovery when opened (and
  again on demand via the "Rescan" button), so it never falls back to a
  generic "unavailable" message here — it shows the real device
  count/table, or a specific, accurate status (e.g. "No devices found on
  the local network") if discovery finds nothing. See
  core/network_discovery.py and core/connected_devices.py for the fast
  ping-sweep-then-ARP-cache strategy that makes this quick without
  admin/root privileges.
"""

from __future__ import annotations

import threading
import tkinter as tk

from config.settings import palette
from core.connected_devices import DeviceAssociationOutcome, associate_devices_for_network
from core.network_discovery import is_current_connection
from core.security_analyzer import analyze_network
from database.models import NetworkRecord
from gui.widgets.device_table import DeviceTable
from gui.widgets.risk_badge import RiskBadge
from utils.logger import get_logger

logger = get_logger(__name__)


class NetworkDetailsDialog(tk.Toplevel):
    def __init__(self, parent, network: NetworkRecord):
        super().__init__(parent, bg=palette.background)
        self.title(f"Network Details — {network.ssid}")

        # Size relative to the actual screen instead of a fixed
        # 640x680 — on smaller/lower-resolution laptop screens a fixed
        # size can run past the visible desktop (behind the taskbar),
        # cutting off the bottom of the dialog with no way to reach it.
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(720, int(screen_w * 0.85))
        height = min(820, int(screen_h * 0.85))
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(480, 420)
        self.resizable(True, True)

        self.configure(bg=palette.background)
        self._network = network
        self._assessment = None
        self._scanning = False
        self._is_current_network = is_current_connection(network.ssid, network.bssid)

        canvas = tk.Canvas(self, bg=palette.background, highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=palette.background)
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        body_window = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        # Keep the embedded content the same width as the canvas, so it
        # always fills the dialog instead of staying a fixed 610px wide
        # (which either wastes space or clips on a resized window).
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(body_window, width=e.width))
        canvas.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=16)
        scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event) -> None:
            delta = -1 if getattr(event, "num", None) == 4 else 1 if getattr(event, "num", None) == 5 else -event.delta // 120
            canvas.yview_scroll(delta, "units")

        def _bind_mousewheel(_e=None) -> None:
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(_e=None) -> None:
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        self._build_network_information(body, network)

        self._security_container = tk.Frame(body, bg=palette.background)
        self._security_container.pack(fill="x")
        self._build_security_analysis(self._security_container, network)

        self._devices_container = tk.Frame(body, bg=palette.background)
        self._devices_container.pack(fill="x")
        self._build_connected_devices(self._devices_container, network)

        self._recommendations_container = tk.Frame(body, bg=palette.background)
        self._recommendations_container.pack(fill="x")
        self._build_recommendations(self._recommendations_container, network)

        tk.Button(self, text="Close", command=self.destroy).pack(side="bottom", pady=8)

        if self._is_current_network:
            self._start_scan()

    # -- shared helpers ---------------------------------------------------
    def _section_header(self, parent, text: str) -> tk.Frame:
        row = tk.Frame(parent, bg=palette.background)
        row.pack(fill="x", pady=(16, 6))
        tk.Label(
            row, text=text, bg=palette.background, fg=palette.accent,
            font=("Segoe UI", 12, "bold"), anchor="w",
        ).pack(side="left")
        return row

    def _field_row(self, parent, label: str, value: str) -> None:
        row = tk.Frame(parent, bg=palette.surface)
        row.pack(fill="x", pady=1)
        tk.Label(
            row, text=label, bg=palette.surface, fg=palette.text_muted, width=18, anchor="w",
            font=("Segoe UI", 9, "bold"), padx=8, pady=4,
        ).pack(side="left")
        tk.Label(
            row, text=value, bg=palette.surface, fg=palette.text, anchor="w", padx=4,
        ).pack(side="left", fill="x")

    # -- Network Information ---------------------------------------------------
    def _build_network_information(self, parent, network: NetworkRecord) -> None:
        self._section_header(parent, "Network Information")
        card = tk.Frame(parent, bg=palette.surface)
        card.pack(fill="x")
        for label, value in [
            ("SSID", network.ssid),
            ("BSSID", network.bssid),
            (
                "Signal Strength",
                f"{network.signal_strength} dBm" if network.signal_strength is not None else "N/A",
            ),
            ("Channel", str(network.channel) if network.channel is not None else "N/A"),
            ("Frequency", f"{network.frequency} GHz" if network.frequency else "N/A"),
        ]:
            self._field_row(card, label, value)

    # -- Security Analysis ---------------------------------------------------
    def _build_security_analysis(self, parent, network: NetworkRecord) -> None:
        self._section_header(parent, "Security Analysis")

        unknown_count = 0
        suspicious = False
        if network.device_info_available:
            # A device the user has explicitly marked "Trusted" is
            # excluded from both signals below — trust is the user
            # vouching for a device they recognize, so it should stop
            # counting against the network's score.
            unknown_count = sum(
                1 for d in network.devices if d.vendor == "Unknown" and not d.trusted
            )
            suspicious = any(
                getattr(d, "risk_level", "") == "HIGH" and not d.trusted for d in network.devices
            )

        assessment = analyze_network(
            ssid=network.ssid,
            bssid=network.bssid,
            authentication=network.authentication,
            encryption=network.encryption,
            unknown_device_count=unknown_count,
            suspicious_device_detected=suspicious,
        )
        self._assessment = assessment

        card = tk.Frame(parent, bg=palette.surface, padx=8, pady=8)
        card.pack(fill="x")

        title_row = tk.Frame(card, bg=palette.surface)
        title_row.pack(fill="x")
        tk.Label(
            title_row, text=f"{assessment.risk.score} / 100", bg=palette.surface,
            fg=palette.text, font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        RiskBadge(title_row, assessment.risk.level).pack(side="right")

        self._field_row(card, "Authentication", assessment.authentication)
        self._field_row(card, "Encryption", assessment.encryption)

        tk.Label(
            card, text="Vulnerabilities", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9, "bold"), anchor="w",
        ).pack(fill="x", pady=(8, 2))
        for vuln in assessment.vulnerabilities:
            tk.Label(
                card, text=f"• {vuln}", bg=palette.surface, fg=palette.text, anchor="w",
                justify="left", wraplength=560,
            ).pack(fill="x")

        tk.Label(
            card, text="Risk Reasons", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9, "bold"), anchor="w",
        ).pack(fill="x", pady=(8, 2))
        for reason in assessment.risk.reasons:
            tk.Label(
                card, text=f"• {reason}", bg=palette.surface, fg=palette.text, anchor="w",
                justify="left", wraplength=560,
            ).pack(fill="x")

    # -- Connected Devices ---------------------------------------------------
    def _build_connected_devices(self, parent, network: NetworkRecord) -> None:
        header_row = self._section_header(parent, "Connected Devices")

        card = tk.Frame(parent, bg=palette.surface, padx=8, pady=8)
        card.pack(fill="x")
        self._devices_card = card

        if not self._is_current_network:
            # Genuinely undeterminable for a network this host isn't
            # associated with — a passive WiFi scan never reveals another
            # AP's connected clients. No Rescan button here; rescanning
            # would not change this.
            tk.Label(
                card,
                text=(
                    "Device information unavailable — not detectable with the current scan "
                    "method. Nearby WiFi scanning only reveals access point information; "
                    "connected-device details are only determinable for the network this "
                    "host is currently, authorizedly connected to."
                ),
                bg=palette.surface, fg=palette.text_muted, anchor="w", justify="left",
                wraplength=560,
            ).pack(fill="x")
            return

        # This IS the currently connected network — always offer a live
        # Rescan, and never show the generic "unavailable" message.
        self._rescan_button = tk.Button(
            header_row, text="Rescan", command=self._start_scan,
            bg=palette.surface_alt, fg=palette.text, relief="flat", padx=10, pady=2,
        )
        self._rescan_button.pack(side="right")

        # Show cached devices immediately if we already have them (e.g.
        # from the last dashboard scan) while the live rescan runs.
        if network.device_info_available and network.devices:
            self._render_devices(card, network.devices)
        else:
            self._render_scanning(card)

    def _render_scanning(self, card: tk.Frame) -> None:
        tk.Label(
            card, text="Scanning for connected devices (usually a couple of seconds)...",
            bg=palette.surface, fg=palette.text_muted, anchor="w",
        ).pack(fill="x")

    def _render_devices(self, card: tk.Frame, devices: list) -> None:
        tk.Label(
            card, text=f"Total Devices: {len(devices)}", bg=palette.surface, fg=palette.text,
            font=("Segoe UI", 10, "bold"), anchor="w",
        ).pack(fill="x", pady=(0, 6))
        table = DeviceTable(card)
        table.pack(fill="x")
        table.load(devices)

    def _render_no_devices(self, card: tk.Frame, message: str) -> None:
        tk.Label(
            card, text=message, bg=palette.surface, fg=palette.text_muted,
            anchor="w", justify="left", wraplength=560,
        ).pack(fill="x")

    # -- Live scan for the currently connected network -----------------------
    def _start_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        if hasattr(self, "_rescan_button"):
            self._rescan_button.config(state="disabled", text="Scanning...")

        for child in self._devices_card.winfo_children():
            child.destroy()
        self._render_scanning(self._devices_card)

        threading.Thread(target=self._scan_current_network, daemon=True).start()

    def _scan_current_network(self) -> None:
        outcome = associate_devices_for_network(is_current_connection=True)
        try:
            self.after(0, lambda: self._on_scan_complete(outcome))
        except tk.TclError:
            pass  # dialog was closed before the scan finished

    def _on_scan_complete(self, outcome: DeviceAssociationOutcome) -> None:
        if not self.winfo_exists():
            return

        self._scanning = False
        if hasattr(self, "_rescan_button"):
            self._rescan_button.config(state="normal", text="Rescan")

        if outcome.devices:
            self._network.device_info_available = True
            self._network.devices = outcome.devices
            self._network.connected_devices = len(outcome.devices)
        else:
            # Zero devices found is a real, accurate result for the
            # current network — it is not the same as "unavailable".
            self._network.device_info_available = False
            self._network.connected_devices = 0

        for child in self._devices_card.winfo_children():
            child.destroy()
        if outcome.devices:
            self._render_devices(self._devices_card, outcome.devices)
        else:
            message = outcome.error or "No devices found on this network."
            self._render_no_devices(self._devices_card, message)

        for child in self._security_container.winfo_children():
            child.destroy()
        self._build_security_analysis(self._security_container, self._network)

        for child in self._recommendations_container.winfo_children():
            child.destroy()
        self._build_recommendations(self._recommendations_container, self._network)

    # -- Recommendations ---------------------------------------------------
    def _build_recommendations(self, parent, network: NetworkRecord) -> None:
        self._section_header(parent, "Recommendations")
        card = tk.Frame(parent, bg=palette.surface, padx=8, pady=8)
        card.pack(fill="x")
        recommendations = self._assessment.recommendations if self._assessment else []
        for rec in recommendations:
            tk.Label(
                card, text=f"• {rec}", bg=palette.surface, fg=palette.text, anchor="w",
                justify="left", wraplength=560,
            ).pack(fill="x")