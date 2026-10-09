"""
Dashboard page: at-a-glance stats, latest scan summary, and network table.

Connected devices are NOT surfaced on this page. Nearby WiFi scanning
only reveals access point information — connected-device details are
only determinable for the ONE network this host is currently,
authorizedly connected to, so that information is shown exclusively in
NetworkDetailsDialog (opened by double-clicking a network row below),
which performs a live device scan for that one network. There is no
global device count across every nearby network here, since a single
reliable global figure isn't determinable from a nearby WiFi scan (see
core/connected_devices.py).
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox

from config.settings import palette
from core import scan_history
from core.connected_devices import associate_devices_for_network
from core.network_discovery import (
    DEFAULT_SSID_FALLBACK,
    get_current_connection_bssid,
    get_current_ssid,
)
from core.security_analyzer import analyze_network, apply_assessment
from core.wifi_scanner import scan_networks
from database.models import NetworkRecord
from database.repositories import NetworkDeviceRepository, NetworkRepository
from gui.dialogs.network_details import NetworkDetailsDialog
from gui.widgets.network_table import NetworkTable
from gui.widgets.stat_card import StatCard
from utils.logger import get_logger
from utils.time_utils import format_display, humanize_duration
from utils.validators import normalize_mac

logger = get_logger(__name__)


class DashboardPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._scanning = False
        self._latest_networks: list[NetworkRecord] = []
        self._build_ui()
        self.refresh_from_db()

    # -- UI construction ------------------------------------------------------
    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=palette.background)
        header.pack(fill="x", padx=20, pady=(20, 10))

        tk.Label(
            header, text="Dashboard", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")

        button_bar = tk.Frame(header, bg=palette.background)
        button_bar.pack(side="right")

        self.scan_button = tk.Button(
            button_bar, text="Scan Networks", command=self.start_scan,
            bg=palette.accent, fg="#0D1117", relief="flat", padx=14, pady=6,
            font=("Segoe UI", 9, "bold"),
        )
        self.scan_button.pack(side="left", padx=4)

        tk.Button(
            button_bar, text="Refresh", command=self.refresh_from_db,
            bg=palette.surface_alt, fg=palette.text, relief="flat", padx=14, pady=6,
        ).pack(side="left", padx=4)

        tk.Button(
            button_bar, text="Export Report", command=self._export_report,
            bg=palette.surface_alt, fg=palette.text, relief="flat", padx=14, pady=6,
        ).pack(side="left", padx=4)

        # Stat cards row
        stats_row = tk.Frame(self, bg=palette.background)
        stats_row.pack(fill="x", padx=20, pady=10)
        self.cards = {
            "networks": StatCard(stats_row, "Networks Detected"),
            "score": StatCard(stats_row, "Security Score"),
            "open": StatCard(stats_row, "Open Networks", accent=palette.risk_high),
            "high_risk": StatCard(stats_row, "High Risk Networks", accent=palette.risk_high),
            "with_devices": StatCard(stats_row, "Networks With Device Info"),
        }
        for card in self.cards.values():
            card.pack(side="left", expand=True, fill="both", padx=6)

        # Latest scan summary
        summary_frame = tk.Frame(self, bg=palette.surface, padx=16, pady=10)
        summary_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.summary_label = tk.Label(
            summary_frame, text="No scans yet.", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9), justify="left", anchor="w",
        )
        self.summary_label.pack(fill="x")

        # Network table
        table_frame = tk.Frame(self, bg=palette.background)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.table = NetworkTable(table_frame, on_double_click=self._open_details)
        self.table.pack(fill="both", expand=True)

        hint = tk.Label(
            self, text="Double-click a network to see its full details, including connected devices.",
            bg=palette.background, fg=palette.text_muted, font=("Segoe UI", 8),
        )
        hint.pack(anchor="w", padx=20, pady=(0, 8))

    # -- data operations ------------------------------------------------------
    def refresh_from_db(self) -> None:
        networks = NetworkRepository().all()
        self._latest_networks = networks
        self._update_stats(networks)
        self.table.load(networks)

    def start_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.scan_button.config(state="disabled", text="Scanning...")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self) -> None:
        outcome = scan_networks()

        # Determine which nearby network (if any) this host is actually,
        # authorizedly connected to — device association is only ever
        # attempted for that ONE network, never for every nearby network.
        #
        # BSSID is tried first (most precise). If it comes back empty, or
        # doesn't match any network in *this* scan's results (e.g. a
        # transient mismatch between the "current connection" command and
        # the "nearby networks" scan), fall back to matching by SSID so a
        # real connection isn't reported as "No active Wi-Fi connection"
        # just because BSSID correlation failed. SSID is looked up lazily
        # (only when needed) to avoid an extra system command on the
        # common, successful path.
        current_bssid = get_current_connection_bssid()
        matched_bssid: str | None = None

        if current_bssid:
            matched_bssid = next(
                (
                    net.bssid
                    for net in outcome.networks
                    if normalize_mac(net.bssid) == normalize_mac(current_bssid)
                ),
                None,
            )

        if matched_bssid is None:
            current_ssid = get_current_ssid()
            if current_ssid and current_ssid != DEFAULT_SSID_FALLBACK:
                matched_bssid = next(
                    (net.bssid for net in outcome.networks if net.ssid == current_ssid),
                    None,
                )

        current_association = None  # populated below only for the matching network

        assessed: list[NetworkRecord] = []
        for net in outcome.networks:
            is_current = bool(matched_bssid and net.bssid == matched_bssid)

            unknown_count = 0
            suspicious = False
            if is_current:
                association = associate_devices_for_network(is_current_connection=True)
                current_association = association
                if association.available:
                    net.device_info_available = True
                    net.devices = association.devices
                    net.connected_devices = len(association.devices)
                    unknown_count = association.unknown_device_count
                    suspicious = association.suspicious_device_detected
                else:
                    net.device_info_available = False
                    net.connected_devices = None
            else:
                net.device_info_available = False
                net.connected_devices = None

            assessment = analyze_network(
                ssid=net.ssid,
                bssid=net.bssid,
                authentication=net.authentication,
                encryption=net.encryption,
                unknown_device_count=unknown_count,
                suspicious_device_detected=suspicious,
            )
            apply_assessment(net, assessment)
            assessed.append(net)

        repo = NetworkRepository()
        device_repo = NetworkDeviceRepository()
        network_ids: dict[str, int] = {}
        for net in assessed:
            network_id = repo.upsert(net)
            if network_id is not None:
                network_ids[net.bssid] = network_id
                if net.device_info_available:
                    device_repo.replace_devices_for_network(network_id, net.devices)

        session_id = None
        if assessed:
            session_id = scan_history.save_scan(
                assessed, duration_seconds=outcome.duration_seconds, network_ids=network_ids
            )

        self.after(
            0,
            lambda: self._on_scan_complete(
                assessed, outcome, session_id, matched_bssid, current_association
            ),
        )

    def _on_scan_complete(self, networks, outcome, session_id, matched_bssid, current_association) -> None:
        self._scanning = False
        self.scan_button.config(state="normal", text="Scan Networks")
        self._latest_networks = networks
        self._update_stats(networks)
        self.table.load(networks)

        if outcome.error and not networks:
            messagebox.showwarning("WiFi Scan", outcome.error)
        self.summary_label.config(
            text=(
                f"Latest Scan: {format_display(networks[0].last_seen) if networks else 'N/A'}   "
                f"Duration: {humanize_duration(outcome.duration_seconds)}   "
                f"Status: {'Completed' if not outcome.error else outcome.error}   "
                f"Session: #{session_id if session_id else 'not saved'}"
            )
        )

    def _update_stats(self, networks: list[NetworkRecord]) -> None:
        total = len(networks)
        open_count = sum(1 for n in networks if n.authentication.upper() in {"OPEN", "NONE", ""})
        high_risk = sum(1 for n in networks if n.risk_level == "HIGH")
        avg_score = round(sum(n.risk_score for n in networks) / total, 1) if total else 0
        security_score = round(100 - avg_score, 1) if total else 100
        with_devices = sum(1 for n in networks if n.device_info_available)

        self.cards["networks"].set_value(str(total))
        self.cards["score"].set_value(f"{security_score}")
        self.cards["open"].set_value(str(open_count))
        self.cards["high_risk"].set_value(str(high_risk))
        self.cards["with_devices"].set_value(str(with_devices))

    def _open_details(self, network) -> None:
        if not network:
            return
        full = NetworkRepository().get_by_bssid(network.bssid) or network
        NetworkDetailsDialog(self, full)

    def _export_report(self) -> None:
        self.app.show_page("Reports")