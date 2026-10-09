"""
Dedicated page listing all currently known WiFi networks.

Selecting a network shows an inline summary (including its own
connected-device count, or "Unavailable" when not determinable);
double-clicking — or the "View Details" button — opens the full
Network Details dialog (Network Information, Security Analysis,
Connected Devices, Recommendations) for that specific network.
"""

from __future__ import annotations

import tkinter as tk

from config.settings import palette
from database.repositories import NetworkRepository
from gui.dialogs.network_details import NetworkDetailsDialog
from gui.widgets.network_table import NetworkTable


class WifiNetworksPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=palette.background)
        header.pack(fill="x", padx=20, pady=(20, 10))
        tk.Label(
            header, text="WiFi Networks", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        button_bar = tk.Frame(header, bg=palette.background)
        button_bar.pack(side="right")
        tk.Button(
            button_bar, text="View Details", command=self._view_details, bg=palette.surface_alt,
            fg=palette.text, relief="flat", padx=14, pady=6,
        ).pack(side="left", padx=4)
        tk.Button(
            button_bar, text="Refresh", command=self.refresh, bg=palette.surface_alt,
            fg=palette.text, relief="flat", padx=14, pady=6,
        ).pack(side="left", padx=4)

        search_frame = tk.Frame(self, bg=palette.background)
        search_frame.pack(fill="x", padx=20, pady=(0, 10))
        tk.Label(
            search_frame, text="Search:", bg=palette.background, fg=palette.text_muted,
        ).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh())
        tk.Entry(
            search_frame, textvariable=self.search_var, bg=palette.surface, fg=palette.text,
            insertbackground=palette.text, relief="flat", width=30,
        ).pack(side="left", padx=8)

        table_frame = tk.Frame(self, bg=palette.background)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.table = NetworkTable(
            table_frame, on_select=self._on_select, on_double_click=self._open_details
        )
        self.table.pack(fill="both", expand=True)

        self.detail_label = tk.Label(
            self, text="Select a network to view details, or double-click for the full report.",
            bg=palette.surface, fg=palette.text_muted, anchor="w", justify="left", padx=16, pady=10,
        )
        self.detail_label.pack(fill="x", padx=20, pady=(0, 20))

    def refresh(self) -> None:
        networks = NetworkRepository().all()
        query = self.search_var.get().strip().lower()
        if query:
            networks = [
                n for n in networks
                if query in n.ssid.lower() or query in n.bssid.lower()
            ]
        self.table.load(networks)

    def _on_select(self, network) -> None:
        if not network:
            self.detail_label.config(text="Select a network to view details.")
            return
        reasons = "; ".join(network.reasons) if network.reasons else "No reasons recorded."
        self.detail_label.config(
            text=(
                f"{network.ssid}  ({network.bssid})\n"
                f"Auth: {network.authentication}   Encryption: {network.encryption}   "
                f"Connected Devices: {network.devices_display()}   "
                f"Risk: {network.risk_level} ({network.risk_score}/100)\n"
                f"Reasons: {reasons}"
            )
        )

    def _view_details(self) -> None:
        self._open_details(self.table.selected_network())

    def _open_details(self, network) -> None:
        if not network:
            return
        full = NetworkRepository().get_by_bssid(network.bssid) or network
        NetworkDetailsDialog(self, full)
