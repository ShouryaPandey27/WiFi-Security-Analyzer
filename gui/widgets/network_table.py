"""Treeview-based table for displaying WiFi networks with risk coloring."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from config.settings import palette
from database.models import NetworkRecord

COLUMNS = ("ssid", "bssid", "signal", "encryption", "channel", "devices", "risk")
HEADINGS = {
    "ssid": "SSID",
    "bssid": "BSSID",
    "signal": "Signal",
    "encryption": "Encryption",
    "channel": "Channel",
    "devices": "Devices",
    "risk": "Risk",
}


class NetworkTable(ttk.Treeview):
    def __init__(self, parent, on_select=None, on_double_click=None):
        style = ttk.Style()
        # Windows' default ttk themes ignore custom Treeview.Heading
        # colors — 'clam' actually honors them. Safe to call repeatedly.
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(
            "Dark.Treeview",
            background=palette.surface,
            fieldbackground=palette.surface,
            foreground=palette.text,
            rowheight=26,
            borderwidth=0,
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=palette.surface_alt,
            foreground=palette.text,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Dark.Treeview", background=[("selected", palette.accent)])
        style.map("Dark.Treeview.Heading", background=[("active", palette.border)])

        super().__init__(
            parent, columns=COLUMNS, show="headings", style="Dark.Treeview", height=12
        )
        for col in COLUMNS:
            self.heading(col, text=HEADINGS[col])
            self.column(col, width=120, anchor="w")
        self.column("ssid", width=180)
        self.column("bssid", width=150)

        self.tag_configure("HIGH", foreground=palette.risk_high)
        self.tag_configure("MEDIUM", foreground=palette.risk_medium)
        self.tag_configure("LOW", foreground=palette.risk_low)

        self._networks: dict[str, NetworkRecord] = {}
        if on_select:
            self.bind("<<TreeviewSelect>>", lambda _e: on_select(self.selected_network()))
        if on_double_click:
            self.bind("<Double-1>", lambda _e: on_double_click(self.selected_network()))

    def load(self, networks: list[NetworkRecord]) -> None:
        self.delete(*self.get_children())
        self._networks.clear()
        for net in networks:
            item_id = net.bssid or net.ssid
            self._networks[item_id] = net
            self.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    net.ssid,
                    net.bssid,
                    f"{net.signal_strength} dBm" if net.signal_strength is not None else "N/A",
                    net.encryption,
                    net.channel if net.channel is not None else "N/A",
                    net.devices_display(),
                    net.risk_level,
                ),
                tags=(net.risk_level,),
            )

    def selected_network(self) -> NetworkRecord | None:
        selection = self.selection()
        if not selection:
            return None
        return self._networks.get(selection[0])