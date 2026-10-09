"""
Reports page (Section 21 of the base spec; Section 8 of the per-network
device addendum): generate PDF/CSV reports for networks, per-network
connected devices, and scan history.

There is no standalone "device report" independent of WiFi networks —
the Connected Devices report lists devices grouped under the specific
network they were associated with, and only for networks where device
information was actually determined.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from config.settings import palette
from core.report_generator import (
    ReportGenerationError,
    export_history_csv,
    export_network_devices_csv,
    export_network_devices_pdf,
    export_networks_csv,
    export_networks_pdf,
)
from database.repositories import NetworkRepository, ScanHistoryRepository


class ReportsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._build_ui()

    def _build_ui(self) -> None:
        tk.Label(
            self, text="Reports", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=20, pady=(20, 10))

        sections = [
            ("Network Report", self._export_networks_pdf, self._export_networks_csv),
            ("Connected Devices Report (by network)", self._export_devices_pdf, self._export_devices_csv),
            ("Scan History Report", None, self._export_history_csv),
        ]

        for title, pdf_cmd, csv_cmd in sections:
            card = tk.Frame(self, bg=palette.surface, padx=16, pady=14)
            card.pack(fill="x", padx=20, pady=8)
            tk.Label(
                card, text=title, bg=palette.surface, fg=palette.text,
                font=("Segoe UI", 12, "bold"),
            ).pack(anchor="w")
            button_row = tk.Frame(card, bg=palette.surface)
            button_row.pack(anchor="w", pady=(8, 0))
            if pdf_cmd:
                tk.Button(
                    button_row, text="Export PDF", command=pdf_cmd, bg=palette.accent,
                    fg="#0D1117", relief="flat", padx=12, pady=6, font=("Segoe UI", 9, "bold"),
                ).pack(side="left", padx=(0, 8))
            tk.Button(
                button_row, text="Export CSV", command=csv_cmd, bg=palette.surface_alt,
                fg=palette.text, relief="flat", padx=12, pady=6,
            ).pack(side="left")

        tk.Label(
            self,
            text=(
                "Connected Devices reports only include networks where device "
                "information was reliably determined (the network this host was "
                "actually connected to at scan time)."
            ),
            bg=palette.background, fg=palette.text_muted, wraplength=600, justify="left",
            anchor="w",
        ).pack(fill="x", padx=20, pady=(4, 0))

    # -- network report ---------------------------------------------------------
    def _export_networks_pdf(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if not path:
            return
        from pathlib import Path
        try:
            export_networks_pdf(NetworkRepository().all(), Path(path))
            messagebox.showinfo("Export", f"Saved to {path}")
        except ReportGenerationError as exc:
            messagebox.showerror("Export Failed", str(exc))

    def _export_networks_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        from pathlib import Path
        export_networks_csv(NetworkRepository().all(), Path(path))
        messagebox.showinfo("Export", f"Saved to {path}")

    # -- per-network connected devices report ------------------------------------
    def _export_devices_pdf(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if not path:
            return
        from pathlib import Path
        try:
            export_network_devices_pdf(NetworkRepository().all(), Path(path))
            messagebox.showinfo("Export", f"Saved to {path}")
        except ReportGenerationError as exc:
            messagebox.showerror("Export Failed", str(exc))

    def _export_devices_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        from pathlib import Path
        export_network_devices_csv(NetworkRepository().all(), Path(path))
        messagebox.showinfo("Export", f"Saved to {path}")

    # -- history report -------------------------------------------------------------
    def _export_history_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        from pathlib import Path
        export_history_csv(ScanHistoryRepository().list_sessions(), Path(path))
        messagebox.showinfo("Export", f"Saved to {path}")
