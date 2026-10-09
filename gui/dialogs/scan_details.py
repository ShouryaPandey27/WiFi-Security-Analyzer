"""Modal dialog showing the full network list for one scan session."""

from __future__ import annotations

import tkinter as tk

from config.settings import palette
from database.models import ScanSession
from database.repositories import ScanHistoryRepository
from gui.widgets.network_table import NetworkTable


class ScanDetailsDialog(tk.Toplevel):
    def __init__(self, parent, session: ScanSession):
        super().__init__(parent, bg=palette.background)
        self.title(f"Scan Details — {session.scan_time}")
        self.geometry("760x420")
        self.configure(bg=palette.background)

        tk.Label(
            self,
            text=f"Scan #{session.id} — {session.scan_time}",
            bg=palette.background, fg=palette.text, font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", padx=16, pady=(16, 4))

        summary = (
            f"{session.total_networks} networks  |  "
            f"HIGH {session.high_risk}  MEDIUM {session.medium_risk}  LOW {session.low_risk}  |  "
            f"Security Score {session.overall_security_score}  |  "
            f"Duration {session.scan_duration}s"
        )
        tk.Label(
            self, text=summary, bg=palette.background, fg=palette.text_muted,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=16, pady=(0, 12))

        table_frame = tk.Frame(self, bg=palette.background)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        table = NetworkTable(table_frame)
        table.pack(fill="both", expand=True)

        if session.id is not None:
            networks = ScanHistoryRepository().get_session_networks(session.id)
            table.load(networks)

        tk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 16))
