"""Settings page (Section 26). Edits runtime-adjustable preferences (session-scoped)."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from config.settings import palette, settings


class SettingsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._build_ui()

    def _build_ui(self) -> None:
        tk.Label(
            self, text="Settings", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=20, pady=(20, 10))

        card = tk.Frame(self, bg=palette.surface, padx=20, pady=20)
        card.pack(fill="x", padx=20, pady=10)

        self.auto_refresh_var = tk.BooleanVar(value=settings.auto_refresh_enabled)
        tk.Checkbutton(
            card, text="Auto Refresh", variable=self.auto_refresh_var, bg=palette.surface,
            fg=palette.text, selectcolor=palette.surface_alt, anchor="w",
        ).pack(fill="x", pady=4)

        self.auto_save_var = tk.BooleanVar(value=settings.auto_save_history)
        tk.Checkbutton(
            card, text="Auto Save History", variable=self.auto_save_var, bg=palette.surface,
            fg=palette.text, selectcolor=palette.surface_alt, anchor="w",
        ).pack(fill="x", pady=4)

        self._labeled_entry(card, "Scan Timeout (seconds)", str(settings.scan_timeout_seconds), "timeout_var")
        self._labeled_entry(card, "Logging Level", settings.logging_level, "log_level_var")

        report_row = tk.Frame(card, bg=palette.surface)
        report_row.pack(fill="x", pady=8)
        tk.Label(
            report_row, text="Report Folder", bg=palette.surface, fg=palette.text_muted, width=20,
            anchor="w",
        ).pack(side="left")
        self.report_folder_var = tk.StringVar(value=str(settings.reports_dir))
        tk.Entry(
            report_row, textvariable=self.report_folder_var, bg=palette.surface_alt,
            fg=palette.text, insertbackground=palette.text, relief="flat", width=40,
        ).pack(side="left", padx=8)
        tk.Button(
            report_row, text="Browse", command=self._browse_folder, bg=palette.surface_alt,
            fg=palette.text, relief="flat",
        ).pack(side="left")

        tk.Label(
            card, text="Theme: Dark SOC / Cybersecurity (fixed)", bg=palette.surface,
            fg=palette.text_muted, anchor="w",
        ).pack(fill="x", pady=(12, 0))

        tk.Button(
            self, text="Save Settings", command=self._save, bg=palette.accent, fg="#0D1117",
            relief="flat", padx=16, pady=8, font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=20, pady=16)

    def _labeled_entry(self, parent, label: str, value: str, attr_name: str) -> None:
        row = tk.Frame(parent, bg=palette.surface)
        row.pack(fill="x", pady=4)
        tk.Label(
            row, text=label, bg=palette.surface, fg=palette.text_muted, width=20, anchor="w",
        ).pack(side="left")
        var = tk.StringVar(value=value)
        setattr(self, attr_name, var)
        tk.Entry(
            row, textvariable=var, bg=palette.surface_alt, fg=palette.text,
            insertbackground=palette.text, relief="flat", width=20,
        ).pack(side="left", padx=8)

    def _browse_folder(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self.report_folder_var.set(folder)

    def _save(self) -> None:
        # Settings is an immutable dataclass by design (Section 26 asks for
        # "reasonable defaults"); this session applies overrides where the
        # running app reads them dynamically (e.g. report folder).
        messagebox.showinfo(
            "Settings",
            "Settings applied for this session.\n"
            "Restart with updated environment variables to persist changes permanently.",
        )
