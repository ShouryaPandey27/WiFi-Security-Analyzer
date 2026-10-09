"""A small dashboard statistic card: title, big value, optional accent color."""

from __future__ import annotations

import tkinter as tk

from config.settings import palette


class StatCard(tk.Frame):
    def __init__(self, parent, title: str, value: str = "--", accent: str | None = None):
        super().__init__(
            parent, bg=palette.surface, highlightbackground=palette.border,
            highlightthickness=1, padx=16, pady=12,
        )
        self._accent = accent or palette.accent

        self.title_label = tk.Label(
            self, text=title.upper(), bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 8, "bold"), anchor="w", justify="left", wraplength=130,
        )
        self.title_label.pack(fill="x")

        self.value_label = tk.Label(
            self, text=value, bg=palette.surface, fg=self._accent,
            font=("Segoe UI", 22, "bold"), anchor="w",
        )
        self.value_label.pack(fill="x", pady=(4, 0))

    def set_value(self, value: str, accent: str | None = None) -> None:
        self.value_label.config(text=value, fg=accent or self._accent)
