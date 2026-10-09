"""A colored pill-style label reflecting a LOW/MEDIUM/HIGH risk level."""

from __future__ import annotations

import tkinter as tk

from config.settings import palette

_COLOR_MAP = {
    "LOW": palette.risk_low,
    "MEDIUM": palette.risk_medium,
    "HIGH": palette.risk_high,
    "CRITICAL": palette.risk_critical,
}


def risk_color(level: str) -> str:
    return _COLOR_MAP.get((level or "").upper(), palette.text_muted)


class RiskBadge(tk.Label):
    def __init__(self, parent, level: str = "LOW"):
        color = risk_color(level)
        super().__init__(
            parent,
            text=f" {level.upper()} ",
            bg=color,
            fg="#0D1117",
            font=("Segoe UI", 9, "bold"),
            padx=6,
            pady=2,
        )

    def set_level(self, level: str) -> None:
        self.config(text=f" {level.upper()} ", bg=risk_color(level))
