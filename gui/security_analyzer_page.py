"""
Dedicated Security Analyzer page (Section 11 of the base spec).

The assessment shown here folds in connected-device context for the
selected network (Section 9 of the per-network device addendum) — but
only when that network's device information was actually determined;
a network is never penalized for devices that couldn't be discovered.
"""

from __future__ import annotations

import tkinter as tk

from config.settings import palette
from core.security_analyzer import analyze_network
from core.vulnerability_evaluator import (
    EVALUATION_DISCLAIMER,
    EvaluationResult,
    format_summary,
    run_evaluation,
)
from database.repositories import NetworkRepository
from gui.dialogs.network_details import NetworkDetailsDialog
from gui.widgets.network_table import NetworkTable
from gui.widgets.risk_badge import RiskBadge


class SecurityAnalyzerPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=palette.background)
        header.pack(fill="x", padx=20, pady=(20, 10))
        tk.Label(
            header, text="Security Analyzer", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")
        tk.Button(
            header, text="Refresh", command=self.refresh, bg=palette.surface_alt,
            fg=palette.text, relief="flat", padx=14, pady=6,
        ).pack(side="right")

        body = tk.Frame(self, bg=palette.background)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        table_frame = tk.Frame(body, bg=palette.background)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.table = NetworkTable(
            table_frame, on_select=self._on_select, on_double_click=self._open_full_details
        )
        self.table.pack(fill="both", expand=True)

        self.detail_frame = tk.Frame(body, bg=palette.surface, padx=16, pady=16)
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        self._build_evaluation_card(body)
        self._placeholder()

    # -- Vulnerability Detection Rate evaluation (predefined known test cases) ----
    def _build_evaluation_card(self, body: tk.Frame) -> None:
        body.rowconfigure(0, weight=1)
        card = tk.Frame(body, bg=palette.surface, padx=16, pady=12)
        card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        top = tk.Frame(card, bg=palette.surface)
        top.pack(fill="x")
        tk.Label(
            top, text="VULNERABILITY DETECTION EVALUATION", bg=palette.surface,
            fg=palette.text_muted, font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        tk.Button(
            top, text="Run Vulnerability Evaluation", command=self._run_evaluation,
            bg=palette.accent, fg="#0D1117", relief="flat", padx=12, pady=5,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right")

        self.eval_rate_label = tk.Label(
            card, text="Not run yet", bg=palette.surface, fg=palette.text,
            font=("Segoe UI", 14, "bold"), anchor="w",
        )
        self.eval_rate_label.pack(fill="x", pady=(8, 0))
        self.eval_count_label = tk.Label(
            card, text="", bg=palette.surface, fg=palette.text, anchor="w",
        )
        self.eval_count_label.pack(fill="x")
        self.eval_detail_label = tk.Label(
            card, text="", bg=palette.surface, fg=palette.text_muted, anchor="w",
            justify="left", wraplength=900,
        )
        self.eval_detail_label.pack(fill="x", pady=(4, 0))
        tk.Label(
            card, text=EVALUATION_DISCLAIMER, bg=palette.surface, fg=palette.text_muted,
            anchor="w", justify="left", wraplength=900, font=("Segoe UI", 8, "italic"),
        ).pack(fill="x", pady=(6, 0))

    def _run_evaluation(self) -> None:
        self._show_evaluation(run_evaluation())

    def _show_evaluation(self, result: EvaluationResult) -> None:
        rate_line, count_line = format_summary(result)
        self.eval_rate_label.config(text=rate_line)
        self.eval_count_label.config(text=count_line)
        lines = [
            f"{'PASS' if c.passed else 'FAIL'}  {c.case_name}: "
            f"expected {', '.join(c.expected) or 'none'}; "
            f"detected {', '.join(c.detected) or 'none'}"
            for c in result.case_results
        ]
        self.eval_detail_label.config(text="\n".join(lines))

    def _placeholder(self) -> None:
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        tk.Label(
            self.detail_frame, text="Select a network to see its full security assessment.",
            bg=palette.surface, fg=palette.text_muted, wraplength=320,
        ).pack(anchor="w")

    def refresh(self) -> None:
        self.table.load(NetworkRepository().all())
        self._placeholder()

    def _on_select(self, network) -> None:
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        if not network:
            self._placeholder()
            return

        # Pull the full record so associated devices (if any) are populated.
        full = NetworkRepository().get_by_bssid(network.bssid) or network

        unknown_count = 0
        if full.device_info_available:
            unknown_count = sum(1 for d in full.devices if d.vendor == "Unknown")

        assessment = analyze_network(
            ssid=full.ssid,
            bssid=full.bssid,
            authentication=full.authentication,
            encryption=full.encryption,
            unknown_device_count=unknown_count,
        )

        title_row = tk.Frame(self.detail_frame, bg=palette.surface)
        title_row.pack(fill="x", pady=(0, 8))
        tk.Label(
            title_row, text="SECURITY STATUS", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        RiskBadge(title_row, assessment.risk.level).pack(side="right")

        tk.Label(
            self.detail_frame, text=f"{assessment.risk.score} / 100",
            bg=palette.surface, fg=palette.text, font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        for label, value in [
            ("Authentication", assessment.authentication),
            ("Encryption", assessment.encryption),
            ("Connected Devices", full.devices_display()),
        ]:
            row = tk.Frame(self.detail_frame, bg=palette.surface)
            row.pack(fill="x", pady=2)
            tk.Label(
                row, text=label, bg=palette.surface, fg=palette.text_muted, width=16, anchor="w",
                font=("Segoe UI", 9, "bold"),
            ).pack(side="left")
            tk.Label(row, text=value, bg=palette.surface, fg=palette.text).pack(side="left")

        tk.Label(
            self.detail_frame, text="Vulnerabilities", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9, "bold"), anchor="w",
        ).pack(fill="x", pady=(12, 4))
        for vuln in assessment.vulnerabilities:
            tk.Label(
                self.detail_frame, text=f"• {vuln}", bg=palette.surface, fg=palette.text,
                anchor="w", justify="left", wraplength=320,
            ).pack(fill="x")

        tk.Label(
            self.detail_frame, text="Recommendations", bg=palette.surface, fg=palette.text_muted,
            font=("Segoe UI", 9, "bold"), anchor="w",
        ).pack(fill="x", pady=(12, 4))
        for rec in assessment.recommendations:
            tk.Label(
                self.detail_frame, text=f"• {rec}", bg=palette.surface, fg=palette.text,
                anchor="w", justify="left", wraplength=320,
            ).pack(fill="x")

        tk.Button(
            self.detail_frame, text="View Full Details (incl. devices)",
            command=lambda: self._open_full_details(full), bg=palette.accent, fg="#0D1117",
            relief="flat", padx=10, pady=6,
        ).pack(anchor="w", pady=(12, 0))

    def _open_full_details(self, network) -> None:
        if not network:
            return
        full = NetworkRepository().get_by_bssid(network.bssid) or network
        NetworkDetailsDialog(self, full)
