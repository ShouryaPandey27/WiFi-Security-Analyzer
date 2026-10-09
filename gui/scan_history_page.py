"""Scan History page (Sections 17-20): sessions table, filters, compare, charts."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from config.settings import palette
from core.history_analyzer import compute_history_statistics
from core.scan_history import compare_sessions
from core.report_generator import export_history_csv
from database.repositories import ScanHistoryRepository
from gui.dialogs.scan_details import ScanDetailsDialog
from gui.widgets.stat_card import StatCard
from utils.time_utils import parse_iso

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure

    _MATPLOTLIB_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MATPLOTLIB_AVAILABLE = False
    Figure = None
    FigureCanvasTkAgg = None

DATE_FILTERS = ["All Time", "Today", "Last 7 Days", "Last 30 Days"]

COLUMNS = ("id", "time", "networks", "high", "medium", "low", "score", "duration")


class ScanHistoryPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=palette.background)
        self.app = app
        self._sessions = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        header = tk.Frame(self, bg=palette.background)
        header.pack(fill="x", padx=20, pady=(20, 10))
        tk.Label(
            header, text="Scan History", bg=palette.background, fg=palette.text,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left")

        controls = tk.Frame(self, bg=palette.background)
        controls.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(controls, text="Search:", bg=palette.background, fg=palette.text_muted).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        tk.Entry(
            controls, textvariable=self.search_var, bg=palette.surface, fg=palette.text,
            insertbackground=palette.text, relief="flat", width=20,
        ).pack(side="left", padx=8)

        tk.Label(controls, text="Date:", bg=palette.background, fg=palette.text_muted).pack(
            side="left", padx=(16, 0)
        )
        self.date_var = tk.StringVar(value="All Time")
        tk.OptionMenu(controls, self.date_var, *DATE_FILTERS, command=lambda _v: self._apply_filters()).pack(
            side="left", padx=8
        )

        for text, command in [
            ("Refresh", self.refresh),
            ("View", self._view_selected),
            ("Compare", self._compare_selected),
            ("Delete", self._delete_selected),
            ("Clear History", self._clear_history),
            ("Export", self._export_csv),
        ]:
            tk.Button(
                controls, text=text, command=command, bg=palette.surface_alt, fg=palette.text,
                relief="flat", padx=10, pady=4,
            ).pack(side="left", padx=4)

        stats_row = tk.Frame(self, bg=palette.background)
        stats_row.pack(fill="x", padx=20, pady=10)
        self.cards = {
            "total": StatCard(stats_row, "Total Scans"),
            "avg_score": StatCard(stats_row, "Avg Security Score"),
            "high_risk": StatCard(stats_row, "High Risk Scans", accent=palette.risk_high),
            "networks": StatCard(stats_row, "Total Networks"),
        }
        for card in self.cards.values():
            card.pack(side="left", expand=True, fill="both", padx=6)

        body_wrap = tk.Frame(self, bg=palette.background)
        body_wrap.pack(fill="both", expand=True, padx=0, pady=0)

        # Everything below the stats cards (table + trend chart) lives in a
        # scrollable region. Without this, a fixed-height Treeview plus a
        # fixed-height chart can together exceed the visible window and
        # the Security Score Trend chart ends up silently cut off below
        # the fold with no way to reach it.
        body_canvas = tk.Canvas(body_wrap, bg=palette.background, highlightthickness=0)
        body_scrollbar = tk.Scrollbar(body_wrap, orient="vertical", command=body_canvas.yview)
        body = tk.Frame(body_canvas, bg=palette.background)
        body.bind("<Configure>", lambda _e: body_canvas.configure(scrollregion=body_canvas.bbox("all")))
        body_window = body_canvas.create_window((0, 0), window=body, anchor="nw")
        body_canvas.configure(yscrollcommand=body_scrollbar.set)
        body_canvas.bind(
            "<Configure>", lambda e: body_canvas.itemconfig(body_window, width=e.width)
        )
        body_canvas.pack(side="left", fill="both", expand=True, padx=20)
        body_scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event) -> None:
            delta = -1 if getattr(event, "num", None) == 4 else 1 if getattr(event, "num", None) == 5 else -event.delta // 120
            body_canvas.yview_scroll(delta, "units")

        def _bind_mousewheel(_event=None) -> None:
            body_canvas.bind_all("<MouseWheel>", _on_mousewheel)
            body_canvas.bind_all("<Button-4>", _on_mousewheel)
            body_canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(_event=None) -> None:
            body_canvas.unbind_all("<MouseWheel>")
            body_canvas.unbind_all("<Button-4>")
            body_canvas.unbind_all("<Button-5>")

        # Only capture the mouse wheel while hovering this page, so it
        # doesn't hijack scrolling anywhere else in the app.
        body_canvas.bind("<Enter>", _bind_mousewheel)
        body_canvas.bind("<Leave>", _unbind_mousewheel)

        style = ttk.Style()
        # Windows' default ttk themes ignore custom Treeview.Heading
        # colors, which is why header rows can render plain white
        # regardless of what's configured below — 'clam' actually
        # honors them. Safe to call even if already set elsewhere.
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(
            "History.Treeview", background=palette.surface, fieldbackground=palette.surface,
            foreground=palette.text, rowheight=26,
        )
        style.map("History.Treeview", background=[("selected", palette.accent)])
        style.configure(
            "History.Treeview.Heading",
            background=palette.surface_alt, foreground=palette.text,
            font=("Segoe UI", 9, "bold"), relief="flat",
        )
        style.map("History.Treeview.Heading", background=[("active", palette.border)])
        self.tree = ttk.Treeview(
            body, columns=COLUMNS, show="headings", style="History.Treeview", height=8,
            selectmode="extended",
        )
        headings = {
            "id": "Scan ID", "time": "Date/Time", "networks": "Networks", "high": "High Risk",
            "medium": "Medium Risk", "low": "Low Risk", "score": "Security Score",
            "duration": "Duration",
        }
        for col in COLUMNS:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=100)
        self.tree.pack(fill="x", pady=(0, 16))

        if _MATPLOTLIB_AVAILABLE:
            chart_header = tk.Frame(body, bg=palette.background)
            chart_header.pack(fill="x", pady=(0, 4))
            tk.Label(
                chart_header, text="Security Score Trend", bg=palette.background,
                fg=palette.text, font=("Segoe UI", 13, "bold"),
            ).pack(side="left")

            self.chart_frame = tk.Frame(body, bg=palette.surface, height=340)
            self.chart_frame.pack(fill="both", expand=False, pady=(0, 20))
            self.chart_frame.pack_propagate(False)
        else:
            self.chart_frame = None

    # -- data ------------------------------------------------------------------
    def refresh(self) -> None:
        self._sessions = ScanHistoryRepository().list_sessions()
        self._apply_filters()
        self._render_charts()

    def _apply_filters(self) -> None:
        from datetime import datetime, timedelta

        sessions = self._sessions
        query = self.search_var.get().strip()
        if query:
            sessions = [s for s in sessions if query in str(s.id)]

        date_filter = self.date_var.get()
        if date_filter != "All Time":
            days = {"Today": 1, "Last 7 Days": 7, "Last 30 Days": 30}[date_filter]
            cutoff = datetime.now() - timedelta(days=days)
            sessions = [
                s for s in sessions
                if (parse_iso(s.scan_time) or datetime.min) >= cutoff
            ]

        self.tree.delete(*self.tree.get_children())
        for s in sessions:
            self.tree.insert(
                "", "end", iid=str(s.id),
                values=(s.id, s.scan_time, s.total_networks, s.high_risk, s.medium_risk,
                        s.low_risk, s.overall_security_score, f"{s.scan_duration}s"),
            )

        total = len(self._sessions)
        avg_score = round(sum(s.overall_security_score for s in self._sessions) / total, 1) if total else 0
        high_risk = sum(1 for s in self._sessions if s.high_risk > 0)
        total_networks = sum(s.total_networks for s in self._sessions)
        self.cards["total"].set_value(str(total))
        self.cards["avg_score"].set_value(str(avg_score))
        self.cards["high_risk"].set_value(str(high_risk))
        self.cards["networks"].set_value(str(total_networks))

    def _render_charts(self) -> None:
        if not self.chart_frame:
            return
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        if not _MATPLOTLIB_AVAILABLE:
            tk.Label(
                self.chart_frame,
                text="Charts are unavailable because matplotlib is not installed.",
                bg=palette.surface, fg=palette.text_muted, font=("Segoe UI", 10),
            ).pack(expand=True)
            return

        stats = compute_history_statistics()
        if not stats.score_trend:
            tk.Label(
                self.chart_frame,
                text="Not enough data yet — run a few scans to see the security score trend.",
                bg=palette.surface, fg=palette.text_muted, font=("Segoe UI", 10),
            ).pack(expand=True)
            return

        points = stats.score_trend  # list[(scan_time_iso, score)], oldest -> newest
        x = list(range(len(points)))
        y = [score for _, score in points]

        # The availability check above guarantees these imports at runtime;
        # make that narrowing explicit for static type checkers.
        assert Figure is not None
        assert FigureCanvasTkAgg is not None
        fig = Figure(figsize=(10, 4.4), dpi=100, facecolor=palette.surface)
        ax = fig.add_subplot(111)
        ax.set_facecolor(palette.surface)

        # Line + markers + a light fill so the trend is unmistakable even
        # at a glance. The y-axis gridlines (0-100) already make each
        # point's approximate score readable, so no per-point number
        # labels are drawn on the line itself.
        ax.plot(
            x, y, color=palette.accent, marker="o", markersize=7,
            markerfacecolor=palette.accent, markeredgecolor=palette.surface,
            markeredgewidth=1.5, linewidth=2.5, zorder=3,
        )
        ax.fill_between(x, y, 0, color=palette.accent, alpha=0.15, zorder=1)

        ax.set_ylim(0, 100)
        ax.set_ylabel("Security Score", color=palette.text_muted, fontsize=9)
        ax.grid(True, axis="y", color=palette.border, linewidth=0.5, alpha=0.6, zorder=0)

        # X-axis: real dates instead of bare indices, thinned out so
        # labels never overlap even with many scan sessions.
        labels = []
        for scan_time, _ in points:
            parsed = parse_iso(scan_time)
            labels.append(parsed.strftime("%m/%d %H:%M") if parsed else scan_time)
        max_labels = 10
        step = max(1, len(labels) // max_labels)
        ax.set_xticks(x[::step])
        ax.set_xticklabels(labels[::step], rotation=30, ha="right", fontsize=8)

        ax.tick_params(colors=palette.text_muted, labelsize=8)
        for spine in ax.spines.values():
            spine.set_color(palette.border)

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    # -- actions -----------------------------------------------------------
    def _selected_ids(self) -> list[int]:
        return [int(iid) for iid in self.tree.selection()]

    def _view_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            messagebox.showinfo("View", "Select a scan session first.")
            return
        session = next((s for s in self._sessions if s.id == ids[0]), None)
        if session:
            ScanDetailsDialog(self, session)

    def _compare_selected(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 2:
            messagebox.showinfo("Compare", "Select exactly two scan sessions to compare.")
            return
        old_id, new_id = sorted(ids)
        diffs = compare_sessions(old_id, new_id)

        window = tk.Toplevel(self, bg=palette.background)
        window.title(f"Compare Scan #{old_id} vs #{new_id}")
        window.geometry("640x420")
        text = tk.Text(window, bg=palette.surface, fg=palette.text, wrap="word")
        text.pack(fill="both", expand=True, padx=12, pady=12)
        for diff in diffs:
            line = f"[{diff.change_type}] {diff.ssid} ({diff.bssid})"
            if diff.details:
                line += "  " + "; ".join(diff.details)
            text.insert("end", line + "\n")
            for change in diff.device_changes:
                text.insert("end", f"      {change.change_type} Device: {change.identifier}\n")
        text.config(state="disabled")

    def _delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        repo = ScanHistoryRepository()
        for session_id in ids:
            repo.delete_session(session_id)
        self.refresh()

    def _clear_history(self) -> None:
        if messagebox.askyesno("Clear History", "Delete all scan history? This cannot be undone."):
            ScanHistoryRepository().clear_all()
            self.refresh()

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        from pathlib import Path
        export_history_csv(self._sessions, Path(path))
        messagebox.showinfo("Export", f"Exported to {path}")