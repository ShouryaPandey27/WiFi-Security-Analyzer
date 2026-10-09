"""Main application window: sidebar navigation + page switching."""

from __future__ import annotations

import tkinter as tk

from config.settings import palette, settings
from gui.dashboard import DashboardPage
from gui.reports_page import ReportsPage
from gui.scan_history_page import ScanHistoryPage
from gui.security_analyzer_page import SecurityAnalyzerPage
from gui.settings_page import SettingsPage
from gui.wifi_networks_page import WifiNetworksPage
from utils.logger import get_logger

logger = get_logger(__name__)

# NOTE: there is intentionally no standalone "Connected Devices" page.
# Connected-device information is shown as part of each WiFi network's
# own details (double-click a network, or the Security Analyzer page).
NAV_ITEMS = [
    "Dashboard",
    "WiFi Networks",
    "Security Analyzer",
    "Scan History",
    "Reports",
    "Settings",
]

PAGE_CLASSES = {
    "Dashboard": DashboardPage,
    "WiFi Networks": WifiNetworksPage,
    "Security Analyzer": SecurityAnalyzerPage,
    "Scan History": ScanHistoryPage,
    "Reports": ReportsPage,
    "Settings": SettingsPage,
}


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{settings.app_name} — {settings.app_subtitle}")
        self.geometry("1200x760")
        self.minsize(1000, 640)
        self.configure(bg=palette.background)

        self._pages: dict[str, tk.Frame] = {}
        self._nav_buttons: dict[str, tk.Button] = {}
        self._current_page: str | None = None

        self._build_layout()
        self.show_page("Dashboard")

    # -- layout ------------------------------------------------------------------
    def _build_layout(self) -> None:
        sidebar = tk.Frame(self, bg=palette.surface, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        title_frame = tk.Frame(sidebar, bg=palette.surface, pady=20)
        title_frame.pack(fill="x")
        tk.Label(
            title_frame, text="🛡  WiFi Security", bg=palette.surface, fg=palette.text,
            font=("Segoe UI", 14, "bold"),
        ).pack()
        tk.Label(
            title_frame, text="Analyzer", bg=palette.surface, fg=palette.accent,
            font=("Segoe UI", 12, "bold"),
        ).pack()

        nav_frame = tk.Frame(sidebar, bg=palette.surface)
        nav_frame.pack(fill="both", expand=True, pady=10)

        for item in NAV_ITEMS:
            button = tk.Button(
                nav_frame,
                text=item,
                anchor="w",
                relief="flat",
                bg=palette.surface,
                fg=palette.text,
                activebackground=palette.surface_alt,
                activeforeground=palette.accent,
                padx=20,
                pady=10,
                font=("Segoe UI", 10),
                command=lambda name=item: self.show_page(name),
            )
            button.pack(fill="x")
            self._nav_buttons[item] = button

        self.content_area = tk.Frame(self, bg=palette.background)
        self.content_area.pack(side="right", fill="both", expand=True)

    # -- navigation ------------------------------------------------------------
    def show_page(self, name: str) -> None:
        if name not in PAGE_CLASSES:
            logger.warning("Unknown page requested: %s", name)
            return

        if self._current_page:
            self._nav_buttons[self._current_page].config(bg=palette.surface, fg=palette.text)
            self._pages[self._current_page].pack_forget()

        if name not in self._pages:
            page_cls = PAGE_CLASSES[name]
            self._pages[name] = page_cls(self.content_area, self)
        else:
            refresher = getattr(self._pages[name], "refresh", None) or getattr(
                self._pages[name], "refresh_from_db", None
            )
            if refresher:
                try:
                    refresher()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Refresh failed for page %s: %s", name, exc)

        self._pages[name].pack(fill="both", expand=True)
        self._nav_buttons[name].config(bg=palette.surface_alt, fg=palette.accent)
        self._current_page = name
