"""
Secure Wave Analyzer — application entry point.

Responsibilities:
    1. Initialize logging.
    2. Initialize the database (creating it if missing).
    3. Verify the runtime environment.
    4. Initialize and launch the GUI.
    5. Handle unexpected startup exceptions gracefully.

Run with:
    python app.py
"""

from __future__ import annotations

import importlib.util
import sys
import tkinter as tk
from tkinter import messagebox

from config.settings import settings
from utils.logger import configure_logging, get_logger


def verify_environment(logger) -> list[str]:
    """Best-effort check of optional dependencies; never raises."""
    warnings: list[str] = []

    for module_name, message in (
        ("scapy", "Scapy not installed — device discovery will use the ARP cache fallback."),
        ("reportlab", "ReportLab not installed — PDF export will be unavailable (CSV still works)."),
        ("matplotlib", "Matplotlib not installed — history charts will be unavailable."),
    ):
        if importlib.util.find_spec(module_name) is None:
            warnings.append(message)

    for warning in warnings:
        logger.warning(warning)

    return warnings


def main() -> int:
    configure_logging()
    logger = get_logger("app")
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)
    
    try:
        settings.ensure_directories()

        # Initialize the database up front so failures surface before the GUI opens.
        from database.database import get_database

        get_database()
        logger.info("Database initialized at %s", settings.db_path)

        verify_environment(logger)

        from gui.main_window import MainWindow

        window = MainWindow()
        logger.info("GUI launched — dashboard displayed")
        window.mainloop()
        return 0

    except Exception as exc:  # noqa: BLE001 - top-level guard, must never crash silently
        logger.exception("Fatal error during startup: %s", exc)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Secure Wave Analyzer — Startup Error",
                f"The application failed to start:\n\n{exc}\n\nSee logs/secure_wave.log for details.",
            )
        except Exception:  # noqa: BLE001 - even the error dialog must not crash us
            print(f"Fatal error during startup: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
