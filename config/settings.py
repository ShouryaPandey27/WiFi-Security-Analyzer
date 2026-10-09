"""
Application-wide configuration for Secure Wave Analyzer.

Settings are loaded from environment variables (via an optional .env file)
with sane, safe defaults so the application runs out of the box.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional .env support (no hard dependency on python-dotenv).
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so we don't require python-dotenv as a dependency."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(BASE_DIR / ".env")


def _get_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable application settings."""

    app_name: str = "WiFi Security Analyzer"
    app_subtitle: str = "Wireless Security Monitoring & Analysis System"
    app_version: str = "1.0.0"

    # Paths
    base_dir: Path = BASE_DIR
    data_dir: Path = BASE_DIR / "data"
    logs_dir: Path = BASE_DIR / "logs"
    reports_dir: Path = BASE_DIR / "reports" / "generated"
    db_path: Path = BASE_DIR / "data" / "secure_wave.db"

    # Scanning behaviour
    scan_timeout_seconds: int = field(default_factory=lambda: _get_int("SCAN_TIMEOUT", 20))
    auto_refresh_enabled: bool = field(default_factory=lambda: _get_bool("AUTO_REFRESH", False))
    auto_refresh_interval_seconds: int = field(
        default_factory=lambda: _get_int("AUTO_REFRESH_INTERVAL", 60)
    )
    auto_save_history: bool = field(default_factory=lambda: _get_bool("AUTO_SAVE_HISTORY", True))
    device_scan_timeout_seconds: int = field(
        default_factory=lambda: _get_int("DEVICE_SCAN_TIMEOUT", 3)
    )
    device_ping_sweep_enabled: bool = field(
        default_factory=lambda: _get_bool("DEVICE_PING_SWEEP_ENABLED", True)
    )
    device_ping_sweep_timeout_ms: int = field(
        default_factory=lambda: _get_int("DEVICE_PING_SWEEP_TIMEOUT_MS", 400)
    )
    device_ping_sweep_max_workers: int = field(
        default_factory=lambda: _get_int("DEVICE_PING_SWEEP_MAX_WORKERS", 120)
    )

    # GUI
    theme: str = "dark_soc"
    logging_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))

    def ensure_directories(self) -> None:
        """Create runtime directories if they do not already exist."""
        for directory in (self.data_dir, self.logs_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Dark SOC / cybersecurity color palette (shared by every GUI module).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Palette:
    background: str = "#0D1117"
    surface: str = "#161B22"
    surface_alt: str = "#1C2129"
    border: str = "#30363D"
    accent: str = "#58A6FF"
    text: str = "#C9D1D9"
    text_muted: str = "#8B949E"
    risk_high: str = "#F85149"
    risk_medium: str = "#D29922"
    risk_low: str = "#3FB950"
    risk_critical: str = "#FF6B6B"


settings = Settings()
palette = Palette()