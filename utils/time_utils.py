"""Small time/date helpers shared across the application."""

from __future__ import annotations

from datetime import datetime, timedelta


def now_iso() -> str:
    """Return the current local time as an ISO-8601 string (seconds precision)."""
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 string produced by :func:`now_iso`, or return None."""
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def humanize_duration(seconds: float) -> str:
    """Render a duration in seconds as e.g. '1m 12s' or '350ms'."""
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    minutes, secs = divmod(int(seconds), 60)
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_display(value: str | None) -> str:
    """Format a stored ISO timestamp for display, or 'Unknown' if missing."""
    dt = parse_iso(value) if value else None
    if not dt:
        return "Unknown"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def within_last(value: str | None, *, minutes: int) -> bool:
    """True if the ISO timestamp is within the last N minutes."""
    dt = parse_iso(value) if value else None
    if not dt:
        return False
    return datetime.now() - dt <= timedelta(minutes=minutes)
