"""
MAC OUI -> vendor lookup.

Backed by data/oui_vendors.txt: a ~38,400-entry, verified snapshot of the
official IEEE Registration Authority MAC address registry
(https://standards-oui.ieee.org/oui/oui.txt), redistributed here under
Apache License 2.0 — see data/oui_vendors_ATTRIBUTION.txt for the full
provenance and license. This covers essentially every organization that
has ever registered a MAC prefix, including phone makers (Apple,
Samsung, Xiaomi, Huawei, ...), network chipset makers (Intel, Realtek,
Qualcomm Atheros, Broadcom, MediaTek, ...), and PC/laptop OEMs
(ASUSTek, Micro-Star International/MSI, Dell, HP, Lenovo, ...).

Loaded once, lazily, into an in-memory dict — no network access, no new
runtime dependency beyond the standard library. Never fabricates a
vendor: unmatched prefixes are reported as 'Unknown', and if the data
file is ever missing/corrupted, a tiny built-in fallback table (below)
is used instead of crashing.
"""

from __future__ import annotations

from pathlib import Path

from utils.logger import get_logger
from utils.validators import is_valid_mac

logger = get_logger(__name__)

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "oui_vendors.txt"

# Used only if data/oui_vendors.txt is missing or fails to load — keeps
# the app from ever crashing over this, at the cost of far narrower
# coverage than the bundled database above.
_FALLBACK_OUI_TABLE: dict[str, str] = {
    "A483E7": "Apple",
    "F01898": "Apple",
    "ACDE48": "Apple",
    "5C0A5B": "Samsung",
    "8C79F5": "Samsung",
    "B827EB": "Raspberry Pi Foundation",
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "Oracle VirtualBox",
    "00E04C": "Realtek",
}

_vendor_table: dict[str, str] | None = None


def _load_vendor_table() -> dict[str, str]:
    global _vendor_table
    if _vendor_table is not None:
        return _vendor_table

    table: dict[str, str] = {}
    try:
        with _DATA_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                prefix, _, vendor = line.partition(":")
                prefix = prefix.strip().upper()
                vendor = vendor.strip()
                if len(prefix) == 6 and vendor:
                    table[prefix] = vendor
        if table:
            logger.info("Loaded %d OUI vendor entries from %s", len(table), _DATA_PATH)
        else:
            raise ValueError("Parsed 0 entries")
    except Exception as exc:  # noqa: BLE001 - never let a bad data file break the app
        logger.warning(
            "Could not load %s (%s); using small built-in fallback vendor table.",
            _DATA_PATH, exc,
        )
        table = dict(_FALLBACK_OUI_TABLE)

    _vendor_table = table
    return table


def lookup_vendor(mac_address: str | None) -> str:
    """Return the best-effort vendor name for a MAC address, or 'Unknown'."""
    if mac_address is None or not is_valid_mac(mac_address):
        return "Unknown"
    prefix = mac_address.strip().upper().replace("-", ":").replace(":", "")[:6]
    return _load_vendor_table().get(prefix, "Unknown")