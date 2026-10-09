"""Best-effort classification of a connected device's type (Section 13)."""

from __future__ import annotations

# Order matters: dict iteration is insertion order, and the FIRST
# matching device_type wins. "redmi" must be checked before "xiaomi" —
# Redmi hostnames like "redmi-note-12" contain the substring "mi-", which
# would otherwise false-match a generic Xiaomi hint first.
_HOSTNAME_HINTS: dict[str, list[str]] = {
    "iPhone": ["iphone"],
    "iPad": ["ipad"],
    "MacBook": ["macbook"],
    "Redmi Phone": ["redmi"],
    "Xiaomi Phone": ["xiaomi", "mi-"],
    "Huawei Phone": ["huawei", "honor"],
    "OnePlus Phone": ["oneplus"],
    "Oppo Phone": ["oppo"],
    "Vivo Phone": ["vivo"],
    "Google Pixel": ["pixel"],
    "Samsung Galaxy": ["galaxy", "samsung", "sm-"],
    "Smartphone": ["android", "mobile"],
    "ASUS Laptop": ["asus", "rog-", "zenbook", "rog "],
    "MSI Laptop": ["msi-", "msi "],
    "Dell Laptop": ["dell"],
    "HP Laptop": ["hp-", "pavilion", "elitebook"],
    "Lenovo Laptop": ["lenovo", "thinkpad", "ideapad"],
    "Laptop": ["laptop", "notebook", "surface"],
    "PC": ["desktop", "pc-", "workstation"],
    "Router": ["router", "gateway", "ap-", "accesspoint", "modem"],
    "IoT": [
        "hue",
        "nest",
        "echo",
        "alexa",
        "chromecast",
        "roku",
        "smarttv",
        "camera",
        "cam-",
        "printer",
        "thermostat",
        "plug",
        "sensor",
    ],
}

# Vendor-based fallback ONLY when hostname gives no hint. Deliberately
# conservative: for phone vendors (Apple/Samsung) the MAC vendor usually
# does match the actual phone brand, so a generic category is a
# reasonable fallback. For PC/laptop network-chipset vendors (Intel,
# Realtek, Qualcomm Atheros, Broadcom, MediaTek), the MAC identifies the
# WiFi CHIP maker, not the computer's brand (MSI/ASUS/Dell/etc. almost
# always use a third-party chipset) — labeling those "Laptop/PC" is
# honest; guessing a specific OEM brand from them would not be.
_VENDOR_HINTS: dict[str, str] = {
    "apple": "Smartphone",  # refined further by hostname above where possible
    "samsung": "Smartphone",
    "raspberry pi": "IoT",
    "philips": "IoT",
    "nest labs": "IoT",
    "amazon": "IoT",
    "tp-link": "Router",
    "synology": "PC",
    "asustek": "ASUS Laptop",
    "micro-star": "MSI Laptop",  # official IEEE name for MSI
    "dell": "Dell Laptop",
    "hewlett packard": "HP Laptop",
    "lenovo": "Lenovo Laptop",
    "intel": "Laptop/PC",
    "realtek": "Laptop/PC",
    "qualcomm": "Laptop/PC",
    "broadcom": "Laptop/PC",
    "mediatek": "Laptop/PC",
}


def classify_device(*, hostname: str | None, vendor: str | None) -> str:
    """
    Guess a device type from hostname/vendor hints; 'Unknown' if no match.

    Hostname hints are checked first and are the more reliable source
    for a brand-specific label (e.g. "MSI Laptop") since a computer's
    own name is sometimes set by its OEM's imaging tools or the user
    themselves. For a guaranteed-accurate label regardless of what the
    hostname/vendor detection can determine, see the "Rename Device"
    feature (gui.widgets.device_table / database.repositories.
    DeviceRepository.set_custom_name) — hostname/vendor guessing is
    inherently best-effort and should never be treated as certain.
    """
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()

    for device_type, hints in _HOSTNAME_HINTS.items():
        if any(hint in hostname_l for hint in hints):
            return device_type

    for vendor_hint, device_type in _VENDOR_HINTS.items():
        if vendor_hint in vendor_l:
            return device_type

    return "Unknown"