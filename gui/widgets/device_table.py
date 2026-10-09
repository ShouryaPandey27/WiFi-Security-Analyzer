"""
Treeview-based table for displaying devices associated with ONE WiFi
network (never a global device list — see database.models.DeviceRecord).

Device names/vendors are entirely automatic — see core.connected_devices
for hostname resolution (reverse DNS -> NetBIOS -> mDNS) and
core.vendor_lookup for the ~38,400-entry, IEEE-sourced MAC vendor
database. There is no manual rename/edit here by design; the literal
word "Unknown" is shown as a muted "—" rather than hidden, since every
device is still worth seeing even when it can't be identified.
"""

from __future__ import annotations

from tkinter import ttk

from config.settings import palette
from database.models import DeviceRecord

COLUMNS = ("status", "name", "ip", "mac", "vendor", "type")
HEADINGS = {
    "status": "Status",
    "name": "Name",
    "ip": "IP Address",
    "mac": "MAC Address",
    "vendor": "Vendor",
    "type": "Device Type",
}


class DeviceTable(ttk.Treeview):
    def __init__(self, parent):
        style = ttk.Style()
        # Windows' default ttk themes ('vista'/'winnative') silently
        # ignore custom Treeview.Heading background/foreground colors,
        # which is why the header row rendered plain white regardless of
        # the colors configured below. 'clam' is a theme-engine that
        # actually honors these colors, so switch to it before applying
        # the dark styling. theme_use() is safe to call repeatedly.
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(
            "DarkDevices.Treeview",
            background=palette.surface,
            fieldbackground=palette.surface,
            foreground=palette.text,
            rowheight=24,
            borderwidth=0,
        )
        style.map("DarkDevices.Treeview", background=[("selected", palette.accent)])
        style.configure(
            "DarkDevices.Treeview.Heading",
            background=palette.surface_alt,
            foreground=palette.text,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map(
            "DarkDevices.Treeview.Heading",
            background=[("active", palette.border)],
        )

        super().__init__(
            parent, columns=COLUMNS, show="headings", style="DarkDevices.Treeview", height=8
        )
        for col in COLUMNS:
            self.heading(col, text=HEADINGS[col])
            self.column(col, width=100, anchor="w")
        self.column("name", width=150)

        self.tag_configure("Unknown", foreground=palette.text_muted)

    def load(self, devices: list[DeviceRecord]) -> None:
        """
        Always render one row per device — including ones with no
        resolvable name/vendor. Hiding those would leave the table
        looking broken when most/all devices on a network are
        unidentified (common on locked-down networks). The literal word
        "Unknown" is replaced with a muted "—" instead of hiding the row.
        """
        self.delete(*self.get_children())
        for dev in devices:
            display_name = dev.hostname if dev.hostname != "Unknown" else "—"
            display_vendor = dev.vendor if dev.vendor != "Unknown" else "—"
            display_type = dev.device_type if dev.device_type != "Unknown" else "—"
            item_id = dev.mac_address or dev.ip_address or dev.hostname
            tags = ("Unknown",) if dev.vendor == "Unknown" and dev.hostname == "Unknown" else ()
            self.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    dev.status, display_name, dev.ip_address, dev.mac_address, display_vendor,
                    display_type,
                ),
                tags=tags,
            )