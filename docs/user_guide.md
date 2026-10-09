# User Guide

## Starting the application

```
python app.py
```

On first launch, Secure Wave Analyzer creates `data/`, `logs/`, and
`reports/generated/` if they don't exist, initializes the SQLite
database, and opens the Dashboard.

## Pages

**Dashboard** — At-a-glance stats (networks detected, security score,
open networks, high-risk networks, and how many currently-known
networks have reliable device information), the latest scan summary,
and the full network table. Click **Scan Networks** to run a new WiFi
scan in the background; the UI stays responsive throughout. Double-click
any network row to open its full details, including connected devices.

**WiFi Networks** — Every currently known network, searchable by SSID
or BSSID, with a **Devices** column showing either a real count or
"Unavailable". Double-click a row (or select it and click **View
Details**) to open the full Network Details dialog.

**Security Analyzer** — Pick a network from the list to see its full
assessment: status, risk score, authentication, encryption,
vulnerabilities, and specific recommendations — including
device-related ones when applicable (e.g. "Verify the unknown device
if it does not belong to an authorized user."). A button opens the
same full Network Details dialog used elsewhere.

**Scan History** — Every completed scan, filterable by date and
searchable by scan ID. Select two sessions and click **Compare** to see
new/removed/changed networks, including per-network connected-device
count changes and, when identity is known, which specific devices were
newly seen or dropped. **View** opens the full network list for one
session. **Export** produces a CSV of session summaries. A Security
Score Trend chart appears below the table when Matplotlib is installed.

**Reports** — Export Network, per-network Connected Devices, and Scan
History reports as PDF (ReportLab) or CSV. The Connected Devices report
only lists networks where device information was actually determined
— it never lists a network with a fabricated empty or zero entry.

**Settings** — Adjust auto-refresh, auto-save-history, scan timeouts,
logging level, and the report output folder for the current session.
Persistent changes should go in a `.env` file (see `.env.example`).

## Connected devices are per-network, not global

There is **no standalone "Connected Devices" page or scan**. Nearby
WiFi scanning only ever reveals information about each access point —
never the list of clients associated with it. Secure Wave Analyzer
therefore only attempts device discovery for the **one** network the
host machine is actually, authorizedly connected to at scan time
(detected via `netsh wlan show interfaces` / `nmcli` / `airport -I`
depending on platform). For every other nearby network, the "Connected
Devices" field is shown as **"Unavailable"** — never a guessed or
zeroed-out number.

When device information is available for a network:

- Discovery uses Scapy-based ARP requests (or the OS ARP cache as a
  fallback) restricted to the local subnet.
- Each device is vendor-looked-up, classified, and risk-scored, then
  associated with that one network in the database.
- Unknown-vendor or suspicious-hostname devices contribute small,
  named point values to that network's own risk score — but simply
  having many *known* devices never raises risk on its own.

## How WiFi scanning works

The scanner shells out to the OS's own WiFi tooling — `netsh` on
Windows, `nmcli` (falling back to `iwlist`) on Linux, `airport` on
macOS — and parses the results into a common `NetworkRecord` format.
No packets are injected, no networks are attacked; this is discovery
and analysis only.

## How risk scoring works

Every network and device risk score is built from small, named,
additive point values (see `core/risk_engine.py`). A network's score is
never a single opaque number — the Security Analyzer page and Network
Details dialog always show which specific factors (e.g. "Open network
(no authentication) +50", "TKIP encryption +20", "1 unknown device
detected +10") contributed to the total.

## Scan history and comparison

Every completed WiFi scan is (by default) saved as a session, including
each network's connected-device count where it was determinable, and a
snapshot of the individual devices for the network that had that
information. Use Scan History's **Compare** feature to see what changed
between any two scans — new/removed/changed networks, connected-device
count deltas, and (when identity was tracked) which specific devices
appeared or disappeared.

## Reports

CSV export always works (standard library only). PDF export requires
`reportlab` — if it isn't installed, the Reports page will show a clear
message rather than crashing.

## Testing

```
pytest
```

Runs the full test suite covering risk scoring (including device-aware
factors), security analysis, device classification, per-network device
association and scoping, scan history/comparison, and database
persistence.

## Troubleshooting

- **"No networks detected"** — Confirm your WiFi adapter is on and, on
  Linux, that `nmcli` or `iwlist` is installed and you have permission
  to run them.
- **A network's devices always show "Unavailable"** — This is expected
  for every network except the one you're currently connected to;
  nearby WiFi scanning cannot see another access point's clients. If
  even your own connected network shows "Unavailable", raw ARP scanning
  (Scapy) may need elevated privileges — the app falls back to the OS
  ARP cache automatically, which only shows hosts your machine has
  already talked to.
- **PDF export fails** — Run `pip install reportlab`.
- **Charts missing on Scan History** — Run `pip install matplotlib`.
- **Windows permissions** — `netsh wlan show networks`/`show interfaces`
  generally work without elevation; ARP scanning via Scapy on Windows
  requires [Npcap](https://npcap.com/) to be installed and the app to
  run with sufficient privileges (Administrator) for raw sockets.

## Limitations

- WiFi scanning quality depends entirely on the OS tool used; some
  fields (frequency, exact signal in dBm) may be approximate or
  unavailable on some platforms.
- Connected-device information is only ever available for the single
  network the host is currently connected to — this is a fundamental
  limitation of passive WiFi scanning, not a missing feature.
- OS/device fingerprinting is best-effort only — no active OS
  fingerprinting techniques are used.
- The built-in vendor OUI table is illustrative, not exhaustive.
- This is a defensive discovery/analysis tool only: no password
  cracking, deauthentication, packet injection, or exploitation is
  implemented or supported.
