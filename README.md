# Secure Wave Analyzer

**Wireless Security Monitoring & Analysis System**

A professional desktop application for discovering nearby WiFi
networks, analyzing their security posture with a transparent risk
score, discovering and classifying devices on your own authorized
local network, tracking scan history over time, and generating
PDF/CSV reports — built for a university cybersecurity project
demonstration.

This is a **defensive-only** tool: it discovers and analyzes networks
and devices you're authorized to inspect. It does not implement
password cracking, deauthentication, packet injection, exploitation,
or any offensive capability.

## Features

- Cross-platform WiFi network discovery (Windows `netsh`, Linux
  `nmcli`/`iwlist`, macOS `airport`)
- Explainable 0–100 risk scoring for every network, with named,
  additive risk factors (never an opaque number)
- **Per-network** connected-device visibility — each WiFi network's own
  "Devices" count and device list, shown in that network's own details.
  There is no separate device-scanning page: device info is only ever
  attempted for the one network the host is actually, authorizedly
  connected to, and every other network clearly shows "Unavailable"
  rather than a fabricated number
- Authenticated local network device discovery (ARP, via Scapy or the
  OS ARP cache), vendor lookup, and best-effort device classification
- Per-device risk scoring (unknown vendor, randomized MAC, duplicate
  IP, suspicious hostname, trusted override) that feeds into its
  network's own risk score — many known devices never raise risk alone
- Dynamic, specific security recommendations — never generic filler
  when a specific issue was detected
- Full scan history with date/risk filtering, session comparison
  (new/removed/changed networks, plus per-network device count and
  identity changes), and trend charts
- PDF (ReportLab) and CSV report generation for networks, per-network
  connected devices, and history
- Dark "SOC" cybersecurity dashboard UI built in Tkinter/ttk, with
  background-threaded scanning so the UI never freezes
- SQLite persistence with a clean repository layer
- 53-test pytest suite covering risk scoring, security analysis,
  device classification, per-network device association/scoping,
  history/comparison, and the database layer

## Architecture

```
GUI  →  Core Services  →  Database / Network Layer
```

See [`docs/architecture.md`](docs/architecture.md) for the full
breakdown and a request-flow walkthrough, and
[`docs/database.md`](docs/database.md) for the schema.

## Technology Stack

| Concern | Choice |
|---|---|
| Language | Python 3.12+ |
| GUI | Tkinter + ttk |
| Database | SQLite (stdlib `sqlite3`) |
| WiFi / network scanning | OS-native tools (`netsh`/`nmcli`/`iwlist`/`airport`) |
| Local device discovery | Scapy (ARP), OS ARP cache fallback |
| Charts | Matplotlib |
| PDF reports | ReportLab |
| Testing | pytest |
| Logging | stdlib `logging` (rotating file handler) |
| Configuration | `.env` / `config/settings.py` |

## Installation

Requires Python 3.12+.

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Copy `.env.example` to `.env` to customize scan timeouts, auto-refresh,
or logging level (all optional — sensible defaults are built in).

## How to Run

```
python app.py
```

The app initializes logging, initializes/creates the SQLite database at
`data/secure_wave.db`, verifies optional dependencies, and opens the
Dashboard.

## How WiFi Scanning Works

See [`docs/user_guide.md`](docs/user_guide.md#how-wifi-scanning-works).

## Risk Assessment

Every network and device risk score is a sum of small, named,
additive point contributions (e.g. Open network +50, WEP +40, TKIP
+20, WPS enabled +20), capped at 100 and classified as:

| Score | Level |
|---|---|
| 0–30 | LOW |
| 31–70 | MEDIUM |
| 71–100 | HIGH |

WPA2 + CCMP intentionally scores LOW/MEDIUM — it is not automatically
treated as maximum risk. See `core/risk_engine.py` for the full table.

## Connected Device Analysis

Connected-device information is **per-network**, not global — see
[`docs/user_guide.md`](docs/user_guide.md#connected-devices-are-per-network-not-global).

## Scan History

Every completed scan is saved as a session (toggle via `AUTO_SAVE_HISTORY`
in `.env`). Compare any two sessions to see new, removed, and changed
networks by BSSID.

## Reports

Network, per-network Connected Devices, and Scan History reports are
available as PDF (ReportLab) or CSV from the **Reports** page.

## Testing

```
pytest
```

53 tests across risk scoring, security analysis, device classification,
per-network device association/scoping, scan history/comparison, and
database persistence — all passing.

## Troubleshooting & Limitations

See [`docs/user_guide.md`](docs/user_guide.md#troubleshooting) and
[`docs/user_guide.md`](docs/user_guide.md#limitations).

## License

MIT — see [`LICENSE`](LICENSE).
