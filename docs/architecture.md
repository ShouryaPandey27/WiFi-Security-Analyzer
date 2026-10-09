# Architecture

Secure Wave Analyzer follows a strict layered architecture:

```
GUI  →  Core Services  →  Database / Network Layer
```

## Layers

**GUI (`gui/`)**
Tkinter/ttk pages and widgets. Pages call into `core/` services and
`database/repositories.py` — they never talk to `sqlite3`, `subprocess`,
or Scapy directly, and never contain scanning or risk-scoring logic.
Long-running work (WiFi scans, device discovery, report generation) runs
on background `threading.Thread`s; results are marshalled back to the
main thread with `Tk.after(0, ...)` so the UI never blocks.

There is **no standalone "Connected Devices" page**. Connected-device
information is always shown scoped to the specific WiFi network it
belongs to — via the "Devices" column in `gui/widgets/network_table.py`
and the full breakdown in `gui/dialogs/network_details.py`, opened by
double-clicking a network on the Dashboard, WiFi Networks, or Security
Analyzer pages.

**Core Services (`core/`)**
Pure(ish) business logic: WiFi scanning (`wifi_scanner.py`), current-
connection detection and local host discovery (`network_discovery.py`),
per-network device association (`connected_devices.py`), classification
(`device_classifier.py`, `vendor_lookup.py`), risk scoring
(`risk_engine.py`), security analysis (`security_analyzer.py`),
recommendations (`recommendation_engine.py`), scan history
(`scan_history.py`, `history_analyzer.py`), and report generation
(`report_generator.py`). These modules depend on `database/` and
`utils/`, never on `gui/`.

**Database / Network Layer (`database/`, OS calls in `core/`)**
`database/database.py` owns the single SQLite connection (thread-local)
and schema bootstrapping. `database/repositories.py` is the *only*
place SQL is written — `NetworkRepository`, `NetworkDeviceRepository`,
`DeviceRepository`, and `ScanHistoryRepository`. Network I/O
(netsh/nmcli/iwlist/airport, ARP requests) lives in
`core/wifi_scanner.py` and `core/network_discovery.py` behind small,
testable functions that return dataclasses, never raw subprocess
output, to the rest of the app.

## Why this shape

- **Testability** — `core/` and `database/` have no GUI dependency, so
  `tests/` can exercise risk scoring, classification, device
  association, and persistence without a display.
- **Graceful degradation** — optional dependencies (Scapy, ReportLab,
  Matplotlib) are imported defensively; their absence disables one
  feature (e.g. PDF export) without crashing the app.
- **Explainability** — `RiskResult.factors` carries the named point
  contributions all the way from `risk_engine.py` to the GUI, so every
  score the user sees can be justified — including device-related
  factors like "1 unknown device detected (+10)".
- **Never fabricate what can't be determined** — `NetworkRecord.
  connected_devices` is `Optional[int]`; `None` always means "not
  determinable with the current scan method" and renders as
  "Unavailable" in every table, dialog, and report. It is never
  silently treated as `0`.

## Data flow: a WiFi scan

```
DashboardPage.start_scan()
  → threading.Thread → core.wifi_scanner.scan_networks()
      → OS backend (netsh / nmcli+iwlist / airport)
      → ScanOutcome(networks=[NetworkRecord, ...])
  → core.network_discovery.get_current_connection_bssid()
      → identifies the ONE nearby network (if any) this host is
        actually, authorizedly connected to
  → for that one network only:
      core.connected_devices.associate_devices_for_network(is_current_connection=True)
        → core.network_discovery.discover_hosts() (Scapy ARP / ARP cache)
        → per-host: vendor_lookup, device_classifier, calculate_device_risk
        → DeviceAssociationOutcome(devices, unknown_device_count, suspicious_device_detected)
      (every other network: device_info_available=False, connected_devices=None)
  → core.security_analyzer.analyze_network() per network
      → core.risk_engine.calculate_network_risk(..., unknown_device_count, suspicious_device_detected)
      → core.recommendation_engine.build_network_recommendations()
  → database.repositories.NetworkRepository.upsert() (live snapshot, returns network id)
  → database.repositories.NetworkDeviceRepository.replace_devices_for_network()
      (only for the network device info was available for)
  → core.scan_history.save_scan()
      → database.repositories.ScanHistoryRepository.save_session()
        (also snapshots scan_network_devices for comparison later)
  → Tk.after(0, ...) → GUI updated on the main thread
```
