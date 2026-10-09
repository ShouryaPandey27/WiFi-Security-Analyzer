# Database

Secure Wave Analyzer uses a single SQLite database at `data/secure_wave.db`,
created automatically on first launch from `database/schema.sql`. The
application never crashes if the file is missing — `Database.__init__`
creates the parent directory and runs the schema script unconditionally.

## Connected-device design

Connected-device information is **per-network**, never global. Nearby
WiFi scanning only ever reveals access-point information (SSID, BSSID,
signal, channel, authentication, encryption) — not the list of clients
associated with that access point. The only network device association
can be reliably determined for is the one the host machine is actually,
authorizedly connected to at scan time (identified via
`core.network_discovery.get_current_connection_bssid()`).

Because of this, every "connected devices" field in the schema is
**nullable**, and `NULL` always means *"not determinable with the
current scan method"* — never a fabricated `0`. The GUI renders this as
`"Unavailable"`.

## Tables

### `networks`
Live/current snapshot of the most recently seen state of every WiFi
network (one row per BSSID, upserted on every scan). Powers the
Dashboard and WiFi Networks page without replaying scan history.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| ssid | TEXT | Defaults to "Hidden Network" |
| bssid | TEXT UNIQUE | |
| signal_strength | INTEGER | dBm, nullable |
| channel | INTEGER | nullable |
| frequency | REAL | nullable |
| authentication | TEXT | OPEN / WEP / WPA / WPA2 / WPA3 / WPA2/WPA3 |
| encryption | TEXT | CCMP / TKIP / Unknown |
| connected_devices | INTEGER | **Nullable.** NULL = not determinable for this network |
| risk_level | TEXT | LOW / MEDIUM / HIGH |
| risk_score | INTEGER | 0-100 |
| last_seen | TEXT | ISO-8601 |

### `devices`
Devices discovered on the user's authorized local network (one row per
MAC address, deduplicated across all networks it's ever been seen on).

| Column | Type |
|---|---|
| id | INTEGER PK |
| hostname, ip_address, mac_address (UNIQUE) | — |
| vendor, device_type, operating_system | — |
| first_seen, last_seen | TEXT (ISO-8601) |
| status | Online / Offline |
| risk_level, risk_score | — |
| trusted | INTEGER (0/1) |

### `network_devices`
The live many-to-many association between `networks` and `devices` —
this is the source of truth for "which devices belong to which WiFi
network" shown in Network Details. In practice a device is associated
with exactly one network (the one it was discovered on), and a fresh
scan's `NetworkDeviceRepository.replace_devices_for_network()` call
drops any stale association for devices no longer seen.

| Column | Type |
|---|---|
| id | INTEGER PK |
| network_id | INTEGER, FK → networks.id (ON DELETE CASCADE) |
| device_id | INTEGER, FK → devices.id (ON DELETE CASCADE) |
| first_seen, last_seen | TEXT (ISO-8601) |
| status | Online / Offline |

`UNIQUE(network_id, device_id)`.

### `scan_sessions`
One row per completed WiFi scan (Section 17).

| Column | Type |
|---|---|
| id | INTEGER PK |
| scan_time | TEXT (ISO-8601) |
| total_networks | INTEGER |
| high_risk / medium_risk / low_risk | INTEGER |
| overall_security_score | REAL |
| scan_duration | REAL (seconds) |

### `scan_networks`
Networks captured within a specific `scan_sessions` row — the historical
record used for Scan History and comparisons. `connected_devices` is
nullable for the same reason as in `networks`.

| Column | Type |
|---|---|
| id | INTEGER PK |
| session_id | INTEGER, FK → scan_sessions.id (ON DELETE CASCADE) |
| network_id | INTEGER, FK → networks.id (ON DELETE SET NULL), nullable |
| ssid, bssid, signal_strength, channel, frequency | — |
| authentication, encryption | — |
| connected_devices | INTEGER, nullable |
| risk_level, risk_score | — |
| recommendation | TEXT, nullable |

### `scan_network_devices`
A snapshot of the individual devices associated with one `scan_networks`
row at the time of that scan. Only ever populated for the network the
host was actually connected to — this is what powers per-network device
identity comparison across scans (new/removed devices).

| Column | Type |
|---|---|
| id | INTEGER PK |
| scan_network_id | INTEGER, FK → scan_networks.id (ON DELETE CASCADE) |
| hostname, ip_address, mac_address, vendor | — |
| status | Online / Offline |

### `device_scan_history`
Per-scan snapshot of a device's status/response time (Section 15 of the
base spec), independent of which network it was seen on.

| Column | Type |
|---|---|
| id | INTEGER PK |
| device_id | INTEGER, FK → devices.id (ON DELETE CASCADE) |
| scan_time | TEXT (ISO-8601) |
| status | Online / Offline |
| response_time | REAL, nullable (seconds) |
| risk_score | INTEGER |

## Indexes

`scan_sessions.scan_time`, `scan_networks.session_id`,
`scan_networks.bssid`, `scan_network_devices.scan_network_id`,
`networks.bssid`, `network_devices.network_id`, `network_devices.device_id`,
`devices.mac_address`, `devices.ip_address`,
`device_scan_history.device_id`, `device_scan_history.scan_time`.

## Access pattern

All SQL lives in `database/repositories.py`. `core/` and `gui/` call
repository methods — no other module issues raw SQL:

- `NetworkRepository` — the live `networks` table. Reads automatically
  join `network_devices`/`devices` and populate `NetworkRecord.devices`
  whenever `connected_devices` is not NULL.
- `NetworkDeviceRepository` — owns `network_devices`;
  `replace_devices_for_network()` is the only way devices get
  associated with a network, and it always replaces the full set
  (dropping stale associations) rather than appending.
- `ScanHistoryRepository` — `scan_sessions`, `scan_networks`, and
  `scan_network_devices`.
- `DeviceRepository` — `devices` and `device_scan_history`.

Every repository method catches `sqlite3.Error`, logs it, and degrades
gracefully (returns `[]`/`None` rather than raising into the GUI).
