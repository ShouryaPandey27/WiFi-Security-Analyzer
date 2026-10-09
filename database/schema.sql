-- Secure Wave Analyzer database schema.
-- SQLite. Created automatically on first launch if it does not exist.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- Scan sessions: one row per completed WiFi scan.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_sessions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time               TEXT NOT NULL,
    total_networks          INTEGER NOT NULL DEFAULT 0,
    high_risk               INTEGER NOT NULL DEFAULT 0,
    medium_risk             INTEGER NOT NULL DEFAULT 0,
    low_risk                INTEGER NOT NULL DEFAULT 0,
    overall_security_score  REAL NOT NULL DEFAULT 0,
    scan_duration           REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_time ON scan_sessions (scan_time);

-- ---------------------------------------------------------------------
-- Networks detected within a scan session (historical record).
-- connected_devices is NULLABLE: NULL means "not determinable" for that
-- network at that time (e.g. it was not the network this host was
-- connected to), never a fabricated 0.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_networks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          INTEGER NOT NULL,
    network_id          INTEGER,
    ssid                TEXT NOT NULL DEFAULT 'Hidden Network',
    bssid               TEXT NOT NULL,
    signal_strength     INTEGER,
    channel             INTEGER,
    frequency           REAL,
    authentication      TEXT NOT NULL DEFAULT 'Unknown',
    encryption          TEXT NOT NULL DEFAULT 'Unknown',
    connected_devices   INTEGER,
    risk_level          TEXT NOT NULL DEFAULT 'LOW',
    risk_score          INTEGER NOT NULL DEFAULT 0,
    recommendation      TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions (id) ON DELETE CASCADE,
    FOREIGN KEY (network_id) REFERENCES networks (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_networks_session ON scan_networks (session_id);
CREATE INDEX IF NOT EXISTS idx_scan_networks_bssid ON scan_networks (bssid);

-- ---------------------------------------------------------------------
-- Snapshot of devices associated with a specific scan_networks row, i.e.
-- the devices seen for THAT network at THAT scan. Only ever populated
-- for the network the host was actually connected to at scan time.
-- Used to power per-network device history and scan comparison.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_network_devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_network_id     INTEGER NOT NULL,
    hostname            TEXT NOT NULL DEFAULT 'Unknown',
    ip_address          TEXT NOT NULL,
    mac_address         TEXT NOT NULL,
    vendor              TEXT NOT NULL DEFAULT 'Unknown',
    status              TEXT NOT NULL DEFAULT 'Online',
    FOREIGN KEY (scan_network_id) REFERENCES scan_networks (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_network_devices_scan_network
    ON scan_network_devices (scan_network_id);

-- ---------------------------------------------------------------------
-- Current/live snapshot of every known WiFi network (one row per BSSID).
-- connected_devices is NULLABLE for the same reason as scan_networks.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS networks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid                TEXT NOT NULL DEFAULT 'Hidden Network',
    bssid               TEXT NOT NULL UNIQUE,
    signal_strength     INTEGER,
    channel             INTEGER,
    frequency           REAL,
    authentication      TEXT NOT NULL DEFAULT 'Unknown',
    encryption          TEXT NOT NULL DEFAULT 'Unknown',
    connected_devices   INTEGER,
    risk_level          TEXT NOT NULL DEFAULT 'LOW',
    risk_score          INTEGER NOT NULL DEFAULT 0,
    last_seen           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks (bssid);

-- ---------------------------------------------------------------------
-- Devices discovered on the user's authorized local network(s).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname            TEXT NOT NULL DEFAULT 'Unknown',
    ip_address          TEXT NOT NULL,
    mac_address         TEXT NOT NULL UNIQUE,
    vendor              TEXT NOT NULL DEFAULT 'Unknown',
    device_type         TEXT NOT NULL DEFAULT 'Unknown',
    operating_system    TEXT NOT NULL DEFAULT 'Unknown',
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'Offline',
    risk_level          TEXT NOT NULL DEFAULT 'LOW',
    risk_score          INTEGER NOT NULL DEFAULT 0,
    trusted             INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices (ip_address);

-- ---------------------------------------------------------------------
-- Live network <-> device association (many-to-many, though in practice
-- a device is associated with the single network it was discovered on).
-- This is the current source of truth for "which devices belong to
-- which WiFi network" shown in Network Details.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS network_devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id          INTEGER NOT NULL,
    device_id           INTEGER NOT NULL,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'Online',
    UNIQUE (network_id, device_id),
    FOREIGN KEY (network_id) REFERENCES networks (id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_network_devices_network ON network_devices (network_id);
CREATE INDEX IF NOT EXISTS idx_network_devices_device ON network_devices (device_id);

-- ---------------------------------------------------------------------
-- Per-scan history for each device (tracks status/response time over time).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_scan_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           INTEGER NOT NULL,
    scan_time           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'Offline',
    response_time       REAL,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_history_device ON device_scan_history (device_id);
CREATE INDEX IF NOT EXISTS idx_device_history_time ON device_scan_history (scan_time);