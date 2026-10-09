"""
Repository layer: every SQL statement used by the application lives here.
Core services and GUI code talk to repositories, never to raw SQL.
"""

from __future__ import annotations

import sqlite3

from database.database import Database, get_database
from database.models import DeviceRecord, NetworkRecord, ScanSession
from utils.logger import get_logger
from utils.time_utils import now_iso

logger = get_logger(__name__)


# ===========================================================================
# Networks (current/live snapshot table)
# ===========================================================================
class NetworkRepository:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def upsert(self, network: NetworkRecord) -> int | None:
        """Insert or update a network by BSSID and return its row id."""
        try:
            self.db.execute(
                """
                INSERT INTO networks
                    (ssid, bssid, signal_strength, channel, frequency,
                     authentication, encryption, connected_devices,
                     risk_level, risk_score, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid=excluded.ssid,
                    signal_strength=excluded.signal_strength,
                    channel=excluded.channel,
                    frequency=excluded.frequency,
                    authentication=excluded.authentication,
                    encryption=excluded.encryption,
                    connected_devices=excluded.connected_devices,
                    risk_level=excluded.risk_level,
                    risk_score=excluded.risk_score,
                    last_seen=excluded.last_seen
                """,
                (
                    network.ssid,
                    network.bssid,
                    network.signal_strength,
                    network.channel,
                    network.frequency,
                    network.authentication,
                    network.encryption,
                    network.connected_devices,
                    network.risk_level,
                    network.risk_score,
                    network.last_seen or now_iso(),
                ),
            )
            row = self.db.fetch_one("SELECT id FROM networks WHERE bssid = ?", (network.bssid,))
            return row["id"] if row else None
        except sqlite3.Error as exc:
            logger.error("Failed to upsert network %s: %s", network.bssid, exc)
            return None

    def all(self) -> list[NetworkRecord]:
        rows = self.db.fetch_all("SELECT * FROM networks ORDER BY risk_score DESC")
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, network_id: int) -> NetworkRecord | None:
        row = self.db.fetch_one("SELECT * FROM networks WHERE id = ?", (network_id,))
        return self._row_to_record(row) if row else None

    def get_by_bssid(self, bssid: str) -> NetworkRecord | None:
        row = self.db.fetch_one("SELECT * FROM networks WHERE bssid = ?", (bssid,))
        return self._row_to_record(row) if row else None

    def clear(self) -> None:
        self.db.execute("DELETE FROM networks")

    def _row_to_record(self, row: sqlite3.Row) -> NetworkRecord:
        record = NetworkRecord(
            id=row["id"],
            ssid=row["ssid"],
            bssid=row["bssid"],
            signal_strength=row["signal_strength"],
            channel=row["channel"],
            frequency=row["frequency"],
            authentication=row["authentication"],
            encryption=row["encryption"],
            connected_devices=row["connected_devices"],
            device_info_available=row["connected_devices"] is not None,
            risk_level=row["risk_level"],
            risk_score=row["risk_score"],
            last_seen=row["last_seen"],
        )
        # Only join for devices when a real count was recorded — avoids an
        # extra query for the common case (most networks have none).
        if record.device_info_available and record.id is not None:
            record.devices = NetworkDeviceRepository(self.db).get_devices_for_network(record.id)
        return record


# ===========================================================================
# Network <-> Device association (live)
# ===========================================================================
class NetworkDeviceRepository:
    """
    Owns the live network_devices association and the devices it points
    to. Devices are only ever associated with the network the host was
    actually connected to at discovery time — never fabricated for
    networks that were merely seen in a beacon scan.
    """

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def replace_devices_for_network(self, network_id: int, devices: list[DeviceRecord]) -> None:
        """
        Set the authoritative device list for a network: upsert each
        device, upsert its association, and drop associations for
        devices no longer seen on this network.
        """
        try:
            device_repo = DeviceRepository(self.db)
            seen_device_ids: list[int] = []

            for device in devices:
                device_id = device_repo.upsert(device)
                if device_id is None:
                    continue
                seen_device_ids.append(device_id)
                existing = self.db.fetch_one(
                    "SELECT id, first_seen FROM network_devices WHERE network_id = ? AND device_id = ?",
                    (network_id, device_id),
                )
                first_seen = existing["first_seen"] if existing else now_iso()
                self.db.execute(
                    """
                    INSERT INTO network_devices (network_id, device_id, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(network_id, device_id) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        status=excluded.status
                    """,
                    (network_id, device_id, first_seen, now_iso(), device.status),
                )

            if seen_device_ids:
                placeholders = ",".join("?" for _ in seen_device_ids)
                self.db.execute(
                    f"""
                    DELETE FROM network_devices
                    WHERE network_id = ? AND device_id NOT IN ({placeholders})
                    """,
                    (network_id, *seen_device_ids),
                )
            else:
                self.db.execute("DELETE FROM network_devices WHERE network_id = ?", (network_id,))
        except sqlite3.Error as exc:
            logger.error("Failed to associate devices with network #%s: %s", network_id, exc)

    def get_devices_for_network(self, network_id: int) -> list[DeviceRecord]:
        rows = self.db.fetch_all(
            """
            SELECT d.* FROM devices d
            INNER JOIN network_devices nd ON nd.device_id = d.id
            WHERE nd.network_id = ?
            ORDER BY d.risk_score DESC
            """,
            (network_id,),
        )
        return [DeviceRepository._row_to_record(row) for row in rows]

    def count_for_network(self, network_id: int) -> int:
        row = self.db.fetch_one(
            "SELECT COUNT(*) AS n FROM network_devices WHERE network_id = ?", (network_id,)
        )
        return row["n"] if row else 0


# ===========================================================================
# Scan sessions + scan_networks (history) + scan_network_devices
# ===========================================================================
class ScanHistoryRepository:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def save_session(
        self,
        session: ScanSession,
        networks: list[NetworkRecord],
        *,
        network_ids: dict[str, int] | None = None,
        devices_by_bssid: dict[str, list[DeviceRecord]] | None = None,
    ) -> int | None:
        """
        Persist a completed scan as a session. ``network_ids`` maps BSSID
        -> live networks.id (optional, for FK linkage). ``devices_by_bssid``
        maps BSSID -> the device list discovered for that network at scan
        time (only ever populated for the connected network).
        """
        network_ids = network_ids or {}
        devices_by_bssid = devices_by_bssid or {}
        try:
            cursor = self.db.execute(
                """
                INSERT INTO scan_sessions
                    (scan_time, total_networks, high_risk, medium_risk, low_risk,
                     overall_security_score, scan_duration)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.scan_time or now_iso(),
                    session.total_networks,
                    session.high_risk,
                    session.medium_risk,
                    session.low_risk,
                    session.overall_security_score,
                    session.scan_duration,
                ),
            )
            session_id = cursor.lastrowid

            for net in networks:
                network_cursor = self.db.execute(
                    """
                    INSERT INTO scan_networks
                        (session_id, network_id, ssid, bssid, signal_strength, channel, frequency,
                         authentication, encryption, connected_devices, risk_level,
                         risk_score, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        network_ids.get(net.bssid),
                        net.ssid,
                        net.bssid,
                        net.signal_strength,
                        net.channel,
                        net.frequency,
                        net.authentication,
                        net.encryption,
                        net.connected_devices,
                        net.risk_level,
                        net.risk_score,
                        "; ".join(net.recommendations) if net.recommendations else None,
                    ),
                )
                scan_network_id = network_cursor.lastrowid
                devices = devices_by_bssid.get(net.bssid)
                if devices:
                    self.db.executemany(
                        """
                        INSERT INTO scan_network_devices
                            (scan_network_id, hostname, ip_address, mac_address, vendor, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (scan_network_id, d.hostname, d.ip_address, d.mac_address, d.vendor, d.status)
                            for d in devices
                        ],
                    )

            logger.info("Saved scan session #%s with %d networks", session_id, len(networks))
            return session_id
        except sqlite3.Error as exc:
            logger.error("Failed to save scan session: %s", exc)
            return None

    def list_sessions(self, limit: int = 200) -> list[ScanSession]:
        rows = self.db.fetch_all(
            "SELECT * FROM scan_sessions ORDER BY scan_time DESC LIMIT ?", (limit,)
        )
        return [
            ScanSession(
                id=row["id"],
                scan_time=row["scan_time"],
                total_networks=row["total_networks"],
                high_risk=row["high_risk"],
                medium_risk=row["medium_risk"],
                low_risk=row["low_risk"],
                overall_security_score=row["overall_security_score"],
                scan_duration=row["scan_duration"],
            )
            for row in rows
        ]

    def get_session_networks(self, session_id: int) -> list[NetworkRecord]:
        rows = self.db.fetch_all(
            "SELECT * FROM scan_networks WHERE session_id = ? ORDER BY risk_score DESC",
            (session_id,),
        )
        return [self._scan_network_row_to_record(row) for row in rows]

    def get_scan_network_devices(self, scan_network_id: int) -> list[DeviceRecord]:
        rows = self.db.fetch_all(
            "SELECT * FROM scan_network_devices WHERE scan_network_id = ?", (scan_network_id,)
        )
        return [
            DeviceRecord(
                hostname=row["hostname"],
                ip_address=row["ip_address"],
                mac_address=row["mac_address"],
                vendor=row["vendor"],
                status=row["status"],
            )
            for row in rows
        ]

    def get_scan_network_by_bssid(self, session_id: int, bssid: str) -> sqlite3.Row | None:
        return self.db.fetch_one(
            "SELECT * FROM scan_networks WHERE session_id = ? AND bssid = ?", (session_id, bssid)
        )

    def delete_session(self, session_id: int) -> None:
        self.db.execute("DELETE FROM scan_sessions WHERE id = ?", (session_id,))

    def clear_all(self) -> None:
        self.db.execute("DELETE FROM scan_sessions")

    def _scan_network_row_to_record(self, row: sqlite3.Row) -> NetworkRecord:
        record = NetworkRecord(
            id=row["id"],
            ssid=row["ssid"],
            bssid=row["bssid"],
            signal_strength=row["signal_strength"],
            channel=row["channel"],
            frequency=row["frequency"],
            authentication=row["authentication"],
            encryption=row["encryption"],
            connected_devices=row["connected_devices"],
            device_info_available=row["connected_devices"] is not None,
            risk_level=row["risk_level"],
            risk_score=row["risk_score"],
            recommendations=[row["recommendation"]] if row["recommendation"] else [],
        )
        if record.device_info_available:
            record.devices = self.get_scan_network_devices(row["id"])
        return record


# ===========================================================================
# Devices + device_scan_history
# ===========================================================================
class DeviceRepository:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_database()

    def upsert(self, device: DeviceRecord) -> int | None:
        try:
            existing = self.db.fetch_one(
                "SELECT id, first_seen, trusted FROM devices WHERE mac_address = ?",
                (device.mac_address,),
            )
            first_seen = existing["first_seen"] if existing else (device.first_seen or now_iso())
            trusted = existing["trusted"] if existing else int(device.trusted)

            self.db.execute(
                """
                INSERT INTO devices
                    (hostname, ip_address, mac_address, vendor, device_type,
                     operating_system, first_seen, last_seen, status,
                     risk_level, risk_score, trusted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    hostname=excluded.hostname,
                    ip_address=excluded.ip_address,
                    vendor=excluded.vendor,
                    device_type=excluded.device_type,
                    operating_system=excluded.operating_system,
                    last_seen=excluded.last_seen,
                    status=excluded.status,
                    risk_level=excluded.risk_level,
                    risk_score=excluded.risk_score
                """,
                (
                    device.hostname,
                    device.ip_address,
                    device.mac_address,
                    device.vendor,
                    device.device_type,
                    device.operating_system,
                    first_seen,
                    device.last_seen or now_iso(),
                    device.status,
                    device.risk_level,
                    device.risk_score,
                    trusted,
                ),
            )
            row = self.db.fetch_one(
                "SELECT id FROM devices WHERE mac_address = ?", (device.mac_address,)
            )
            device_id = row["id"] if row else None
            if device_id is not None:
                self.db.execute(
                    """
                    INSERT INTO device_scan_history
                        (device_id, scan_time, status, response_time, risk_score)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        now_iso(),
                        device.status,
                        device.response_time,
                        device.risk_score,
                    ),
                )
            return device_id
        except sqlite3.Error as exc:
            logger.error("Failed to upsert device %s: %s", device.mac_address, exc)
            return None

    def all(self) -> list[DeviceRecord]:
        rows = self.db.fetch_all("SELECT * FROM devices ORDER BY risk_score DESC")
        return [self._row_to_record(row) for row in rows]

    def get_by_mac(self, mac_address: str) -> DeviceRecord | None:
        row = self.db.fetch_one("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
        return self._row_to_record(row) if row else None

    def set_trusted(self, device: DeviceRecord, trusted: bool) -> None:
        """
        Mark (or unmark) a device as trusted.

        Persists a ``devices`` row for it first if one doesn't exist yet
        — e.g. it was only just discovered by a live Rescan in the
        Network Details dialog and hasn't been through the dashboard's
        own scan-persist flow (``NetworkDeviceRepository.
        replace_devices_for_network``) yet. Without this, toggling trust
        on a freshly-scanned device would silently update zero rows.
        """
        self.upsert(device)
        self.db.execute(
            "UPDATE devices SET trusted = ? WHERE mac_address = ?",
            (int(trusted), device.mac_address),
        )

    def history_for_device(self, device_id: int, limit: int = 50) -> list[sqlite3.Row]:
        return self.db.fetch_all(
            """
            SELECT * FROM device_scan_history
            WHERE device_id = ? ORDER BY scan_time DESC LIMIT ?
            """,
            (device_id, limit),
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DeviceRecord:
        return DeviceRecord(
            id=row["id"],
            hostname=row["hostname"],
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            vendor=row["vendor"],
            device_type=row["device_type"],
            operating_system=row["operating_system"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            status=row["status"],
            risk_level=row["risk_level"],
            risk_score=row["risk_score"],
            trusted=bool(row["trusted"]),
        )