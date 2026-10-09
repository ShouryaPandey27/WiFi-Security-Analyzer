import pytest

from database.database import Database
from database.models import DeviceRecord, NetworkRecord
from database.repositories import DeviceRepository, NetworkRepository


@pytest.fixture()
def db(tmp_path):
    return Database(db_path=tmp_path / "test.db")


def test_database_creates_file(db):
    assert db.db_path.exists()


def test_database_never_crashes_on_missing_file(tmp_path):
    # Pointing at a path that doesn't exist yet should still initialize cleanly.
    missing_path = tmp_path / "nested" / "does_not_exist.db"
    database = Database(db_path=missing_path)
    assert database.db_path.exists()


def test_network_repository_upsert_and_fetch(db):
    repo = NetworkRepository(db=db)
    network = NetworkRecord(
        ssid="TestNet", bssid="AA:AA:AA:AA:AA:AA", authentication="WPA2",
        encryption="CCMP", risk_level="LOW", risk_score=5, last_seen="2026-01-01T00:00:00",
    )
    repo.upsert(network)
    all_networks = repo.all()
    assert len(all_networks) == 1
    assert all_networks[0].ssid == "TestNet"


def test_network_repository_upsert_updates_existing(db):
    repo = NetworkRepository(db=db)
    bssid = "AA:AA:AA:AA:AA:AA"
    repo.upsert(NetworkRecord(ssid="Old", bssid=bssid, risk_score=5, last_seen="t"))
    repo.upsert(NetworkRecord(ssid="New", bssid=bssid, risk_score=50, last_seen="t"))
    all_networks = repo.all()
    assert len(all_networks) == 1
    assert all_networks[0].ssid == "New"
    assert all_networks[0].risk_score == 50


def test_device_repository_upsert_and_fetch(db):
    repo = DeviceRepository(db=db)
    device = DeviceRecord(
        hostname="TestDevice", ip_address="192.168.1.10", mac_address="BB:BB:BB:BB:BB:BB",
        vendor="Unknown", device_type="Unknown", status="Online", risk_level="LOW", risk_score=10,
    )
    repo.upsert(device)
    all_devices = repo.all()
    assert len(all_devices) == 1
    assert all_devices[0].hostname == "TestDevice"


def test_device_repository_preserves_first_seen(db):
    repo = DeviceRepository(db=db)
    mac = "CC:CC:CC:CC:CC:CC"
    repo.upsert(DeviceRecord(mac_address=mac, ip_address="10.0.0.1", first_seen="2026-01-01T00:00:00"))
    repo.upsert(DeviceRecord(mac_address=mac, ip_address="10.0.0.1", first_seen="2026-06-01T00:00:00"))
    devices = repo.all()
    assert devices[0].first_seen == "2026-01-01T00:00:00"
