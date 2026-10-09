import pytest

from database.database import Database
from database.models import DeviceRecord, NetworkRecord
from database.repositories import NetworkDeviceRepository, NetworkRepository
from core.security_analyzer import analyze_network
from core.recommendation_engine import build_network_recommendations


@pytest.fixture()
def db(tmp_path):
    return Database(db_path=tmp_path / "test.db")


def _network(bssid="AA:AA:AA:AA:AA:01", ssid="Mahar Net"):
    return NetworkRecord(
        ssid=ssid, bssid=bssid, authentication="WPA2", encryption="CCMP",
        last_seen="2026-01-01T00:00:00",
    )


def _device(mac, ip="192.168.1.5", hostname="Android-Phone", vendor="Samsung"):
    return DeviceRecord(
        hostname=hostname, ip_address=ip, mac_address=mac, vendor=vendor,
        status="Online", first_seen="2026-01-01T00:00:00", last_seen="2026-01-01T00:00:00",
    )


# ===========================================================================
# NetworkRecord.devices_display()
# ===========================================================================
def test_devices_display_unavailable_when_none():
    net = NetworkRecord(connected_devices=None)
    assert net.devices_display() == "Unavailable"


def test_devices_display_shows_count_when_known():
    net = NetworkRecord(connected_devices=5)
    assert net.devices_display() == "5"


def test_devices_display_never_shows_zero_for_unknown():
    # A count was never determined -> must read "Unavailable", not "0".
    net = NetworkRecord()
    assert net.connected_devices is None
    assert net.devices_display() != "0"


# ===========================================================================
# NetworkDeviceRepository / per-network association
# ===========================================================================
def test_network_upsert_persists_null_connected_devices_by_default(db):
    repo = NetworkRepository(db=db)
    network_id = repo.upsert(_network())
    assert network_id is not None

    stored = repo.get_by_id(network_id)
    assert stored is not None
    assert stored.connected_devices is None
    assert stored.device_info_available is False
    assert stored.devices == []


def test_associate_devices_sets_count_and_join_rows(db):
    net_repo = NetworkRepository(db=db)
    nd_repo = NetworkDeviceRepository(db=db)

    network_id = net_repo.upsert(_network())
    assert network_id is not None

    devices = [_device("11:22:33:44:55:01"), _device("11:22:33:44:55:02", ip="192.168.1.6")]
    nd_repo.replace_devices_for_network(network_id, devices)

    associated = nd_repo.get_devices_for_network(network_id)
    assert len(associated) == 2
    assert nd_repo.count_for_network(network_id) == 2


def test_network_repository_join_populates_devices(db):
    net_repo = NetworkRepository(db=db)
    nd_repo = NetworkDeviceRepository(db=db)

    net = _network()
    net.connected_devices = 1
    network_id = net_repo.upsert(net)
    assert network_id is not None
    nd_repo.replace_devices_for_network(network_id, [_device("11:22:33:44:55:03")])

    stored = net_repo.get_by_bssid(net.bssid)
    assert stored is not None
    assert stored.device_info_available is True
    assert len(stored.devices) == 1
    assert stored.devices[0].mac_address == "11:22:33:44:55:03"


def test_devices_are_scoped_to_their_own_network_only(db):
    # The critical requirement: devices under one network must never leak
    # into another network's device list.
    net_repo = NetworkRepository(db=db)
    nd_repo = NetworkDeviceRepository(db=db)

    mahar_id = net_repo.upsert(_network(bssid="AA:AA:AA:AA:AA:01", ssid="Mahar Net"))
    home_id = net_repo.upsert(_network(bssid="AA:AA:AA:AA:AA:02", ssid="Home WiFi"))
    assert mahar_id is not None
    assert home_id is not None

    nd_repo.replace_devices_for_network(mahar_id, [_device("11:11:11:11:11:11")])
    nd_repo.replace_devices_for_network(home_id, [_device("22:22:22:22:22:22")])

    mahar_devices = nd_repo.get_devices_for_network(mahar_id)
    home_devices = nd_repo.get_devices_for_network(home_id)

    assert {d.mac_address for d in mahar_devices} == {"11:11:11:11:11:11"}
    assert {d.mac_address for d in home_devices} == {"22:22:22:22:22:22"}


def test_replace_devices_drops_stale_associations(db):
    net_repo = NetworkRepository(db=db)
    nd_repo = NetworkDeviceRepository(db=db)

    network_id = net_repo.upsert(_network())
    assert network_id is not None
    nd_repo.replace_devices_for_network(network_id, [_device("33:33:33:33:33:33")])
    assert nd_repo.count_for_network(network_id) == 1

    # Re-scan finds a different device only -> the old association is dropped.
    nd_repo.replace_devices_for_network(network_id, [_device("44:44:44:44:44:44")])
    remaining = nd_repo.get_devices_for_network(network_id)
    assert {d.mac_address for d in remaining} == {"44:44:44:44:44:44"}


# ===========================================================================
# Security analyzer / recommendations: device-aware, spec-compliant
# ===========================================================================
def test_analyze_network_with_one_unknown_device_recommends_verification():
    assessment = analyze_network(
        ssid="Mahar Net", bssid="AA:AA:AA:AA:AA:01", authentication="WPA2",
        encryption="CCMP", unknown_device_count=1,
    )
    assert "Verify the unknown device if it does not belong to an authorized user." in (
        assessment.recommendations
    )


def test_analyze_network_without_device_info_has_no_device_recommendation():
    assessment = analyze_network(
        ssid="ABC WiFi", bssid="AA:AA:AA:AA:AA:03", authentication="Open", encryption="None",
    )
    assert not any("unknown device" in r.lower() for r in assessment.recommendations)


def test_many_known_devices_alone_does_not_force_high_risk():
    # Devices with no unknown/suspicious flags must not push risk to HIGH.
    assessment = analyze_network(
        ssid="Office WiFi", bssid="AA:AA:AA:AA:AA:04", authentication="WPA2", encryption="CCMP",
        unknown_device_count=0, suspicious_device_detected=False,
    )
    assert assessment.risk.level == "LOW"


def test_build_network_recommendations_specific_over_generic():
    recs = build_network_recommendations(
        authentication="Open", encryption="None", unknown_device_count=2
    )
    assert "Enable WPA2 or WPA3 security." in recs
    assert any("2 unknown devices" in r for r in recs)
