import pytest

from database.database import Database
from database.models import DeviceRecord, NetworkRecord
from database.repositories import ScanHistoryRepository
from core.scan_history import build_session_from_networks, compare_sessions


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    db = Database(db_path=tmp_path / "test.db")
    monkeypatch.setattr("database.repositories.get_database", lambda: db)
    return ScanHistoryRepository(db=db)


def _network(bssid, ssid="Net", risk_level="LOW", risk_score=5, auth="WPA2", enc="CCMP", signal=-50):
    return NetworkRecord(
        ssid=ssid, bssid=bssid, authentication=auth, encryption=enc,
        risk_level=risk_level, risk_score=risk_score, signal_strength=signal,
    )


def test_build_session_from_empty_networks():
    session = build_session_from_networks([], duration_seconds=1.0)
    assert session.total_networks == 0
    assert session.overall_security_score == 100


def test_build_session_summarizes_risk_counts():
    networks = [
        _network("AA:AA:AA:AA:AA:AA", risk_level="HIGH", risk_score=90),
        _network("BB:BB:BB:BB:BB:BB", risk_level="LOW", risk_score=5),
    ]
    session = build_session_from_networks(networks, duration_seconds=2.0)
    assert session.total_networks == 2
    assert session.high_risk == 1
    assert session.low_risk == 1


def test_save_and_list_sessions(repo):
    networks = [_network("AA:AA:AA:AA:AA:AA")]
    session = build_session_from_networks(networks, duration_seconds=1.0)
    session_id = repo.save_session(session, networks)
    assert session_id is not None

    sessions = repo.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].total_networks == 1


def test_get_session_networks_round_trips(repo):
    networks = [_network("AA:AA:AA:AA:AA:AA", ssid="HomeNet")]
    session = build_session_from_networks(networks, duration_seconds=1.0)
    session_id = repo.save_session(session, networks)

    stored = repo.get_session_networks(session_id)
    assert len(stored) == 1
    assert stored[0].ssid == "HomeNet"


def test_compare_sessions_detects_new_and_removed(repo):
    old_networks = [_network("AA:AA:AA:AA:AA:AA", ssid="Old")]
    new_networks = [_network("BB:BB:BB:BB:BB:BB", ssid="New")]

    old_session = build_session_from_networks(old_networks, duration_seconds=1.0)
    new_session = build_session_from_networks(new_networks, duration_seconds=1.0)
    old_id = repo.save_session(old_session, old_networks)
    new_id = repo.save_session(new_session, new_networks)

    diffs = compare_sessions(old_id, new_id)
    change_types = {d.change_type for d in diffs}
    assert "NEW" in change_types
    assert "REMOVED" in change_types


def test_compare_sessions_detects_changed_risk(repo):
    bssid = "CC:CC:CC:CC:CC:CC"
    old_networks = [_network(bssid, risk_score=5, risk_level="LOW")]
    new_networks = [_network(bssid, risk_score=80, risk_level="HIGH")]

    old_id = repo.save_session(build_session_from_networks(old_networks, duration_seconds=1.0), old_networks)
    new_id = repo.save_session(build_session_from_networks(new_networks, duration_seconds=1.0), new_networks)

    diffs = compare_sessions(old_id, new_id)
    changed = [d for d in diffs if d.bssid == bssid]
    assert changed[0].change_type == "CHANGED"


def _device(mac, ip="192.168.1.10"):
    return DeviceRecord(hostname="Device", ip_address=ip, mac_address=mac, status="Online")


def test_compare_sessions_shows_device_count_change_when_available(repo):
    bssid = "DD:DD:DD:DD:DD:DD"
    old_net = _network(bssid, risk_score=5)
    old_net.connected_devices = 3
    old_net.device_info_available = True
    old_net.devices = [_device("11:11:11:11:11:11")]

    new_net = _network(bssid, risk_score=5)
    new_net.connected_devices = 5
    new_net.device_info_available = True
    new_net.devices = [_device("11:11:11:11:11:11"), _device("22:22:22:22:22:22"), _device("33:33:33:33:33:33")]

    old_id = repo.save_session(
        build_session_from_networks([old_net], duration_seconds=1.0), [old_net],
        devices_by_bssid={bssid: old_net.devices},
    )
    new_id = repo.save_session(
        build_session_from_networks([new_net], duration_seconds=1.0), [new_net],
        devices_by_bssid={bssid: new_net.devices},
    )

    diffs = compare_sessions(old_id, new_id)
    match = next(d for d in diffs if d.bssid == bssid)
    assert match.device_count_before == 3
    assert match.device_count_after == 5
    assert any("Connected devices: 3 -> 5" in detail for detail in match.details)
    new_changes = [c for c in match.device_changes if c.change_type == "NEW"]
    assert len(new_changes) == 2


def test_compare_sessions_no_device_claim_when_unavailable(repo):
    bssid = "EE:EE:EE:EE:EE:EE"
    old_net = _network(bssid, risk_score=5)  # connected_devices stays None/unavailable
    new_net = _network(bssid, risk_score=5)

    old_id = repo.save_session(build_session_from_networks([old_net], duration_seconds=1.0), [old_net])
    new_id = repo.save_session(build_session_from_networks([new_net], duration_seconds=1.0), [new_net])

    diffs = compare_sessions(old_id, new_id)
    match = next(d for d in diffs if d.bssid == bssid)
    assert match.device_count_available is False
    assert not any("Connected devices:" in detail for detail in match.details)
