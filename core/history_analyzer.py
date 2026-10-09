"""Aggregate statistics and trend data over scan history (Section 20)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from database.repositories import ScanHistoryRepository


@dataclass
class HistoryStatistics:
    total_scans: int = 0
    average_security_score: float = 0.0
    high_risk_scans: int = 0
    total_networks_seen: int = 0
    most_frequent_ssid: str | None = None
    score_trend: list[tuple[str, float]] = field(default_factory=list)
    risk_distribution: dict[str, int] = field(default_factory=dict)
    networks_over_time: list[tuple[str, int]] = field(default_factory=list)


def compute_history_statistics(limit: int = 200) -> HistoryStatistics:
    repo = ScanHistoryRepository()
    sessions = repo.list_sessions(limit=limit)

    if not sessions:
        return HistoryStatistics()

    total_scans = len(sessions)
    avg_score = round(sum(s.overall_security_score for s in sessions) / total_scans, 1)
    high_risk_scans = sum(1 for s in sessions if s.high_risk > 0)
    total_networks = sum(s.total_networks for s in sessions)

    ssid_counter: Counter[str] = Counter()
    risk_totals = Counter({"LOW": 0, "MEDIUM": 0, "HIGH": 0})
    for session in sessions:
        if session.id is not None:
            for net in repo.get_session_networks(session.id):
                ssid_counter[net.ssid] += 1
                risk_totals[net.risk_level] += 1

    most_frequent = ssid_counter.most_common(1)
    most_frequent_ssid = most_frequent[0][0] if most_frequent else None

    # Trends, oldest -> newest for charting.
    ordered = list(reversed(sessions))
    score_trend = [(s.scan_time, s.overall_security_score) for s in ordered]
    networks_over_time = [(s.scan_time, s.total_networks) for s in ordered]

    return HistoryStatistics(
        total_scans=total_scans,
        average_security_score=avg_score,
        high_risk_scans=high_risk_scans,
        total_networks_seen=total_networks,
        most_frequent_ssid=most_frequent_ssid,
        score_trend=score_trend,
        risk_distribution=dict(risk_totals),
        networks_over_time=networks_over_time,
    )
