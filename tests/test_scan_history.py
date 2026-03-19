"""Tests for the scan history store and scan diff."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from navil.crawler.scan_history import ScanHistoryStore, ScanRecord, ServerResult
from navil.report.scan_diff import generate_scan_diff, render_scan_diff_markdown

# ── Fixtures ──────────────────────────────────────────────────


def _make_scan_records(
    servers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a list of batch-scanner-style result dicts."""
    records: list[dict[str, Any]] = []
    for srv in servers:
        rec: dict[str, Any] = {
            "server_name": srv["name"],
            "source": srv.get("source", "test"),
            "url": srv.get("url", f"https://example.com/{srv['name']}"),
            "status": srv.get("status", "success"),
        }
        if rec["status"] == "success":
            rec["scan"] = {
                "security_score": srv.get("score", 50),
                "vulnerabilities": srv.get("vulnerabilities", []),
                "findings": srv.get("findings", []),
            }
        elif rec["status"] == "error":
            rec["error"] = srv.get("error", "scan failed")
        elif rec["status"] == "timeout":
            rec["error"] = "timed out"
        records.append(rec)
    return records


@pytest.fixture
def store(tmp_path: Path) -> ScanHistoryStore:
    """Create a ScanHistoryStore backed by a temp database."""
    return ScanHistoryStore(db_path=tmp_path / "test_history.db")


@pytest.fixture
def populated_store(store: ScanHistoryStore) -> ScanHistoryStore:
    """Store with 3 scan runs for trend testing."""
    # Scan 1: baseline
    store.store_scan_results(
        _make_scan_records(
            [
                {
                    "name": "server-a",
                    "score": 40,
                    "vulnerabilities": [
                        {"id": "VULN-001", "risk_level": "HIGH"},
                        {"id": "VULN-002", "risk_level": "MEDIUM"},
                    ],
                },
                {
                    "name": "server-b",
                    "score": 70,
                    "vulnerabilities": [
                        {"id": "VULN-001", "risk_level": "HIGH"},
                    ],
                },
                {"name": "server-c", "score": 90, "vulnerabilities": []},
            ]
        ),
        source_file="scan_1.jsonl",
    )

    # Scan 2: server-a improves, server-d added
    store.store_scan_results(
        _make_scan_records(
            [
                {
                    "name": "server-a",
                    "score": 60,
                    "vulnerabilities": [
                        {"id": "VULN-002", "risk_level": "MEDIUM"},
                    ],
                },
                {
                    "name": "server-b",
                    "score": 65,
                    "vulnerabilities": [
                        {"id": "VULN-001", "risk_level": "HIGH"},
                        {"id": "VULN-003", "risk_level": "LOW"},
                    ],
                },
                {"name": "server-c", "score": 90, "vulnerabilities": []},
                {
                    "name": "server-d",
                    "score": 30,
                    "vulnerabilities": [
                        {"id": "VULN-004", "risk_level": "CRITICAL"},
                    ],
                },
            ]
        ),
        source_file="scan_2.jsonl",
    )

    # Scan 3: server-c removed, server-d still low
    store.store_scan_results(
        _make_scan_records(
            [
                {"name": "server-a", "score": 75, "vulnerabilities": []},
                {
                    "name": "server-b",
                    "score": 60,
                    "vulnerabilities": [
                        {"id": "VULN-001", "risk_level": "HIGH"},
                    ],
                },
                {
                    "name": "server-d",
                    "score": 35,
                    "vulnerabilities": [
                        {"id": "VULN-004", "risk_level": "CRITICAL"},
                        {"id": "VULN-005", "risk_level": "HIGH"},
                    ],
                },
            ]
        ),
        source_file="scan_3.jsonl",
    )

    return store


# ── Basic storage tests ──────────────────────────────────────


class TestScanHistoryStore:
    def test_store_empty_results(self, store: ScanHistoryStore) -> None:
        """Storing empty results creates a scan with zero counts."""
        scan_id = store.store_scan_results([])
        assert scan_id == 1
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan.total_servers == 0
        assert scan.successful == 0
        assert scan.avg_score == 0.0

    def test_store_and_retrieve_results(self, store: ScanHistoryStore) -> None:
        """Store and retrieve scan results."""
        records = _make_scan_records(
            [
                {
                    "name": "test-server",
                    "score": 85,
                    "vulnerabilities": [
                        {"id": "V1", "risk_level": "LOW"},
                    ],
                },
                {"name": "failing-server", "status": "error", "error": "connection refused"},
            ]
        )

        scan_id = store.store_scan_results(records, source_file="test.jsonl")
        assert scan_id >= 1

        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan.total_servers == 2
        assert scan.successful == 1
        assert scan.failed == 1
        assert scan.avg_score == 85.0

        results = store.get_scan_results(scan_id)
        assert len(results) == 2
        names = {r.server_name for r in results}
        assert "test-server" in names
        assert "failing-server" in names

    def test_store_timeout_result(self, store: ScanHistoryStore) -> None:
        """Timeout results are tracked correctly."""
        records = _make_scan_records(
            [
                {"name": "slow-server", "status": "timeout"},
            ]
        )
        scan_id = store.store_scan_results(records)
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan.timed_out == 1
        assert scan.successful == 0

    def test_multiple_scans(self, store: ScanHistoryStore) -> None:
        """Multiple scans get distinct IDs."""
        id1 = store.store_scan_results(_make_scan_records([{"name": "a", "score": 50}]))
        id2 = store.store_scan_results(_make_scan_records([{"name": "b", "score": 60}]))
        assert id1 != id2
        assert id2 > id1

    def test_get_scan_history(self, populated_store: ScanHistoryStore) -> None:
        """get_scan_history returns scans in most-recent-first order."""
        history = populated_store.get_scan_history()
        assert len(history) == 3
        assert history[0].scan_id > history[1].scan_id > history[2].scan_id

    def test_get_scan_history_with_limit(self, populated_store: ScanHistoryStore) -> None:
        """Limit parameter restricts number of results."""
        history = populated_store.get_scan_history(limit=2)
        assert len(history) == 2

    def test_get_nonexistent_scan(self, store: ScanHistoryStore) -> None:
        """Getting a nonexistent scan returns None."""
        assert store.get_scan(9999) is None

    def test_get_scan_results_empty(self, store: ScanHistoryStore) -> None:
        """Getting results for nonexistent scan returns empty list."""
        results = store.get_scan_results(9999)
        assert results == []

    def test_get_latest_scan_id_empty(self, store: ScanHistoryStore) -> None:
        """Latest scan ID is None when no scans exist."""
        assert store.get_latest_scan_id() is None

    def test_get_latest_scan_id(self, populated_store: ScanHistoryStore) -> None:
        """Latest scan ID is the most recently inserted."""
        latest = populated_store.get_latest_scan_id()
        assert latest == 3

    def test_get_all_server_names(self, populated_store: ScanHistoryStore) -> None:
        """All unique server names are returned."""
        names = populated_store.get_all_server_names()
        assert set(names) == {"server-a", "server-b", "server-c", "server-d"}


# ── Server trend tests ───────────────────────────────────────


class TestServerTrend:
    def test_server_trend(self, populated_store: ScanHistoryStore) -> None:
        """Server trend returns chronological score history."""
        trend = populated_store.get_server_trend("server-a")
        assert len(trend) == 3
        scores = [t["score"] for t in trend]
        assert scores == [40, 60, 75]

    def test_server_trend_with_limit(self, populated_store: ScanHistoryStore) -> None:
        """Server trend respects limit."""
        trend = populated_store.get_server_trend("server-a", limit=2)
        assert len(trend) == 2

    def test_server_trend_unknown_server(self, store: ScanHistoryStore) -> None:
        """Trend for unknown server returns empty list."""
        trend = store.get_server_trend("nonexistent")
        assert trend == []

    def test_server_trend_vuln_count(self, populated_store: ScanHistoryStore) -> None:
        """Vulnerability counts are tracked in trend data."""
        trend = populated_store.get_server_trend("server-a")
        vuln_counts = [t["vulnerability_count"] for t in trend]
        assert vuln_counts == [2, 1, 0]  # decreasing as server improves


# ── Compare scans tests ──────────────────────────────────────


class TestCompareScans:
    def test_compare_adjacent_scans(self, populated_store: ScanHistoryStore) -> None:
        """Compare scan 1 and scan 2."""
        diff = populated_store.compare_scans(1, 2)
        assert "error" not in diff
        assert diff["new_servers"] == ["server-d"]
        assert diff["removed_servers"] == []
        assert diff["summary"]["servers_added"] == 1

    def test_compare_first_and_last(self, populated_store: ScanHistoryStore) -> None:
        """Compare scan 1 and scan 3."""
        diff = populated_store.compare_scans(1, 3)
        assert "server-c" in diff["removed_servers"]
        assert "server-d" in diff["new_servers"]
        # server-a improved: 40 -> 75
        score_changes = {sc["server_name"]: sc for sc in diff["score_changes"]}
        assert "server-a" in score_changes
        assert score_changes["server-a"]["delta"] == 35

    def test_compare_nonexistent_scan(self, store: ScanHistoryStore) -> None:
        """Comparing with nonexistent scan returns error."""
        diff = store.compare_scans(1, 999)
        assert "error" in diff

    def test_compare_fixed_vulnerabilities(self, populated_store: ScanHistoryStore) -> None:
        """Fixed vulnerabilities are detected."""
        diff = populated_store.compare_scans(1, 3)
        # VULN-002 was on server-a in scan 1, not in scan 3
        fixed = diff["fixed_vulnerabilities"]
        assert any("VULN-002" in v for v in fixed)

    def test_compare_new_vulnerabilities(self, populated_store: ScanHistoryStore) -> None:
        """New vulnerabilities are detected."""
        diff = populated_store.compare_scans(1, 3)
        new = diff["new_vulnerabilities"]
        assert any("VULN-004" in v for v in new)
        assert any("VULN-005" in v for v in new)


# ── Scan diff report tests ───────────────────────────────────


class TestScanDiff:
    def test_generate_scan_diff(self, populated_store: ScanHistoryStore) -> None:
        """generate_scan_diff returns enriched diff data."""
        diff = generate_scan_diff(populated_store, 1, 3)
        assert "error" not in diff
        assert (
            "notable_improvements" in diff
            or "notable_regressions" in diff
            or "score_changes" in diff
        )

    def test_render_scan_diff_markdown(self, populated_store: ScanHistoryStore) -> None:
        """Rendered diff contains expected sections."""
        diff = generate_scan_diff(populated_store, 1, 3)
        md = render_scan_diff_markdown(diff)
        assert "Scan Comparison Report" in md
        assert "Summary" in md

    def test_render_error_diff(self, store: ScanHistoryStore) -> None:
        """Rendering an error diff produces error message."""
        diff = generate_scan_diff(store, 1, 999)
        md = render_scan_diff_markdown(diff)
        assert "Error" in md

    def test_generate_diff_single_scan(self, store: ScanHistoryStore) -> None:
        """Diff with a nonexistent scan returns error."""
        store.store_scan_results(_make_scan_records([{"name": "x", "score": 50}]))
        diff = generate_scan_diff(store, 1, 999)
        assert "error" in diff


# ── Data types tests ──────────────────────────────────────────


class TestDataTypes:
    def test_scan_record_to_dict(self) -> None:
        """ScanRecord.to_dict() returns all fields."""
        rec = ScanRecord(
            scan_id=1,
            timestamp="2024-01-01T00:00:00Z",
            total_servers=10,
            successful=8,
            failed=1,
            timed_out=1,
            avg_score=75.5,
            min_score=30,
            max_score=95,
            source_file="test.jsonl",
        )
        d = rec.to_dict()
        assert d["scan_id"] == 1
        assert d["avg_score"] == 75.5

    def test_server_result_to_dict(self) -> None:
        """ServerResult.to_dict() deserializes JSON fields."""
        result = ServerResult(
            scan_id=1,
            server_name="test",
            source="npm",
            url="https://example.com",
            status="success",
            score=80,
            vulnerabilities_json='[{"id": "V1"}]',
            findings_json="[]",
        )
        d = result.to_dict()
        assert d["vulnerabilities"] == [{"id": "V1"}]
        assert d["findings"] == []


# ── Edge cases ────────────────────────────────────────────────


class TestEdgeCases:
    def test_first_scan_no_history(self, store: ScanHistoryStore) -> None:
        """First scan produces valid results with no prior history."""
        scan_id = store.store_scan_results(
            _make_scan_records(
                [
                    {"name": "new-server", "score": 60},
                ]
            )
        )
        assert scan_id == 1
        history = store.get_scan_history()
        assert len(history) == 1

    def test_all_failures(self, store: ScanHistoryStore) -> None:
        """Scan with all failures has avg_score 0."""
        scan_id = store.store_scan_results(
            _make_scan_records(
                [
                    {"name": "fail-1", "status": "error"},
                    {"name": "fail-2", "status": "timeout"},
                ]
            )
        )
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan.avg_score == 0.0
        assert scan.successful == 0

    def test_single_server_score_stats(self, store: ScanHistoryStore) -> None:
        """Single server: min == max == avg."""
        scan_id = store.store_scan_results(_make_scan_records([{"name": "only", "score": 72}]))
        scan = store.get_scan(scan_id)
        assert scan is not None
        assert scan.min_score == 72
        assert scan.max_score == 72
        assert scan.avg_score == 72.0

    def test_db_persistence(self, tmp_path: Path) -> None:
        """Data persists after store is re-opened."""
        db_path = tmp_path / "persist.db"
        store1 = ScanHistoryStore(db_path=db_path)
        store1.store_scan_results(_make_scan_records([{"name": "persist-test", "score": 88}]))

        # Re-open
        store2 = ScanHistoryStore(db_path=db_path)
        history = store2.get_scan_history()
        assert len(history) == 1
        assert history[0].avg_score == 88.0
