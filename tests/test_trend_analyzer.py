"""Tests for the trend analyzer and trend report generator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from navil.crawler.scan_history import ScanHistoryStore
from navil.report.trend_analyzer import TrendAnalyzer
from navil.report.trend_report import generate_trend_report, render_trend_report_markdown

# ── Fixtures ──────────────────────────────────────────────────


def _make_records(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build batch-scanner-style result dicts."""
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
        records.append(rec)
    return records


@pytest.fixture
def store(tmp_path: Path) -> ScanHistoryStore:
    """Empty scan history store."""
    return ScanHistoryStore(db_path=tmp_path / "trend_test.db")


@pytest.fixture
def multi_scan_store(store: ScanHistoryStore) -> ScanHistoryStore:
    """Store with 4 scans showing clear trends."""
    # Scan 1
    store.store_scan_results(_make_records([
        {"name": "alpha", "score": 30, "vulnerabilities": [
            {"id": "V-001", "risk_level": "CRITICAL"},
            {"id": "V-002", "risk_level": "HIGH"},
        ]},
        {"name": "beta", "score": 80, "vulnerabilities": []},
        {"name": "gamma", "score": 60, "vulnerabilities": [
            {"id": "V-003", "risk_level": "MEDIUM"},
        ]},
    ]))

    # Scan 2: alpha improves, gamma degrades
    store.store_scan_results(_make_records([
        {"name": "alpha", "score": 50, "vulnerabilities": [
            {"id": "V-002", "risk_level": "HIGH"},
        ]},
        {"name": "beta", "score": 85, "vulnerabilities": []},
        {"name": "gamma", "score": 45, "vulnerabilities": [
            {"id": "V-003", "risk_level": "MEDIUM"},
            {"id": "V-004", "risk_level": "HIGH"},
        ]},
        {"name": "delta", "score": 25, "vulnerabilities": [
            {"id": "V-005", "risk_level": "CRITICAL"},
        ]},
    ]))

    # Scan 3: alpha continues improving, delta stays bad
    store.store_scan_results(_make_records([
        {"name": "alpha", "score": 70, "vulnerabilities": []},
        {"name": "beta", "score": 82, "vulnerabilities": []},
        {"name": "gamma", "score": 50, "vulnerabilities": [
            {"id": "V-003", "risk_level": "MEDIUM"},
        ]},
        {"name": "delta", "score": 28, "vulnerabilities": [
            {"id": "V-005", "risk_level": "CRITICAL"},
            {"id": "V-006", "risk_level": "HIGH"},
        ]},
    ]))

    # Scan 4: gamma removed, epsilon added
    store.store_scan_results(_make_records([
        {"name": "alpha", "score": 85, "vulnerabilities": []},
        {"name": "beta", "score": 88, "vulnerabilities": []},
        {"name": "delta", "score": 30, "vulnerabilities": [
            {"id": "V-005", "risk_level": "CRITICAL"},
        ]},
        {"name": "epsilon", "score": 70, "vulnerabilities": [
            {"id": "V-007", "risk_level": "LOW"},
        ]},
    ]))

    return store


# ── TrendAnalyzer tests ──────────────────────────────────────


class TestTrendAnalyzer:
    def test_analyze_no_history(self, store: ScanHistoryStore) -> None:
        """Analysis with no scans returns empty result."""
        analyzer = TrendAnalyzer(store)
        result = analyzer.analyze()
        assert result["scan_count"] == 0
        assert "message" in result

    def test_analyze_single_scan(self, store: ScanHistoryStore) -> None:
        """Single scan produces baseline result."""
        store.store_scan_results(_make_records([
            {"name": "solo", "score": 60, "vulnerabilities": [
                {"id": "V-X", "risk_level": "MEDIUM"},
            ]},
        ]))
        analyzer = TrendAnalyzer(store)
        result = analyzer.analyze()
        assert result["scan_count"] == 1
        assert "baseline" in result
        assert result["baseline"]["avg_score"] == 60.0

    def test_analyze_multiple_scans(self, multi_scan_store: ScanHistoryStore) -> None:
        """Full analysis across multiple scans."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()

        assert result["scan_count"] == 4
        assert "score_trend" in result
        assert len(result["score_trend"]) == 4
        assert "overall_score_change" in result
        assert "most_improved" in result
        assert "most_degraded" in result

    def test_analyze_with_limit(self, multi_scan_store: ScanHistoryStore) -> None:
        """Limit restricts number of scans analyzed."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze(last_n=2)
        assert result["scan_count"] == 2

    def test_most_improved(self, multi_scan_store: ScanHistoryStore) -> None:
        """Alpha should be among most improved (30 -> 85)."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()
        improved = result.get("most_improved", [])
        improved_names = {s["server_name"] for s in improved}
        assert "alpha" in improved_names

    def test_repeat_offenders(self, multi_scan_store: ScanHistoryStore) -> None:
        """Delta (25, 28, 30) should be a repeat offender."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()
        offenders = result.get("repeat_offenders", [])
        offender_names = {o["server_name"] for o in offenders}
        assert "delta" in offender_names

    def test_server_churn(self, multi_scan_store: ScanHistoryStore) -> None:
        """Server churn detects added/removed servers."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()
        churn = result.get("server_churn", {})
        assert "epsilon" in churn.get("added", [])
        assert "gamma" in churn.get("removed", [])

    def test_new_vulnerability_types(self, multi_scan_store: ScanHistoryStore) -> None:
        """New vulnerability types are detected."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()
        new_types = result.get("new_vulnerability_types", [])
        # V-007 only appears in scan 4
        assert "V-007" in new_types

    def test_vuln_distribution_change(self, multi_scan_store: ScanHistoryStore) -> None:
        """Vulnerability distribution changes are tracked."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze()
        changes = result.get("vuln_distribution_change", [])
        assert len(changes) > 0
        # Each entry has type, old_count, new_count, delta
        for c in changes:
            assert "vulnerability_type" in c
            assert "delta" in c


# ── Per-server trend tests ────────────────────────────────────


class TestServerTrend:
    def test_analyze_server(self, multi_scan_store: ScanHistoryStore) -> None:
        """Per-server analysis shows correct trend."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze_server("alpha")
        assert result["server_name"] == "alpha"
        assert result["data_points"] == 4
        assert result["trend"] == "improving"
        assert result["score_change"] == 55  # 85 - 30
        assert result["current_score"] == 85

    def test_analyze_server_degrading(self, multi_scan_store: ScanHistoryStore) -> None:
        """Per-server analysis detects degradation."""
        analyzer = TrendAnalyzer(multi_scan_store)
        # gamma: 60, 45, 50 (removed in scan 4)
        result = analyzer.analyze_server("gamma")
        assert result["trend"] == "degrading"

    def test_analyze_server_not_found(self, store: ScanHistoryStore) -> None:
        """Analyzing unknown server gives appropriate message."""
        analyzer = TrendAnalyzer(store)
        result = analyzer.analyze_server("nonexistent")
        assert result["data_points"] == 0
        assert "No history found" in result["message"]

    def test_analyze_server_with_limit(self, multi_scan_store: ScanHistoryStore) -> None:
        """Limit restricts data points."""
        analyzer = TrendAnalyzer(multi_scan_store)
        result = analyzer.analyze_server("alpha", last_n=2)
        assert result["data_points"] == 2


# ── Markdown rendering tests ─────────────────────────────────


class TestMarkdownRendering:
    def test_render_empty(self, store: ScanHistoryStore) -> None:
        """Rendering empty analysis produces valid markdown."""
        analyzer = TrendAnalyzer(store)
        data = analyzer.analyze()
        md = analyzer.render_markdown(data)
        assert "Trend Analysis" in md

    def test_render_baseline(self, store: ScanHistoryStore) -> None:
        """Rendering baseline produces valid markdown."""
        store.store_scan_results(_make_records([
            {"name": "x", "score": 50, "vulnerabilities": [
                {"id": "V", "risk_level": "LOW"},
            ]},
        ]))
        analyzer = TrendAnalyzer(store)
        data = analyzer.analyze()
        md = analyzer.render_markdown(data)
        assert "Baseline" in md or "baseline" in md.lower()

    def test_render_full_trend(self, multi_scan_store: ScanHistoryStore) -> None:
        """Full trend render contains expected sections."""
        analyzer = TrendAnalyzer(multi_scan_store)
        data = analyzer.analyze()
        md = analyzer.render_markdown(data)
        assert "Score Trend" in md
        assert "Most Improved" in md
        assert "Repeat Offenders" in md


# ── Trend report tests ───────────────────────────────────────


class TestTrendReport:
    def test_generate_trend_report_empty(self, store: ScanHistoryStore) -> None:
        """Trend report with no data returns message."""
        report = generate_trend_report(store)
        assert report["report_type"] == "trend"
        assert "message" in report

    def test_generate_trend_report(self, multi_scan_store: ScanHistoryStore) -> None:
        """Trend report contains expected fields."""
        report = generate_trend_report(multi_scan_store)
        assert report["report_type"] == "trend"
        assert "latest_scan" in report
        assert "score_distribution" in report
        assert "top_vulnerabilities" in report
        assert "trend_data" in report
        assert "month_over_month" in report

    def test_trend_report_month_over_month(self, multi_scan_store: ScanHistoryStore) -> None:
        """Month-over-month section is present with 2+ scans."""
        report = generate_trend_report(multi_scan_store)
        mom = report["month_over_month"]
        assert "avg_score_change" in mom
        assert "new_servers" in mom
        assert "fixed_vulnerabilities" in mom

    def test_render_trend_report_markdown(self, multi_scan_store: ScanHistoryStore) -> None:
        """Rendered trend report contains expected content."""
        report = generate_trend_report(multi_scan_store)
        md = render_trend_report_markdown(report)
        assert "State of MCP Security" in md
        assert "Current State" in md
        assert "Month-over-Month" in md

    def test_render_empty_trend_report(self, store: ScanHistoryStore) -> None:
        """Empty trend report renders without error."""
        report = generate_trend_report(store)
        md = render_trend_report_markdown(report)
        assert "State of MCP Security" in md

    def test_trend_report_json_serializable(self, multi_scan_store: ScanHistoryStore) -> None:
        """Trend report data is JSON-serializable (for dashboard export)."""
        report = generate_trend_report(multi_scan_store)
        # Should not raise
        serialized = json.dumps(report)
        deserialized = json.loads(serialized)
        assert deserialized["report_type"] == "trend"

    def test_trend_report_with_limit(self, multi_scan_store: ScanHistoryStore) -> None:
        """Trend report with limit parameter."""
        report = generate_trend_report(multi_scan_store, last_n=2)
        # Should still generate without errors
        assert report["report_type"] == "trend"


# ── CLI integration tests ────────────────────────────────────


class TestCLIIntegration:
    def test_crawl_history_no_data(self, tmp_path: Path) -> None:
        """History command with empty DB works."""
        import sys
        from unittest.mock import patch

        from navil.cli import main

        # Point to empty DB
        with patch(
            "navil.crawler.scan_history.DEFAULT_DB_PATH",
            tmp_path / "cli_test.db",
        ), patch.object(sys, "argv", ["navil", "crawl", "history"]):
            exit_code = main()
        assert exit_code == 0

    def test_crawl_trend_no_data(self, tmp_path: Path) -> None:
        """Trend command with empty DB works."""
        import sys
        from unittest.mock import patch

        from navil.cli import main

        with patch(
            "navil.crawler.scan_history.DEFAULT_DB_PATH",
            tmp_path / "cli_test2.db",
        ), patch.object(sys, "argv", ["navil", "crawl", "trend", "--last", "5"]):
            exit_code = main()
        assert exit_code == 0

    def test_crawl_diff_missing_scan(self, tmp_path: Path) -> None:
        """Diff command with missing scan IDs returns error."""
        import sys
        from unittest.mock import patch

        from navil.cli import main

        with patch(
            "navil.crawler.scan_history.DEFAULT_DB_PATH",
            tmp_path / "cli_test3.db",
        ), patch.object(sys, "argv", ["navil", "crawl", "diff", "1", "2"]):
            exit_code = main()
        assert exit_code == 1

    def test_crawl_schedule_crontab(self, capsys) -> None:
        """Schedule command with crontab mode outputs an entry."""
        import sys
        from unittest.mock import patch

        from navil.cli import main

        with patch.object(
            sys, "argv",
            ["navil", "crawl", "schedule", "--interval", "daily", "--mode", "crontab"],
        ):
            exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "crontab" in captured.out.lower()

    def test_crawl_schedule_systemd(self, capsys) -> None:
        """Schedule command with systemd mode outputs unit files."""
        import sys
        from unittest.mock import patch

        from navil.cli import main

        with patch.object(
            sys, "argv",
            ["navil", "crawl", "schedule", "--interval", "weekly", "--mode", "systemd"],
        ):
            exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "navil-scan.service" in captured.out
        assert "navil-scan.timer" in captured.out
