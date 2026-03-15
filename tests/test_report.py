"""Tests for the State of MCP report generator."""

from __future__ import annotations

import json
from pathlib import Path

import orjson
import pytest

from navil.report.state_of_mcp import generate_state_of_mcp_report


# ── Helpers ───────────────────────────────────────────────────


def _write_jsonl(path: Path, records: list[dict]) -> None:
    """Write records as JSONL to *path*."""
    with open(path, "wb") as f:
        for rec in records:
            f.write(orjson.dumps(rec))
            f.write(b"\n")


def _make_scan_record(
    server_name: str = "server",
    source: str = "npm",
    score: int = 80,
    findings: list[dict] | None = None,
    vulns: list[dict] | None = None,
    status: str = "success",
) -> dict:
    """Create a sample batch scan result record."""
    rec: dict = {
        "server_name": server_name,
        "source": source,
        "url": f"https://example.com/{server_name}",
        "status": status,
    }
    if status == "success":
        rec["scan"] = {
            "status": "completed",
            "security_score": score,
            "total_vulnerabilities": len(vulns or []),
            "findings": findings or [],
            "vulnerabilities": vulns or [],
        }
    elif status == "error":
        rec["error"] = "Something went wrong"
    elif status == "timeout":
        rec["error"] = "Scan timed out"
    return rec


# ── Tests ─────────────────────────────────────────────────────


class TestEmptyData:
    """Tests with no data or empty JSONL."""

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        report = generate_state_of_mcp_report(tmp_path / "missing.jsonl")
        assert "State of MCP" in report
        assert "Total servers scanned | 0" in report

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        report = generate_state_of_mcp_report(path)
        assert "Total servers scanned | 0" in report

    def test_no_successful_scans(self, tmp_path: Path) -> None:
        """Guard against division by zero when all scans fail."""
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(status="error"),
            _make_scan_record(status="timeout"),
        ])
        report = generate_state_of_mcp_report(path)
        assert "Average security score | 0.0" in report
        assert "Failed scans | 1" in report
        assert "Timed out | 1" in report


class TestWithSampleData:
    """Tests with valid scan data."""

    def test_basic_report(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(
                server_name="server-a",
                score=80,
                findings=[{"severity": "HIGH", "id": "AUTH-MISSING"}],
                vulns=[{"id": "AUTH-MISSING", "title": "Missing Auth"}],
            ),
            _make_scan_record(
                server_name="server-b",
                score=60,
                findings=[
                    {"severity": "CRITICAL", "id": "CRED-API_KEY"},
                    {"severity": "MEDIUM", "id": "NET-UNENCRYPTED"},
                ],
                vulns=[
                    {"id": "CRED-API_KEY", "title": "Plaintext Credential"},
                    {"id": "NET-UNENCRYPTED", "title": "Unencrypted"},
                ],
            ),
        ])

        report = generate_state_of_mcp_report(path)

        assert "State of MCP Security Report" in report
        assert "Total servers scanned | 2" in report
        assert "Successful scans | 2" in report
        assert "Average security score | 70.0" in report
        assert "CRITICAL" in report
        assert "HIGH" in report
        assert "MEDIUM" in report

    def test_vulnerability_types_counted(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(
                vulns=[
                    {"id": "AUTH-MISSING"},
                    {"id": "AUTH-MISSING"},
                    {"id": "CRED-API_KEY"},
                ],
            ),
        ])
        report = generate_state_of_mcp_report(path)
        assert "AUTH-MISSING" in report
        assert "CRED-API_KEY" in report

    def test_source_breakdown(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(source="npm"),
            _make_scan_record(source="npm"),
            _make_scan_record(source="pypi"),
        ])
        report = generate_state_of_mcp_report(path)
        assert "npm" in report
        assert "pypi" in report

    def test_score_distribution(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(score=10),
            _make_scan_record(score=50),
            _make_scan_record(score=90),
        ])
        report = generate_state_of_mcp_report(path)
        assert "Score Distribution" in report
        assert "0-20" in report
        assert "81-100" in report

    def test_mixed_statuses(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _make_scan_record(status="success", score=80),
            _make_scan_record(status="error"),
            _make_scan_record(status="timeout"),
        ])
        report = generate_state_of_mcp_report(path)
        assert "Total servers scanned | 3" in report
        assert "Successful scans | 1" in report
        assert "Failed scans | 1" in report
        assert "Timed out | 1" in report

    def test_output_is_valid_markdown(self, tmp_path: Path) -> None:
        """Report should have Markdown headers and table formatting."""
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_make_scan_record()])
        report = generate_state_of_mcp_report(path)

        # Check for Markdown structure
        assert report.startswith("# ")
        assert "| Metric | Value |" in report
        assert "|--------|-------|" in report

    def test_malformed_jsonl_lines_skipped(self, tmp_path: Path) -> None:
        """Malformed JSONL lines should be skipped, not crash."""
        path = tmp_path / "results.jsonl"
        content = (
            'not valid json\n'
            + orjson.dumps(_make_scan_record(score=90)).decode() + '\n'
        )
        path.write_text(content)
        report = generate_state_of_mcp_report(path)
        # Should still process the valid line
        assert "Total servers scanned | 1" in report
