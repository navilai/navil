"""Tests for the registry scanner risk scorer."""

from __future__ import annotations

from typing import Any

from navil.crawler.risk_scorer import (
    DEFAULT_HIGH_RISK_THRESHOLD,
    score_batch,
    score_server_risk,
)

# ── Test data helpers ────────────────────────────────────────


def _make_scan_record(
    *,
    server_name: str = "test-server",
    source: str = "npm",
    url: str = "https://npmjs.com/package/test-server",
    status: str = "success",
    security_score: int = 50,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a batch-scanner-style result dict."""
    rec: dict[str, Any] = {
        "server_name": server_name,
        "source": source,
        "url": url,
        "status": status,
    }
    if status == "success":
        rec["scan"] = {
            "security_score": security_score,
            "findings": findings or [],
            "vulnerabilities": [],
        }
    return rec


def _finding(
    finding_id: str,
    severity: str = "HIGH",
    title: str = "Test finding",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": "Test description",
        "source": "scanner",
        "affected_field": "config",
        "remediation": "Fix it",
    }


# ── Basic scoring tests ─────────────────────────────────────


class TestScoreServerRisk:
    """Tests for the score_server_risk function."""

    def test_clean_server_low_risk(self) -> None:
        """A server with no findings should have near-zero risk."""
        record = _make_scan_record(findings=[])
        result = score_server_risk(record)

        assert result.risk_score == 0.0
        assert result.is_high_risk is False
        assert result.server_name == "test-server"
        assert result.high_risk_findings == []

    def test_failed_scan_moderate_risk(self) -> None:
        """Failed scans should get a moderate baseline risk."""
        record = _make_scan_record(status="error")
        result = score_server_risk(record)

        assert result.risk_score == 0.3
        assert result.is_high_risk is False

    def test_timeout_scan_moderate_risk(self) -> None:
        """Timed-out scans should also get moderate risk."""
        record = _make_scan_record(status="timeout")
        result = score_server_risk(record)

        assert result.risk_score == 0.3
        assert result.is_high_risk is False

    def test_critical_findings_high_risk(self) -> None:
        """Multiple CRITICAL findings across dimensions should produce high risk."""
        findings = [
            _finding("MALICIOUS-001", "CRITICAL"),
            _finding("MALICIOUS-002", "CRITICAL"),
            _finding("CRED-API_KEY", "CRITICAL"),
            _finding("CRED-PASSWORD", "CRITICAL"),
            _finding("PERM-EXCESSIVE-001", "HIGH"),
            _finding("SUPPLY-CHAIN-NPX", "HIGH"),
            _finding("EXFIL-READ_SEND", "HIGH"),
        ]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.risk_score > DEFAULT_HIGH_RISK_THRESHOLD
        assert result.is_high_risk is True
        assert len(result.high_risk_findings) >= 2

    def test_single_medium_finding_low_risk(self) -> None:
        """A single MEDIUM finding should not trigger high risk."""
        findings = [_finding("CONFIG-001", "MEDIUM")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.risk_score < DEFAULT_HIGH_RISK_THRESHOLD
        assert result.is_high_risk is False

    def test_custom_threshold(self) -> None:
        """Custom threshold should be respected."""
        findings = [_finding("CRED-API_KEY", "HIGH")]
        record = _make_scan_record(findings=findings)

        # With low threshold, should be flagged
        result_low = score_server_risk(record, threshold=0.1)
        assert result_low.is_high_risk is True

        # With high threshold, should not be flagged
        result_high = score_server_risk(record, threshold=0.99)
        assert result_high.is_high_risk is False

    def test_risk_breakdown_populated(self) -> None:
        """Risk breakdown should have per-dimension scores."""
        findings = [
            _finding("CRED-API_KEY", "HIGH"),
            _finding("SUPPLY-CHAIN-001", "HIGH"),
        ]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.vulnerability_severity > 0
        assert isinstance(result.breakdown.to_dict(), dict)

    def test_assessment_to_dict(self) -> None:
        """RiskAssessment.to_dict() should produce a serializable dict."""
        record = _make_scan_record(findings=[_finding("TEST-001", "LOW")])
        result = score_server_risk(record)
        d = result.to_dict()

        assert isinstance(d, dict)
        assert "risk_score" in d
        assert "breakdown" in d
        assert isinstance(d["breakdown"], dict)


# ── Dimension-specific tests ─────────────────────────────────


class TestVulnerabilitySeverityScoring:
    """Tests for the vulnerability severity dimension."""

    def test_critical_scores_highest(self) -> None:
        """CRITICAL severity should produce maximum dimension score."""
        findings = [_finding("TEST-001", "CRITICAL")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.vulnerability_severity >= 0.9

    def test_info_scores_zero(self) -> None:
        """INFO severity should produce zero dimension score."""
        findings = [_finding("TEST-001", "INFO")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.vulnerability_severity == 0.0

    def test_multiple_high_findings_density_bonus(self) -> None:
        """Multiple CRITICAL/HIGH findings should get a density bonus."""
        single = _make_scan_record(findings=[_finding("TEST-001", "HIGH")])
        many = _make_scan_record(
            findings=[
                _finding("TEST-001", "HIGH"),
                _finding("TEST-002", "HIGH"),
                _finding("TEST-003", "CRITICAL"),
                _finding("TEST-004", "HIGH"),
            ]
        )

        single_score = score_server_risk(single).breakdown.vulnerability_severity
        many_score = score_server_risk(many).breakdown.vulnerability_severity

        assert many_score > single_score


class TestPermissionScopeScoring:
    """Tests for the permission scope dimension."""

    def test_no_permission_findings(self) -> None:
        """No permission-related findings → zero score."""
        findings = [_finding("OTHER-001", "HIGH")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.permission_scope == 0.0

    def test_credential_findings(self) -> None:
        """Credential-related findings should score."""
        findings = [_finding("CRED-API_KEY", "HIGH")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.permission_scope > 0.0

    def test_excessive_perms(self) -> None:
        """PERM-EXCESSIVE should score."""
        findings = [_finding("PERM-EXCESSIVE-001", "HIGH")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.permission_scope > 0.0


class TestSupplyChainScoring:
    """Tests for the supply chain risk dimension."""

    def test_supply_chain_finding(self) -> None:
        """Supply chain findings should score."""
        findings = [_finding("SUPPLY-CHAIN-NPX", "HIGH")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.supply_chain > 0.0

    def test_source_unverified(self) -> None:
        """SOURCE-UNVERIFIED findings should score."""
        findings = [_finding("SOURCE-UNVERIFIED-001", "MEDIUM")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.supply_chain > 0.0


class TestKnownBadPatternScoring:
    """Tests for the known bad patterns dimension."""

    def test_malicious_pattern(self) -> None:
        """MALICIOUS findings should produce high score."""
        findings = [_finding("MALICIOUS-EXFIL", "CRITICAL")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.known_bad_patterns >= 0.7

    def test_prompt_injection(self) -> None:
        """PROMPT-INJECTION findings should score."""
        findings = [_finding("PROMPT-INJECTION-001", "HIGH")]
        record = _make_scan_record(findings=findings)
        result = score_server_risk(record)

        assert result.breakdown.known_bad_patterns >= 0.7


# ── Batch scoring tests ──────────────────────────────────────


class TestScoreBatch:
    """Tests for the score_batch function."""

    def test_empty_batch(self) -> None:
        """Empty input should produce empty output."""
        assert score_batch([]) == []

    def test_sorted_by_risk_descending(self) -> None:
        """Results should be sorted by risk_score, highest first."""
        records = [
            _make_scan_record(server_name="safe", findings=[]),
            _make_scan_record(
                server_name="dangerous",
                findings=[
                    _finding("MALICIOUS-001", "CRITICAL"),
                    _finding("CRED-API_KEY", "CRITICAL"),
                ],
            ),
            _make_scan_record(
                server_name="moderate",
                findings=[_finding("CONFIG-001", "MEDIUM")],
            ),
        ]
        results = score_batch(records)

        assert len(results) == 3
        assert results[0].server_name == "dangerous"
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_batch_preserves_metadata(self) -> None:
        """Batch scoring should preserve server metadata."""
        records = [
            _make_scan_record(
                server_name="my-server",
                source="pypi",
                url="https://pypi.org/project/my-server/",
                findings=[],
            ),
        ]
        results = score_batch(records)

        assert results[0].server_name == "my-server"
        assert results[0].source == "pypi"
        assert results[0].url == "https://pypi.org/project/my-server/"

    def test_batch_with_mixed_statuses(self) -> None:
        """Batch should handle mixed success/error/timeout records."""
        records = [
            _make_scan_record(server_name="ok", status="success", findings=[]),
            _make_scan_record(server_name="broken", status="error"),
            _make_scan_record(server_name="slow", status="timeout"),
        ]
        results = score_batch(records)

        assert len(results) == 3
        names = {r.server_name for r in results}
        assert names == {"ok", "broken", "slow"}
