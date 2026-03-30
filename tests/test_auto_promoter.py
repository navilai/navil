"""Tests for the registry scanner auto-promoter."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from navil.crawler.auto_promoter import (
    THREAT_INTEL_CHANNEL,
    promote_high_risk_to_threat_intel,
)
from navil.crawler.risk_scorer import RiskAssessment, RiskBreakdown

# ── Test data helpers ────────────────────────────────────────


def _make_assessment(
    *,
    server_name: str = "malicious-server",
    source: str = "npm",
    url: str = "https://npmjs.com/package/malicious-server",
    risk_score: float = 0.85,
    is_high_risk: bool = True,
    high_risk_findings: list[str] | None = None,
) -> RiskAssessment:
    return RiskAssessment(
        server_name=server_name,
        source=source,
        url=url,
        risk_score=risk_score,
        is_high_risk=is_high_risk,
        breakdown=RiskBreakdown(
            vulnerability_severity=0.9,
            permission_scope=0.6,
            supply_chain=0.4,
            known_bad_patterns=0.8,
            package_freshness=0.0,
        ),
        high_risk_findings=high_risk_findings or ["MALICIOUS-001", "CRED-API_KEY"],
    )


# ── Tests ────────────────────────────────────────────────────


class TestPromoteHighRisk:
    """Tests for promote_high_risk_to_threat_intel."""

    @pytest.mark.asyncio
    async def test_publishes_high_risk_to_redis(self) -> None:
        """High-risk assessments should be published to Redis."""
        redis = AsyncMock()
        redis.publish = AsyncMock(return_value=1)

        assessments = [_make_assessment()]
        count = await promote_high_risk_to_threat_intel(assessments, redis)

        assert count == 1
        redis.publish.assert_called_once()

        # Verify the channel and payload
        call_args = redis.publish.call_args
        assert call_args[0][0] == THREAT_INTEL_CHANNEL

        payload = json.loads(call_args[0][1])
        assert payload["source"] == "registry-scanner"
        assert payload["entry_type"] == "pattern"
        assert "malicious-server" in payload["pattern_data"]["pattern_id"]
        assert payload["pattern_data"]["anomaly_type"] == "suspicious_mcp_server"

    @pytest.mark.asyncio
    async def test_skips_low_risk(self) -> None:
        """Low-risk assessments should not be published."""
        redis = AsyncMock()

        assessments = [
            _make_assessment(
                server_name="safe-server",
                risk_score=0.2,
                is_high_risk=False,
            )
        ]
        count = await promote_high_risk_to_threat_intel(assessments, redis)

        assert count == 0
        redis.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_list(self) -> None:
        """Empty assessment list should publish nothing."""
        redis = AsyncMock()
        count = await promote_high_risk_to_threat_intel([], redis)

        assert count == 0
        redis.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_mixed_risk_levels(self) -> None:
        """Only high-risk assessments should be published."""
        redis = AsyncMock()
        redis.publish = AsyncMock(return_value=1)

        assessments = [
            _make_assessment(server_name="bad-1", is_high_risk=True),
            _make_assessment(server_name="ok", risk_score=0.3, is_high_risk=False),
            _make_assessment(server_name="bad-2", is_high_risk=True),
        ]
        count = await promote_high_risk_to_threat_intel(assessments, redis)

        assert count == 2
        assert redis.publish.call_count == 2

    @pytest.mark.asyncio
    async def test_redis_error_handled_gracefully(self) -> None:
        """Redis errors should be caught, not crash the promoter."""
        redis = AsyncMock()
        redis.publish = AsyncMock(side_effect=ConnectionError("Redis down"))

        assessments = [_make_assessment()]
        count = await promote_high_risk_to_threat_intel(assessments, redis)

        # Should return 0 (failed to publish) but not raise
        assert count == 0

    @pytest.mark.asyncio
    async def test_partial_redis_failure(self) -> None:
        """If one publish fails, others should still succeed."""
        redis = AsyncMock()
        redis.publish = AsyncMock(side_effect=[1, ConnectionError("Redis down"), 1])

        assessments = [
            _make_assessment(server_name="bad-1"),
            _make_assessment(server_name="bad-2"),
            _make_assessment(server_name="bad-3"),
        ]
        count = await promote_high_risk_to_threat_intel(assessments, redis)

        assert count == 2  # 2 succeeded, 1 failed

    @pytest.mark.asyncio
    async def test_payload_structure(self) -> None:
        """Published payload should have correct ThreatIntelEntry structure."""
        redis = AsyncMock()
        redis.publish = AsyncMock(return_value=1)

        assessment = _make_assessment(
            server_name="evil-tool",
            source="pypi",
            risk_score=0.92,
            high_risk_findings=["MALICIOUS-BACKDOOR"],
        )
        await promote_high_risk_to_threat_intel([assessment], redis)

        payload = json.loads(redis.publish.call_args[0][1])

        # Top-level structure
        assert set(payload.keys()) == {
            "source",
            "entry_type",
            "agent_name_hash",
            "tool_name",
            "pattern_data",
        }
        assert payload["agent_name_hash"] is None
        assert payload["tool_name"] is None

        # Pattern data
        pd = payload["pattern_data"]
        assert pd["pattern_id"] == "registry:pypi:evil-tool"
        assert pd["anomaly_type"] == "suspicious_mcp_server"
        assert "0.92" in pd["description"]
        assert pd["features"]["risk_score"] == 0.92
        assert pd["features"]["high_risk_findings"] == ["MALICIOUS-BACKDOOR"]
        assert pd["confidence_boost"] <= 0.4  # capped

    @pytest.mark.asyncio
    async def test_confidence_boost_capped(self) -> None:
        """Confidence boost should be capped at 0.4."""
        redis = AsyncMock()
        redis.publish = AsyncMock(return_value=1)

        # Even with max risk score, confidence_boost should cap at 0.4
        assessment = _make_assessment(risk_score=1.0)
        await promote_high_risk_to_threat_intel([assessment], redis)

        payload = json.loads(redis.publish.call_args[0][1])
        assert payload["pattern_data"]["confidence_boost"] <= 0.4
