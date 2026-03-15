"""Tests for ThreatIntelFetcher — cloud pattern polling."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from navil.cloud.threat_intel_fetcher import ThreatIntelFetcher

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeRedis:
    """Minimal async Redis mock that records publish calls."""

    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    async def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 1


def _make_cloud_response(patterns: list[dict[str, Any]], as_of: str = "2026-03-14T00:00:00Z"):
    """Build a mock httpx.Response for the patterns endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "patterns": patterns,
        "total": len(patterns),
        "as_of": as_of,
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _mock_client(mock_resp: MagicMock) -> AsyncMock:
    """Create a mock httpx.AsyncClient that returns the given response."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=mock_resp)
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFetcherEnabled:
    def test_disabled_without_api_key(self) -> None:
        fetcher = ThreatIntelFetcher(redis_client=FakeRedis(), api_key="")
        assert fetcher.is_enabled() is False

    def test_enabled_with_api_key(self) -> None:
        fetcher = ThreatIntelFetcher(redis_client=FakeRedis(), api_key="nvl_test")
        assert fetcher.is_enabled() is True

    def test_env_var_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NAVIL_API_KEY", "nvl_from_env")
        fetcher = ThreatIntelFetcher(redis_client=FakeRedis())
        assert fetcher.is_enabled() is True


class TestFetchAndPublish:
    @pytest.mark.asyncio
    async def test_publishes_patterns_to_redis(self) -> None:
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        patterns = [
            {
                "pattern_id": "community_recon_001",
                "anomaly_type": "RECONNAISSANCE",
                "description": "Tools list probe",
                "features": {"tool_sequence": ["__tools_list__"]},
                "source": "community",
                "confidence_boost": 0.3,
            },
            {
                "pattern_id": "community_exfil_001",
                "anomaly_type": "DATA_EXFILTRATION",
                "description": "Bulk read",
                "features": {"tool_sequence": ["read_all"]},
                "source": "community",
                "confidence_boost": 0.4,
            },
        ]

        mock_resp = _make_cloud_response(patterns, as_of="2026-03-14T12:00:00Z")
        fetcher._http_client = _mock_client(mock_resp)
        count = await fetcher._fetch_and_publish()

        assert count == 2
        assert len(redis.published) == 2

        # Verify channel
        for channel, _ in redis.published:
            assert channel == "navil:threat_intel:inbound"

        # Verify first published entry
        entry = json.loads(redis.published[0][1])
        assert entry["source"] == "navil-cloud"
        assert entry["entry_type"] == "pattern"
        assert entry["pattern_data"]["pattern_id"] == "community_recon_001"
        assert entry["pattern_data"]["anomaly_type"] == "RECONNAISSANCE"

    @pytest.mark.asyncio
    async def test_handles_403_gracefully(self) -> None:
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"detail": "Community tier requires active threat sharing."}
        fetcher._http_client = _mock_client(mock_resp)
        count = await fetcher._fetch_and_publish()

        assert count == 0
        assert len(redis.published) == 0

    @pytest.mark.asyncio
    async def test_cursor_advances_after_fetch(self) -> None:
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        assert fetcher._last_cursor is None

        patterns = [{"pattern_id": "p1", "anomaly_type": "TEST", "description": "t"}]
        mock_resp = _make_cloud_response(patterns, as_of="2026-03-14T15:00:00Z")
        fetcher._http_client = _mock_client(mock_resp)
        await fetcher._fetch_and_publish()

        assert fetcher._last_cursor == "2026-03-14T15:00:00Z"

    @pytest.mark.asyncio
    async def test_empty_response_returns_zero(self) -> None:
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        mock_resp = _make_cloud_response([], as_of="2026-03-14T15:00:00Z")
        fetcher._http_client = _mock_client(mock_resp)
        count = await fetcher._fetch_and_publish()

        assert count == 0
        assert len(redis.published) == 0

    @pytest.mark.asyncio
    async def test_filters_pattern_data_fields(self) -> None:
        """Only allowed pattern fields are published — unexpected keys stripped."""
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        patterns = [
            {
                "pattern_id": "p1",
                "anomaly_type": "TEST",
                "description": "test",
                "features": {},
                "source": "community",
                "unexpected_field": "should_be_stripped",
                "internal_id": 12345,
            }
        ]
        mock_resp = _make_cloud_response(patterns)
        fetcher._http_client = _mock_client(mock_resp)
        await fetcher._fetch_and_publish()

        entry = json.loads(redis.published[0][1])
        assert "unexpected_field" not in entry["pattern_data"]
        assert "internal_id" not in entry["pattern_data"]
        assert entry["pattern_data"]["pattern_id"] == "p1"


class TestFetcherStats:
    @pytest.mark.asyncio
    async def test_stats_tracks_published_count(self) -> None:
        redis = FakeRedis()
        fetcher = ThreatIntelFetcher(
            redis_client=redis,
            api_key="nvl_test",
            cloud_url="https://test.navil.ai",
        )

        patterns = [
            {"pattern_id": "p1", "anomaly_type": "A", "description": "x"},
            {"pattern_id": "p2", "anomaly_type": "B", "description": "y"},
        ]
        mock_resp = _make_cloud_response(patterns)
        fetcher._http_client = _mock_client(mock_resp)
        await fetcher._fetch_and_publish()

        assert fetcher.stats["published_count"] == 2
