"""Tests for the BlocklistDistributor — tier-aware blocklist distribution.

Validates:
  - Tier resolution from API key metadata and env vars
  - Rate limiting per tier (community 48h, pro 5min, etc.)
  - Content delay for community tier
  - Fetch, merge, and Redis push flow
  - Stats and cleanup
"""

from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navil.blocklist import BlocklistEntry, BlocklistManager
from navil.cloud.blocklist_distribution import (
    BlocklistDistributor,
    _COMMUNITY_CONTENT_DELAY_H,
    _REALTIME_TIERS,
    _TIER_RATE_LIMITS,
)


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def blocklist_manager():
    """A fresh BlocklistManager with no Redis."""
    return BlocklistManager(redis_client=None)


@pytest.fixture
def sample_patterns():
    """Sample blocklist pattern dicts as returned by the API."""
    return [
        {
            "pattern_id": "BL-001",
            "pattern_type": "tool_name",
            "value": "inject_backdoor",
            "severity": "CRITICAL",
            "description": "Known malicious tool",
            "confidence": 0.95,
        },
        {
            "pattern_id": "BL-002",
            "pattern_type": "argument_pattern",
            "value": ".*\\.ssh/.*",
            "severity": "HIGH",
            "description": "SSH directory access pattern",
            "confidence": 0.85,
        },
        {
            "pattern_id": "BL-003",
            "pattern_type": "tool_sequence",
            "value": "read_env,exec_command",
            "severity": "HIGH",
            "description": "Env read followed by command execution",
            "confidence": 0.80,
        },
    ]


# ── Tier Resolution ─────────────────────────────────────────────


class TestTierResolution:
    """Tests for tier resolution from API key metadata."""

    @pytest.mark.asyncio
    async def test_no_api_key_is_community(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="")
        tier = await dist.resolve_tier()
        assert tier == "community"

    @pytest.mark.asyncio
    async def test_tier_from_env_var(self, blocklist_manager):
        with patch.dict("os.environ", {"NAVIL_TIER": "enterprise"}):
            dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
            tier = await dist.resolve_tier()
            assert tier == "enterprise"

    @pytest.mark.asyncio
    async def test_tier_from_api_metadata(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")

        # Use MagicMock for response (json() is sync in httpx)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tier": "team", "org": "test-org"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        # Ensure NAVIL_TIER is not set so API resolution is used
        env_copy = {k: v for k, v in os.environ.items() if k != "NAVIL_TIER"}
        with patch.dict("os.environ", env_copy, clear=True):
            tier = await dist.resolve_tier()
            assert tier == "team"

    @pytest.mark.asyncio
    async def test_tier_cached_after_resolution(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="")
        await dist.resolve_tier()
        # Second call should use cached value without network
        tier = await dist.resolve_tier()
        assert tier == "community"

    @pytest.mark.asyncio
    async def test_tier_fallback_on_api_error(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        env_copy = {k: v for k, v in os.environ.items() if k != "NAVIL_TIER"}
        with patch.dict("os.environ", env_copy, clear=True):
            tier = await dist.resolve_tier()
            assert tier == "community"


# ── Rate Limiting ───────────────────────────────────────────────


class TestRateLimiting:
    """Tests for tier-based rate limiting."""

    def test_first_request_never_rate_limited(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "community"
        assert not dist._is_rate_limited()

    def test_community_rate_limit(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "community"
        dist._last_fetch_time = time.time()  # just fetched
        assert dist._is_rate_limited()
        # Rate limit should be 48 hours
        assert dist._get_rate_limit() == 48 * 3600

    def test_pro_rate_limit(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "pro"
        dist._last_fetch_time = time.time()
        assert dist._is_rate_limited()
        assert dist._get_rate_limit() == 5 * 60

    def test_enterprise_rate_limit(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "enterprise"
        assert dist._get_rate_limit() == 30

    def test_time_until_next_fetch(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "pro"
        dist._last_fetch_time = time.time() - 100  # 100 seconds ago
        remaining = dist.time_until_next_fetch()
        # Pro rate limit is 300s, so ~200s remaining
        assert 190 < remaining < 210

    def test_time_until_next_fetch_first_request(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "pro"
        assert dist.time_until_next_fetch() == 0.0

    def test_rate_limit_expired(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        dist._tier = "enterprise"
        dist._last_fetch_time = time.time() - 60  # 60 seconds ago, limit is 30
        assert not dist._is_rate_limited()

    def test_all_tiers_have_rate_limits(self):
        for tier in ("community", "pro", "team", "enterprise"):
            assert tier in _TIER_RATE_LIMITS


# ── Pull Updates ────────────────────────────────────────────────


class TestPullUpdates:
    """Tests for the pull_updates flow."""

    @pytest.mark.asyncio
    async def test_pull_rate_limited(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="")
        dist._tier = "community"
        dist._last_fetch_time = time.time()  # just fetched

        result = await dist.pull_updates()
        assert result["rate_limited"] is True
        assert result["fetched"] == 0

    @pytest.mark.asyncio
    async def test_pull_community_delayed(self, blocklist_manager, sample_patterns):
        dist = BlocklistDistributor(blocklist_manager, api_key="")
        dist._tier = "community"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"patterns": sample_patterns}
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["delayed"] is True
        assert result["fetched"] == 3
        assert result["merged"] == 3

        # Verify delay_hours parameter was sent
        call_args = mock_client.get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params")
        assert params["delay_hours"] == _COMMUNITY_CONTENT_DELAY_H

    @pytest.mark.asyncio
    async def test_pull_pro_realtime(self, blocklist_manager, sample_patterns):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"patterns": sample_patterns}
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["delayed"] is False
        assert result["fetched"] == 3
        assert result["tier"] == "pro"

        # Verify no delay_hours parameter
        call_args = mock_client.get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params")
        assert "delay_hours" not in params

    @pytest.mark.asyncio
    async def test_pull_304_not_modified(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 304
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["fetched"] == 0
        assert result["merged"] == 0

    @pytest.mark.asyncio
    async def test_pull_429_server_rate_limit(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "120"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["rate_limited"] is True

    @pytest.mark.asyncio
    async def test_pull_merges_with_existing(self, blocklist_manager, sample_patterns):
        """New patterns should merge with existing blocklist entries."""
        # Pre-load one entry
        existing = BlocklistEntry(
            pattern_id="BL-001",
            pattern_type="tool_name",
            value="inject_backdoor",
            severity="HIGH",
            description="Existing entry",
            confidence=0.5,  # lower confidence than sample
        )
        blocklist_manager.merge([existing])
        assert blocklist_manager.pattern_count == 1

        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "team"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"patterns": sample_patterns}
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        # BL-001 should be updated (higher confidence), BL-002 and BL-003 added
        assert result["merged"] == 3
        assert blocklist_manager.pattern_count == 3

    @pytest.mark.asyncio
    async def test_pull_empty_patterns(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"patterns": []}
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["fetched"] == 0

    @pytest.mark.asyncio
    async def test_pull_http_error(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        result = await dist.pull_updates()
        assert result["fetched"] == 0


# ── Stats ───────────────────────────────────────────────────────


class TestDistributorStats:
    """Tests for distributor statistics."""

    def test_initial_stats(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        stats = dist.stats
        assert stats["tier"] == "unresolved"
        assert stats["fetch_count"] == 0
        assert stats["blocklist_version"] == 0
        assert stats["blocklist_pattern_count"] == 0

    @pytest.mark.asyncio
    async def test_stats_after_fetch(self, blocklist_manager, sample_patterns):
        dist = BlocklistDistributor(blocklist_manager, api_key="test-key")
        dist._tier = "pro"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"patterns": sample_patterns}
        mock_response.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        dist._http_client = mock_client

        await dist.pull_updates()
        stats = dist.stats
        assert stats["tier"] == "pro"
        assert stats["fetch_count"] == 1
        assert stats["blocklist_pattern_count"] == 3


# ── Realtime Tiers ──────────────────────────────────────────────


class TestRealtimeTiers:
    """Verify that paid tiers get real-time access."""

    def test_pro_is_realtime(self):
        assert "pro" in _REALTIME_TIERS

    def test_team_is_realtime(self):
        assert "team" in _REALTIME_TIERS

    def test_enterprise_is_realtime(self):
        assert "enterprise" in _REALTIME_TIERS

    def test_community_is_not_realtime(self):
        assert "community" not in _REALTIME_TIERS


# ── Cleanup ─────────────────────────────────────────────────────


class TestDistributorCleanup:
    """Tests for resource cleanup."""

    @pytest.mark.asyncio
    async def test_close(self, blocklist_manager):
        dist = BlocklistDistributor(blocklist_manager)
        mock_client = AsyncMock()
        dist._http_client = mock_client
        await dist.close()
        mock_client.aclose.assert_called_once()
        assert dist._http_client is None
