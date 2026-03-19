"""Tests for the scheduler module — Redis lock, async scheduler, and errors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from navil.crawler.scheduler import (
    REDIS_LOCK_KEY,
    _feed_results_to_cloud,
    _send_slack_alert,
    _write_scan_summary,
    acquire_redis_lock,
    release_redis_lock,
    run_async_scheduler,
)

# ── Fake async Redis with NX support ─────────────────────────


class FakeAsyncRedis:
    """Minimal async Redis mock supporting SET NX EX for lock tests."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    async def set(
        self,
        name: str,
        value: Any,
        *,
        nx: bool = False,
        ex: int | None = None,
        **kwargs: Any,
    ) -> bool | None:
        if nx and name in self._data:
            return None  # Key already exists, NX fails
        self._data[name] = str(value).encode()
        return True

    async def get(self, name: str) -> bytes | None:
        return self._data.get(name)

    async def delete(self, *names: str) -> int:
        count = 0
        for n in names:
            if n in self._data:
                del self._data[n]
                count += 1
        return count


@pytest.fixture
def fake_async_redis() -> FakeAsyncRedis:
    return FakeAsyncRedis()


# ── Redis lock tests ──────────────────────────────────────────


class TestRedisLock:
    """Tests for the Redis-based distributed lock."""

    @pytest.mark.asyncio
    async def test_acquire_lock_succeeds(self, fake_async_redis: FakeAsyncRedis) -> None:
        result = await acquire_redis_lock(fake_async_redis)
        assert result is True
        # Lock key should exist in Redis
        stored = await fake_async_redis.get(REDIS_LOCK_KEY)
        assert stored is not None

    @pytest.mark.asyncio
    async def test_acquire_lock_fails_when_held(self, fake_async_redis: FakeAsyncRedis) -> None:
        # First acquire succeeds
        result1 = await acquire_redis_lock(fake_async_redis)
        assert result1 is True

        # Second acquire should fail (lock already held)
        result2 = await acquire_redis_lock(fake_async_redis)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_release_lock(self, fake_async_redis: FakeAsyncRedis) -> None:
        await acquire_redis_lock(fake_async_redis)
        await release_redis_lock(fake_async_redis)

        # After release, key should be gone
        stored = await fake_async_redis.get(REDIS_LOCK_KEY)
        assert stored is None

    @pytest.mark.asyncio
    async def test_acquire_after_release(self, fake_async_redis: FakeAsyncRedis) -> None:
        await acquire_redis_lock(fake_async_redis)
        await release_redis_lock(fake_async_redis)

        # Should be able to acquire again
        result = await acquire_redis_lock(fake_async_redis)
        assert result is True

    @pytest.mark.asyncio
    async def test_custom_lock_key(self, fake_async_redis: FakeAsyncRedis) -> None:
        custom_key = "navil:test:lock"
        result = await acquire_redis_lock(fake_async_redis, lock_key=custom_key)
        assert result is True

        stored = await fake_async_redis.get(custom_key)
        assert stored is not None

    @pytest.mark.asyncio
    async def test_set_called_with_nx_and_ex(self) -> None:
        """Verify that acquire_redis_lock passes nx=True and ex=TTL."""
        mock_redis = AsyncMock()
        mock_redis.set.return_value = True

        await acquire_redis_lock(mock_redis, ttl=3600)

        mock_redis.set.assert_called_once_with(REDIS_LOCK_KEY, "locked", nx=True, ex=3600)


# ── Concurrent run prevention ────────────────────────────────


class TestConcurrentRunPrevention:
    """Tests that the async scheduler prevents concurrent runs."""

    @pytest.mark.asyncio
    async def test_skips_scan_when_lock_held(self, fake_async_redis: FakeAsyncRedis) -> None:
        """When the Redis lock is already held, the scheduler should skip."""
        # Pre-acquire the lock
        await acquire_redis_lock(fake_async_redis)

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                side_effect=AssertionError("Should not run scan when lock is held"),
            ),
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                max_iterations=1,
            )

    @pytest.mark.asyncio
    async def test_runs_scan_when_lock_free(self, fake_async_redis: FakeAsyncRedis) -> None:
        """When the Redis lock is free, the scheduler should acquire it and run."""
        mock_result = {
            "status": "complete",
            "scan_id": 1,
            "servers_discovered": 5,
            "stats": {"total": 5, "successful": 5, "failed": 0, "timed_out": 0},
            "elapsed_seconds": 1.0,
        }

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                return_value=mock_result,
            ) as mock_scan,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                max_iterations=1,
            )

        mock_scan.assert_called_once()

        # Lock should be released after the scan
        stored = await fake_async_redis.get(REDIS_LOCK_KEY)
        assert stored is None


# ── Scan summary ──────────────────────────────────────────────


class TestScanSummary:
    """Tests for writing scan summaries to disk."""

    def test_writes_summary(self, tmp_path: Path) -> None:
        summary_path = tmp_path / "last_scan.json"
        result_info = {
            "status": "complete",
            "scan_id": 42,
            "servers_discovered": 10,
            "stats": {"total": 10, "successful": 8, "failed": 2, "timed_out": 0},
            "elapsed_seconds": 5.5,
        }

        path = _write_scan_summary(result_info, path=summary_path)
        assert path == summary_path
        assert summary_path.exists()

        data = json.loads(summary_path.read_text())
        assert data["status"] == "complete"
        assert data["scan_id"] == 42
        assert "timestamp" in data

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        summary_path = tmp_path / "deep" / "nested" / "last_scan.json"
        _write_scan_summary({"status": "complete"}, path=summary_path)
        assert summary_path.exists()

    def test_overwrites_existing_summary(self, tmp_path: Path) -> None:
        summary_path = tmp_path / "last_scan.json"
        summary_path.write_text('{"old": true}')

        _write_scan_summary({"status": "new_scan"}, path=summary_path)
        data = json.loads(summary_path.read_text())
        assert data["status"] == "new_scan"
        assert "old" not in data


# ── Error handling ────────────────────────────────────────────


class TestErrorHandling:
    """Tests for error handling in the scheduler."""

    @pytest.mark.asyncio
    async def test_scan_failure_sends_slack_alert(self, fake_async_redis: FakeAsyncRedis) -> None:
        """When a scan fails, a Slack alert should be sent if configured."""
        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                side_effect=RuntimeError("Scan explosion"),
            ),
            patch("navil.crawler.scheduler._send_slack_alert") as mock_slack,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                slack_webhook_url="https://hooks.slack.com/test",
                max_iterations=1,
            )

        mock_slack.assert_called_once()
        call_args = mock_slack.call_args
        assert call_args[0][0] == "https://hooks.slack.com/test"
        assert "Scan explosion" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_scan_failure_no_slack_if_not_configured(
        self, fake_async_redis: FakeAsyncRedis
    ) -> None:
        """When no Slack webhook is configured, no alert is sent."""
        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                side_effect=RuntimeError("boom"),
            ),
            patch("navil.crawler.scheduler._send_slack_alert") as mock_slack,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                slack_webhook_url=None,
                max_iterations=1,
            )

        mock_slack.assert_not_called()

    @pytest.mark.asyncio
    async def test_lock_released_after_scan_failure(self, fake_async_redis: FakeAsyncRedis) -> None:
        """The Redis lock should be released even if the scan fails."""
        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                side_effect=RuntimeError("crash"),
            ),
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                max_iterations=1,
            )

        # Lock should be released
        stored = await fake_async_redis.get(REDIS_LOCK_KEY)
        assert stored is None

    @pytest.mark.asyncio
    async def test_invalid_interval_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown interval"):
            await run_async_scheduler(interval="biweekly")


# ── Slack alert ──────────────────────────────────────────────


class TestSlackAlert:
    """Tests for the Slack alert function."""

    def test_sends_slack_message(self) -> None:
        import httpx

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("POST", "https://hooks.slack.com/test"),
        )
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            _send_slack_alert("https://hooks.slack.com/test", "Scan failed!")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[1]["json"] == {"text": "Scan failed!"}

    def test_handles_slack_error_gracefully(self) -> None:
        import httpx

        with patch(
            "httpx.post",
            side_effect=httpx.ConnectError("no network"),
        ):
            # Should not raise
            _send_slack_alert("https://hooks.slack.com/test", "error")


# ── Cloud feed ───────────────────────────────────────────────


class TestCloudFeed:
    """Tests for feeding results to the cloud threat intel endpoint."""

    def test_feeds_results_successfully(self) -> None:
        import httpx

        mock_resp = httpx.Response(
            200,
            request=httpx.Request("POST", "https://api.navil.ai/v1/threat-intel/ingest"),
        )
        result_info = {"status": "complete", "scan_id": 1}
        with patch("httpx.post", return_value=mock_resp):
            ok = _feed_results_to_cloud(
                result_info,
                api_key="navil_live_test",
            )
        assert ok is True

    def test_returns_false_on_error(self) -> None:
        import httpx

        mock_resp = httpx.Response(
            500,
            request=httpx.Request("POST", "https://api.navil.ai/v1/threat-intel/ingest"),
        )
        with patch("httpx.post", return_value=mock_resp):
            ok = _feed_results_to_cloud(
                {"status": "complete"},
                api_key="navil_live_test",
            )
        assert ok is False

    def test_returns_false_without_api_key(self) -> None:
        with patch("navil.crawler.scheduler._load_api_key_from_config", return_value=None):
            ok = _feed_results_to_cloud({"status": "complete"})
        assert ok is False

    def test_handles_network_error(self) -> None:
        import httpx

        with patch(
            "httpx.post",
            side_effect=httpx.ConnectError("no network"),
        ):
            ok = _feed_results_to_cloud(
                {"status": "complete"},
                api_key="navil_live_test",
            )
        assert ok is False


# ── Async scheduler integration ──────────────────────────────


class TestAsyncSchedulerIntegration:
    """Integration-level tests for the async scheduler."""

    @pytest.mark.asyncio
    async def test_runs_without_redis(self) -> None:
        """Scheduler should work without Redis (no lock)."""
        mock_result = {
            "status": "complete",
            "scan_id": 1,
            "servers_discovered": 3,
            "stats": {"total": 3, "successful": 3, "failed": 0, "timed_out": 0},
            "elapsed_seconds": 0.5,
        }

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                return_value=mock_result,
            ) as mock_scan,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"daily": 0.01}),
        ):
            await run_async_scheduler(
                interval="daily",
                redis_client=None,
                max_iterations=1,
            )

        mock_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_feeds_to_cloud_when_enabled(self, fake_async_redis: FakeAsyncRedis) -> None:
        mock_result = {
            "status": "complete",
            "scan_id": 1,
            "servers_discovered": 3,
            "stats": {"total": 3, "successful": 3, "failed": 0, "timed_out": 0},
            "elapsed_seconds": 0.5,
        }

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                return_value=mock_result,
            ),
            patch("navil.crawler.scheduler._feed_results_to_cloud") as mock_feed,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                feed_to_cloud=True,
                max_iterations=1,
            )

        mock_feed.assert_called_once_with(mock_result)

    @pytest.mark.asyncio
    async def test_does_not_feed_to_cloud_when_disabled(
        self, fake_async_redis: FakeAsyncRedis
    ) -> None:
        mock_result = {
            "status": "complete",
            "scan_id": 1,
            "servers_discovered": 3,
            "stats": {},
            "elapsed_seconds": 0.5,
        }

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                return_value=mock_result,
            ),
            patch("navil.crawler.scheduler._feed_results_to_cloud") as mock_feed,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"weekly": 0.01}),
        ):
            await run_async_scheduler(
                interval="weekly",
                redis_client=fake_async_redis,
                feed_to_cloud=False,
                max_iterations=1,
            )

        mock_feed.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_iterations(self, fake_async_redis: FakeAsyncRedis) -> None:
        mock_result = {
            "status": "complete",
            "scan_id": 1,
            "stats": {},
            "elapsed_seconds": 0.1,
        }

        with (
            patch(
                "navil.crawler.scheduler.run_full_scan",
                return_value=mock_result,
            ) as mock_scan,
            patch("navil.crawler.scheduler.INTERVAL_SECONDS", {"hourly": 0.01}),
        ):
            await run_async_scheduler(
                interval="hourly",
                redis_client=fake_async_redis,
                max_iterations=3,
            )

        assert mock_scan.call_count == 3
