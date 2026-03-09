"""Tests for the TelemetryWorker (Rust→Python telemetry bridge)."""

from __future__ import annotations

import orjson
import pytest

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.telemetry_worker import TELEMETRY_QUEUE, TelemetryWorker


@pytest.fixture
def detector(fake_redis) -> BehavioralAnomalyDetector:
    return BehavioralAnomalyDetector(redis_client=fake_redis)


@pytest.fixture
def worker(fake_redis, detector) -> TelemetryWorker:
    return TelemetryWorker(redis_client=fake_redis, detector=detector)


def _push_event(fake_redis, event: dict) -> None:
    """Synchronous helper to seed the queue (bypasses async for setup)."""
    raw = orjson.dumps(event)
    if TELEMETRY_QUEUE not in fake_redis._data:
        fake_redis._data[TELEMETRY_QUEUE] = []
    fake_redis._data[TELEMETRY_QUEUE].insert(0, raw)


class TestTelemetryWorkerProcessing:
    async def test_run_once_processes_event(self, worker, fake_redis, detector):
        """A single FORWARDED event should be consumed and recorded."""
        _push_event(
            fake_redis,
            {
                "agent_name": "rust-agent",
                "tool_name": "read_file",
                "method": "tools/call",
                "action": "FORWARDED",
                "payload_bytes": 256,
                "response_bytes": 1024,
                "duration_ms": 5,
                "timestamp": "2026-03-08T12:00:00Z",
                "target_server": "http://localhost:3000",
            },
        )

        processed = await worker.run_once()

        assert processed is True
        assert worker.stats["processed"] == 1
        assert worker.stats["errors"] == 0
        assert len(detector.invocations) == 1

        inv = detector.invocations[0]
        assert inv.agent_name == "rust-agent"
        assert inv.tool_name == "read_file"
        assert inv.duration_ms == 5
        assert inv.data_accessed_bytes == 1024
        assert inv.success is True

    async def test_run_once_empty_queue(self, worker):
        """run_once on empty queue should return False."""
        processed = await worker.run_once()
        assert processed is False
        assert worker.stats["processed"] == 0

    async def test_blocked_event_records_failure(self, worker, fake_redis, detector):
        """A BLOCKED event should record success=False."""
        _push_event(
            fake_redis,
            {
                "agent_name": "bad-agent",
                "tool_name": "write_file",
                "method": "tools/call",
                "action": "BLOCKED_RATE",
                "payload_bytes": 512,
                "response_bytes": 0,
                "duration_ms": 1,
                "timestamp": "2026-03-08T12:00:01Z",
                "target_server": "http://localhost:3000",
            },
        )

        await worker.run_once()

        assert len(detector.invocations) == 1
        inv = detector.invocations[0]
        assert inv.agent_name == "bad-agent"
        assert inv.success is False
        assert inv.action == "BLOCKED_RATE"

    async def test_multiple_events_processed_in_order(self, worker, fake_redis, detector):
        """Events should be processed FIFO (LPUSH + BRPOP = queue)."""
        for i in range(3):
            _push_event(
                fake_redis,
                {
                    "agent_name": f"agent-{i}",
                    "tool_name": "tool",
                    "method": "tools/call",
                    "action": "FORWARDED",
                    "payload_bytes": 100,
                    "response_bytes": 200,
                    "duration_ms": 10,
                    "timestamp": f"2026-03-08T12:00:0{i}Z",
                    "target_server": "http://localhost:3000",
                },
            )

        for _ in range(3):
            await worker.run_once()

        assert worker.stats["processed"] == 3
        assert [inv.agent_name for inv in detector.invocations] == [
            "agent-0",
            "agent-1",
            "agent-2",
        ]

    async def test_invalid_json_skipped(self, worker, fake_redis, detector):
        """Malformed JSON in the queue should be skipped with an error count."""
        fake_redis._data[TELEMETRY_QUEUE] = [b"not valid json"]

        await worker.run_once()

        assert worker.stats["processed"] == 0
        assert worker.stats["errors"] == 1
        assert len(detector.invocations) == 0


class TestTelemetryWorkerThresholdSync:
    async def test_thresholds_written_to_redis(self, worker, fake_redis, detector):
        """After processing an event, thresholds should be synced to Redis."""
        _push_event(
            fake_redis,
            {
                "agent_name": "sync-agent",
                "tool_name": "read_file",
                "method": "tools/call",
                "action": "FORWARDED",
                "payload_bytes": 100,
                "response_bytes": 500,
                "duration_ms": 10,
                "timestamp": "2026-03-08T12:00:00Z",
                "target_server": "http://localhost:3000",
            },
        )

        await worker.run_once()

        # Thresholds should now be in Redis
        key = "navil:agent:sync-agent:thresholds"
        assert key in fake_redis._data
        threshold_hash = fake_redis._data[key]
        assert "max_payload_bytes" in threshold_hash
        assert "rate_limit_per_min" in threshold_hash
        assert "blocked" in threshold_hash

    async def test_tools_list_event(self, worker, fake_redis, detector):
        """tools/list events should be marked as is_list_tools=True."""
        _push_event(
            fake_redis,
            {
                "agent_name": "list-agent",
                "tool_name": "",
                "method": "tools/list",
                "action": "FORWARDED",
                "payload_bytes": 50,
                "response_bytes": 300,
                "duration_ms": 2,
                "timestamp": "2026-03-08T12:00:00Z",
                "target_server": "http://localhost:3000",
            },
        )

        await worker.run_once()

        assert len(detector.invocations) == 1
        assert detector.invocations[0].is_list_tools is True


class TestTelemetryWorkerLifecycle:
    async def test_stop_flag(self, worker):
        """stop() should set _running to False."""
        worker._running = True
        worker.stop()
        assert worker._running is False
