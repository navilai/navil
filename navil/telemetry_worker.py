# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Telemetry Bridge Worker — consumes events from the Rust data plane.

The Rust proxy LPUSHes request metadata to ``navil:telemetry:queue`` in Redis.
This worker BRPOPs events, feeds them into the Python anomaly detection
pipeline, and writes updated thresholds back to Redis so the Rust proxy
always has the latest ML baselines.

Usage (standalone)::

    worker = TelemetryWorker(redis_client=redis, detector=detector)
    await worker.run()          # blocks, processing events forever
    await worker.run_once()     # process one event (for tests)

Architecture::

    Rust data plane → LPUSH navil:telemetry:queue → Redis
                                                      ↓
    Python control plane ← BRPOP ← TelemetryWorker
                              ↓
                   record_invocation_async()
                              ↓
                   _run_detectors() → _recompute_thresholds()
                              ↓
                   HSET navil:agent:{name}:thresholds → Redis → Rust reads
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import orjson

from navil.telemetry_event import TELEMETRY_QUEUE

logger = logging.getLogger(__name__)
BRPOP_TIMEOUT = 5  # seconds; short enough that shutdown is responsive


class TelemetryWorker:
    """Async worker that bridges Rust telemetry to Python anomaly detection."""

    def __init__(
        self,
        redis_client: Any,
        detector: Any,
    ) -> None:
        self.redis = redis_client
        self.detector = detector
        self._running = False
        self._processed = 0
        self._errors = 0

    @property
    def stats(self) -> dict[str, int]:
        return {"processed": self._processed, "errors": self._errors}

    async def run(self) -> None:
        """Run the consumer loop indefinitely.  Call ``stop()`` to exit."""
        self._running = True
        logger.info("TelemetryWorker started — listening on %s", TELEMETRY_QUEUE)
        while self._running:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception:
                self._errors += 1
                logger.exception("TelemetryWorker loop error")
                await asyncio.sleep(1)  # back off on unexpected errors

    def stop(self) -> None:
        """Signal the worker to stop after the current iteration."""
        self._running = False

    async def run_once(self) -> bool:
        """Process a single event from the queue.

        Returns True if an event was processed, False if the queue was empty
        (timed out).
        """
        return await self._poll_once()

    async def _poll_once(self) -> bool:
        """BRPOP one event, deserialize, and feed into the detector."""
        try:
            result = await self.redis.brpop(TELEMETRY_QUEUE, timeout=BRPOP_TIMEOUT)
        except Exception:
            logger.debug("Redis BRPOP failed, will retry")
            self._errors += 1
            return False

        if result is None:
            return False  # timeout, no event

        # result is (key, value) tuple
        _key, raw = result

        try:
            event = orjson.loads(raw)
        except Exception:
            logger.warning("Invalid JSON in telemetry event, skipping")
            self._errors += 1
            return False

        await self._process_event(event)
        self._processed += 1

        # Periodic backpressure check
        if self._processed % 1000 == 0:
            try:
                queue_len = await self.redis.llen(TELEMETRY_QUEUE)
                if queue_len > 50_000:
                    await self.redis.ltrim(TELEMETRY_QUEUE, -50_000, -1)
                    logger.warning("Telemetry queue trimmed from %d to 50k", queue_len)
            except Exception:
                pass  # backpressure check is best-effort

        return True

    async def _process_event(self, event: dict[str, Any]) -> None:
        """Feed a telemetry event into the anomaly detection pipeline."""
        agent_name = event.get("agent_name", "unknown")
        tool_name = event.get("tool_name", "")
        method = event.get("method", "tools/call")
        action_taken = event.get("action", "FORWARDED")
        payload_bytes = event.get("payload_bytes", 0)
        response_bytes = event.get("response_bytes", 0)
        duration_ms = event.get("duration_ms", 0)
        target_server = event.get("target_server")
        timestamp = event.get("timestamp")

        is_list_tools = method == "tools/list"

        # Feed into the full anomaly detection pipeline.
        # record_invocation_async() runs _run_detectors() → _recompute_thresholds()
        # and then syncs the updated thresholds back to Redis.
        try:
            await self.detector.record_invocation_async(
                agent_name=agent_name,
                tool_name=tool_name,
                action=action_taken,
                duration_ms=duration_ms,
                data_accessed_bytes=response_bytes,
                success=action_taken == "FORWARDED",
                target_server=target_server,
                arguments_size_bytes=payload_bytes,
                response_size_bytes=response_bytes,
                is_list_tools=is_list_tools,
                timestamp=timestamp,
            )
        except Exception:
            logger.exception(
                "Failed to process telemetry for agent=%s tool=%s",
                agent_name,
                tool_name,
            )
            self._errors += 1
