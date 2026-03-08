# Copyright (c) 2026 Pantheon Lab Limited
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Shared telemetry event builder and constants.

Canonical event format matching the Rust TelemetryEvent shape from
navil-proxy/src/main.rs.  Both Python producers (proxy, REST API) and
the TelemetryWorker consumer use this module to stay in sync.
"""
from __future__ import annotations

from datetime import datetime, timezone

import orjson

TELEMETRY_QUEUE = "navil:telemetry:queue"


def build_telemetry_event(
    agent_name: str,
    tool_name: str,
    method: str = "tools/call",
    action: str = "FORWARDED",
    payload_bytes: int = 0,
    response_bytes: int = 0,
    duration_ms: int = 0,
    timestamp: str | None = None,
    target_server: str = "",
    arguments_hash: str | None = None,
    arguments_size_bytes: int = 0,
    is_list_tools: bool = False,
) -> bytes:
    """Build canonical telemetry event matching Rust TelemetryEvent shape.

    Returns orjson-serialized bytes ready for LPUSH.
    """
    event: dict[str, object] = {
        "agent_name": agent_name,
        "tool_name": tool_name,
        "method": method,
        "action": action,
        "payload_bytes": payload_bytes,
        "response_bytes": response_bytes,
        "duration_ms": duration_ms,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "target_server": target_server,
    }
    if arguments_hash:
        event["arguments_hash"] = arguments_hash
    if arguments_size_bytes:
        event["arguments_size_bytes"] = arguments_size_bytes
    if is_list_tools:
        event["is_list_tools"] = True
    return orjson.dumps(event)
