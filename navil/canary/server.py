"""MCP Canary Server — standalone canary MCP server.

A self-contained, extractable MCP honeypot server with minimal dependencies.
Implements JSON-RPC 2.0 over HTTP, compatible with the MCP protocol.

This module is designed to be independently deployable with zero navil-core
imports.  It bundles its own profile data, request handling, and interaction
recording so that it can be extracted into a standalone pip package.

Usage::

    # Standalone
    from navil.canary.server import CanaryServer
    server = CanaryServer(profile="dev_tools", port=8080)
    server.start()          # blocking
    server.start_background()  # threaded

    # Context manager
    with CanaryServer(profile="dev_tools", port=0) as srv:
        print(f"Canary running at {srv.url}")
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger(__name__)


# ── Interaction Record ──────────────────────────────────────────


class CanaryRecord:
    """A single recorded interaction with the canary.

    Captures tool name, arguments, source IP, headers, and timing.
    Designed to be serializable to JSON for analysis or contribution.
    """

    __slots__ = (
        "timestamp",
        "tool_name",
        "arguments",
        "source_ip",
        "request_headers",
        "method",
        "raw_body",
    )

    def __init__(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        source_ip: str,
        request_headers: dict[str, str],
        method: str = "tools/call",
        raw_body: str = "",
    ) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.tool_name = tool_name
        self.arguments = arguments
        self.source_ip = source_ip
        self.request_headers = request_headers
        self.method = method
        self.raw_body = raw_body

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (excludes raw_body for safety)."""
        return {
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "source_ip": self.source_ip,
            "request_headers": self.request_headers,
            "method": self.method,
        }


# ── Interaction Collector ───────────────────────────────────────


class CanaryCollector:
    """Thread-safe collector that buffers canary interaction records.

    Designed to be lightweight and self-contained with no external
    dependencies (no Redis, no ML).

    Args:
        max_records: Maximum records to keep in the ring buffer.
    """

    def __init__(self, max_records: int = 10000) -> None:
        self._records: deque[dict[str, Any]] = deque(maxlen=max_records)
        self._lock = threading.Lock()
        self._total_count: int = 0

    def record(self, canary_record: CanaryRecord) -> None:
        """Record a canary interaction."""
        entry = canary_record.to_dict()
        with self._lock:
            self._records.append(entry)
            self._total_count += 1

    @property
    def records(self) -> list[dict[str, Any]]:
        """Return a snapshot of all buffered records."""
        with self._lock:
            return list(self._records)

    @property
    def total_count(self) -> int:
        """Total interactions recorded (including evicted)."""
        return self._total_count

    @property
    def current_count(self) -> int:
        """Number of records currently in buffer."""
        with self._lock:
            return len(self._records)

    def get_records_since(self, since: str) -> list[dict[str, Any]]:
        """Get records collected after the given ISO timestamp."""
        with self._lock:
            return [r for r in self._records if r["timestamp"] > since]

    def get_tool_call_counts(self) -> dict[str, int]:
        """Get per-tool call count summary."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records:
                tool = r["tool_name"]
                counts[tool] = counts.get(tool, 0) + 1
        return counts

    def get_source_ip_counts(self) -> dict[str, int]:
        """Get per-source-IP call count summary."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records:
                ip = r["source_ip"]
                counts[ip] = counts.get(ip, 0) + 1
        return counts

    def export_json(self) -> str:
        """Export all buffered records as a JSON string."""
        return json.dumps(self.records, indent=2)

    def clear(self) -> int:
        """Clear all records. Returns the number of records cleared."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
            return count


# ── Canary MCP Server ──────────────────────────────────────────


class CanaryServer:
    """Standalone canary MCP server exposing decoy tools.

    Implements the MCP JSON-RPC 2.0 protocol over HTTP.  All tool call
    attempts are logged to the built-in collector.  Responses are
    realistic-looking but contain only fake/dummy data.

    This server is fully self-contained and can be extracted from the
    navil package for independent deployment.

    Args:
        profile: Profile name string or a dict of tool definitions.
            If a string, loads from the built-in profile catalog.
        host: Bind address (default: 0.0.0.0).
        port: Bind port (default: 8080, use 0 for auto-assign).
        collector: Optional CanaryCollector; one is created if not provided.
        max_records: Max records for the auto-created collector.
    """

    def __init__(
        self,
        profile: str | dict[str, Any] = "dev_tools",
        host: str = "0.0.0.0",
        port: int = 8080,
        collector: CanaryCollector | None = None,
        max_records: int = 10000,
    ) -> None:
        self.host = host
        self.port = port
        self.collector = collector or CanaryCollector(max_records=max_records)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Load tool definitions
        if isinstance(profile, dict):
            self.tools = profile
            self.profile_name = "custom"
        else:
            self.tools = self._load_profile(profile)
            self.profile_name = profile

    @staticmethod
    def _load_profile(name: str) -> dict[str, Any]:
        """Load tool definitions from the canary config module.

        Falls back to an empty tool set if the profile is not found.
        """
        try:
            from navil.canary.config import get_profile_tools
            return get_profile_tools(name)
        except (ImportError, KeyError):
            logger.warning("Profile %r not found, using empty tool set", name)
            return {}

    # ── MCP Protocol ────────────────────────────────────────────

    @property
    def tool_list(self) -> list[dict[str, str]]:
        """Return MCP-compatible tools/list response items."""
        return [
            {"name": name, "description": info.get("description", "")}
            for name, info in self.tools.items()
        ]

    def handle_request(
        self,
        body: dict[str, Any],
        source_ip: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Process a JSON-RPC 2.0 MCP request.

        Args:
            body: Parsed JSON-RPC request body.
            source_ip: Client IP address.
            headers: HTTP request headers.

        Returns:
            JSON-RPC 2.0 response dict.
        """
        method = body.get("method", "")
        params = body.get("params", {})
        req_id = body.get("id", 1)

        if method == "tools/list":
            record = CanaryRecord(
                tool_name="__tools_list__",
                arguments={},
                source_ip=source_ip,
                request_headers=headers,
                method=method,
            )
            self.collector.record(record)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.tool_list},
            }

        elif method == "tools/call":
            tool_name = params.get("name", params.get("tool", "unknown"))
            arguments = params.get("arguments", params.get("args", {}))

            record = CanaryRecord(
                tool_name=tool_name,
                arguments=arguments,
                source_ip=source_ip,
                request_headers=headers,
                method=method,
                raw_body=json.dumps(body),
            )
            self.collector.record(record)

            # Return realistic response from profile
            tool_info = self.tools.get(tool_name, {})
            fake_response = tool_info.get("response", {"status": "ok", "data": "..."})

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": fake_response,
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    # ── Server Lifecycle ────────────────────────────────────────

    def start(self) -> None:
        """Start the canary server (blocking)."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        logger.info(
            "Canary server started on %s:%d (profile=%s, tools=%d)",
            self.host,
            self.port,
            self.profile_name,
            len(self.tools),
        )
        self._server.serve_forever()

    def start_background(self) -> None:
        """Start the canary server in a background thread."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(
            "Canary server started in background on %s:%d (profile=%s)",
            self.host,
            self.port,
            self.profile_name,
        )

    def stop(self) -> None:
        """Stop the canary server."""
        if self._server:
            self._server.shutdown()
            if self._thread:
                self._thread.join(timeout=5)
            logger.info("Canary server stopped")

    @property
    def url(self) -> str:
        """Base URL of the running server."""
        return f"http://{self.host}:{self.port}"

    @property
    def records(self) -> list[dict[str, Any]]:
        """Get all recorded interactions."""
        return self.collector.records

    def __enter__(self) -> CanaryServer:
        self.start_background()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    # ── HTTP Handler ────────────────────────────────────────────

    def _make_handler(self) -> type:
        """Create an HTTP request handler class bound to this server."""
        server_ref = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                content_len = int(self.headers.get("Content-Length", 0))
                body_bytes = self.rfile.read(content_len) if content_len else b""

                try:
                    body = json.loads(body_bytes) if body_bytes else {}
                except (json.JSONDecodeError, ValueError):
                    body = {}

                source_ip = self.client_address[0]
                headers = {k: v for k, v in self.headers.items()}

                response = server_ref.handle_request(body, source_ip, headers)
                payload = json.dumps(response).encode()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                """Suppress default stderr logging."""
                pass

        return _Handler
