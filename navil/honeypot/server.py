"""Honeypot MCP Server -- a configurable MCP server exposing decoy tools.

Implements JSON-RPC 2.0 over HTTP, compatible with the MCP protocol.
All tool call attempts are logged with full request details to a collector.

Usage::

    from navil.honeypot.server import HoneypotMCPServer
    server = HoneypotMCPServer(profile="dev_tools", port=8080)
    server.start()  # blocks; use start_background() for threading
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger(__name__)


class HoneypotRecord:
    """A single recorded interaction with the honeypot."""

    __slots__ = (
        "timestamp",
        "tool_name",
        "arguments",
        "source_ip",
        "user_agent",
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
        user_agent: str = "",
    ) -> None:
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.tool_name = tool_name
        self.arguments = arguments
        self.source_ip = source_ip
        self.user_agent = user_agent or request_headers.get("User-Agent", "")
        self.request_headers = request_headers
        self.method = method
        self.raw_body = raw_body

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_headers": self.request_headers,
            "method": self.method,
        }


class HoneypotMCPServer:
    """A decoy MCP server that logs all tool call attempts.

    Loads tool definitions from a profile module and returns realistic
    but fake responses to all tool calls.  Never executes any real
    operations -- all responses are sandboxed fakes.

    Args:
        profile: Profile name or a dict of tool definitions.
        host: Bind address.
        port: Bind port (0 = auto-assign).
        collector: Optional collector instance for structured logging.
    """

    def __init__(
        self,
        profile: str | dict[str, Any] = "dev_tools",
        host: str = "0.0.0.0",
        port: int = 0,
        collector: Any | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.collector = collector
        self._records: list[HoneypotRecord] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Load tool definitions from profile
        if isinstance(profile, dict):
            self.tools = profile
        else:
            self.tools = self._load_profile(profile)

        self.profile_name = profile if isinstance(profile, str) else "custom"

    @staticmethod
    def _load_profile(name: str) -> dict[str, Any]:
        """Load tool definitions from a profile module."""
        import importlib

        try:
            mod = importlib.import_module(f"navil.honeypot.profiles.{name}")
            return mod.TOOLS  # type: ignore[attr-defined]
        except (ImportError, AttributeError):
            logger.warning("Profile '%s' not found, using empty tool set", name)
            return {}

    @property
    def records(self) -> list[HoneypotRecord]:
        with self._lock:
            return list(self._records)

    @property
    def tool_list(self) -> list[dict[str, Any]]:
        """Return MCP-compatible tools/list response with inputSchema."""
        result = []
        for name, info in self.tools.items():
            entry: dict[str, Any] = {
                "name": name,
                "description": info.get("description", ""),
            }
            if "inputSchema" in info:
                entry["inputSchema"] = info["inputSchema"]
            result.append(entry)
        return result

    @property
    def tool_names(self) -> list[str]:
        """Return sorted list of tool names in this profile."""
        return sorted(self.tools.keys())

    def record_interaction(self, record: HoneypotRecord) -> None:
        """Record an interaction and forward to collector if available."""
        with self._lock:
            self._records.append(record)

        if self.collector is not None:
            self.collector.record(record)

        logger.info(
            "Honeypot interaction: tool=%s source=%s user_agent=%s",
            record.tool_name,
            record.source_ip,
            record.user_agent,
        )

    def handle_request(
        self, body: dict[str, Any], source_ip: str, headers: dict[str, str]
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

        if method == "initialize":
            # MCP initialization handshake
            record = HoneypotRecord(
                tool_name="__initialize__",
                arguments=params,
                source_ip=source_ip,
                request_headers=headers,
                method=method,
            )
            self.record_interaction(record)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": f"honeypot-{self.profile_name}",
                        "version": "1.0.0",
                    },
                },
            }

        if method == "tools/list":
            record = HoneypotRecord(
                tool_name="__tools_list__",
                arguments={},
                source_ip=source_ip,
                request_headers=headers,
                method=method,
            )
            self.record_interaction(record)

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.tool_list},
            }

        elif method == "tools/call":
            tool_name = params.get("name", params.get("tool", "unknown"))
            arguments = params.get("arguments", params.get("args", {}))

            record = HoneypotRecord(
                tool_name=tool_name,
                arguments=arguments,
                source_ip=source_ip,
                request_headers=headers,
                method=method,
                raw_body=json.dumps(body),
            )
            self.record_interaction(record)

            # Return realistic response from profile -- never execute anything real
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

    def start(self) -> None:
        """Start the honeypot server (blocking)."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        logger.info(
            "Honeypot server started on %s:%d (profile=%s)",
            self.host,
            self.port,
            self.profile_name,
        )
        self._server.serve_forever()

    def start_background(self) -> None:
        """Start the honeypot server in a background thread."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(
            "Honeypot server started in background on %s:%d (profile=%s)",
            self.host,
            self.port,
            self.profile_name,
        )

    def stop(self) -> None:
        """Stop the honeypot server."""
        if self._server:
            self._server.shutdown()
            if self._thread:
                self._thread.join(timeout=5)
            logger.info("Honeypot server stopped")

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> HoneypotMCPServer:
        self.start_background()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def _make_handler(self) -> type:
        """Create a request handler class bound to this server instance."""
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


if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO)
    profile = os.environ.get("HONEYPOT_PROFILE", "dev_tools")
    port = int(os.environ.get("HONEYPOT_PORT", "8080"))

    server = HoneypotMCPServer(
        profile=profile,
        port=port,
    )
    logger.info("Starting honeypot: profile=%s port=%d", profile, port)
    server.start()
