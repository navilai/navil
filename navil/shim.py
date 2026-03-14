"""Navil Stdio Shim — transparent MCP security wrapper for stdio-based servers.

Sits between an MCP client (e.g., OpenClaw) and a real MCP server by wrapping
the server's stdin/stdout.  The client spawns ``navil shim`` instead of the
real server binary; Navil spawns the real server as a child process and
intercepts every JSON-RPC 2.0 message in both directions.

Usage:
    navil shim --cmd "npx -y @modelcontextprotocol/server-filesystem /tmp"
    navil shim --cmd "python -m my_mcp_server" --agent my-agent --policy policy.yaml

Architecture:
    MCP Client (stdin) → [Navil Shim] → Real MCP Server (stdin)
    MCP Client (stdout) ← [Navil Shim] ← Real MCP Server (stdout)
                               │
                         Policy check, rate limit, anomaly detection,
                         telemetry → Redis queue (if available)
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import sys
import time
from typing import Any

import orjson

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.credential_manager import CredentialManager
from navil.policy_engine import PolicyEngine
from navil.proxy import MCPSecurityProxy
from navil.telemetry_event import TELEMETRY_QUEUE, build_telemetry_event

logger = logging.getLogger(__name__)


# —— Message framing helpers ———————————————————————————————————————


async def _detect_and_read_message(stream: asyncio.StreamReader) -> bytes | None:
    """Auto-detect framing and read one complete JSON-RPC message.

    Supports both NDJSON (newline-delimited) and Content-Length header
    framing (used by some MCP implementations like the official TS SDK).
    """
    # Peek at the first line
    try:
        line = await stream.readline()
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    if not line:
        return None

    stripped = line.strip()

    # —— Content-Length framing ————————————————————————————————
    if stripped.lower().startswith(b"content-length:"):
        length_str = stripped.split(b":", 1)[1].strip()
        try:
            content_length = int(length_str)
        except ValueError:
            logger.warning("Bad Content-Length header: %s", stripped)
            return None

        # Read until blank line (header/body separator)
        while True:
            header_line = await stream.readline()
            if not header_line or header_line.strip() == b"":
                break

        # Read exactly content_length bytes
        try:
            body = await stream.readexactly(content_length)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None
        return body

    # —— NDJSON framing (bare JSON line) ——————————————————————
    if stripped:
        return stripped

    # Empty line → skip and try again
    return await _detect_and_read_message(stream)


def _write_message(stream: asyncio.StreamWriter | Any, data: bytes) -> None:
    """Write a JSON-RPC message with Content-Length framing.

    Uses Content-Length headers for compatibility with the broadest
    range of MCP clients and servers.
    """
    header = f"Content-Length: {len(data)}\r\n\r\n".encode()
    stream.write(header + data)


# —— Shim core —————————————————————————————————————————————————————


class StdioShim:
    """Transparent security shim for stdio-based MCP servers.

    Spawns the real MCP server as a child process and intercepts all
    JSON-RPC messages in both directions, applying Navil's full security
    stack (sanitization, policy, anomaly detection, telemetry).
    """

    def __init__(
        self,
        cmd: list[str],
        agent_name: str = "stdio-agent",
        policy_engine: PolicyEngine | None = None,
        anomaly_detector: BehavioralAnomalyDetector | None = None,
        credential_manager: CredentialManager | None = None,
        redis_url: str | None = None,
    ) -> None:
        self.cmd = cmd
        self.agent_name = agent_name
        self.policy_engine = policy_engine or PolicyEngine()
        self.detector = anomaly_detector or BehavioralAnomalyDetector()
        self.credential_manager = credential_manager or CredentialManager()
        self.redis_url = redis_url or os.environ.get("NAVIL_REDIS_URL")

        self._redis: Any | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._target_server = f"stdio://{' '.join(cmd)}"
        self._running = False

        self.stats = {
            "total_requests": 0,
            "blocked": 0,
            "forwarded": 0,
            "alerts_generated": 0,
            "notifications_forwarded": 0,
        }

    async def _init_redis(self) -> None:
        """Try to connect to Redis for telemetry.  Non-fatal if unavailable."""
        if not self.redis_url:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(self.redis_url)
            await self._redis.ping()
            logger.info("Connected to Redis at %s", self.redis_url)
        except Exception as e:
            logger.info("Redis unavailable (%s) — running without telemetry queue", e)
            self._redis = None

    async def _spawn_server(self) -> asyncio.subprocess.Process:
        """Spawn the real MCP server as a child process."""
        logger.info("Spawning MCP server: %s", " ".join(self.cmd))
        process = await asyncio.create_subprocess_exec(
            *self.cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return process

    # —— Security checks (reuses MCPSecurityProxy logic) ——————

    def _check_request(self, body: bytes) -> tuple[bool, bytes, dict[str, Any] | None]:
        """Run pre-execution security checks on a client→server message.

        Returns (allowed, sanitized_body, error_response_or_None).
        """
        # Sanitize
        try:
            body = MCPSecurityProxy.sanitize_request(body)
        except ValueError as e:
            err = self._jsonrpc_error(-32700, f"Request rejected: {e}", None)
            return False, body, err

        # Parse JSON-RPC
        try:
            parsed = MCPSecurityProxy.parse_jsonrpc(body)
        except ValueError as e:
            err = self._jsonrpc_error(-32700, f"Parse error: {e}", None)
            return False, body, err

        req_id = parsed["id"]
        method = parsed["method"]

        # Only enforce policy on tools/call
        if method == "tools/call":
            tool_name, action, _arguments = MCPSecurityProxy.extract_tool_info(parsed)

            # Policy check
            if hasattr(self.policy_engine, "check_tool_call"):
                decision = self.policy_engine.check_tool_call(
                    self.agent_name, tool_name, action
                )
                # check_tool_call returns (allowed: bool, reason: str)
                if isinstance(decision, tuple):
                    is_allowed, _deny_reason = decision
                elif hasattr(decision, "decision"):
                    is_allowed = decision.decision.value != "DENY"
                else:
                    is_allowed = True

                if not is_allowed:
                    self.stats["blocked"] += 1
                    err = self._jsonrpc_error(
                        -32001, f"Blocked by policy: {tool_name}", req_id
                    )
                    return False, body, err

            # Fast anomaly gate (sync context).
            # check_fast is async (needs Redis), so we do a lightweight
            # local check: scan recent alerts for CRITICAL on this agent.
            # Full async detection runs in _record_telemetry after response.
            try:
                recent_alerts = self.detector.get_alerts(
                    agent_name=self.agent_name
                )[-10:]
                has_critical = any(
                    (a.get("severity") if isinstance(a, dict) else getattr(a, "severity", ""))
                    == "CRITICAL"
                    for a in recent_alerts
                )
                if has_critical:
                    allowed, reason = False, "Agent blocked due to critical anomaly"
                else:
                    allowed, reason = True, ""
            except Exception:
                allowed, reason = True, ""

            if not allowed:
                self.stats["blocked"] += 1
                err = self._jsonrpc_error(
                    -32002, f"Blocked by anomaly detector: {reason}", req_id
                )
                return False, body, err

        return True, body, None

    async def _record_telemetry(
        self,
        method: str,
        tool_name: str,
        action: str,
        arguments: dict[str, Any],
        duration_ms: int,
        response_bytes: int,
        success: bool,
    ) -> None:
        """Record telemetry and run anomaly detection (background, non-blocking)."""
        try:
            args_bytes = orjson.dumps(arguments, option=orjson.OPT_SORT_KEYS)
            args_hash = hashlib.sha256(args_bytes).hexdigest()

            if self._redis is not None:
                event_bytes = build_telemetry_event(
                    agent_name=self.agent_name,
                    tool_name=tool_name,
                    method=method,
                    action="FORWARDED",
                    payload_bytes=len(args_bytes),
                    response_bytes=response_bytes,
                    duration_ms=duration_ms,
                    target_server=self._target_server,
                    arguments_hash=args_hash,
                    arguments_size_bytes=len(args_bytes),
                    is_list_tools=(method == "tools/list"),
                )
                await self._redis.lpush(TELEMETRY_QUEUE, event_bytes)
                return

            # No Redis — run detection in-process
            alert_count_before = len(self.detector.alerts)
            await self.detector.record_invocation_async(
                agent_name=self.agent_name,
                tool_name=tool_name,
                action=action,
                duration_ms=duration_ms,
                data_accessed_bytes=response_bytes,
                success=success,
                target_server=self._target_server,
                arguments_hash=args_hash,
                arguments_size_bytes=len(args_bytes),
                response_size_bytes=response_bytes,
                is_list_tools=(method == "tools/list"),
            )
            new_alerts = len(self.detector.alerts) - alert_count_before
            if new_alerts > 0:
                self.stats["alerts_generated"] += new_alerts
        except Exception:
            logger.debug("Telemetry recording failed", exc_info=True)

    # —— Main bidirectional I/O loop ——————————————————————————

    async def run(self) -> int:
        """Run the shim: spawn server, bridge stdin/stdout with security checks."""
        await self._init_redis()
        self._process = await self._spawn_server()
        self._running = True

        assert self._process.stdin is not None
        assert self._process.stdout is not None

        # Wrap raw stdin as an async stream reader
        client_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(client_reader)
        loop = asyncio.get_event_loop()
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        # Client stdout writer (we write responses back to the MCP client)
        client_transport, client_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer
        )
        client_writer = asyncio.StreamWriter(
            client_transport, client_protocol, None, loop
        )

        server_reader = self._process.stdout
        server_writer = self._process.stdin

        # Stderr passthrough (log server stderr for debugging)
        stderr_task = asyncio.create_task(
            self._pipe_stderr(self._process.stderr)
        )

        # Two concurrent tasks: client→server and server→client
        client_to_server = asyncio.create_task(
            self._client_to_server(client_reader, server_writer, client_writer)
        )
        server_to_client = asyncio.create_task(
            self._server_to_client(server_reader, client_writer)
        )

        # Wait for either direction to finish (usually means EOF / process exit)
        done, pending = await asyncio.wait(
            [client_to_server, server_to_client, stderr_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cleanup
        self._running = False
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        # Terminate child if still running
        if self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()

        if self._redis:
            await self._redis.close()

        return self._process.returncode or 0

    async def _client_to_server(
        self,
        client_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter | Any,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Forward messages from MCP client → real MCP server, with security checks."""
        # Track pending requests for response correlation
        self._pending_requests: dict[Any, dict[str, Any]] = {}

        while self._running:
            msg = await _detect_and_read_message(client_reader)
            if msg is None:
                break  # EOF from client

            self.stats["total_requests"] += 1
            start = time.time()

            # Parse to extract method + request ID for correlation
            try:
                parsed = orjson.loads(msg)
            except orjson.JSONDecodeError:
                # Can't parse → forward raw and hope for the best
                _write_message(server_writer, msg)
                await server_writer.drain()
                continue

            req_id = parsed.get("id")
            method = parsed.get("method", "")

            # Run security checks
            allowed, sanitized, error_response = self._check_request(msg)

            if not allowed and error_response is not None:
                # Send error back to client, don't forward to server
                error_bytes = orjson.dumps(error_response)
                _write_message(client_writer, error_bytes)
                await client_writer.drain()
                logger.info(
                    "BLOCKED %s (id=%s): %s",
                    method,
                    req_id,
                    error_response.get("error", {}).get("message", ""),
                )
                continue

            # Track this request for response correlation
            if req_id is not None and method:
                tool_name = ""
                arguments: dict[str, Any] = {}
                if method == "tools/call":
                    tool_name, _, arguments = MCPSecurityProxy.extract_tool_info(
                        {"method": method, "params": parsed.get("params", {})}
                    )
                self._pending_requests[req_id] = {
                    "method": method,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "start": start,
                }

            # Forward to real server
            _write_message(server_writer, sanitized)
            await server_writer.drain()
            self.stats["forwarded"] += 1

    async def _server_to_client(
        self,
        server_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Forward messages from real MCP server → MCP client, with telemetry."""
        while self._running:
            msg = await _detect_and_read_message(server_reader)
            if msg is None:
                break  # EOF from server (process exited)

            # Parse to check if this is a response or notification
            try:
                parsed = orjson.loads(msg)
            except orjson.JSONDecodeError:
                # Can't parse → forward raw
                _write_message(client_writer, msg)
                await client_writer.drain()
                continue

            req_id = parsed.get("id")

            # If it has an ID and matches a pending request → it's a response
            if req_id is not None and hasattr(self, "_pending_requests"):
                pending = self._pending_requests.pop(req_id, None)
                if pending:
                    duration_ms = int((time.time() - pending["start"]) * 1000)
                    method = pending["method"]
                    tool_name = pending["tool_name"]
                    arguments = pending["arguments"]
                    success = "error" not in parsed

                    # Track tools/list responses for supply chain detection
                    if method == "tools/list":
                        try:
                            result = parsed.get("result", {})
                            tools = result.get("tools", []) if isinstance(result, dict) else []
                            tool_names = [t.get("name", "") for t in tools if isinstance(t, dict)]
                            if tool_names:
                                self.detector.register_server_tools(
                                    self._target_server, tool_names
                                )
                        except Exception:
                            pass

                    # Background telemetry (non-blocking)
                    asyncio.create_task(
                        self._record_telemetry(
                            method=method,
                            tool_name=tool_name or "__tools_list__",
                            action=method,
                            arguments=arguments,
                            duration_ms=duration_ms,
                            response_bytes=len(msg),
                            success=success,
                        )
                    )
            else:
                # No ID or not in pending → notification from server
                self.stats["notifications_forwarded"] += 1

            # Forward to client
            _write_message(client_writer, msg)
            await client_writer.drain()

    async def _pipe_stderr(self, stderr: asyncio.StreamReader | None) -> None:
        """Pipe child process stderr to our own stderr for debugging."""
        if stderr is None:
            return
        while True:
            line = await stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    # —— Helpers ——————————————————————————————————————————————

    @staticmethod
    def _jsonrpc_error(code: int, message: str, req_id: Any) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }


# —— Entry point ———————————————————————————————————————————————————


async def run_shim(
    cmd: list[str],
    agent_name: str = "stdio-agent",
    policy_path: str | None = None,
    redis_url: str | None = None,
) -> int:
    """Entry point for ``navil shim``."""
    from navil.anomaly_detector import BehavioralAnomalyDetector
    from navil.credential_manager import CredentialManager
    from navil.policy_engine import PolicyEngine

    policy_engine = PolicyEngine()
    if policy_path:
        from pathlib import Path
        policy_engine.policy_file = Path(policy_path)
        policy_engine._load_policy()

    detector = BehavioralAnomalyDetector()
    credential_manager = CredentialManager()

    shim = StdioShim(
        cmd=cmd,
        agent_name=agent_name,
        policy_engine=policy_engine,
        anomaly_detector=detector,
        credential_manager=credential_manager,
        redis_url=redis_url,
    )

    return await shim.run()
