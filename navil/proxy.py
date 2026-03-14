"""MCP Security Proxy — real-time JSON-RPC 2.0 reverse proxy.

Sits between AI agents and MCP servers, intercepting every tool call
for policy enforcement and anomaly detection.

Usage (standalone):
    navil proxy start --target http://localhost:3000 --port 9090

Architecture:
    Agent → POST /mcp → Navil Proxy → httpx → MCP Server
                            ↓
                    Pre-execution:  policy check, rate limit, auth
                    Post-execution: record invocation, anomaly detection
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx
import orjson

from navil.telemetry_event import TELEMETRY_QUEUE, build_telemetry_event

try:
    from starlette.requests import Request as _StarletteRequest
except ModuleNotFoundError:  # starlette is optional (proxy extras)
    _StarletteRequest = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


class MCPSecurityProxy:
    """Real-time MCP security proxy.

    Intercepts JSON-RPC 2.0 messages (tools/call, tools/list) and applies
    security checks before forwarding to the upstream MCP server.
    """

    MAX_TRAFFIC_LOG = 1000
    MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB hard ceiling
    MAX_JSON_DEPTH = 10

    def __init__(
        self,
        target_url: str,
        policy_engine: Any,
        anomaly_detector: Any,
        credential_manager: Any,
        require_auth: bool = True,
        cloud_client: Any | None = None,
        redis_client: Any | None = None,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.policy_engine = policy_engine
        self.detector = anomaly_detector
        self.credential_manager = credential_manager
        self.require_auth = require_auth
        self.cloud_client = cloud_client  # NavilCloudClient for telemetry
        self.redis_client = redis_client  # async Redis for LPUSH telemetry path

        self.http_client: httpx.AsyncClient | None = None

        self.traffic_log: deque[dict[str, Any]] = deque(maxlen=self.MAX_TRAFFIC_LOG)
        self.stats = {
            "total_requests": 0,
            "blocked": 0,
            "alerts_generated": 0,
            "forwarded": 0,
        }
        self.start_time = time.time()

    async def init_client(self) -> None:
        """Initialize the shared httpx.AsyncClient (call on app startup)."""
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def close_client(self) -> None:
        """Close the shared httpx.AsyncClient (call on app shutdown)."""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None

    # ── Request Sanitization ─────────────────────────────────

    @classmethod
    def sanitize_request(cls, body: bytes) -> bytes:
        """Sanitize raw request bytes before any processing.

        1. Reject payloads over MAX_PAYLOAD_BYTES (413).
        2. Parse + re-serialize via orjson to strip whitespace padding.
        3. Reject nesting depth > MAX_JSON_DEPTH (JSON bomb defence).

        Returns the compacted bytes on success.
        Raises ValueError with a descriptive message on rejection.
        """
        # ── Byte limit ────────────────────────────────────────
        if len(body) > cls.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload too large: {len(body)} bytes " f"(limit {cls.MAX_PAYLOAD_BYTES} bytes)"
            )

        # ── Parse & compact ───────────────────────────────────
        try:
            data = orjson.loads(body)
        except orjson.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

        # ── Depth check ───────────────────────────────────────
        depth = cls._json_depth(data)
        if depth > cls.MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting depth {depth} exceeds limit {cls.MAX_JSON_DEPTH}")

        # Re-serialize tightly (no whitespace, no padding)
        return orjson.dumps(data)

    @staticmethod
    def _json_depth(obj: Any, _current: int = 1) -> int:
        """Return the maximum nesting depth of a JSON-compatible object."""
        if isinstance(obj, dict):
            if not obj:
                return _current
            return max(MCPSecurityProxy._json_depth(v, _current + 1) for v in obj.values())
        if isinstance(obj, list):
            if not obj:
                return _current
            return max(MCPSecurityProxy._json_depth(v, _current + 1) for v in obj)
        return _current

    # ── JSON-RPC Parsing ──────────────────────────────────────

    @staticmethod
    def parse_jsonrpc(body: bytes) -> dict[str, Any]:
        """Parse a JSON-RPC 2.0 request envelope.

        Returns dict with keys: method, params, id, raw.
        Raises ValueError on invalid JSON-RPC.
        """
        try:
            data = orjson.loads(body)
        except orjson.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("JSON-RPC request must be an object")

        return {
            "method": data.get("method", ""),
            "params": data.get("params", {}),
            "id": data.get("id"),
            "raw": data,
        }

    @staticmethod
    def extract_tool_info(parsed: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        """Extract tool name, action, and arguments from a tools/call request.

        Returns (tool_name, action, arguments).
        """
        params = parsed.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        # MCP doesn't have a formal "action" field — derive from method
        action = parsed.get("method", "tools/call")
        return tool_name, action, arguments

    # ── Identity ──────────────────────────────────────────────

    def extract_agent_name(self, headers: dict[str, str]) -> str | None:
        """Extract agent identity from request headers.

        Checks Authorization header (Bearer JWT) first. If a Bearer token is
        present but fails verification, returns None — never falls back to
        X-Agent-Name to prevent auth bypass.

        X-Agent-Name is only honoured when no Bearer token was attempted and
        require_auth is False.
        """
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            # Try JWT verification first
            try:
                payload = self.credential_manager.verify_credential(token)
                if payload and "agent_name" in payload:
                    return payload["agent_name"]
            except Exception:
                pass
            # Fallback: match token against stored credentials (constant-time comparison)
            if hasattr(self.credential_manager, "credentials"):
                for cred in self.credential_manager.credentials.values():
                    status = cred.status
                    status_str = status.value if hasattr(status, "value") else str(status)
                    try:
                        token_match = hmac.compare_digest(
                            cred.token.encode(), token.encode()
                        )
                    except Exception:
                        token_match = False
                    if token_match and status_str == "ACTIVE":
                        return cred.agent_name
            # Bearer was attempted but failed — do NOT fall through to X-Agent-Name
            return None

        # No Bearer token: only honour X-Agent-Name when auth is not required
        if not self.require_auth:
            return headers.get("x-agent-name")
        return None

    # ── Core Request Handler ──────────────────────────────────

    async def handle_jsonrpc(
        self, body: bytes, headers: dict[str, str]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Handle an incoming JSON-RPC request.

        Returns (json_rpc_response, upstream_headers) tuple.
        """
        self.stats["total_requests"] += 1
        start = time.time()

        # Sanitize raw bytes (size limit, whitespace strip, depth check)
        try:
            body = self.sanitize_request(body)
        except ValueError as e:
            return self._jsonrpc_error(-32700, f"Request rejected: {e}", None), {}

        # Parse JSON-RPC
        try:
            parsed = self.parse_jsonrpc(body)
        except ValueError as e:
            return self._jsonrpc_error(-32700, f"Parse error: {e}", None), {}

        req_id = parsed["id"]
        method = parsed["method"]

        # Extract identity
        agent_name = self.extract_agent_name(headers)
        if self.require_auth and not agent_name:
            self.stats["blocked"] += 1
            self._log_traffic(agent_name, method, "", "AUTH_REQUIRED", 0, 0)
            return self._jsonrpc_error(-32003, "Authentication required", req_id), {}

        agent_name = agent_name or "anonymous"

        # Pre-execution checks (only for tools/call)
        if method == "tools/call":
            tool_name, action, arguments = self.extract_tool_info(parsed)

            # Policy check
            if hasattr(self.policy_engine, "check_tool_call"):
                decision = self.policy_engine.check_tool_call(agent_name, tool_name, action)
                # check_tool_call returns tuple[bool, str] — (allowed, reason)
                if isinstance(decision, tuple):
                    allowed_by_policy, deny_reason = decision
                elif hasattr(decision, "decision"):
                    allowed_by_policy = decision.decision.value != "DENY"
                    deny_reason = str(decision)
                else:
                    allowed_by_policy = str(decision) != "DENY"
                    deny_reason = str(decision)

                if not allowed_by_policy:
                    self.stats["blocked"] += 1
                    duration_ms = int((time.time() - start) * 1000)
                    self._log_traffic(agent_name, method, tool_name, "DENIED", duration_ms, 0)
                    return self._jsonrpc_error(
                        -32001,
                        f"Blocked by policy: {deny_reason}",
                        req_id,
                    ), {}

            # O(1) fast-path anomaly gate (pre-computed thresholds)
            allowed, reason = await self.detector.check_fast(agent_name, len(body))
            if not allowed:
                self.stats["blocked"] += 1
                duration_ms = int((time.time() - start) * 1000)
                self._log_traffic(agent_name, method, tool_name, "ANOMALY_BLOCKED", duration_ms, 0)
                msg = f"Blocked by anomaly detector: {reason}"
                return self._jsonrpc_error(-32002, msg, req_id), {}

            # Forward to upstream
            response_data, response_bytes, upstream_hdrs = await self._forward(body, headers)
            duration_ms = int((time.time() - start) * 1000)

            self.stats["forwarded"] += 1
            self._log_traffic(agent_name, method, tool_name, "ALLOWED", duration_ms, response_bytes)

            # Heavy anomaly detection + telemetry → background task
            asyncio.create_task(
                self._background_record(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    action=action,
                    arguments=arguments,
                    duration_ms=duration_ms,
                    response_data=response_data,
                    response_bytes=response_bytes,
                )
            )

            return response_data, upstream_hdrs

        elif method == "tools/list":
            # Forward tools/list and track registered tools
            response_data, response_bytes, upstream_hdrs = await self._forward(body, headers)
            duration_ms = int((time.time() - start) * 1000)

            # Extract tool names from response for supply chain tracking
            try:
                result = response_data.get("result", {})
                tools = result.get("tools", []) if isinstance(result, dict) else []
                tool_names = [t.get("name", "") for t in tools if isinstance(t, dict)]
                if tool_names:
                    self.detector.register_server_tools(self.target_url, tool_names)
            except Exception:
                pass

            self.stats["forwarded"] += 1
            self._log_traffic(agent_name, method, "", "ALLOWED", duration_ms, response_bytes)

            # Background: reconnaissance detection
            asyncio.create_task(
                self._background_record_list(
                    agent_name=agent_name,
                    duration_ms=duration_ms,
                    response_data=response_data,
                    response_bytes=response_bytes,
                )
            )

            return response_data, upstream_hdrs

        else:
            # Forward all other methods transparently
            response_data, response_bytes, upstream_hdrs = await self._forward(body, headers)
            duration_ms = int((time.time() - start) * 1000)
            self.stats["forwarded"] += 1
            self._log_traffic(agent_name, method, "", "FORWARDED", duration_ms, response_bytes)
            return response_data, upstream_hdrs

    # ── Background Heavy Detection ─────────────────────────────

    async def _background_record(
        self,
        agent_name: str,
        tool_name: str,
        action: str,
        arguments: dict[str, Any],
        duration_ms: int,
        response_data: dict[str, Any],
        response_bytes: int,
    ) -> None:
        """Run heavy anomaly detection off the hot path."""
        try:
            args_bytes = orjson.dumps(arguments, option=orjson.OPT_SORT_KEYS)
            args_hash = hashlib.sha256(args_bytes).hexdigest()

            # Redis LPUSH path: enqueue canonical event and return early.
            # The TelemetryWorker will consume and run full detection.
            if self.redis_client is not None:
                event_bytes = build_telemetry_event(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    method="tools/call",
                    action="FORWARDED",
                    payload_bytes=len(args_bytes),
                    response_bytes=response_bytes,
                    duration_ms=duration_ms,
                    target_server=self.target_url,
                    arguments_hash=args_hash,
                    arguments_size_bytes=len(args_bytes),
                )
                await self.redis_client.lpush(TELEMETRY_QUEUE, event_bytes)
                return

            alert_count_before = len(self.detector.alerts)
            await self.detector.record_invocation_async(
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
                duration_ms=duration_ms,
                data_accessed_bytes=response_bytes,
                success="error" not in response_data,
                target_server=self.target_url,
                arguments_hash=args_hash,
                arguments_size_bytes=len(args_bytes),
                response_size_bytes=response_bytes,
                is_list_tools=False,
            )
            alert_count_after = len(self.detector.alerts)
            new_alerts = alert_count_after - alert_count_before
            if new_alerts > 0:
                self.stats["alerts_generated"] += new_alerts

            # Cloud telemetry (best-effort)
            if self.cloud_client:
                try:
                    asyncio.ensure_future(
                        self.cloud_client.record_event(
                            agent_name=agent_name,
                            tool_name=tool_name,
                            action=action,
                            duration_ms=duration_ms,
                            data_accessed_bytes=response_bytes,
                            success="error" not in response_data,
                        )
                    )
                    for a in list(self.detector.alerts)[-new_alerts:] if new_alerts > 0 else []:
                        a_dict = a if isinstance(a, dict) else a.__dict__
                        asyncio.ensure_future(
                            self.cloud_client.report_alert(
                                agent_name=a_dict.get("agent_name", agent_name),
                                anomaly_type=a_dict.get("anomaly_type", "UNKNOWN"),
                                severity=a_dict.get("severity", "MEDIUM"),
                                description=a_dict.get("description", ""),
                                evidence=a_dict.get("evidence", []),
                            )
                        )
                except Exception:
                    pass
        except Exception:
            logger.exception("Background anomaly detection failed for agent=%s", agent_name)

    async def _background_record_list(
        self,
        agent_name: str,
        duration_ms: int,
        response_data: dict[str, Any],
        response_bytes: int,
    ) -> None:
        """Run heavy anomaly detection for tools/list off the hot path."""
        try:
            # Redis LPUSH path: enqueue canonical event and return early.
            if self.redis_client is not None:
                event_bytes = build_telemetry_event(
                    agent_name=agent_name,
                    tool_name="__tools_list__",
                    method="tools/list",
                    action="tools/list",
                    response_bytes=response_bytes,
                    duration_ms=duration_ms,
                    target_server=self.target_url,
                    is_list_tools=True,
                )
                await self.redis_client.lpush(TELEMETRY_QUEUE, event_bytes)
                return

            alert_count_before = len(self.detector.alerts)
            await self.detector.record_invocation_async(
                agent_name=agent_name,
                tool_name="__tools_list__",
                action="tools/list",
                duration_ms=duration_ms,
                data_accessed_bytes=response_bytes,
                success="error" not in response_data,
                target_server=self.target_url,
                is_list_tools=True,
            )
            alert_count_after = len(self.detector.alerts)
            if alert_count_after > alert_count_before:
                self.stats["alerts_generated"] += alert_count_after - alert_count_before
        except Exception:
            logger.exception(
                "Background anomaly detection failed for tools/list agent=%s",
                agent_name,
            )

    # ── Upstream Forwarding ───────────────────────────────────

    async def _forward(
        self, body: bytes, headers: dict[str, str]
    ) -> tuple[dict[str, Any], int, dict[str, str]]:
        """Forward request to upstream MCP server via httpx.

        Returns (response_json, response_size_bytes, upstream_headers).
        """
        assert self.http_client is not None, "http_client not initialised — call init_client()"

        # Strip hop-by-hop headers
        forward_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in ("host", "connection", "transfer-encoding")
        }
        forward_headers["content-type"] = "application/json"
        forward_headers["accept"] = "application/json, text/event-stream"

        resp = await self.http_client.post(
            self.target_url,
            content=body,
            headers=forward_headers,
        )

        response_bytes = len(resp.content)
        content_type = resp.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            # Parse SSE: extract JSON from "data: {...}" lines
            response_data = self._parse_sse_response(resp.text)
        else:
            try:
                response_data = orjson.loads(resp.content)
            except orjson.JSONDecodeError:
                response_data = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Upstream returned non-JSON"},
                    "id": None,
                }

        # Collect headers to forward back (e.g. mcp-session-id)
        upstream_headers = {
            k: v for k, v in resp.headers.items() if k.lower() in ("mcp-session-id",)
        }

        return response_data, response_bytes, upstream_headers

    @staticmethod
    def _parse_sse_response(text: str) -> dict[str, Any]:
        """Extract JSON-RPC response from SSE stream (text/event-stream)."""
        for line in text.splitlines():
            if line.startswith("data: "):
                try:
                    return orjson.loads(line[6:])
                except orjson.JSONDecodeError:
                    continue
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": "No valid JSON in SSE response"},
            "id": None,
        }

    # ── Traffic Logging ───────────────────────────────────────

    def _log_traffic(
        self,
        agent: str | None,
        method: str,
        tool: str,
        decision: str,
        duration_ms: int,
        data_bytes: int,
    ) -> None:
        """Append entry to the traffic ring buffer."""
        self.traffic_log.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent": agent or "unknown",
                "method": method,
                "tool": tool,
                "decision": decision,
                "duration_ms": duration_ms,
                "data_bytes": data_bytes,
            }
        )

    def get_traffic(
        self,
        limit: int = 100,
        agent: str | None = None,
        blocked_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Get recent traffic log entries."""
        entries = list(self.traffic_log)

        if agent:
            entries = [e for e in entries if e["agent"] == agent]
        if blocked_only:
            entries = [e for e in entries if e["decision"] in ("DENIED", "AUTH_REQUIRED")]

        return list(reversed(entries[-limit:]))

    def get_status(self) -> dict[str, Any]:
        """Get proxy status summary."""
        return {
            "running": True,
            "target_url": self.target_url,
            "stats": dict(self.stats),
            "uptime_seconds": int(time.time() - self.start_time),
            "traffic_log_size": len(self.traffic_log),
        }

    # ── JSON-RPC Helpers ──────────────────────────────────────

    @staticmethod
    def _jsonrpc_error(code: int, message: str, req_id: Any) -> dict[str, Any]:
        """Build a JSON-RPC 2.0 error response."""
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }


def create_proxy_app(proxy: MCPSecurityProxy) -> Any:
    """Create a FastAPI app wrapping the proxy.

    The proxy runs on its own port (separate from the dashboard)
    so agents connect to it directly.
    """
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        await proxy.init_client()
        yield
        await proxy.close_client()

    app = FastAPI(
        title="Navil MCP Security Proxy",
        description="Real-time MCP security proxy with policy enforcement and anomaly detection",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.post("/mcp")
    async def handle_mcp(request: Request) -> JSONResponse:
        # Early byte-length check before reading the full body into memory
        content_length = int(request.headers.get("content-length", 0))
        if content_length > MCPSecurityProxy.MAX_PAYLOAD_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": (
                            f"Payload too large: {content_length} bytes "
                            f"(limit {MCPSecurityProxy.MAX_PAYLOAD_BYTES} bytes)"
                        ),
                    },
                    "id": None,
                },
            )
        body = await request.body()
        headers = dict(request.headers)
        result, upstream_headers = await proxy.handle_jsonrpc(body, headers)
        return JSONResponse(content=result, headers=upstream_headers)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return proxy.get_status()

    @app.get("/traffic")
    async def traffic(
        limit: int = 100,
        agent: str | None = None,
        blocked_only: bool = False,
    ) -> list[dict[str, Any]]:
        return proxy.get_traffic(limit=limit, agent=agent, blocked_only=blocked_only)

    return app
