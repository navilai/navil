"""Tests for the MCP Security Proxy (all mocked, no network)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

import jwt as pyjwt
import pytest

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.credential_manager import CredentialManager, _InMemoryStore
from navil.policy_engine import PolicyEngine
from navil.proxy import MCPSecurityProxy


@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture
def detector(fake_redis) -> BehavioralAnomalyDetector:
    return BehavioralAnomalyDetector(redis_client=fake_redis)


@pytest.fixture
def cred_manager() -> CredentialManager:
    cm = CredentialManager()
    cm._redis = _InMemoryStore()
    return cm


@pytest.fixture
def proxy(
    policy_engine: PolicyEngine,
    detector: BehavioralAnomalyDetector,
    cred_manager: CredentialManager,
) -> MCPSecurityProxy:
    return MCPSecurityProxy(
        target_url="http://localhost:3000",
        policy_engine=policy_engine,
        anomaly_detector=detector,
        credential_manager=cred_manager,
        require_auth=False,  # Disable auth for easier testing
    )


def _mock_forward(response_data: dict) -> AsyncMock:
    """Create an AsyncMock for proxy._forward that returns given response."""
    response_bytes = len(json.dumps(response_data).encode())
    return AsyncMock(return_value=(response_data, response_bytes, {}))


class TestParseJsonRPC:
    """JSON-RPC 2.0 parsing tests."""

    def test_parse_valid_tools_call(self) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
                "id": 1,
            }
        ).encode()

        parsed = MCPSecurityProxy.parse_jsonrpc(body)
        assert parsed["method"] == "tools/call"
        assert parsed["params"]["name"] == "read_file"
        assert parsed["id"] == 1

    def test_parse_tools_list(self) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 2,
            }
        ).encode()

        parsed = MCPSecurityProxy.parse_jsonrpc(body)
        assert parsed["method"] == "tools/list"
        assert parsed["id"] == 2

    def test_parse_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            MCPSecurityProxy.parse_jsonrpc(b"not json")

    def test_parse_non_object(self) -> None:
        with pytest.raises(ValueError, match="must be an object"):
            MCPSecurityProxy.parse_jsonrpc(b"[1,2,3]")


class TestExtractToolInfo:
    def test_extract(self) -> None:
        parsed = {
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"content": "hello"}},
            "id": 1,
        }
        tool_name, action, arguments = MCPSecurityProxy.extract_tool_info(parsed)
        assert tool_name == "write_file"
        assert arguments == {"content": "hello"}


class TestIdentity:
    def test_x_agent_name_header(self, proxy: MCPSecurityProxy) -> None:
        name = proxy.extract_agent_name({"x-agent-name": "test-agent"})
        assert name == "test-agent"

    def test_no_identity(self, proxy: MCPSecurityProxy) -> None:
        name = proxy.extract_agent_name({})
        assert name is None

    def test_jwt_bearer_with_valid_credential(self, proxy: MCPSecurityProxy) -> None:
        """JWT auth should work when credential manager validates."""
        cred = proxy.credential_manager.issue_credential(
            agent_name="jwt-agent", scope="*", ttl_seconds=3600
        )
        token = cred["token"]
        name = proxy.extract_agent_name({"authorization": f"Bearer {token}"})
        assert name == "jwt-agent"

    def test_bearer_failure_does_not_fall_through_to_x_agent_name(
        self,
        proxy: MCPSecurityProxy,
    ) -> None:
        """If Bearer token fails, x-agent-name must NOT be used as fallback."""
        headers = {
            "authorization": "Bearer invalid_token_xyz",
            "x-agent-name": "attacker",
        }
        name = proxy.extract_agent_name(headers)
        assert name is None, "Fallthrough from failed Bearer to X-Agent-Name is an auth bypass"

    def test_x_agent_name_not_honored_when_require_auth_true(
        self,
        detector: BehavioralAnomalyDetector,
        cred_manager: CredentialManager,
    ) -> None:
        """When require_auth=True, X-Agent-Name alone must not authenticate."""
        from navil.policy_engine import PolicyEngine

        strict_proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=detector,
            credential_manager=cred_manager,
            require_auth=True,
        )
        name = strict_proxy.extract_agent_name({"x-agent-name": "legit-agent"})
        assert name is None

    def test_hmac_valid_signature_authenticates(self, proxy: MCPSecurityProxy) -> None:
        """A correct HMAC signature over the request body should authenticate."""
        proxy.credential_manager.secret_key = "test-secret"
        body = b'{"jsonrpc":"2.0","method":"tools/call","id":1}'
        sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        headers = {
            "x-navil-signature": f"sha256={sig}",
            "x-agent-name": "hmac-agent",
        }
        identity = proxy.extract_identity(headers, body=body)
        assert identity["agent_name"] == "hmac-agent"

    def test_hmac_wrong_signature_rejected(self, proxy: MCPSecurityProxy) -> None:
        """An incorrect HMAC signature must NOT authenticate."""
        proxy.credential_manager.secret_key = "test-secret"
        body = b'{"jsonrpc":"2.0","method":"tools/call","id":1}'
        headers = {
            "x-navil-signature": "sha256=deadbeef0000",
            "x-agent-name": "attacker",
        }
        identity = proxy.extract_identity(headers, body=body)
        assert identity["agent_name"] is None, (
            "Invalid HMAC signature must not authenticate"
        )

    def test_hmac_signature_over_wrong_body_rejected(self, proxy: MCPSecurityProxy) -> None:
        """HMAC signed over a different body must be rejected."""
        proxy.credential_manager.secret_key = "test-secret"
        signed_body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
        actual_body = b'{"jsonrpc":"2.0","method":"tools/call","id":1}'
        sig = hmac.new(b"test-secret", signed_body, hashlib.sha256).hexdigest()
        headers = {
            "x-navil-signature": f"sha256={sig}",
            "x-agent-name": "attacker",
        }
        identity = proxy.extract_identity(headers, body=actual_body)
        assert identity["agent_name"] is None, (
            "HMAC over different body must not authenticate"
        )

    def test_hmac_empty_body_signature_rejected_for_nonempty_body(
        self, proxy: MCPSecurityProxy
    ) -> None:
        """HMAC signed over empty bytes must not authenticate a non-empty body.

        This is the specific regression test for the bug where the HMAC was
        computed over b'' instead of the actual request body.
        """
        proxy.credential_manager.secret_key = "test-secret"
        body = b'{"jsonrpc":"2.0","method":"tools/call","id":1}'
        # Sign empty bytes (the old buggy behavior)
        sig = hmac.new(b"test-secret", b"", hashlib.sha256).hexdigest()
        headers = {
            "x-navil-signature": f"sha256={sig}",
            "x-agent-name": "attacker",
        }
        identity = proxy.extract_identity(headers, body=body)
        assert identity["agent_name"] is None, (
            "HMAC over empty body must not authenticate a non-empty request"
        )


class TestHandleJsonRPC:
    @pytest.mark.asyncio
    async def test_auth_required_blocks_unauthenticated(
        self,
        detector: BehavioralAnomalyDetector,
        cred_manager: CredentialManager,
    ) -> None:
        """When require_auth=True, missing identity returns error -32003."""
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=detector,
            credential_manager=cred_manager,
            require_auth=True,
        )

        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "read"},
                "id": 1,
            }
        ).encode()

        result, _headers = await proxy.handle_jsonrpc(body, {})
        assert result["error"]["code"] == -32003
        assert proxy.stats["blocked"] == 1

    @pytest.mark.asyncio
    async def test_invalid_json_returns_parse_error(self, proxy: MCPSecurityProxy) -> None:
        result, _headers = await proxy.handle_jsonrpc(b"not json", {})
        assert result["error"]["code"] == -32700

    @pytest.mark.asyncio
    async def test_tools_call_forwarded(self, proxy: MCPSecurityProxy) -> None:
        """Successful tools/call should forward and record invocation."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
                "id": 1,
            }
        ).encode()

        upstream_response = {
            "jsonrpc": "2.0",
            "result": {"content": "file data"},
            "id": 1,
        }

        proxy._forward = _mock_forward(upstream_response)

        result, _headers = await proxy.handle_jsonrpc(body, {"x-agent-name": "test-agent"})
        await asyncio.sleep(0)  # let background task run

        assert "result" in result
        assert proxy.stats["forwarded"] == 1
        assert len(proxy.detector.invocations) == 1
        assert proxy.detector.invocations[0].agent_name == "test-agent"
        assert proxy.detector.invocations[0].tool_name == "read_file"

    @pytest.mark.asyncio
    async def test_tools_list_registers_tools(self, proxy: MCPSecurityProxy) -> None:
        """tools/list should register tool names for supply chain detection."""
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1,
            }
        ).encode()

        upstream_response = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read a file"},
                    {"name": "write_file", "description": "Write a file"},
                ]
            },
            "id": 1,
        }

        proxy._forward = _mock_forward(upstream_response)

        result, _headers = await proxy.handle_jsonrpc(body, {"x-agent-name": "test-agent"})
        await asyncio.sleep(0)  # let background task run

        assert "result" in result
        assert "http://localhost:3000" in proxy.detector.registered_tools
        assert proxy.detector.registered_tools["http://localhost:3000"] == {
            "read_file",
            "write_file",
        }


class TestTrafficLog:
    def test_ring_buffer_max_size(self, proxy: MCPSecurityProxy) -> None:
        """Traffic log should be capped at MAX_TRAFFIC_LOG entries."""
        for i in range(proxy.MAX_TRAFFIC_LOG + 100):
            proxy._log_traffic(f"agent-{i}", "tools/call", "tool", "ALLOWED", 10, 100)

        assert len(proxy.traffic_log) == proxy.MAX_TRAFFIC_LOG

    def test_get_traffic_filter(self, proxy: MCPSecurityProxy) -> None:
        proxy._log_traffic("agent-a", "tools/call", "read", "ALLOWED", 10, 100)
        proxy._log_traffic("agent-b", "tools/call", "write", "DENIED", 5, 0)
        proxy._log_traffic("agent-a", "tools/list", "", "ALLOWED", 3, 50)

        # Filter by agent
        result = proxy.get_traffic(agent="agent-a")
        assert len(result) == 2

        # Filter blocked only
        result = proxy.get_traffic(blocked_only=True)
        assert len(result) == 1
        assert result[0]["decision"] == "DENIED"


class TestGetStatus:
    def test_status_structure(self, proxy: MCPSecurityProxy) -> None:
        status = proxy.get_status()
        assert status["running"] is True
        assert status["target_url"] == "http://localhost:3000"
        assert "total_requests" in status["stats"]
        assert "uptime_seconds" in status


class TestSanitizeRequest:
    """Request sanitization: byte limit, whitespace strip, depth limit."""

    def test_normal_payload_passes(self) -> None:
        body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1}).encode()
        result = MCPSecurityProxy.sanitize_request(body)
        # Should be valid JSON and compacted (no extra whitespace)
        assert b"tools/call" in result

    def test_whitespace_padding_stripped(self) -> None:
        """Padded JSON should be compacted to tight form."""
        padded = b'  {  "method" :  "tools/call" ,  "id" : 1  }  '
        result = MCPSecurityProxy.sanitize_request(padded)
        # orjson produces compact output — no spaces around colons/commas
        assert b"  " not in result
        assert b"tools/call" in result

    def test_payload_too_large(self) -> None:
        body = b"x" * (MCPSecurityProxy.MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(ValueError, match="Payload too large"):
            MCPSecurityProxy.sanitize_request(body)

    def test_depth_limit_exceeded(self) -> None:
        """Deeply nested JSON should be rejected."""
        # Build nesting depth of 15 (exceeds limit of 10)
        inner: dict = {"leaf": True}
        for _ in range(14):
            inner = {"nested": inner}
        body = json.dumps(inner).encode()
        with pytest.raises(ValueError, match="nesting depth"):
            MCPSecurityProxy.sanitize_request(body)

    def test_depth_at_limit_passes(self) -> None:
        """Nesting exactly at the limit should pass."""
        inner: dict = {"leaf": True}
        for _ in range(MCPSecurityProxy.MAX_JSON_DEPTH - 2):
            inner = {"nested": inner}
        body = json.dumps(inner).encode()
        result = MCPSecurityProxy.sanitize_request(body)
        assert b"leaf" in result

    def test_invalid_json_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            MCPSecurityProxy.sanitize_request(b"not json at all")

    @pytest.mark.asyncio
    async def test_oversized_payload_blocked_in_handler(self, proxy: MCPSecurityProxy) -> None:
        """handle_jsonrpc should reject oversized payloads."""
        body = b"{" + b" " * (MCPSecurityProxy.MAX_PAYLOAD_BYTES + 1) + b"}"
        result, _headers = await proxy.handle_jsonrpc(body, {"x-agent-name": "test"})
        assert result["error"]["code"] == -32700
        assert "too large" in result["error"]["message"]

    @pytest.mark.asyncio
    async def test_deep_json_blocked_in_handler(self, proxy: MCPSecurityProxy) -> None:
        """handle_jsonrpc should reject deeply nested JSON."""
        inner: dict = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
        for _ in range(15):
            inner = {"nested": inner}
        body = json.dumps(inner).encode()
        result, _headers = await proxy.handle_jsonrpc(body, {"x-agent-name": "test"})
        assert result["error"]["code"] == -32700
        assert "nesting depth" in result["error"]["message"]


class TestJsonRPCError:
    def test_error_format(self) -> None:
        err = MCPSecurityProxy._jsonrpc_error(-32001, "Blocked", 42)
        assert err["jsonrpc"] == "2.0"
        assert err["error"]["code"] == -32001
        assert err["error"]["message"] == "Blocked"
        assert err["id"] == 42


# ── JWT Authentication Tests (proxy-interface-spec.md Section 3) ──


def _make_jwt(
    secret: str,
    agent_name: str = "test-agent",
    scope: str = "read:tools",
    human_context: dict | None = None,
    delegation_chain: list[str] | None = None,
    exp_offset_hours: float = 1.0,
    token_id: str = "cred_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
) -> str:
    """Helper: build a JWT with Navil claims."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=exp_offset_hours)
    payload = {
        "token_id": token_id,
        "agent_name": agent_name,
        "scope": scope,
        "human_context": human_context,
        "delegation_chain": delegation_chain,
        "parent_credential_id": None,
        "iat": now.isoformat(),
        "exp": exp.isoformat(),
    }
    return pyjwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture
def jwt_proxy(
    policy_engine: PolicyEngine,
    detector: BehavioralAnomalyDetector,
    cred_manager: CredentialManager,
) -> MCPSecurityProxy:
    """Proxy with a known JWT secret configured."""
    cred_manager.secret_key = "jwt-test-secret-that-is-long-enough"
    return MCPSecurityProxy(
        target_url="http://localhost:3000",
        policy_engine=policy_engine,
        anomaly_detector=detector,
        credential_manager=cred_manager,
        require_auth=True,
    )


class TestJWTAuthentication:
    """JWT validation per proxy-interface-spec.md Section 3."""

    def test_valid_jwt_accepted(self, jwt_proxy: MCPSecurityProxy) -> None:
        """Valid JWT should authenticate and extract agent_name."""
        token = _make_jwt("jwt-test-secret-that-is-long-enough", agent_name="deploy-bot")
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] == "deploy-bot"
        assert identity["is_jwt"] is True
        assert identity["error"] is None

    def test_expired_jwt_rejected(self, jwt_proxy: MCPSecurityProxy) -> None:
        """Expired JWT must return error, not authenticate."""
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="expired-agent",
            exp_offset_hours=-1.0,
        )
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] is None
        assert identity["error"] is not None
        assert "expired" in identity["error"].lower()

    def test_invalid_signature_rejected(self, jwt_proxy: MCPSecurityProxy) -> None:
        """JWT signed with wrong secret must be rejected."""
        token = _make_jwt("wrong-secret-definitely-not-correct", agent_name="attacker")
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] is None
        assert identity["error"] is not None
        assert "signature" in identity["error"].lower() or "validation" in identity["error"].lower()

    def test_failed_jwt_does_not_fall_back_to_hmac(self, jwt_proxy: MCPSecurityProxy) -> None:
        """If Bearer token is present but invalid, MUST NOT fall back to x-agent-name."""
        token = _make_jwt("wrong-secret-xxxxxxxxxxxxxxxxx", agent_name="attacker")
        headers = {
            "authorization": f"Bearer {token}",
            "x-agent-name": "legitimate-agent",
        }
        identity = jwt_proxy.extract_identity(headers)
        assert identity["agent_name"] is None, (
            "Failed JWT must NOT fall back to x-agent-name"
        )

    def test_jwt_human_context_extraction(self, jwt_proxy: MCPSecurityProxy) -> None:
        """JWT with human_context should extract sub, email, roles."""
        human_ctx = {
            "sub": "google-oauth2|108234567890",
            "email": "alice@example.com",
            "roles": ["engineer", "on-call"],
        }
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="deploy-bot",
            human_context=human_ctx,
        )
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] == "deploy-bot"
        assert identity["human_context"] is not None
        assert identity["human_context"]["sub"] == "google-oauth2|108234567890"
        assert identity["human_context"]["email"] == "alice@example.com"
        assert identity["human_context"]["roles"] == ["engineer", "on-call"]

    def test_jwt_no_human_context(self, jwt_proxy: MCPSecurityProxy) -> None:
        """JWT without human_context should still authenticate."""
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="ci-bot",
            human_context=None,
        )
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] == "ci-bot"
        assert identity["human_context"] is None

    def test_jwt_with_delegation_chain(self, jwt_proxy: MCPSecurityProxy) -> None:
        """JWT with delegation_chain should extract chain IDs."""
        chain = [
            "cred_0000000000000000000000000000000000000000000000000000000000000001",
            "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="delegated-bot",
            delegation_chain=chain,
        )
        identity = jwt_proxy.extract_identity({"authorization": f"Bearer {token}"})
        assert identity["agent_name"] == "delegated-bot"
        assert identity["delegation_chain"] == chain

    @pytest.mark.asyncio
    async def test_expired_jwt_blocked_in_handler(self, jwt_proxy: MCPSecurityProxy) -> None:
        """Expired JWT should return -32003 from handle_jsonrpc."""
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="expired-agent",
            exp_offset_hours=-1.0,
        )
        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "read"}, "id": 1,
        }).encode()
        result, _ = await jwt_proxy.handle_jsonrpc(body, {"authorization": f"Bearer {token}"})
        assert result["error"]["code"] == -32003


# ── Delegation Chain Tests (proxy-interface-spec.md Section 6) ──


class TestDelegationChain:
    """Delegation chain verification per spec Section 6."""

    @pytest.mark.asyncio
    async def test_all_ancestors_active_passes(self, fake_redis) -> None:
        """All ancestors ACTIVE => request allowed."""
        cred_manager = CredentialManager()
        cred_manager.secret_key = "test-secret-long-enough-for-hs256"
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(redis_client=fake_redis),
            credential_manager=cred_manager,
            require_auth=True,
            redis_client=fake_redis,
        )

        chain = [
            "cred_0000000000000000000000000000000000000000000000000000000000000001",
            "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        # Set status keys in Redis
        for cred_id in chain:
            await fake_redis.set(f"navil:cred:{cred_id}:status", "ACTIVE")

        result = await proxy._verify_delegation_chain(chain)
        assert result is None  # None = success

    @pytest.mark.asyncio
    async def test_one_ancestor_revoked_rejected(self, fake_redis) -> None:
        """One ancestor REVOKED => request rejected."""
        cred_manager = CredentialManager()
        cred_manager.secret_key = "test-secret-long-enough-for-hs256"
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(redis_client=fake_redis),
            credential_manager=cred_manager,
            require_auth=True,
            redis_client=fake_redis,
        )

        chain = [
            "cred_0000000000000000000000000000000000000000000000000000000000000001",
            "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        await fake_redis.set(f"navil:cred:{chain[0]}:status", "ACTIVE")
        await fake_redis.set(f"navil:cred:{chain[1]}:status", "REVOKED")

        result = await proxy._verify_delegation_chain(chain)
        assert result is not None
        assert "not active" in result

    @pytest.mark.asyncio
    async def test_missing_redis_key_rejected(self, fake_redis) -> None:
        """Missing Redis key => treated as not active."""
        cred_manager = CredentialManager()
        cred_manager.secret_key = "test-secret-long-enough-for-hs256"
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(redis_client=fake_redis),
            credential_manager=cred_manager,
            require_auth=True,
            redis_client=fake_redis,
        )

        chain = ["cred_0000000000000000000000000000000000000000000000000000000000000001"]
        # Don't set any key — it should be treated as not active

        result = await proxy._verify_delegation_chain(chain)
        assert result is not None
        assert "not active" in result

    @pytest.mark.asyncio
    async def test_chain_depth_exceeds_limit(self) -> None:
        """Chain with >10 entries should be rejected immediately."""
        cred_manager = CredentialManager()
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(),
            credential_manager=cred_manager,
            require_auth=False,
        )

        chain = [f"cred_{i:064x}" for i in range(11)]
        result = await proxy._verify_delegation_chain(chain)
        assert result is not None
        assert "too deep" in result.lower()

    @pytest.mark.asyncio
    async def test_empty_chain_passes(self) -> None:
        """Empty chain should pass."""
        cred_manager = CredentialManager()
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(),
            credential_manager=cred_manager,
            require_auth=False,
        )

        result = await proxy._verify_delegation_chain([])
        assert result is None


# ── Header Injection Tests (proxy-interface-spec.md Section 8) ──


class TestHeaderInjection:
    """Header injection for upstream MCP servers."""

    @pytest.mark.asyncio
    async def test_jwt_headers_include_human_identity(self, jwt_proxy: MCPSecurityProxy) -> None:
        """JWT with human_context should inject X-Human-Identity and X-Human-Email."""
        human_ctx = {
            "sub": "google-oauth2|108234567890",
            "email": "alice@example.com",
            "roles": ["engineer"],
        }
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="deploy-bot",
            human_context=human_ctx,
        )
        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}}, "id": 1,
        }).encode()

        upstream_response = {"jsonrpc": "2.0", "result": {}, "id": 1}
        jwt_proxy._forward = AsyncMock(
            return_value=(upstream_response, 10, {})
        )

        await jwt_proxy.handle_jsonrpc(body, {"authorization": f"Bearer {token}"})
        await asyncio.sleep(0)

        # Verify _forward was called with correct identity headers
        call_kwargs = jwt_proxy._forward.call_args
        assert call_kwargs is not None
        _, kwargs = call_kwargs
        assert kwargs["agent_name"] == "deploy-bot"
        assert kwargs["human_context"]["sub"] == "google-oauth2|108234567890"
        assert kwargs["human_context"]["email"] == "alice@example.com"
        assert kwargs["is_jwt"] is True

    @pytest.mark.asyncio
    async def test_hmac_headers_no_human_identity(self, proxy: MCPSecurityProxy) -> None:
        """HMAC-authenticated requests must NOT get human identity headers."""
        proxy.credential_manager.secret_key = "test-secret"
        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}}, "id": 1,
        }).encode()
        compact_body = proxy.sanitize_request(body)
        sig = hmac.new(b"test-secret", compact_body, hashlib.sha256).hexdigest()

        upstream_response = {"jsonrpc": "2.0", "result": {}, "id": 1}
        proxy._forward = AsyncMock(return_value=(upstream_response, 10, {}))

        await proxy.handle_jsonrpc(
            body,
            {
                "x-navil-signature": f"sha256={sig}",
                "x-agent-name": "hmac-agent",
            },
        )
        await asyncio.sleep(0)

        call_kwargs = proxy._forward.call_args
        assert call_kwargs is not None
        _, kwargs = call_kwargs
        assert kwargs["agent_name"] == "hmac-agent"
        assert kwargs["human_context"] is None
        assert kwargs["is_jwt"] is False

    @pytest.mark.asyncio
    async def test_delegation_depth_header_correct(self, jwt_proxy: MCPSecurityProxy) -> None:
        """X-Delegation-Depth should equal len(delegation_chain)."""
        chain = [
            "cred_0000000000000000000000000000000000000000000000000000000000000001",
            "cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="delegated-bot",
            delegation_chain=chain,
        )
        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/list", "id": 1,
        }).encode()

        upstream_response = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}
        jwt_proxy._forward = AsyncMock(return_value=(upstream_response, 10, {}))

        # Mock delegation chain verification to pass
        jwt_proxy._verify_delegation_chain = AsyncMock(return_value=None)

        await jwt_proxy.handle_jsonrpc(body, {"authorization": f"Bearer {token}"})
        await asyncio.sleep(0)

        call_kwargs = jwt_proxy._forward.call_args
        _, kwargs = call_kwargs
        assert kwargs["delegation_chain"] == chain


# ── Telemetry Tests (proxy-interface-spec.md Section 10) ──


class TestTelemetry:
    """Telemetry event emission per spec Section 10."""

    @pytest.mark.asyncio
    async def test_forwarded_event_emitted(self, fake_redis) -> None:
        """FORWARDED event should be emitted on successful forward."""
        cred_manager = CredentialManager()
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(redis_client=fake_redis),
            credential_manager=cred_manager,
            require_auth=False,
            redis_client=fake_redis,
        )

        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp"}}, "id": 1,
        }).encode()

        upstream_response = {"jsonrpc": "2.0", "result": {}, "id": 1}
        proxy._forward = _mock_forward(upstream_response)

        await proxy.handle_jsonrpc(body, {"x-agent-name": "test-agent"})
        await asyncio.sleep(0.1)  # let background task run

        queue = fake_redis._data.get("navil:telemetry:queue", [])
        assert len(queue) > 0
        import orjson
        event = orjson.loads(queue[0])
        assert event["agent_name"] == "test-agent"
        assert event["tool_name"] == "read_file"
        assert event["action"] == "FORWARDED"

    @pytest.mark.asyncio
    async def test_telemetry_includes_human_email(self, fake_redis) -> None:
        """Telemetry for JWT requests should include human_email and delegation_depth."""
        cred_manager = CredentialManager()
        cred_manager.secret_key = "jwt-test-secret-that-is-long-enough"
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(redis_client=fake_redis),
            credential_manager=cred_manager,
            require_auth=True,
            redis_client=fake_redis,
        )

        human_ctx = {
            "sub": "google-oauth2|108234567890",
            "email": "alice@example.com",
            "roles": ["engineer"],
        }
        chain = ["cred_0000000000000000000000000000000000000000000000000000000000000001"]
        token = _make_jwt(
            "jwt-test-secret-that-is-long-enough",
            agent_name="deploy-bot",
            human_context=human_ctx,
            delegation_chain=chain,
        )

        body = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "deploy", "arguments": {}}, "id": 1,
        }).encode()

        upstream_response = {"jsonrpc": "2.0", "result": {}, "id": 1}
        proxy._forward = _mock_forward(upstream_response)
        proxy._verify_delegation_chain = AsyncMock(return_value=None)

        await proxy.handle_jsonrpc(body, {"authorization": f"Bearer {token}"})
        await asyncio.sleep(0.1)

        queue = fake_redis._data.get("navil:telemetry:queue", [])
        assert len(queue) > 0
        import orjson
        event = orjson.loads(queue[0])
        assert event["agent_name"] == "deploy-bot"
        assert event.get("human_email") == "alice@example.com"
        assert event.get("delegation_depth") == 1


# ── SSE Response Parsing Tests ──


class TestSSEParsing:
    """SSE response handling."""

    def test_parse_sse_valid(self) -> None:
        text = 'event: message\ndata: {"jsonrpc":"2.0","result":{"tools":[]},"id":1}\n\n'
        result = MCPSecurityProxy._parse_sse_response(text)
        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1

    def test_parse_sse_no_data(self) -> None:
        text = "event: message\nno-data-here\n\n"
        result = MCPSecurityProxy._parse_sse_response(text)
        assert result["error"]["code"] == -32603

    def test_parse_sse_multiple_data_lines(self) -> None:
        text = 'data: invalid\ndata: {"jsonrpc":"2.0","result":"ok","id":2}\n\n'
        result = MCPSecurityProxy._parse_sse_response(text)
        assert result["id"] == 2
