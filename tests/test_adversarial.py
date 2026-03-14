"""Adversarial QA test suite — red-team tests for Navil security controls.

Each test is written to EXPECT the security control to hold.
A pytest FAILURE = a confirmed security finding.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import jwt
import pytest
from pydantic import ValidationError

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.api.local.routes import (
    AutoRemediateRequest,
    CredentialIssueRequest,
    PolicyCheckRequest,
)
from navil.credential_manager import Credential, CredentialManager, CredentialStatus
from navil.policy_engine import PolicyEngine
from navil.proxy import MCPSecurityProxy

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_proxy(
    require_auth: bool = False,
    fake_redis: Any = None,
) -> MCPSecurityProxy:
    """Construct a proxy with real sub-components, no network."""
    detector = BehavioralAnomalyDetector(redis_client=fake_redis)
    return MCPSecurityProxy(
        target_url="http://localhost:3000",
        policy_engine=PolicyEngine(),
        anomaly_detector=detector,
        credential_manager=CredentialManager(),
        require_auth=require_auth,
    )


def _make_jwt(secret: str, overrides: dict[str, Any] | None = None) -> str:
    """Craft a JWT with integer iat/exp (unlike issue_credential which uses ISO strings)."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "token_id": "cred_test001",
        "agent_name": "test-agent",
        "scope": "*",
        "iat": now,
        "exp": now + 3600,
    }
    if overrides:
        payload.update(overrides)
    # Remove keys explicitly set to None so we can test missing fields
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(payload, secret, algorithm="HS256")


def _mock_forward(response_data: dict[str, Any]) -> AsyncMock:
    """Return an AsyncMock for proxy._forward that yields a canned response."""
    size = len(json.dumps(response_data).encode())
    return AsyncMock(return_value=(response_data, size, {}))


# ---------------------------------------------------------------------------
# 1. Auth bypass attacks
# ---------------------------------------------------------------------------


class TestAuthBypass:
    """Attempt to bypass extract_agent_name() identity checks."""

    def test_empty_bearer_token_returns_none(self) -> None:
        """Bearer header with empty token after the space must not authenticate."""
        proxy = _make_proxy(require_auth=True)
        # "Bearer " — token is empty string after split
        result = proxy.extract_agent_name({"authorization": "Bearer "})
        assert result is None

    def test_bearer_whitespace_only_returns_none(self) -> None:
        """Bearer header with all-whitespace token must not authenticate."""
        proxy = _make_proxy(require_auth=True)
        result = proxy.extract_agent_name({"authorization": "Bearer    "})
        assert result is None

    def test_lowercase_bearer_not_matched(self) -> None:
        """Lowercase 'bearer' is not matched by startswith('Bearer ') — documented behaviour."""
        proxy = _make_proxy(require_auth=False)
        # Falls through to x-agent-name path (no Bearer check)
        result = proxy.extract_agent_name({
            "authorization": "bearer some_token",
            "x-agent-name": "fallback-agent",
        })
        # With require_auth=False and no Bearer match, x-agent-name is honoured
        assert result == "fallback-agent"

    def test_bearer_failure_does_not_fall_through_to_x_agent_name_auth_false(self) -> None:
        """Bad Bearer + X-Agent-Name with require_auth=False: Bearer was attempted, must return None."""
        proxy = _make_proxy(require_auth=False)
        result = proxy.extract_agent_name({
            "authorization": "Bearer invalid_token_xyz",
            "x-agent-name": "attacker",
        })
        assert result is None, "Auth bypass: failed Bearer fell through to X-Agent-Name"

    def test_bearer_failure_does_not_fall_through_to_x_agent_name_auth_true(self) -> None:
        """Bad Bearer + X-Agent-Name with require_auth=True: must also return None."""
        proxy = _make_proxy(require_auth=True)
        result = proxy.extract_agent_name({
            "authorization": "Bearer invalid",
            "x-agent-name": "attacker",
        })
        assert result is None

    def test_require_auth_blocks_x_agent_name_only(self) -> None:
        """With require_auth=True, X-Agent-Name header alone must not authenticate."""
        proxy = _make_proxy(require_auth=True)
        result = proxy.extract_agent_name({"x-agent-name": "admin"})
        assert result is None

    def test_require_auth_blocks_no_headers(self) -> None:
        """With require_auth=True and no headers, identity must be None."""
        proxy = _make_proxy(require_auth=True)
        result = proxy.extract_agent_name({})
        assert result is None

    def test_forged_x_agent_name_no_sanitization(self) -> None:
        """X-Agent-Name accepts path-like strings verbatim — documenting lack of validation (finding)."""
        proxy = _make_proxy(require_auth=False)
        malicious = "../../admin"
        result = proxy.extract_agent_name({"x-agent-name": malicious})
        # FINDING: no validation — raw string accepted
        assert result == malicious, "Expected raw string passthrough (known finding)"

    def test_very_long_bearer_token_does_not_crash(self) -> None:
        """A 1 MB Bearer token must not crash the proxy or hang."""
        proxy = _make_proxy(require_auth=True)
        huge_token = "x" * 1_000_000
        result = proxy.extract_agent_name({"authorization": f"Bearer {huge_token}"})
        assert result is None


# ---------------------------------------------------------------------------
# 2. JWT security attacks
# ---------------------------------------------------------------------------


class TestJWTSecurity:
    """Attack CredentialManager.verify_credential() directly.

    IMPORTANT: All tokens must be hand-crafted with integer iat/exp.
    DO NOT use cm.issue_credential() — it stores ISO-format claims that
    always cause DecodeError in jwt.decode(), breaking verification.
    """

    def test_issued_tokens_fail_jwt_decode(self) -> None:
        """FINDING (High): issue_credential() produces ISO exp/iat — verify_credential always raises.

        This means token expiry is never enforced in the real proxy auth flow.
        """
        cm = CredentialManager()
        cred = cm.issue_credential("agent-x", "read:tools", ttl_seconds=3600)
        token = cred["token"]
        with pytest.raises(Exception):
            # Should raise DecodeError: "Issued At claim (iat) must be an integer"
            cm.verify_credential(token)

    def test_alg_none_rejected(self) -> None:
        """JWT with alg:none must be rejected when algorithms=['HS256'] is specified."""
        cm = CredentialManager()
        # Craft alg:none token manually (base64 imported at top level)
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload_data = json.dumps({
            "token_id": "cred_x", "agent_name": "evil", "scope": "*",
            "iat": int(time.time()), "exp": int(time.time()) + 3600,
        })
        payload = base64.urlsafe_b64encode(payload_data.encode()).rstrip(b"=").decode()
        none_token = f"{header}.{payload}."
        with pytest.raises(Exception):
            cm.verify_credential(none_token)

    def test_tampered_payload_rejected(self) -> None:
        """A token with a flipped agent_name in the payload must be rejected."""
        cm = CredentialManager()
        good_token = _make_jwt(cm.secret_key, {"agent_name": "legit-agent"})
        # Decode without verification, flip name, re-encode with NO signature
        parts = good_token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        decoded["agent_name"] = "evil-agent"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        with pytest.raises(Exception):
            cm.verify_credential(tampered)

    def test_expired_token_rejected(self) -> None:
        """A JWT with exp in the past must be rejected."""
        cm = CredentialManager()
        expired_token = _make_jwt(cm.secret_key, {
            "exp": int(time.time()) - 3600,  # 1 hour ago
        })
        with pytest.raises(Exception):
            cm.verify_credential(expired_token)

    def test_missing_exp_accepted_as_eternal(self) -> None:
        """FINDING: JWT with no exp claim is accepted indefinitely.

        PyJWT does not require exp unless options['require_exp'] is set.
        """
        cm = CredentialManager()
        eternal_token = _make_jwt(cm.secret_key, {"exp": None})  # _make_jwt strips None values
        # Should succeed (no expiry check) — this is the finding
        result = cm.verify_credential(eternal_token)
        assert "agent_name" in result, "Eternal token accepted — finding: no expiry required"

    def test_revoked_token_rejected(self) -> None:
        """A token whose token_id is REVOKED in the credential store must be rejected."""
        cm = CredentialManager()
        token = _make_jwt(cm.secret_key, {"token_id": "cred_revoked_001"})
        # Manually insert a REVOKED credential with this token_id (Credential imported at top)
        cm.credentials["cred_revoked_001"] = Credential(
            token_id="cred_revoked_001",
            agent_name="revokedagent",
            scope="*",
            token=token,
            issued_at="2026-01-01T00:00:00+00:00",
            expires_at="2027-01-01T00:00:00+00:00",
            status=CredentialStatus.REVOKED,
        )
        with pytest.raises(Exception, match="revoked"):
            cm.verify_credential(token)

    def test_wrong_secret_rejected(self) -> None:
        """A token signed with the wrong secret must be rejected."""
        cm = CredentialManager()
        wrong_secret_token = _make_jwt("completely-wrong-secret-key-abcdefg", {})
        with pytest.raises(Exception):
            cm.verify_credential(wrong_secret_token)

    def test_rs256_algorithm_confusion_rejected(self) -> None:
        """A JWT claiming alg:RS256 must be rejected (only HS256 is allowed)."""
        cm = CredentialManager()
        # Attempt to create an RS256 token — will fail at creation or verification
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            rs256_token = jwt.encode(
                {"agent_name": "evil", "iat": int(time.time()), "exp": int(time.time()) + 3600},
                private_key,
                algorithm="RS256",
            )
            with pytest.raises(Exception):
                cm.verify_credential(rs256_token)
        except ImportError:
            # cryptography package not installed — test the rejection via header manipulation
            header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
            payload = base64.urlsafe_b64encode(b'{"agent_name":"evil"}').rstrip(b"=").decode()
            fake_rs256 = f"{header}.{payload}.fakesig"
            with pytest.raises(Exception):
                cm.verify_credential(fake_rs256)

    def test_empty_string_token_rejected(self) -> None:
        """Empty string must not authenticate."""
        cm = CredentialManager()
        with pytest.raises(Exception):
            cm.verify_credential("")


# ---------------------------------------------------------------------------
# 3. Rate limit bypass attacks
# ---------------------------------------------------------------------------


class TestRateLimitBypass:
    """Attack PolicyEngine._check_rate_limit()."""

    def _engine_with_limit(self, limit: int = 5) -> PolicyEngine:
        """Build a PolicyEngine with a known rate limit for a test agent."""
        engine = PolicyEngine()
        engine.policy = {
            "agents": {
                "limited-agent": {
                    "tools_allowed": ["*"],
                    "rate_limit_per_hour": limit,
                }
            },
            "tools": {
                "any_tool": {"allowed_actions": ["*"]},
                "tool": {"allowed_actions": ["*"]},
            },
        }
        return engine

    def test_concurrent_limit_holds(self) -> None:
        """20 concurrent threads against limit=5 must not allow more than 5."""
        engine = self._engine_with_limit(5)
        results: list[bool] = []
        lock = threading.Lock()

        def check() -> None:
            allowed, _reason = engine.check_tool_call("limited-agent", "any_tool", "tools/call")
            with lock:
                results.append(allowed)

        threads = [threading.Thread(target=check) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(results)
        assert allowed_count <= 5, (
            f"Rate limit exceeded under concurrent load: {allowed_count} allowed (limit 5)"
        )

    def test_key_collision_different_agents(self) -> None:
        """FINDING (Medium): agent='a:b' + tool='c' produces key 'a:b:c',
        same as agent='a' + tool='b:c'. These agents share a rate limit bucket.
        """
        engine = PolicyEngine()
        engine.policy = {
            "agents": {
                "a:b": {"tools_allowed": ["*"], "rate_limit_per_hour": 3},
                "a": {"tools_allowed": ["*"], "rate_limit_per_hour": 3},
            },
            "tools": {
                "c": {"allowed_actions": ["*"]},
                "b:c": {"allowed_actions": ["*"]},
            },
        }
        # Exhaust agent "a:b"'s bucket with tool "c"
        for _ in range(3):
            engine.check_tool_call("a:b", "c", "tools/call")

        # Now agent "a" calling tool "b:c" should have its OWN full bucket
        # But due to key collision ("a:b:c" == "a:b:c"), it will be exhausted too
        allowed, _ = engine.check_tool_call("a", "b:c", "tools/call")

        # This assert WILL FAIL if the bug exists (shared bucket = finding)
        assert allowed is True, (
            "FINDING: rate limit key collision — agent 'a' + tool 'b:c' shares "
            "bucket with agent 'a:b' + tool 'c' via key 'a:b:c'"
        )

    def test_limit_exact_boundary(self) -> None:
        """Calls 1-5 must be allowed; call 6 must be the first rejection (limit=5)."""
        engine = self._engine_with_limit(5)
        results = [
            engine.check_tool_call("limited-agent", "tool", "tools/call")[0]
            for _ in range(6)
        ]
        assert all(results[:5]), "Calls 1-5 must all be allowed"
        assert results[5] is False, "Call 6 must be rejected (limit=5, counter reaches 5)"

    def test_limit_resets_after_hour(self) -> None:
        """After the hour window, the counter must reset and allow calls again."""
        engine = self._engine_with_limit(2)
        # Exhaust the limit
        engine.check_tool_call("limited-agent", "tool", "tools/call")
        engine.check_tool_call("limited-agent", "tool", "tools/call")
        blocked, _ = engine.check_tool_call("limited-agent", "tool", "tools/call")
        assert blocked is False, "Must be blocked after exhausting limit"

        # Wind back the reset_at to simulate an hour passing
        key = "limited-agent:tool"
        engine.rate_limits[key]["reset_at"] = int(time.time()) - 3601

        allowed, _ = engine.check_tool_call("limited-agent", "tool", "tools/call")
        assert allowed is True, "Must be allowed after hour window resets"


# ---------------------------------------------------------------------------
# 4. Input validation boundary attacks
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Probe Pydantic model field constraints at and beyond their limits."""

    def test_agent_name_at_max_length_valid(self) -> None:
        """Exactly 256 chars must pass validation."""
        req = PolicyCheckRequest(agent_name="a" * 256, tool_name="tool", action="tools/call")
        assert len(req.agent_name) == 256

    def test_agent_name_over_max_length_rejected(self) -> None:
        """257 chars must fail validation."""
        with pytest.raises(ValidationError):
            PolicyCheckRequest(agent_name="a" * 257, tool_name="tool", action="tools/call")

    def test_unicode_emoji_at_char_limit_valid(self) -> None:
        """256 emoji chars (each 4 bytes = 1024 total bytes) must pass.

        Pydantic counts characters, not bytes — this is documented behaviour.
        """
        emoji_str = "𝕳" * 256  # 256 chars, 1024 UTF-8 bytes
        req = PolicyCheckRequest(agent_name=emoji_str, tool_name="tool", action="tools/call")
        assert len(req.agent_name) == 256

    def test_null_byte_passes_pydantic(self) -> None:
        """FINDING (Low): Null bytes pass Pydantic string validation.

        This means null bytes can appear in agent names stored in logs/telemetry.
        """
        try:
            req = PolicyCheckRequest(
                agent_name="hello\x00world", tool_name="tool", action="tools/call"
            )
            # If we reach here, null byte was accepted — this is the finding
            assert "\x00" in req.agent_name, "FINDING: null byte accepted in agent_name"
        except ValidationError:
            pytest.skip("Pydantic rejected null byte — finding disproved, update spec")

    def test_newline_passes_pydantic(self) -> None:
        """FINDING (Low): Newlines pass Pydantic string validation.

        Newlines in agent names enable log injection attacks.
        """
        try:
            req = PolicyCheckRequest(
                agent_name="hello\nworld", tool_name="tool", action="tools/call"
            )
            assert "\n" in req.agent_name, "FINDING: newline accepted in agent_name"
        except ValidationError:
            pytest.skip("Pydantic rejected newline — finding disproved, update spec")

    def test_negative_ttl_rejected(self) -> None:
        """Negative TTL must be rejected."""
        with pytest.raises(ValidationError):
            CredentialIssueRequest(agent_name="agent", scope="read:tools", ttl_seconds=-1)

    def test_zero_ttl_rejected(self) -> None:
        """Zero TTL must be rejected (ge=1)."""
        with pytest.raises(ValidationError):
            CredentialIssueRequest(agent_name="agent", scope="read:tools", ttl_seconds=0)

    def test_confidence_over_one_rejected(self) -> None:
        """confidence_threshold > 1.0 must be rejected."""
        with pytest.raises(ValidationError):
            AutoRemediateRequest(confidence_threshold=1.5)

    def test_confidence_negative_rejected(self) -> None:
        """confidence_threshold < 0.0 must be rejected."""
        with pytest.raises(ValidationError):
            AutoRemediateRequest(confidence_threshold=-0.1)

    def test_empty_agent_name_rejected(self) -> None:
        """Empty string must be rejected (min_length=1)."""
        with pytest.raises(ValidationError):
            PolicyCheckRequest(agent_name="", tool_name="tool", action="tools/call")

    def test_scope_at_max_length_valid(self) -> None:
        """Exactly 512-char scope must pass."""
        req = CredentialIssueRequest(agent_name="agent", scope="s" * 512)
        assert len(req.scope) == 512

    def test_scope_over_max_length_rejected(self) -> None:
        """513-char scope must be rejected."""
        with pytest.raises(ValidationError):
            CredentialIssueRequest(agent_name="agent", scope="s" * 513)


# ---------------------------------------------------------------------------
# 5. JSON-RPC abuse attacks
# ---------------------------------------------------------------------------


class TestJSONRPCAbuse:
    """Attack the proxy's JSON-RPC parsing and size-limiting pipeline."""

    @pytest.fixture
    def proxy(self, fake_redis: Any) -> MCPSecurityProxy:
        detector = BehavioralAnomalyDetector(redis_client=fake_redis)
        p = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=detector,
            credential_manager=CredentialManager(),
            require_auth=False,
        )
        # Pre-wire a mock http_client so _forward() doesn't assert
        p.http_client = AsyncMock()
        p.http_client.post = AsyncMock(return_value=MagicMock(
            content=json.dumps({"jsonrpc": "2.0", "result": {}, "id": 1}).encode(),
            headers={"content-type": "application/json"},
            text='',
        ))
        return p

    @pytest.mark.asyncio
    async def test_null_method_does_not_crash(self, proxy: MCPSecurityProxy) -> None:
        """method:null hits the else-branch and forwards — no crash."""
        body = json.dumps({"jsonrpc": "2.0", "method": None, "id": 1}).encode()
        result, _ = await proxy.handle_jsonrpc(body, {"x-agent-name": "agent"})
        # Must return a dict (either forwarded response or error), never raise
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_non_string_method_does_not_crash(self, proxy: MCPSecurityProxy) -> None:
        """method as a nested object hits the else-branch — no crash."""
        body = json.dumps({"jsonrpc": "2.0", "method": {"k": "v"}, "id": 1}).encode()
        result, _ = await proxy.handle_jsonrpc(body, {"x-agent-name": "agent"})
        assert isinstance(result, dict)

    def test_payload_at_size_limit_accepted(self) -> None:
        """Body exactly MAX_PAYLOAD_BYTES must be accepted by sanitize_request."""
        limit = MCPSecurityProxy.MAX_PAYLOAD_BYTES
        # json.dumps({"k": "x" * N}) produces '{"k": "xxx..."}' = N + 9 bytes
        # Set N so the encoded body is exactly limit bytes
        overhead = len(b'{"k": ""}')  # 9 bytes
        body = json.dumps({"k": "x" * (limit - overhead)}).encode()
        assert len(body) == limit, f"Test setup error: body is {len(body)} bytes, expected {limit}"
        result = MCPSecurityProxy.sanitize_request(body)
        assert result, "At-limit payload must be accepted (non-empty result)"

    def test_payload_over_size_limit_rejected(self) -> None:
        """Body MAX_PAYLOAD_BYTES + 1 must raise ValueError with 'too large'."""
        body = b"x" * (MCPSecurityProxy.MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(ValueError, match="too large"):
            MCPSecurityProxy.sanitize_request(body)

    def test_json_depth_at_limit_accepted(self) -> None:
        """JSON nesting exactly at MAX_JSON_DEPTH must be accepted."""
        def nest(depth: int) -> Any:
            if depth == 0:
                return "leaf"
            return {"k": nest(depth - 1)}

        # _json_depth starts counting at _current=1 and increments per level,
        # so nest(N) produces a structure with _json_depth == N + 1.
        # To hit exactly MAX_JSON_DEPTH we therefore nest MAX_JSON_DEPTH - 1 times.
        data = nest(MCPSecurityProxy.MAX_JSON_DEPTH - 1)
        body = json.dumps(data).encode()
        result = MCPSecurityProxy.sanitize_request(body)
        assert result  # non-empty bytes

    def test_json_depth_over_limit_rejected(self) -> None:
        """JSON nesting MAX_JSON_DEPTH + 1 must raise ValueError."""
        def nest(depth: int) -> Any:
            if depth == 0:
                return "leaf"
            return {"k": nest(depth - 1)}

        # nest(MAX_JSON_DEPTH) produces _json_depth == MAX_JSON_DEPTH + 1, which exceeds the limit.
        data = nest(MCPSecurityProxy.MAX_JSON_DEPTH)
        body = json.dumps(data).encode()
        with pytest.raises(ValueError, match="depth"):
            MCPSecurityProxy.sanitize_request(body)

    @pytest.mark.asyncio
    async def test_sql_injection_in_tool_name_reaches_policy(
        self, proxy: MCPSecurityProxy
    ) -> None:
        """SQL injection in tool_name is forwarded unchanged — proxy does not sanitize params.

        This is documented behaviour (proxy is transport-layer, not WAF).
        """
        sqli_tool = "'; DROP TABLE agents; --"
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": sqli_tool, "arguments": {}},
            "id": 1,
        }).encode()
        result, _ = await proxy.handle_jsonrpc(body, {"x-agent-name": "agent"})
        # Should forward (or block via policy), not crash
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_path_traversal_in_tool_params_forwarded(
        self, proxy: MCPSecurityProxy
    ) -> None:
        """Path traversal in params.arguments is forwarded to upstream — proxy does not sanitize.

        Documented info finding: upstream MCP server must handle this.
        """
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
            "id": 1,
        }).encode()
        result, _ = await proxy.handle_jsonrpc(body, {"x-agent-name": "agent"})
        assert isinstance(result, dict)

    def test_batch_request_rejected(self) -> None:
        """JSON array (batch request) must be rejected — not a dict."""
        body = json.dumps([
            {"jsonrpc": "2.0", "method": "tools/call", "id": 1},
        ]).encode()
        with pytest.raises(ValueError, match="object"):
            MCPSecurityProxy.parse_jsonrpc(body)

    def test_huge_id_blocked_by_size_limit(self) -> None:
        """A request whose id is a 6MB string must be blocked by MAX_PAYLOAD_BYTES."""
        huge_id = "x" * (MCPSecurityProxy.MAX_PAYLOAD_BYTES + 1)
        body = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": huge_id}).encode()
        with pytest.raises(ValueError, match="too large"):
            MCPSecurityProxy.sanitize_request(body)


# ---------------------------------------------------------------------------
# 6. Path traversal attacks (ASGI layer)
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """Attack serve_frontend() via real HTTP through the ASGI stack.

    Requires monkeypatching module-level DASHBOARD_DIR and re-creating the app
    inside each test, because route registration happens at create_app() time.
    """

    @pytest.fixture
    def dashboard_app(self, tmp_path: Path, monkeypatch: Any) -> Any:
        """Create a minimal dashboard directory and a patched FastAPI app."""
        import navil.api.local.app as app_module

        (tmp_path / "index.html").write_text("<html>index</html>")
        (tmp_path / "style.css").write_text("body{color:red}")
        # create_app mounts DASHBOARD_DIR/assets as a StaticFiles directory
        (tmp_path / "assets").mkdir()
        monkeypatch.setattr(app_module, "DASHBOARD_DIR", tmp_path)
        app = app_module.create_app(with_demo=False)
        # Guard: verify serve_frontend catch-all route was actually registered
        assert any("{path" in getattr(r, "path", "") for r in app.routes), (
            "serve_frontend route not registered — DASHBOARD_DIR patch may have failed"
        )
        return app

    @pytest.mark.asyncio
    async def test_dotdot_slash_blocked(self, dashboard_app: Any) -> None:
        """../../etc/passwd must serve index.html, not the actual file."""
        import httpx
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app), base_url="http://test"
        ) as client:
            resp = await client.get("/../../etc/passwd")
        assert resp.status_code == 200
        assert "<html>index</html>" in resp.text, "Path traversal served non-index content"

    @pytest.mark.asyncio
    async def test_valid_file_served(self, dashboard_app: Any) -> None:
        """A legitimate file inside DASHBOARD_DIR must be served normally."""
        import httpx
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app), base_url="http://test"
        ) as client:
            resp = await client.get("/style.css")
        assert resp.status_code == 200
        assert "color:red" in resp.text

    @pytest.mark.asyncio
    async def test_nonexistent_file_spa_fallback(self, dashboard_app: Any) -> None:
        """A non-existent path must fall back to index.html (SPA routing)."""
        import httpx
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app), base_url="http://test"
        ) as client:
            resp = await client.get("/some/unknown/deep/route")
        assert resp.status_code == 200
        assert "<html>index</html>" in resp.text

    @pytest.mark.asyncio
    async def test_symlink_outside_root_blocked(self, dashboard_app: Any) -> None:
        """A symlink from inside DASHBOARD_DIR pointing outside must be blocked."""
        import navil.api.local.app as app_module

        # DASHBOARD_DIR is the monkeypatched tmp_path from the dashboard_app fixture
        dashboard_dir = app_module.DASHBOARD_DIR
        evil_link = dashboard_dir / "evil_link"
        evil_link.symlink_to("/etc")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app), base_url="http://test"
        ) as client:
            resp = await client.get("/evil_link/passwd")
        assert resp.status_code == 200
        assert "<html>index</html>" in resp.text, (
            "Symlink traversal outside root was not blocked"
        )

    @pytest.mark.asyncio
    async def test_dotdot_in_middle_blocked(self, dashboard_app: Any) -> None:
        """assets/../../etc/passwd must serve index.html.

        Note: Starlette normalizes the URL path before routing, collapsing the
        '..' segments into 'etc/passwd'. The traversal guard in serve_frontend
        then also catches it, but this test primarily validates Starlette's
        built-in normalization as the first line of defence.
        """
        import httpx
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=dashboard_app), base_url="http://test"
        ) as client:
            resp = await client.get("/assets/../../etc/passwd")
        assert resp.status_code == 200
        assert "<html>index</html>" in resp.text


# ---------------------------------------------------------------------------
# 7. CORS behavior attacks (ASGI layer)
# ---------------------------------------------------------------------------


class TestCORSBehavior:
    """Verify CORS headers via real HTTP through the ASGI stack.

    Module-level _allow_origins and _allow_credentials are monkeypatched
    because they are evaluated at import time from os.environ.
    """

    def _make_cors_app(self, monkeypatch: Any, origins: list[str], credentials: bool) -> Any:
        import navil.api.local.app as app_module
        monkeypatch.setattr(app_module, "_allow_origins", origins)
        monkeypatch.setattr(app_module, "_allow_credentials", credentials)
        return app_module.create_app(with_demo=False)

    @pytest.mark.asyncio
    async def test_wildcard_origin_no_credentials_header(self, monkeypatch: Any) -> None:
        """With allow_origins=['*'] and allow_credentials=False, response must not
        include Access-Control-Allow-Credentials: true."""
        app = self._make_cors_app(monkeypatch, ["*"], False)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/local/overview", headers={"Origin": "http://evil.com"})
        credentials_header = resp.headers.get("access-control-allow-credentials", "")
        assert credentials_header.lower() != "true", (
            "CORS: credentials must not be sent with wildcard origin"
        )

    @pytest.mark.asyncio
    async def test_explicit_origin_sends_credentials(self, monkeypatch: Any) -> None:
        """With explicit origin and allow_credentials=True, response includes credentials header."""
        app = self._make_cors_app(monkeypatch, ["http://localhost:8484"], True)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/local/overview", headers={"Origin": "http://localhost:8484"}
            )
        credentials_header = resp.headers.get("access-control-allow-credentials", "")
        assert credentials_header.lower() == "true"

    @pytest.mark.asyncio
    async def test_wrong_origin_blocked(self, monkeypatch: Any) -> None:
        """With explicit origin list, a different origin must not get CORS headers."""
        app = self._make_cors_app(monkeypatch, ["http://localhost:8484"], True)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/local/overview", headers={"Origin": "http://evil.com"}
            )
        # No Access-Control-Allow-Origin for an unrecognised origin
        acao = resp.headers.get("access-control-allow-origin", "")
        assert acao != "http://evil.com", "Evil origin must not be allowed"

    @pytest.mark.asyncio
    async def test_space_only_origins_edge_case(self, monkeypatch: Any) -> None:
        """EDGE CASE: _allow_origins=[] (from ' ' env) + _allow_credentials=True.

        Empty origins list blocks all cross-origin requests — credentials setting
        is irrelevant. No CORS allow header should be present.
        """
        app = self._make_cors_app(monkeypatch, [], True)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/local/overview", headers={"Origin": "http://any.com"}
            )
        acao = resp.headers.get("access-control-allow-origin", "")
        assert not acao, "No origin should be allowed when origins list is empty"


# ---------------------------------------------------------------------------
# 8. Novel vulnerabilities (not covered by the 6 hardening fixes)
# ---------------------------------------------------------------------------


class TestNewVulnerabilities:
    """Attack surfaces discovered during the audit that weren't fixed yet."""

    def test_rate_limit_key_collision_confirmed(self) -> None:
        """FINDING (Medium): Colon-separated key format allows cross-agent bucket sharing.

        agent='a:b' + tool='c'  →  key 'a:b:c'
        agent='a'   + tool='b:c' →  key 'a:b:c'  (same!)

        One agent can exhaust another agent's rate limit.
        """
        engine = PolicyEngine()
        engine.policy = {
            "agents": {
                # Both agents have the same limit so the collision is visible:
                # "a:b" exhausts the shared "a:b:c" bucket (2 calls),
                # leaving "a" with 0 remaining calls in that bucket.
                "a:b": {"tools_allowed": ["*"], "rate_limit_per_hour": 2},
                "a": {"tools_allowed": ["*"], "rate_limit_per_hour": 2},
            },
            "tools": {
                "c": {"allowed_actions": ["*"]},
                "b:c": {"allowed_actions": ["*"]},
            },
        }
        # Exhaust "a:b"'s limit using tool "c" (fills key "a:b:c" counter to 2)
        engine.check_tool_call("a:b", "c", "tools/call")
        engine.check_tool_call("a:b", "c", "tools/call")

        # "a" calling "b:c" has its own limit=2 and should be allowed in isolation.
        # But due to key collision ("a:b:c" == "a:b:c"), the shared counter=2 >= 2 → blocked.
        # Per the file header: a pytest FAILURE here = CONFIRMED FINDING.
        allowed, _ = engine.check_tool_call("a", "b:c", "tools/call")
        assert allowed is True, (
            "CONFIRMED FINDING: rate limit key collision — "
            "agent 'a' blocked by agent 'a:b' exhausting shared key 'a:b:c'"
        )

    def test_x_agent_name_no_length_limit(self) -> None:
        """FINDING (Low): X-Agent-Name has no length constraint when require_auth=False.

        A 10,000-char agent name is accepted and would be stored in traffic logs.
        """
        proxy = _make_proxy(require_auth=False)
        huge_name = "a" * 10_000
        result = proxy.extract_agent_name({"x-agent-name": huge_name})
        assert result == huge_name, (
            "FINDING: X-Agent-Name has no length limit — 10,000-char name accepted verbatim"
        )

    def test_x_agent_name_newline_log_injection(self) -> None:
        """FINDING (Low): Newlines in X-Agent-Name enable log injection.

        The newline is stored in the traffic log agent field without sanitization.
        """
        proxy = _make_proxy(require_auth=False)
        injected = "admin\nX-Injected: injected-header-value"
        result = proxy.extract_agent_name({"x-agent-name": injected})
        assert result == injected, (
            "FINDING: newline in X-Agent-Name accepted — enables log/header injection"
        )

    def test_jwt_expiry_not_enforced_via_proxy_hmac_path(self) -> None:
        """FINDING (High): Proxy auth falls back to hmac.compare_digest, bypassing JWT expiry.

        issue_credential() produces ISO iat/exp → jwt.decode() always fails →
        proxy uses plaintext token comparison → expired tokens still authenticate.

        This test uses the actual proxy flow (extract_agent_name), not verify_credential.
        """
        cm = CredentialManager()
        # Issue a credential with a very short TTL (conceptually expired)
        cred_info = cm.issue_credential("expiry-test-agent", "read:tools", ttl_seconds=1)
        token = cred_info["token"]

        # The token is in cm.credentials as ACTIVE
        # The proxy never checks JWT exp because verify_credential() always raises first

        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=PolicyEngine(),
            anomaly_detector=BehavioralAnomalyDetector(),  # redis_client=None is safe
            credential_manager=cm,
            require_auth=True,
        )

        # Authenticate using the real proxy path
        result = proxy.extract_agent_name({"authorization": f"Bearer {token}"})
        assert result == "expiry-test-agent", (
            "FINDING: proxy accepts token despite broken JWT verification — "
            "expiry is never checked; auth works via plaintext hmac.compare_digest"
        )

    def test_anonymous_identity_via_x_agent_name(self) -> None:
        """FINDING (Medium): A caller can claim identity 'anonymous' via X-Agent-Name.

        Caller-controlled values appear in audit logs as 'anonymous', indistinguishable
        from truly unauthenticated requests — non-repudiation failure.
        """
        proxy = _make_proxy(require_auth=False)
        # No header — becomes "anonymous" in handle_jsonrpc
        result_none = proxy.extract_agent_name({})
        # Explicit claim
        result_claimed = proxy.extract_agent_name({"x-agent-name": "anonymous"})
        # Both return the same thing from extract_agent_name perspective
        # (handle_jsonrpc converts None to "anonymous" — we document the ambiguity)
        assert result_none is None  # actual return; handle_jsonrpc adds the label
        assert result_claimed == "anonymous"


# ---------------------------------------------------------------------------
# 9. Policy enforcement bypass (Critical Finding)
# ---------------------------------------------------------------------------


class TestPolicyBypass:
    """Critical finding: the proxy's DENY check is structurally broken.

    check_tool_call() returns tuple[bool, str].
    proxy.handle_jsonrpc() checks hasattr(decision, "decision") — False for tuple.
    Falls back to str(decision) which produces "(False, ...)", never equal to "DENY".
    Every policy DENY is silently ignored; forbidden tools are forwarded.
    """

    @pytest.mark.asyncio
    async def test_tools_denied_bypassed_in_proxy_hot_path(self, fake_redis: Any) -> None:
        """FINDING (Critical): tools_denied not enforced in proxy hot path.

        Expected: handle_jsonrpc returns JSON-RPC error code -32001 (Blocked by policy).
        Actual:   request is forwarded to upstream; no error is returned.
        """
        engine = PolicyEngine()
        engine.policy = {
            "agents": {
                "agent-x": {
                    "tools_allowed": ["*"],
                    "tools_denied": ["forbidden_tool"],
                }
            },
            "tools": {"forbidden_tool": {"allowed_actions": ["*"]}},
        }
        detector = BehavioralAnomalyDetector(redis_client=fake_redis)
        proxy = MCPSecurityProxy(
            target_url="http://localhost:3000",
            policy_engine=engine,
            anomaly_detector=detector,
            credential_manager=CredentialManager(),
            require_auth=False,
        )
        upstream = {"jsonrpc": "2.0", "result": {"content": "secret"}, "id": 1}
        proxy._forward = _mock_forward(upstream)

        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "forbidden_tool", "arguments": {}},
            "id": 1,
        }).encode()

        result, _ = await proxy.handle_jsonrpc(body, {"x-agent-name": "agent-x"})
        assert result.get("error", {}).get("code") == -32001, (
            "CONFIRMED CRITICAL FINDING: tools_denied not enforced in proxy hot path — "
            "forbidden_tool was forwarded to upstream instead of blocked. "
            "Root cause: check_tool_call() returns tuple[bool, str]; "
            "proxy checks hasattr(tuple, 'decision') == False; "
            "falls back to str((False, ...)) which never equals 'DENY'."
        )

    def test_policy_deny_return_type_causes_bypass(self) -> None:
        """Documents the root cause: str(tuple) != 'DENY' is always True."""
        engine = PolicyEngine()
        engine.policy = {
            "agents": {"agent-x": {"tools_denied": ["forbidden_tool"]}},
            "tools": {},
        }
        decision = engine.check_tool_call("agent-x", "forbidden_tool", "tools/call")
        assert isinstance(decision, tuple)
        allowed, _ = decision
        assert allowed is False
        # The proxy compares str(decision) to "DENY" — this is always False
        assert str(decision) != "DENY"


# ---------------------------------------------------------------------------
# 10. Unauthenticated credential management endpoints (Critical Finding)
# ---------------------------------------------------------------------------


class TestUnauthenticatedEndpoints:
    """Critical finding: /api/local/credentials has zero authentication guards.

    Any caller on localhost can list, issue, and revoke agent credentials.
    """

    @pytest.fixture
    def local_api_app(self, tmp_path: Path, monkeypatch: Any) -> Any:
        """Minimal local dashboard app with a fresh AppState."""
        import navil.api.local.app as app_module
        from navil.api.local.state import AppState

        AppState.reset()
        (tmp_path / "assets").mkdir()
        (tmp_path / "index.html").write_text("<html>test</html>")
        monkeypatch.setattr(app_module, "DASHBOARD_DIR", tmp_path)
        app = app_module.create_app(with_demo=False)
        yield app
        AppState.reset()

    @pytest.mark.asyncio
    async def test_list_credentials_no_auth(self, local_api_app: Any) -> None:
        """FINDING (Critical): GET /api/local/credentials requires no authentication."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=local_api_app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/local/credentials")
        assert resp.status_code == 401, (
            f"CONFIRMED CRITICAL FINDING: GET /api/local/credentials returned "
            f"{resp.status_code} (expected 401) — "
            "unauthenticated callers can enumerate all agent credentials"
        )

    @pytest.mark.asyncio
    async def test_issue_credential_no_auth(self, local_api_app: Any) -> None:
        """FINDING (Critical): POST /api/local/credentials issues credentials without auth."""
        payload = {"agent_name": "attacker", "scope": "*", "ttl_seconds": 86400}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=local_api_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/local/credentials", json=payload)
        assert resp.status_code == 401, (
            f"CONFIRMED CRITICAL FINDING: POST /api/local/credentials returned "
            f"{resp.status_code} (expected 401) — "
            "unauthenticated callers can issue credentials with arbitrary scope"
        )

    @pytest.mark.asyncio
    async def test_revoke_credential_no_auth(self, local_api_app: Any) -> None:
        """FINDING (Critical): DELETE /api/local/credentials/{id} needs no auth.

        An unauthenticated attacker can perform a denial-of-service attack by
        revoking all active agent credentials.
        """
        from navil.api.local.state import AppState

        state = AppState.get()
        cred = state.credential_manager.issue_credential("victim-agent", "*")
        token_id = cred["token_id"]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=local_api_app), base_url="http://test"
        ) as client:
            resp = await client.delete(f"/api/local/credentials/{token_id}")
        assert resp.status_code == 401, (
            f"CONFIRMED CRITICAL FINDING: DELETE /api/local/credentials/{token_id} "
            f"returned {resp.status_code} (expected 401) — "
            "unauthenticated attacker can revoke any agent credential (DoS)"
        )


# ---------------------------------------------------------------------------
# 11. Resource exhaustion and rate-limit edge cases (High / Medium Findings)
# ---------------------------------------------------------------------------


class TestResourceExhaustion:
    """High/Medium findings: unbounded resource growth and rate-limit edge cases."""

    def test_unbounded_credential_issuance(self) -> None:
        """FINDING (High): CredentialManager has no per-agent or global issuance cap.

        An attacker or runaway agent can issue unlimited credentials, growing
        in-process memory without bound.

        Expected: some cap limits issuance before 1,000 credentials.
        Actual:   all 1,000 succeed — no limit enforced.
        """
        cm = CredentialManager()
        for i in range(1000):
            cm.issue_credential(f"agent-{i % 10}", "read:tools")
        assert len(cm.credentials) < 1000, (
            f"CONFIRMED HIGH FINDING: issued {len(cm.credentials)} credentials with no cap — "
            "CredentialManager grows unbounded (no per-agent or global issuance limit)"
        )

    def test_zero_rate_limit_blocks_first_call(self) -> None:
        """FINDING (Medium): rate_limit_per_hour=0 blocks every call, including the first.

        _check_rate_limit: count(0) >= rate_limit(0) → True on the very first call.
        Operators expecting 0 = unlimited get the opposite: total traffic block.
        """
        engine = PolicyEngine()
        engine.policy = {
            "agents": {"agent": {"tools_allowed": ["*"], "rate_limit_per_hour": 0}},
            "tools": {"tool": {"allowed_actions": ["*"]}},
        }
        allowed, _ = engine.check_tool_call("agent", "tool", "tools/call")
        assert allowed is True, (
            "CONFIRMED MEDIUM FINDING: rate_limit_per_hour=0 blocks the first call "
            "(count=0 >= rate_limit=0 is True). "
            "Setting rate_limit_per_hour=0 to mean 'unlimited' blocks all traffic."
        )

    def test_registered_tools_unbounded_growth(self) -> None:
        """FINDING (Medium): register_server_tools() stores all tool names without a size cap.

        A malicious tools/list response with 10,000 tool names stores all of them
        in registered_tools, growing detector memory without bound.
        """
        detector = BehavioralAnomalyDetector()
        large_toolset = [f"tool_{i}" for i in range(10_000)]
        detector.register_server_tools("http://malicious:3000", large_toolset)
        stored = detector.registered_tools.get("http://malicious:3000", set())
        assert len(stored) <= 1_000, (
            f"CONFIRMED MEDIUM FINDING: register_server_tools stored {len(stored)} tool names — "
            "no size cap enforced on registered_tools (expected ≤ 1,000 to bound memory)"
        )


# ---------------------------------------------------------------------------
# 12. Credential rotation edge cases (High Finding)
# ---------------------------------------------------------------------------


class TestRotationEdgeCases:
    """High finding: rotate_credential has a negative-TTL bug and a TOCTOU race."""

    def test_rotate_already_expired_credential_gets_negative_ttl(self) -> None:
        """FINDING (High): rotating an expired credential passes negative TTL to issue_credential.

        rotate_credential computes: ttl = int((expires_at - now).total_seconds())
        If expires_at is in the past, ttl is negative.
        issue_credential silently stores a credential born already expired.
        """
        from datetime import datetime, timedelta, timezone

        cm = CredentialManager()
        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        token_id = cred["token_id"]

        # Backdate expires_at by 7,200 s (expired 2 hours ago)
        stored = cm.credentials[token_id]
        past_expiry = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
        stored.expires_at = past_expiry

        try:
            new_cred = cm.rotate_credential(token_id)
            new_stored = cm.credentials[new_cred["token_id"]]
            new_expires = datetime.fromisoformat(new_stored.expires_at)
            now = datetime.now(timezone.utc)
            assert new_expires > now, (
                "CONFIRMED HIGH FINDING: rotating an expired credential creates a "
                "new credential that is already expired at birth "
                f"(expires_at={new_stored.expires_at})"
            )
        except ValueError:
            pytest.skip("rotate_credential raised ValueError — finding partially mitigated")

    def test_concurrent_rotation_creates_duplicate_active(self) -> None:
        """FINDING (High): rotate_credential has a TOCTOU race.

        Two concurrent threads can both read status=ACTIVE and both call
        issue_credential, creating two simultaneously ACTIVE replacements.
        The original credential is then marked EXPIRED twice (idempotent),
        but both new credentials remain ACTIVE.
        """
        cm = CredentialManager()
        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        token_id = cred["token_id"]
        results: list[dict[str, Any]] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def rotate() -> None:
            try:
                result = cm.rotate_credential(token_id)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append(e)

        t1 = threading.Thread(target=rotate)
        t2 = threading.Thread(target=rotate)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if len(results) == 2:
            # Both rotations succeeded — count ACTIVE credentials for agent-a
            active = [
                v for v in cm.credentials.values()
                if v.agent_name == "agent-a" and v.status == CredentialStatus.ACTIVE
            ]
            assert len(active) <= 1, (
                "CONFIRMED HIGH FINDING: concurrent rotation created "
                f"{len(active)} ACTIVE credentials for the same agent — "
                "TOCTOU race in rotate_credential"
            )
