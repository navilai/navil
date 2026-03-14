"""Adversarial QA test suite — red-team tests for Navil security controls.

Each test is written to EXPECT the security control to hold.
A pytest FAILURE = a confirmed security finding.
"""
from __future__ import annotations

import base64
import hmac
import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.api.local.routes import (
    AutoRemediateRequest,
    CredentialIssueRequest,
    FeedbackRequest,
    InvocationRequest,
    LLMConfigRequest,
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
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
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
                    "allowed_tools": ["*"],
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
                "a:b": {"allowed_tools": ["*"], "rate_limit_per_hour": 3},
                "a": {"allowed_tools": ["*"], "rate_limit_per_hour": 3},
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
        engine.rate_limits[key]["reset_at"] -= 3601

        allowed, _ = engine.check_tool_call("limited-agent", "tool", "tools/call")
        assert allowed is True, "Must be allowed after hour window resets"
