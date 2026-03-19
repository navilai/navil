"""Tests for the CredentialManager module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from navil.credential_manager import CredentialManager, CredentialStatus

# ---------------------------------------------------------------------------
# Try to use fakeredis so tests exercise the real Redis-hash code path
# rather than the _InMemoryStore fallback.
# ---------------------------------------------------------------------------
try:
    import fakeredis

    _FAKEREDIS_AVAILABLE = True
except ImportError:
    _FAKEREDIS_AVAILABLE = False


def _make_manager(
    audit_log_path: str | None = None,
    secret_key: str = "",
    redis_client: object | None = None,
) -> CredentialManager:
    """Create a CredentialManager backed by fakeredis (if available) or in-memory."""
    cm = CredentialManager(
        secret_key=secret_key,
        audit_log_path=audit_log_path,
    )
    # Inject a fakeredis client so we get full Redis-hash coverage without a server
    if redis_client is not None:
        cm._redis = redis_client
    elif _FAKEREDIS_AVAILABLE:
        cm._redis = fakeredis.FakeRedis(decode_responses=True)
    return cm


@pytest.fixture
def cm(tmp_path) -> CredentialManager:
    """CredentialManager with audit log in tmp dir."""
    return _make_manager(audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def cm_no_log() -> CredentialManager:
    """CredentialManager with no audit log (in-memory only)."""
    return _make_manager()


def test_issue_credential(cm: CredentialManager) -> None:
    """Issue a credential and verify all returned fields."""
    result = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
    assert result["agent_name"] == "agent-a"
    assert result["scope"] == "read:tools"
    assert result["token_id"].startswith("cred_")
    assert "token" in result
    assert result["ttl_seconds"] == 3600


def test_revoke_credential(cm: CredentialManager) -> None:
    """Revoke an active credential."""
    cred = cm.issue_credential("agent-a", "read:tools")
    assert cm.revoke_credential(cred["token_id"]) is True
    info = cm.get_credential_info(cred["token_id"])
    assert info["status"] == CredentialStatus.REVOKED


def test_revoke_nonexistent_raises(cm: CredentialManager) -> None:
    """Revoking a nonexistent token raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        cm.revoke_credential("cred_nonexistent")


def test_rotate_credential(cm: CredentialManager) -> None:
    """Rotate a credential: old one expires, new one is active."""
    old = cm.issue_credential("agent-a", "read:tools", ttl_seconds=7200)
    new = cm.rotate_credential(old["token_id"])
    assert new["token_id"] != old["token_id"]
    old_info = cm.get_credential_info(old["token_id"])
    assert old_info["status"] == CredentialStatus.EXPIRED


def test_rotate_revoked_raises(cm: CredentialManager) -> None:
    """Cannot rotate a revoked credential."""
    cred = cm.issue_credential("agent-a", "read:tools")
    cm.revoke_credential(cred["token_id"])
    with pytest.raises(ValueError, match="Cannot rotate revoked"):
        cm.rotate_credential(cred["token_id"])


def test_list_credentials_filters(cm: CredentialManager) -> None:
    """List credentials with agent and status filters."""
    cm.issue_credential("agent-a", "read:tools")
    cm.issue_credential("agent-b", "write:tools")
    assert len(cm.list_credentials(agent_name="agent-a")) == 1
    assert len(cm.list_credentials()) == 2
    assert len(cm.list_credentials(status="ACTIVE")) == 2


def test_record_usage(cm: CredentialManager) -> None:
    """Recording usage increments the used_count."""
    cred = cm.issue_credential("agent-a", "read:tools")
    cm.record_usage(cred["token_id"])
    cm.record_usage(cred["token_id"])
    info = cm.get_credential_info(cred["token_id"])
    assert info["used_count"] == 2


def test_audit_log_written(cm: CredentialManager, tmp_path) -> None:
    """Audit log file contains entries after operations."""
    cm.issue_credential("agent-a", "read:tools")
    log_path = tmp_path / "audit.log"
    assert log_path.exists()
    content = log_path.read_text()
    assert "issued" in content


def test_rotation_policy(cm: CredentialManager) -> None:
    """Set rotation policy and check rotation needed."""
    cred = cm.issue_credential("agent-a", "read:tools")
    cm.set_rotation_policy("agent-a", rotate_after_days=0, max_age_days=30)
    needs = cm.check_rotation_needed()
    assert cred["token_id"] in needs


def test_cleanup_expired(cm: CredentialManager) -> None:
    """Cleanup removes old expired/revoked credentials."""
    cred = cm.issue_credential("agent-a", "read:tools")
    cm.revoke_credential(cred["token_id"])
    # Force the issued_at to 91 days ago to trigger cleanup
    stored = cm.credentials[cred["token_id"]]
    old_time = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
    stored.issued_at = old_time
    # Write the modified credential back to the store
    cm._store_credential(stored)
    removed = cm.cleanup_expired()
    assert removed == 1


def test_no_log_path(cm_no_log: CredentialManager) -> None:
    """CredentialManager works without audit log path."""
    result = cm_no_log.issue_credential("agent-a", "read:tools")
    assert "token" in result


def test_get_credential_info_nonexistent(cm: CredentialManager) -> None:
    """Getting info for nonexistent credential returns empty dict."""
    assert cm.get_credential_info("cred_nonexistent") == {}


def test_default_secret_key_has_sufficient_entropy() -> None:
    """Auto-generated secret key must have at least 64 bytes of entropy.

    secrets.token_urlsafe(n) produces a base64url string of length ceil(n * 4/3).
    64 bytes -> at least 86 characters.
    """
    cm = _make_manager()
    assert len(cm.secret_key) >= 86, (
        f"Secret key too short: {len(cm.secret_key)} chars (need >=86 for 64 bytes entropy)"
    )


def test_token_id_has_sufficient_entropy() -> None:
    """Token IDs must be long enough to prevent collision attacks at scale."""
    cm = _make_manager()
    cred = cm.issue_credential("agent-x", "read:tools")
    token_id = cred["token_id"]
    # cred_{32 hex bytes} = "cred_" (5 chars) + 64 hex chars
    assert token_id.startswith("cred_")
    hex_part = token_id[len("cred_") :]
    assert len(hex_part) == 64, (
        f"Token ID hex part too short: {len(hex_part)} chars (need 64 for 256-bit)"
    )


def test_credentials_survive_reinitialization() -> None:
    """Credentials stored in Redis persist across CredentialManager instances.

    This verifies the core motivation for the Redis migration: data survives
    a process restart (simulated by creating a second CredentialManager that
    shares the same backing store).
    """
    if _FAKEREDIS_AVAILABLE:
        # Both managers share the same fakeredis server instance
        shared_redis = fakeredis.FakeRedis(decode_responses=True)
    else:
        # Fallback: share the same _InMemoryStore instance
        from navil.credential_manager import _InMemoryStore

        shared_redis = _InMemoryStore()

    secret = "shared-secret-for-test"

    cm1 = _make_manager(secret_key=secret, redis_client=shared_redis)
    cred = cm1.issue_credential("agent-persist", "read:tools", ttl_seconds=7200)
    token_id = cred["token_id"]

    # Simulate restart — new manager, same store
    cm2 = _make_manager(secret_key=secret, redis_client=shared_redis)

    info = cm2.get_credential_info(token_id)
    assert info != {}, "Credential should survive re-initialization"
    assert info["agent_name"] == "agent-persist"
    assert info["scope"] == "read:tools"
    assert info["status"] == CredentialStatus.ACTIVE

    # Operations on the "new" manager should work against the persisted credential
    cm2.record_usage(token_id)
    info2 = cm2.get_credential_info(token_id)
    assert info2["used_count"] == 1
