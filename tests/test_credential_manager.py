"""Tests for the CredentialManager module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from navil.credential_manager import CredentialManager, CredentialStatus


@pytest.fixture
def cm(tmp_path) -> CredentialManager:
    """CredentialManager with audit log in tmp dir."""
    return CredentialManager(audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def cm_no_log() -> CredentialManager:
    """CredentialManager with no audit log (in-memory only)."""
    return CredentialManager()


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
    64 bytes → at least 86 characters.
    """
    cm = CredentialManager()
    assert len(cm.secret_key) >= 86, (
        f"Secret key too short: {len(cm.secret_key)} chars (need ≥86 for 64 bytes entropy)"
    )


def test_token_id_has_sufficient_entropy() -> None:
    """Token IDs must be long enough to prevent collision attacks at scale."""
    cm = CredentialManager()
    cred = cm.issue_credential("agent-x", "read:tools")
    token_id = cred["token_id"]
    # cred_{32 hex bytes} = "cred_" (5 chars) + 64 hex chars
    assert token_id.startswith("cred_")
    hex_part = token_id[len("cred_"):]
    assert len(hex_part) == 64, (
        f"Token ID hex part too short: {len(hex_part)} chars (need 64 for 256-bit)"
    )
