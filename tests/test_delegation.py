"""Tests for credential delegation — depth, scope subset, TTL, parent states."""

from __future__ import annotations

import time

import pytest

from navil.credential_manager import CredentialManager


@pytest.fixture
def cm() -> CredentialManager:
    """Create a CredentialManager with in-memory store."""
    return CredentialManager(
        secret_key="test-secret-key-for-delegation",
        redis_url="redis://127.0.0.1:1",  # bogus port → forces in-memory fallback
    )


class TestDelegationBasic:
    """Basic delegation tests."""

    def test_delegate_creates_child_credential(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent_credential_id=parent["token_id"],
            agent_name="agent-b",
            narrowed_scope="read:tools",
            ttl_seconds=1800,
        )
        assert child["agent_name"] == "agent-b"
        assert child["scope"] == "read:tools"
        assert child["parent_credential_id"] == parent["token_id"]
        assert child["delegation_chain"] == [parent["token_id"]]

    def test_child_inherits_human_context(self, cm: CredentialManager) -> None:
        hc = {"sub": "user123", "email": "alice@example.com", "roles": ["engineer"]}
        parent = cm.issue_credential(
            "agent-a", "read:tools write:logs", ttl_seconds=3600, human_context=hc
        )
        child = cm.delegate_credential(
            parent_credential_id=parent["token_id"],
            agent_name="agent-b",
            narrowed_scope="read:tools",
            ttl_seconds=1800,
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["human_context"] == hc

    def test_delegation_chain_builds_correctly(self, cm: CredentialManager) -> None:
        root = cm.issue_credential(
            "root-agent", "read:tools write:logs admin:policy", ttl_seconds=7200
        )
        child1 = cm.delegate_credential(
            root["token_id"], "agent-1", "read:tools write:logs", ttl_seconds=3600
        )
        child2 = cm.delegate_credential(
            child1["token_id"], "agent-2", "read:tools", ttl_seconds=1800
        )
        assert child2["delegation_chain"] == [root["token_id"], child1["token_id"]]

    def test_delegated_by_field(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("parent-agent", "read:tools", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "child-agent", "read:tools", ttl_seconds=1800
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["delegated_by"] == "parent-agent"


class TestDelegationDepth:
    """Tests for delegation depth enforcement."""

    def test_max_delegation_depth_decrements(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=7200)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=3600
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["max_delegation_depth"] == 9  # 10 - 1

    def test_custom_max_depth(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=7200)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=3600, max_depth=3
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["max_delegation_depth"] == 3

    def test_custom_max_depth_capped_by_parent(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential(
            "agent-a", "read:tools", ttl_seconds=7200, max_delegation_depth=2
        )
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=3600, max_depth=5
        )
        child_info = cm.get_credential_info(child["token_id"])
        # parent has depth=2, child gets min(2-1, 5) = 1
        assert child_info["max_delegation_depth"] == 1

    def test_depth_exhaustion_raises(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential(
            "agent-a", "read:tools", ttl_seconds=7200, max_delegation_depth=1
        )
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=3600
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["max_delegation_depth"] == 0

        with pytest.raises(ValueError, match="depth exhausted"):
            cm.delegate_credential(child["token_id"], "agent-c", "read:tools", ttl_seconds=1800)

    def test_global_depth_cap_10(self, cm: CredentialManager) -> None:
        """Build a chain of 10 and verify the 11th is rejected."""
        cred = cm.issue_credential("agent-0", "read:tools", ttl_seconds=36000)
        for i in range(1, 10):
            cred = cm.delegate_credential(
                cred["token_id"], f"agent-{i}", "read:tools", ttl_seconds=36000 - i * 100
            )
        # Chain length is now 9 (9 parents), trying to delegate the 10th
        # should fail because chain + 1 >= MAX_DELEGATION_DEPTH(10)
        with pytest.raises(ValueError, match="global cap"):
            cm.delegate_credential(cred["token_id"], "agent-10", "read:tools", ttl_seconds=100)


class TestDelegationScope:
    """Tests for scope subset enforcement."""

    def test_valid_subset_scope(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential(
            "agent-a", "read:tools write:logs admin:policy", ttl_seconds=3600
        )
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        assert child["scope"] == "read:tools"

    def test_equal_scope_allowed(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools write:logs", ttl_seconds=1800
        )
        assert child["scope"] == "read:tools write:logs"

    def test_empty_scope_allowed(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(parent["token_id"], "agent-b", "", ttl_seconds=1800)
        assert child["scope"] == ""

    def test_superset_scope_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        with pytest.raises(ValueError, match="not a subset"):
            cm.delegate_credential(
                parent["token_id"], "agent-b", "read:tools write:logs", ttl_seconds=1800
            )

    def test_disjoint_scope_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        with pytest.raises(ValueError, match="not a subset"):
            cm.delegate_credential(parent["token_id"], "agent-b", "write:logs", ttl_seconds=1800)


class TestDelegationTTL:
    """Tests for TTL enforcement in delegation."""

    def test_ttl_within_parent_allowed(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        assert child["ttl_seconds"] == 1800

    def test_ttl_exceeds_parent_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=1800)
        with pytest.raises(ValueError, match="exceeds parent's remaining TTL"):
            cm.delegate_credential(parent["token_id"], "agent-b", "read:tools", ttl_seconds=3600)


class TestDelegationParentStates:
    """Tests for parent credential state validation."""

    def test_revoked_parent_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        cm.revoke_credential(parent["token_id"])
        with pytest.raises(ValueError, match="not active"):
            cm.delegate_credential(parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800)

    def test_expired_parent_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=1)
        # Wait for expiry
        time.sleep(1.1)
        with pytest.raises(ValueError, match="expired"):
            cm.delegate_credential(parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800)

    def test_nonexistent_parent_rejected(self, cm: CredentialManager) -> None:
        with pytest.raises(ValueError, match="not found"):
            cm.delegate_credential("cred_nonexistent", "agent-b", "read:tools", ttl_seconds=1800)

    def test_inactive_parent_rejected(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        # Manually set status to INACTIVE
        from navil.credential_manager import _CRED_KEY_PREFIX

        cm._redis.hset(_CRED_KEY_PREFIX + parent["token_id"], mapping={"status": "INACTIVE"})
        with pytest.raises(ValueError, match="not active"):
            cm.delegate_credential(parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800)


class TestDelegationScopeNarrowingOnly:
    """Tests for the scope_narrowing_only field."""

    def test_scope_narrowing_only_defaults_true(self, cm: CredentialManager) -> None:
        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        info = cm.get_credential_info(cred["token_id"])
        assert info["scope_narrowing_only"] is True

    def test_scope_narrowing_only_inherited_by_child(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        child_info = cm.get_credential_info(child["token_id"])
        assert child_info["scope_narrowing_only"] is True

    def test_scope_narrowing_only_serialization_roundtrip(self, cm: CredentialManager) -> None:
        """Verify the field survives Redis hash serialization/deserialization."""
        from navil.credential_manager import Credential, _credential_to_hash, _hash_to_credential

        cred = Credential(
            token_id="test-id",
            agent_name="agent-a",
            scope="read:tools",
            token="fake-token",
            issued_at="2026-03-16T00:00:00+00:00",
            expires_at="2026-03-16T01:00:00+00:00",
            status="ACTIVE",
            scope_narrowing_only=True,
        )
        h = _credential_to_hash(cred)
        assert h["scope_narrowing_only"] == "1"

        restored = _hash_to_credential(h)
        assert restored.scope_narrowing_only is True

        # Test False value
        cred.scope_narrowing_only = False
        h2 = _credential_to_hash(cred)
        assert h2["scope_narrowing_only"] == "0"
        restored2 = _hash_to_credential(h2)
        assert restored2.scope_narrowing_only is False


class TestDelegationChildrenTracking:
    """Tests that parent-children index is maintained in Redis."""

    def test_children_set_populated(self, cm: CredentialManager) -> None:
        from navil.credential_manager import _CRED_KEY_PREFIX

        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child1 = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        child2 = cm.delegate_credential(
            parent["token_id"], "agent-c", "read:tools", ttl_seconds=1800
        )
        children_key = f"{_CRED_KEY_PREFIX}{parent['token_id']}:children"
        children = cm._redis.smembers(children_key)
        assert child1["token_id"] in children
        assert child2["token_id"] in children
        assert len(children) == 2

    def test_children_set_empty_for_leaf(self, cm: CredentialManager) -> None:
        from navil.credential_manager import _CRED_KEY_PREFIX

        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        children_key = f"{_CRED_KEY_PREFIX}{cred['token_id']}:children"
        children = cm._redis.smembers(children_key)
        assert len(children) == 0


class TestDelegationJWT:
    """Tests that JWT payload contains delegation fields."""

    def test_jwt_contains_delegation_fields(self, cm: CredentialManager) -> None:
        import jwt as pyjwt

        parent = cm.issue_credential(
            "agent-a",
            "read:tools write:logs",
            ttl_seconds=3600,
            human_context={"sub": "user1", "email": "a@b.com", "roles": ["admin"]},
        )
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        # Load the child credential and decode its JWT
        # iat/exp are ISO strings (not numeric), so disable those checks
        child_cred = cm._load_credential(child["token_id"])
        payload = pyjwt.decode(
            child_cred.token,
            cm.secret_key,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_iat": False},
        )
        assert payload["human_context"] == {"sub": "user1", "email": "a@b.com", "roles": ["admin"]}
        assert payload["delegation_chain"] == [parent["token_id"]]
        assert payload["parent_credential_id"] == parent["token_id"]
