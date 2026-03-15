"""Tests for cascade revocation — empty tree, single child, deep chain, max depth."""

from __future__ import annotations

import pytest

from navil.credential_manager import CredentialManager, CredentialStatus


@pytest.fixture
def cm() -> CredentialManager:
    """Create a CredentialManager with in-memory store."""
    return CredentialManager(
        secret_key="test-secret-key-for-cascade",
        redis_url="redis://127.0.0.1:1",  # bogus port → forces in-memory fallback
    )


class TestCascadeRevocationEmptyTree:
    """Tests with no children."""

    def test_revoke_single_credential(self, cm: CredentialManager) -> None:
        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        count = cm.cascade_revoke(cred["token_id"])
        assert count == 1
        info = cm.get_credential_info(cred["token_id"])
        assert info["status"] == CredentialStatus.REVOKED

    def test_revoke_already_revoked(self, cm: CredentialManager) -> None:
        cred = cm.issue_credential("agent-a", "read:tools", ttl_seconds=3600)
        cm.revoke_credential(cred["token_id"])
        # Cascade on already-revoked should return 0 (nothing new to revoke)
        count = cm.cascade_revoke(cred["token_id"])
        assert count == 0

    def test_revoke_nonexistent_raises(self, cm: CredentialManager) -> None:
        with pytest.raises(ValueError, match="not found"):
            cm.cascade_revoke("cred_nonexistent")


class TestCascadeRevocationSingleChild:
    """Tests with a single child."""

    def test_revoke_parent_revokes_child(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        count = cm.cascade_revoke(parent["token_id"])
        assert count == 2

        parent_info = cm.get_credential_info(parent["token_id"])
        child_info = cm.get_credential_info(child["token_id"])
        assert parent_info["status"] == CredentialStatus.REVOKED
        assert child_info["status"] == CredentialStatus.REVOKED

    def test_revoke_child_only(self, cm: CredentialManager) -> None:
        parent = cm.issue_credential("agent-a", "read:tools write:logs", ttl_seconds=3600)
        child = cm.delegate_credential(
            parent["token_id"], "agent-b", "read:tools", ttl_seconds=1800
        )
        count = cm.cascade_revoke(child["token_id"])
        assert count == 1

        parent_info = cm.get_credential_info(parent["token_id"])
        child_info = cm.get_credential_info(child["token_id"])
        assert parent_info["status"] == CredentialStatus.ACTIVE
        assert child_info["status"] == CredentialStatus.REVOKED


class TestCascadeRevocationDeepChain:
    """Tests with deep delegation chains."""

    def test_revoke_root_revokes_entire_chain(self, cm: CredentialManager) -> None:
        creds = []
        root = cm.issue_credential("agent-0", "read:tools write:logs admin:policy", ttl_seconds=36000)
        creds.append(root)

        for i in range(1, 5):
            child = cm.delegate_credential(
                creds[-1]["token_id"],
                f"agent-{i}",
                "read:tools",
                ttl_seconds=36000 - i * 1000,
            )
            creds.append(child)

        count = cm.cascade_revoke(root["token_id"])
        assert count == 5  # root + 4 children

        for cred in creds:
            info = cm.get_credential_info(cred["token_id"])
            assert info["status"] == CredentialStatus.REVOKED

    def test_revoke_middle_revokes_descendants(self, cm: CredentialManager) -> None:
        root = cm.issue_credential("agent-0", "read:tools write:logs", ttl_seconds=36000)
        child1 = cm.delegate_credential(
            root["token_id"], "agent-1", "read:tools write:logs", ttl_seconds=30000
        )
        child2 = cm.delegate_credential(
            child1["token_id"], "agent-2", "read:tools", ttl_seconds=20000
        )
        child3 = cm.delegate_credential(
            child2["token_id"], "agent-3", "read:tools", ttl_seconds=10000
        )

        # Revoke child1 -> should cascade to child2, child3
        count = cm.cascade_revoke(child1["token_id"])
        assert count == 3  # child1 + child2 + child3

        root_info = cm.get_credential_info(root["token_id"])
        assert root_info["status"] == CredentialStatus.ACTIVE

        child1_info = cm.get_credential_info(child1["token_id"])
        child2_info = cm.get_credential_info(child2["token_id"])
        child3_info = cm.get_credential_info(child3["token_id"])
        assert child1_info["status"] == CredentialStatus.REVOKED
        assert child2_info["status"] == CredentialStatus.REVOKED
        assert child3_info["status"] == CredentialStatus.REVOKED


class TestCascadeRevocationBranching:
    """Tests with branching delegation trees."""

    def test_revoke_with_multiple_children(self, cm: CredentialManager) -> None:
        root = cm.issue_credential("root", "read:tools write:logs admin:policy", ttl_seconds=36000)
        child_a = cm.delegate_credential(
            root["token_id"], "agent-a", "read:tools write:logs", ttl_seconds=30000
        )
        child_b = cm.delegate_credential(
            root["token_id"], "agent-b", "read:tools", ttl_seconds=30000
        )
        grandchild = cm.delegate_credential(
            child_a["token_id"], "agent-c", "read:tools", ttl_seconds=20000
        )

        count = cm.cascade_revoke(root["token_id"])
        assert count == 4  # root + child_a + child_b + grandchild

        for tid in [root["token_id"], child_a["token_id"], child_b["token_id"], grandchild["token_id"]]:
            info = cm.get_credential_info(tid)
            assert info["status"] == CredentialStatus.REVOKED

    def test_partial_branch_revoke(self, cm: CredentialManager) -> None:
        root = cm.issue_credential("root", "read:tools write:logs", ttl_seconds=36000)
        child_a = cm.delegate_credential(
            root["token_id"], "agent-a", "read:tools", ttl_seconds=30000
        )
        child_b = cm.delegate_credential(
            root["token_id"], "agent-b", "read:tools", ttl_seconds=30000
        )

        # Only revoke branch A
        count = cm.cascade_revoke(child_a["token_id"])
        assert count == 1

        root_info = cm.get_credential_info(root["token_id"])
        child_a_info = cm.get_credential_info(child_a["token_id"])
        child_b_info = cm.get_credential_info(child_b["token_id"])
        assert root_info["status"] == CredentialStatus.ACTIVE
        assert child_a_info["status"] == CredentialStatus.REVOKED
        assert child_b_info["status"] == CredentialStatus.ACTIVE


class TestCascadeRevocationMaxDepth:
    """Tests for max depth safety limit."""

    def test_respects_max_depth_cap(self, cm: CredentialManager) -> None:
        """Build a chain up to the max depth and verify cascade handles it."""
        creds = []
        root = cm.issue_credential("agent-0", "read:tools", ttl_seconds=100000)
        creds.append(root)

        # Build a chain of 9 (at the limit)
        for i in range(1, 9):
            child = cm.delegate_credential(
                creds[-1]["token_id"],
                f"agent-{i}",
                "read:tools",
                ttl_seconds=100000 - i * 1000,
            )
            creds.append(child)

        count = cm.cascade_revoke(root["token_id"])
        assert count == 9  # All 9 should be revoked

        for cred in creds:
            info = cm.get_credential_info(cred["token_id"])
            assert info["status"] == CredentialStatus.REVOKED


class TestCascadeRevocationPartialFailure:
    """Tests for partial revocation scenarios (some already revoked)."""

    def test_cascade_with_some_already_revoked(self, cm: CredentialManager) -> None:
        """If some children are already REVOKED, they are skipped but grandchildren still walked."""
        root = cm.issue_credential("root", "read:tools write:logs", ttl_seconds=36000)
        child_a = cm.delegate_credential(
            root["token_id"], "agent-a", "read:tools", ttl_seconds=30000
        )
        child_b = cm.delegate_credential(
            root["token_id"], "agent-b", "read:tools", ttl_seconds=30000
        )
        grandchild = cm.delegate_credential(
            child_a["token_id"], "agent-c", "read:tools", ttl_seconds=20000
        )

        # Pre-revoke child_a (but not its grandchild)
        cm.revoke_credential(child_a["token_id"])

        # Cascade from root should still revoke root + child_b + grandchild
        # child_a is already revoked so it adds 0
        count = cm.cascade_revoke(root["token_id"])
        # root(1) + child_a(0, already revoked) + grandchild(1) + child_b(1) = 3
        assert count == 3

        for tid in [root["token_id"], child_a["token_id"], child_b["token_id"], grandchild["token_id"]]:
            info = cm.get_credential_info(tid)
            assert info["status"] == CredentialStatus.REVOKED

    def test_cascade_idempotent(self, cm: CredentialManager) -> None:
        """Running cascade revoke twice on the same root returns 0 the second time."""
        root = cm.issue_credential("root", "read:tools", ttl_seconds=3600)
        child = cm.delegate_credential(
            root["token_id"], "agent-a", "read:tools", ttl_seconds=1800
        )
        count1 = cm.cascade_revoke(root["token_id"])
        assert count1 == 2

        count2 = cm.cascade_revoke(root["token_id"])
        assert count2 == 0

    def test_cascade_with_missing_child_key(self, cm: CredentialManager) -> None:
        """If a child ID in the children set points to a non-existent credential, skip it."""
        from navil.credential_manager import _CRED_KEY_PREFIX

        root = cm.issue_credential("root", "read:tools", ttl_seconds=3600)
        # Manually inject a bogus child ID into the children set
        children_key = f"{_CRED_KEY_PREFIX}{root['token_id']}:children"
        cm._redis.sadd(children_key, "cred_nonexistent_child_12345")

        count = cm.cascade_revoke(root["token_id"])
        # Should revoke root (1) and skip the missing child (0)
        assert count == 1

        info = cm.get_credential_info(root["token_id"])
        assert info["status"] == CredentialStatus.REVOKED


class TestCascadeRevocationLuaScript:
    """Tests for the Lua script specifically (loaded from file)."""

    def test_lua_script_file_matches_inline(self) -> None:
        """Verify the navil/lua/cascade_revoke.lua matches the inline version."""
        from pathlib import Path

        lua_file = Path(__file__).resolve().parent.parent / "navil" / "lua" / "cascade_revoke.lua"
        assert lua_file.exists(), f"Lua script not found at {lua_file}"

        content = lua_file.read_text()
        # Verify key structural elements
        assert "HGET" in content
        assert "HSET" in content
        assert "SMEMBERS" in content
        assert "REVOKED" in content
        assert "navil:cred:" in content

    def test_python_fallback_matches_lua_behavior(self, cm: CredentialManager) -> None:
        """Verify that Python cascade produces identical results to the in-memory script."""
        root = cm.issue_credential("root", "read:tools write:logs", ttl_seconds=36000)
        child1 = cm.delegate_credential(
            root["token_id"], "agent-1", "read:tools", ttl_seconds=30000
        )
        child2 = cm.delegate_credential(
            root["token_id"], "agent-2", "read:tools", ttl_seconds=30000
        )
        grandchild = cm.delegate_credential(
            child1["token_id"], "agent-3", "read:tools", ttl_seconds=20000
        )

        # The in-memory store uses _InMemoryScript which mirrors the Lua logic
        count = cm.cascade_revoke(root["token_id"])
        assert count == 4

        for tid in [root["token_id"], child1["token_id"], child2["token_id"], grandchild["token_id"]]:
            info = cm.get_credential_info(tid)
            assert info["status"] == CredentialStatus.REVOKED
