"""Tests for the community threat intelligence consumer."""
from __future__ import annotations

import os
from typing import Any

import pytest

from navil.adaptive.pattern_store import LearnedPattern, PatternStore
from navil.threat_intel import ThreatIntelConsumer, ThreatIntelEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeRedis:
    """Minimal FakeRedis for threat intel tests — tracks hset calls."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self.hset_calls: list[tuple[str, dict[str, Any]]] = []

    async def hset(self, name: str, mapping: dict[str, Any] | None = None, **kwargs: Any) -> int:
        fields = mapping or {}
        fields.update(kwargs)
        self.hset_calls.append((name, dict(fields)))
        if name not in self._data:
            self._data[name] = {}
        self._data[name].update(fields)
        return len(fields)


# ---------------------------------------------------------------------------
# Test 1: Blocklist entry -> Redis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocklist_entry_sets_redis_blocked() -> None:
    """A blocklist entry should HSET blocked=1 on the agent threshold key."""
    redis = FakeRedis()
    store = PatternStore()
    consumer = ThreatIntelConsumer(redis_client=redis, pattern_store=store)

    entry = ThreatIntelEntry(
        source="community",
        entry_type="blocklist",
        agent_name_hash="abc123",
    )
    await consumer.apply_entry(entry)

    assert len(redis.hset_calls) == 1
    key, mapping = redis.hset_calls[0]
    assert key == "navil:agent:abc123:thresholds"
    assert mapping == {"blocked": "1"}


# ---------------------------------------------------------------------------
# Test 2: Pattern entry -> PatternStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pattern_entry_added_to_store() -> None:
    """A pattern entry should land in PatternStore with source='community'."""
    redis = FakeRedis()
    store = PatternStore()
    consumer = ThreatIntelConsumer(redis_client=redis, pattern_store=store)

    entry = ThreatIntelEntry(
        source="community",
        entry_type="pattern",
        pattern_data={
            "pattern_id": "community_exfil_001",
            "anomaly_type": "DATA_EXFILTRATION",
            "description": "Bulk read followed by external upload",
            "features": {"tool_sequence": ["read_all", "upload"]},
        },
    )
    await consumer.apply_entry(entry)

    assert len(store.patterns) == 1
    p = store.patterns[0]
    assert p.pattern_id == "community_exfil_001"
    assert p.source == "community"
    assert p.anomaly_type == "DATA_EXFILTRATION"


# ---------------------------------------------------------------------------
# Test 3: Opt-out flag
# ---------------------------------------------------------------------------


def test_opt_out_disables_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Setting NAVIL_DISABLE_CLOUD_SYNC=1 should disable the consumer."""
    monkeypatch.setenv("NAVIL_DISABLE_CLOUD_SYNC", "1")
    assert ThreatIntelConsumer.is_enabled() is False

    monkeypatch.setenv("NAVIL_DISABLE_CLOUD_SYNC", "true")
    assert ThreatIntelConsumer.is_enabled() is False

    monkeypatch.setenv("NAVIL_DISABLE_CLOUD_SYNC", "yes")
    assert ThreatIntelConsumer.is_enabled() is False


def test_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the env var, is_enabled() should return True."""
    monkeypatch.delenv("NAVIL_DISABLE_CLOUD_SYNC", raising=False)
    assert ThreatIntelConsumer.is_enabled() is True


# ---------------------------------------------------------------------------
# Test 4: Community eviction preference
# ---------------------------------------------------------------------------


def test_community_patterns_evicted_before_local() -> None:
    """When PatternStore is full, community patterns are evicted first."""
    store = PatternStore(max_patterns=5)

    # Add 3 local patterns with high match_count
    for i in range(3):
        store.add_pattern(LearnedPattern(
            pattern_id=f"local_{i}",
            anomaly_type="TEST",
            description=f"local pattern {i}",
            source="local",
            match_count=100,
        ))

    # Add 2 community patterns with low match_count
    for i in range(2):
        store.add_pattern(LearnedPattern(
            pattern_id=f"community_{i}",
            anomaly_type="TEST",
            description=f"community pattern {i}",
            source="community",
            match_count=1,
        ))

    assert len(store.patterns) == 5

    # Add one more community pattern — should evict a community pattern, not local
    store.add_community_pattern(LearnedPattern(
        pattern_id="community_new",
        anomaly_type="TEST",
        description="new community pattern",
    ))

    assert len(store.patterns) == 5
    local_ids = [p.pattern_id for p in store.patterns if p.source == "local"]
    assert len(local_ids) == 3, "All local patterns should survive eviction"
    assert "community_new" in [p.pattern_id for p in store.patterns]


# ---------------------------------------------------------------------------
# Test 5: Pattern entry with None pattern_store is handled gracefully
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pattern_entry_with_none_pattern_store() -> None:
    """Pattern entry should be skipped gracefully when pattern_store is None."""
    redis = FakeRedis()
    consumer = ThreatIntelConsumer(redis_client=redis, pattern_store=None)

    entry = ThreatIntelEntry(
        source="community",
        entry_type="pattern",
        pattern_data={
            "pattern_id": "community_exfil_001",
            "anomaly_type": "DATA_EXFILTRATION",
            "description": "Bulk read followed by external upload",
        },
    )
    # Should not raise
    await consumer.apply_entry(entry)
    # No errors tracked — this is a graceful skip
    assert consumer.stats["errors"] == 0
