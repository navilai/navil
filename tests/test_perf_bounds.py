"""Layer 1 performance bounds integration tests.

Verify that all bounded data structures (deques, OrderedDict LRU, PatternStore,
FeedbackLoop) enforce their capacity limits correctly.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from navil.adaptive.feedback import FeedbackLoop
from navil.adaptive.pattern_store import LearnedPattern, PatternStore
from navil.anomaly_detector import AnomalyAlert, BehavioralAnomalyDetector


@pytest.fixture
def detector() -> BehavioralAnomalyDetector:
    return BehavioralAnomalyDetector()


# ── 1. Per-agent deque bounds ────────────────────────────────


def test_per_agent_deque_bounds(detector: BehavioralAnomalyDetector) -> None:
    """Recording 600 invocations for one agent retains only the latest 500."""
    for i in range(600):
        detector.record_invocation(
            agent_name="agent-flood",
            tool_name="tool_x",
            action="read",
            duration_ms=10,
        )

    dq = detector._per_agent_invocations["agent-flood"]
    assert len(dq) == 500


# ── 2. Max-agents LRU eviction ───────────────────────────────


def test_max_agents_lru_eviction(detector: BehavioralAnomalyDetector) -> None:
    """Recording invocations for 501 distinct agents evicts the first (LRU) agent."""
    for i in range(501):
        detector.record_invocation(
            agent_name=f"agent-{i:04d}",
            tool_name="tool_y",
            action="read",
            duration_ms=5,
        )

    assert len(detector._per_agent_invocations) == 500
    # agent-0000 was the first in and never re-accessed, so it should be evicted
    assert "agent-0000" not in detector._per_agent_invocations
    # The most recent agent should still be present
    assert "agent-0500" in detector._per_agent_invocations


# ── 3. timestamp_dt populated correctly ──────────────────────


def test_timestamp_dt_explicit(detector: BehavioralAnomalyDetector) -> None:
    """An explicit ISO timestamp is parsed into timestamp_dt."""
    detector.record_invocation(
        agent_name="agent-ts",
        tool_name="tool_z",
        action="read",
        duration_ms=1,
        timestamp="2026-01-15T10:30:00+00:00",
    )

    inv = detector._per_agent_invocations["agent-ts"][-1]
    assert inv.timestamp_dt is not None
    expected = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
    assert inv.timestamp_dt == expected


def test_timestamp_dt_auto_generated(detector: BehavioralAnomalyDetector) -> None:
    """When no explicit timestamp is given, timestamp_dt is still populated."""
    detector.record_invocation(
        agent_name="agent-auto",
        tool_name="tool_z",
        action="read",
        duration_ms=1,
    )

    inv = detector._per_agent_invocations["agent-auto"][-1]
    assert inv.timestamp_dt is not None
    # Should be a recent UTC datetime
    assert inv.timestamp_dt.tzinfo is not None


# ── 4. Alerts deque bound ────────────────────────────────────


def test_alerts_deque_bound(detector: BehavioralAnomalyDetector) -> None:
    """The alerts deque never exceeds its maxlen of 5000."""
    for i in range(5500):
        detector.alerts.append(
            AnomalyAlert(
                anomaly_type="TEST",
                severity="LOW",
                agent_name="agent-alert",
                description=f"alert {i}",
                timestamp="2026-01-01T00:00:00+00:00",
                evidence=[],
                recommended_action="none",
            )
        )

    assert len(detector.alerts) <= 5000


# ── 5. PatternStore max_patterns + eviction ──────────────────


def test_pattern_store_max_patterns_eviction() -> None:
    """PatternStore with max_patterns=5 evicts the lowest match_count entry."""
    store = PatternStore(store_path=None, max_patterns=5)

    # Add 5 patterns with varying match_count
    for i in range(5):
        pattern = LearnedPattern(
            pattern_id=f"pat-{i}",
            anomaly_type="TEST",
            description=f"pattern {i}",
            match_count=i * 10,  # 0, 10, 20, 30, 40
        )
        store.add_pattern(pattern)

    assert len(store.patterns) == 5

    # Add a 6th pattern -- should evict the one with lowest match_count (pat-0, count=0)
    store.add_pattern(
        LearnedPattern(
            pattern_id="pat-5",
            anomaly_type="TEST",
            description="pattern 5",
            match_count=50,
        )
    )

    assert len(store.patterns) == 5
    remaining_ids = {p.pattern_id for p in store.patterns}
    assert "pat-0" not in remaining_ids  # lowest match_count was evicted
    assert "pat-5" in remaining_ids  # newly added is present


# ── 6. FeedbackLoop bounded entries ──────────────────────────


def test_feedback_loop_bounded_entries() -> None:
    """FeedbackLoop with max_entries=5 drops the oldest entry when exceeding capacity."""
    loop = FeedbackLoop(persistence_path=None, max_entries=5)

    for i in range(6):
        loop.submit_feedback(
            alert_timestamp=f"2026-01-{i + 1:02d}T00:00:00+00:00",
            anomaly_type="RATE_SPIKE",
            agent_name=f"agent-{i}",
            verdict="confirmed",
        )

    assert len(loop.entries) == 5
    # Oldest entry (agent-0) should have been evicted (deque drops from left)
    agent_names = [e.agent_name for e in loop.entries]
    assert "agent-0" not in agent_names
    assert "agent-5" in agent_names


# ── 7. Backward-compat invocations property ──────────────────


def test_invocations_flat_list(detector: BehavioralAnomalyDetector) -> None:
    """The invocations property returns a flat list spanning all agents."""
    agents = ["alpha", "beta", "gamma"]
    invocations_per_agent = 4

    for agent in agents:
        for _ in range(invocations_per_agent):
            detector.record_invocation(
                agent_name=agent,
                tool_name="tool_flat",
                action="read",
                duration_ms=1,
            )

    flat = detector.invocations
    assert isinstance(flat, list)
    assert len(flat) == len(agents) * invocations_per_agent

    # Verify all agents are represented
    agent_names_in_flat = {inv.agent_name for inv in flat}
    assert agent_names_in_flat == set(agents)
