"""Tests for the Blocklist Engine."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import fakeredis
import pytest

from navil.blocklist import BlocklistEntry, BlocklistManager, REDIS_PATTERNS_KEY, REDIS_VERSION_KEY


# ── BlocklistEntry ───────────────────────────────────────────


class TestBlocklistEntry:
    """Tests for the BlocklistEntry dataclass."""

    def test_creation(self):
        entry = BlocklistEntry(
            pattern_id="BL-TEST-001",
            pattern_type="tool_name",
            value="inject_backdoor",
            severity="CRITICAL",
            description="Test entry",
            confidence=0.95,
        )
        assert entry.pattern_id == "BL-TEST-001"
        assert entry.pattern_type == "tool_name"
        assert entry.confidence == 0.95
        assert entry.created_at != ""  # auto-populated
        assert entry.source == "local"  # default source

    def test_creation_with_source(self):
        entry = BlocklistEntry(
            pattern_id="BL-TEST-001",
            pattern_type="tool_name",
            value="inject_backdoor",
            severity="CRITICAL",
            description="Test entry",
            confidence=0.95,
            source="cloud",
        )
        assert entry.source == "cloud"

    def test_to_dict(self):
        entry = BlocklistEntry(
            pattern_id="BL-TEST-001",
            pattern_type="tool_name",
            value="test",
            severity="HIGH",
            description="desc",
            confidence=0.8,
            source="manual",
            created_at="2026-01-01T00:00:00Z",
        )
        d = entry.to_dict()
        assert d["pattern_id"] == "BL-TEST-001"
        assert d["confidence"] == 0.8
        assert d["source"] == "manual"

    def test_from_dict(self):
        d = {
            "pattern_id": "BL-TEST-002",
            "pattern_type": "argument_pattern",
            "value": ".*\\.ssh/.*",
            "severity": "CRITICAL",
            "description": "SSH key access",
            "confidence": 0.9,
            "source": "community",
        }
        entry = BlocklistEntry.from_dict(d)
        assert entry.pattern_id == "BL-TEST-002"
        assert entry.pattern_type == "argument_pattern"
        assert entry.source == "community"

    def test_from_dict_default_source(self):
        d = {
            "pattern_id": "BL-TEST-003",
            "pattern_type": "tool_name",
            "value": "test",
            "severity": "LOW",
            "description": "No source field",
            "confidence": 0.5,
        }
        entry = BlocklistEntry.from_dict(d)
        assert entry.source == "local"

    def test_roundtrip(self):
        entry = BlocklistEntry(
            pattern_id="BL-RT-001",
            pattern_type="tool_sequence",
            value="read_file,fetch_url",
            severity="HIGH",
            description="Read-then-send",
            confidence=0.85,
            source="cloud",
        )
        d = entry.to_dict()
        restored = BlocklistEntry.from_dict(d)
        assert restored.pattern_id == entry.pattern_id
        assert restored.value == entry.value
        assert restored.confidence == entry.confidence
        assert restored.source == entry.source


# ── BlocklistManager Loading ─────────────────────────────────


class TestBlocklistManagerLoad:
    """Tests for loading blocklist data."""

    def test_load_from_default_file(self):
        mgr = BlocklistManager()
        loaded = mgr.load_from_file()
        assert loaded > 0
        assert mgr.pattern_count > 0
        assert mgr.version >= 1

    def test_load_from_custom_file(self):
        data = {
            "version": 42,
            "patterns": [
                {
                    "pattern_id": "TEST-001",
                    "pattern_type": "tool_name",
                    "value": "test_tool",
                    "severity": "LOW",
                    "description": "Test",
                    "confidence": 0.5,
                }
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            path = f.name

        try:
            mgr = BlocklistManager()
            loaded = mgr.load_from_file(path)
            assert loaded == 1
            assert mgr.version == 42
        finally:
            os.unlink(path)

    def test_load_nonexistent_file_raises(self):
        mgr = BlocklistManager()
        with pytest.raises(FileNotFoundError):
            mgr.load_from_file("/nonexistent/path.json")

    def test_load_from_redis_with_fakeredis(self):
        """Use fakeredis for real Redis behavior testing."""
        r = fakeredis.FakeRedis()

        patterns = [
            {
                "pattern_id": "REDIS-001",
                "pattern_type": "tool_name",
                "value": "redis_tool",
                "severity": "HIGH",
                "description": "From Redis",
                "confidence": 0.8,
                "source": "cloud",
            }
        ]
        r.set(REDIS_PATTERNS_KEY, json.dumps(patterns))
        r.set(REDIS_VERSION_KEY, "5")

        mgr = BlocklistManager(redis_client=r)
        loaded = mgr.load_from_redis()
        assert loaded == 1
        assert mgr.version == 5
        assert mgr.entries[0].source == "cloud"

    def test_load_from_redis_mock(self):
        mock_redis = MagicMock()
        patterns = [
            {
                "pattern_id": "REDIS-001",
                "pattern_type": "tool_name",
                "value": "redis_tool",
                "severity": "HIGH",
                "description": "From Redis",
                "confidence": 0.8,
            }
        ]
        mock_redis.get.side_effect = lambda key: (
            json.dumps(patterns).encode() if key == REDIS_PATTERNS_KEY else b"5"
        )

        mgr = BlocklistManager(redis_client=mock_redis)
        loaded = mgr.load_from_redis()
        assert loaded == 1
        assert mgr.version == 5

    def test_load_from_redis_empty(self):
        r = fakeredis.FakeRedis()
        mgr = BlocklistManager(redis_client=r)
        loaded = mgr.load_from_redis()
        assert loaded == 0

    def test_load_from_redis_no_client(self):
        mgr = BlocklistManager()
        loaded = mgr.load_from_redis()
        assert loaded == 0


# ── BlocklistManager Save ────────────────────────────────────


class TestBlocklistManagerSave:
    """Tests for saving blocklist data."""

    def test_save_to_redis_with_fakeredis(self):
        """Use fakeredis for real Redis pipeline behavior."""
        r = fakeredis.FakeRedis()

        mgr = BlocklistManager(redis_client=r)
        mgr._entries["TEST-001"] = BlocklistEntry(
            pattern_id="TEST-001",
            pattern_type="tool_name",
            value="test",
            severity="HIGH",
            description="Test",
            confidence=0.9,
        )

        result = mgr.save_to_redis()
        assert result is True
        assert mgr.version == 1  # first INCR from 0

        # Verify the data is actually in Redis
        raw = r.get(REDIS_PATTERNS_KEY)
        assert raw is not None
        patterns = json.loads(raw)
        assert len(patterns) == 1
        assert patterns[0]["pattern_id"] == "TEST-001"

        # Verify version key
        version = r.get(REDIS_VERSION_KEY)
        assert int(version) == 1

    def test_save_to_redis_increments_version(self):
        """Verify version increments on each save."""
        r = fakeredis.FakeRedis()

        mgr = BlocklistManager(redis_client=r)
        mgr._entries["TEST-001"] = BlocklistEntry(
            pattern_id="TEST-001",
            pattern_type="tool_name",
            value="test",
            severity="HIGH",
            description="Test",
            confidence=0.9,
        )

        mgr.save_to_redis()
        assert mgr.version == 1

        mgr.save_to_redis()
        assert mgr.version == 2

        mgr.save_to_redis()
        assert mgr.version == 3

    def test_save_to_redis_no_client(self):
        mgr = BlocklistManager()
        result = mgr.save_to_redis()
        assert result is False

    def test_save_to_file(self):
        mgr = BlocklistManager()
        mgr._entries["TEST-001"] = BlocklistEntry(
            pattern_id="TEST-001",
            pattern_type="tool_name",
            value="test",
            severity="HIGH",
            description="Test",
            confidence=0.9,
        )
        mgr._version = 7

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            mgr.save_to_file(path)
            with open(path) as fh:
                data = json.load(fh)
            assert data["version"] == 7
            assert len(data["patterns"]) == 1
        finally:
            os.unlink(path)

    def test_redis_keys_for_rust_proxy(self):
        """Verify the Redis key names match what the Rust proxy expects."""
        assert REDIS_PATTERNS_KEY == "navil:blocklist:patterns"
        assert REDIS_VERSION_KEY == "navil:blocklist:version"

        r = fakeredis.FakeRedis()
        mgr = BlocklistManager(redis_client=r)
        mgr._entries["TEST-001"] = BlocklistEntry(
            pattern_id="TEST-001",
            pattern_type="tool_name",
            value="test",
            severity="HIGH",
            description="Test",
            confidence=0.9,
        )
        mgr.save_to_redis()

        # The Rust proxy reads these exact keys
        assert r.get("navil:blocklist:patterns") is not None
        assert r.get("navil:blocklist:version") is not None

        # Verify the patterns key contains valid JSON the proxy can deserialize
        patterns = json.loads(r.get("navil:blocklist:patterns"))
        assert isinstance(patterns, list)
        assert len(patterns) == 1


# ── BlocklistManager Merge ───────────────────────────────────


class TestBlocklistManagerMerge:
    """Tests for merging blocklist entries."""

    def test_merge_new_entries(self):
        mgr = BlocklistManager()
        entries = [
            BlocklistEntry("NEW-001", "tool_name", "tool_a", "HIGH", "A", 0.8),
            BlocklistEntry("NEW-002", "tool_name", "tool_b", "MEDIUM", "B", 0.7),
        ]
        changes = mgr.merge(entries)
        assert changes == 2
        assert mgr.pattern_count == 2

    def test_merge_conflict_keeps_higher_confidence(self):
        mgr = BlocklistManager()
        mgr._entries["CONF-001"] = BlocklistEntry(
            "CONF-001", "tool_name", "tool_a", "HIGH", "Original", 0.7
        )

        higher = [BlocklistEntry("CONF-001", "tool_name", "tool_a", "HIGH", "Updated", 0.9)]
        changes = mgr.merge(higher)
        assert changes == 1
        assert mgr._entries["CONF-001"].confidence == 0.9
        assert mgr._entries["CONF-001"].description == "Updated"

    def test_merge_conflict_keeps_existing_when_lower(self):
        mgr = BlocklistManager()
        mgr._entries["CONF-001"] = BlocklistEntry(
            "CONF-001", "tool_name", "tool_a", "HIGH", "Original", 0.9
        )

        lower = [BlocklistEntry("CONF-001", "tool_name", "tool_a", "HIGH", "Lower", 0.5)]
        changes = mgr.merge(lower)
        assert changes == 0
        assert mgr._entries["CONF-001"].description == "Original"

    def test_merge_multiple_sources(self):
        """Merge patterns from local, Redis, and cloud sources."""
        mgr = BlocklistManager()
        mgr.load_from_file()  # local patterns

        cloud_entries = [
            BlocklistEntry(
                "CLOUD-001", "tool_name", "cloud_malware", "CRITICAL",
                "Cloud-sourced threat", 0.95, source="cloud",
            ),
        ]
        community_entries = [
            BlocklistEntry(
                "COMM-001", "tool_name", "community_threat", "HIGH",
                "Community-reported threat", 0.75, source="community",
            ),
        ]

        cloud_merged = mgr.merge(cloud_entries)
        community_merged = mgr.merge(community_entries)

        assert cloud_merged == 1
        assert community_merged == 1
        assert mgr._entries["CLOUD-001"].source == "cloud"
        assert mgr._entries["COMM-001"].source == "community"


# ── BlocklistManager Add Entry ───────────────────────────────


class TestBlocklistManagerAddEntry:
    """Tests for the add_entry method."""

    def test_add_new_entry(self):
        mgr = BlocklistManager()
        entry = BlocklistEntry(
            "ADD-001", "tool_name", "evil_tool", "CRITICAL",
            "Manually added", 0.9, source="manual",
        )
        result = mgr.add_entry(entry)
        assert result is True
        assert mgr.pattern_count == 1
        assert mgr._entries["ADD-001"].source == "manual"

    def test_add_entry_replaces_lower_confidence(self):
        mgr = BlocklistManager()
        mgr._entries["ADD-001"] = BlocklistEntry(
            "ADD-001", "tool_name", "evil_tool", "HIGH", "Old", 0.5,
        )
        new = BlocklistEntry(
            "ADD-001", "tool_name", "evil_tool", "CRITICAL", "New", 0.9,
        )
        result = mgr.add_entry(new)
        assert result is True
        assert mgr._entries["ADD-001"].confidence == 0.9

    def test_add_entry_skips_lower_confidence(self):
        mgr = BlocklistManager()
        mgr._entries["ADD-001"] = BlocklistEntry(
            "ADD-001", "tool_name", "evil_tool", "CRITICAL", "Original", 0.9,
        )
        new = BlocklistEntry(
            "ADD-001", "tool_name", "evil_tool", "HIGH", "Lower", 0.5,
        )
        result = mgr.add_entry(new)
        assert result is False
        assert mgr._entries["ADD-001"].confidence == 0.9

    def test_add_argument_pattern_compiles_regex(self):
        mgr = BlocklistManager()
        entry = BlocklistEntry(
            "ADD-REGEX", "argument_pattern", ".*\\.ssh/.*", "CRITICAL",
            "SSH access", 0.9,
        )
        result = mgr.add_entry(entry)
        assert result is True
        assert "ADD-REGEX" in mgr._regex_cache

    def test_add_invalid_regex_warns(self):
        mgr = BlocklistManager()
        entry = BlocklistEntry(
            "ADD-BAD-REGEX", "argument_pattern", "[invalid(regex",
            "HIGH", "Bad regex", 0.5,
        )
        # Should not raise, just log a warning
        result = mgr.add_entry(entry)
        assert result is True
        assert "ADD-BAD-REGEX" not in mgr._regex_cache


# ── BlocklistManager Match ───────────────────────────────────


class TestBlocklistManagerMatch:
    """Tests for matching tool calls against the blocklist."""

    @pytest.fixture
    def loaded_manager(self):
        mgr = BlocklistManager()
        mgr.load_from_file()
        return mgr

    def test_match_tool_name(self, loaded_manager):
        matches = loaded_manager.match("inject_backdoor")
        assert len(matches) >= 1
        assert any(m.pattern_id == "BL-TOOL-001" for m in matches)

    def test_match_tool_name_no_match(self, loaded_manager):
        matches = loaded_manager.match("safe_normal_tool")
        assert len(matches) == 0

    def test_match_argument_pattern(self, loaded_manager):
        matches = loaded_manager.match("read_file", {"path": "~/.ssh/id_rsa"})
        assert len(matches) >= 1
        assert any(m.pattern_type == "argument_pattern" for m in matches)

    def test_match_aws_credentials(self, loaded_manager):
        matches = loaded_manager.match("read_file", {"path": "/home/user/.aws/credentials"})
        assert len(matches) >= 1

    def test_match_etc_shadow(self, loaded_manager):
        matches = loaded_manager.match("read_file", {"path": "/etc/shadow"})
        assert len(matches) >= 1

    def test_match_sequence_member(self, loaded_manager):
        matches = loaded_manager.match("fetch_url")
        seq_matches = [m for m in matches if m.pattern_type == "tool_sequence"]
        assert len(seq_matches) >= 1

    def test_matches_sorted_by_confidence(self, loaded_manager):
        # Add entries with varying confidence
        loaded_manager.merge([
            BlocklistEntry("SORT-001", "tool_name", "test_sort", "HIGH", "A", 0.5),
            BlocklistEntry("SORT-002", "tool_name", "test_sort", "HIGH", "B", 0.9),
            BlocklistEntry("SORT-003", "tool_name", "test_sort", "HIGH", "C", 0.7),
        ])
        matches = loaded_manager.match("test_sort")
        assert len(matches) >= 2
        for i in range(len(matches) - 1):
            assert matches[i].confidence >= matches[i + 1].confidence


# ── BlocklistManager Finding Generation ──────────────────────


class TestBlocklistManagerFindings:
    """Tests for match_to_findings integration with navil.types.Finding."""

    @pytest.fixture
    def loaded_manager(self):
        mgr = BlocklistManager()
        mgr.load_from_file()
        return mgr

    def test_findings_for_tool_name_match(self, loaded_manager):
        findings = loaded_manager.match_to_findings("inject_backdoor")
        assert len(findings) >= 1
        f = findings[0]
        assert f.source == "blocklist"
        assert f.affected_field == "inject_backdoor"
        assert "BLOCKLIST-" in f.id
        assert f.confidence > 0

    def test_findings_for_argument_match(self, loaded_manager):
        findings = loaded_manager.match_to_findings("read_file", {"path": "/etc/shadow"})
        assert len(findings) >= 1
        f = findings[0]
        assert f.severity == "CRITICAL"
        assert f.source == "blocklist"

    def test_no_findings_for_safe_tool(self, loaded_manager):
        findings = loaded_manager.match_to_findings("safe_tool")
        assert len(findings) == 0

    def test_finding_fields(self, loaded_manager):
        findings = loaded_manager.match_to_findings("inject_backdoor")
        f = findings[0]
        # Verify all Finding fields are populated
        assert f.id.startswith("BLOCKLIST-")
        assert f.title != ""
        assert f.description != ""
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f.source == "blocklist"
        assert f.affected_field == "inject_backdoor"
        assert f.remediation != ""
        assert f.evidence != ""
        assert 0.0 <= f.confidence <= 1.0


# ── BlocklistManager Search ──────────────────────────────────


class TestBlocklistManagerSearch:
    """Tests for searching blocklist entries."""

    @pytest.fixture
    def loaded_manager(self):
        mgr = BlocklistManager()
        mgr.load_from_file()
        return mgr

    def test_search_by_id(self, loaded_manager):
        results = loaded_manager.search("BL-TOOL-001")
        assert len(results) >= 1

    def test_search_by_description(self, loaded_manager):
        results = loaded_manager.search("SSH")
        assert len(results) >= 1

    def test_search_by_value(self, loaded_manager):
        results = loaded_manager.search("inject_backdoor")
        assert len(results) >= 1

    def test_search_case_insensitive(self, loaded_manager):
        results = loaded_manager.search("ssh")
        assert len(results) >= 1

    def test_search_no_results(self, loaded_manager):
        results = loaded_manager.search("zzz_nonexistent_zzz")
        assert len(results) == 0


# ── BlocklistManager Status ──────────────────────────────────


class TestBlocklistManagerStatus:
    """Tests for status reporting."""

    def test_status_after_load(self):
        mgr = BlocklistManager()
        mgr.load_from_file()
        status = mgr.status()

        assert status["version"] >= 1
        assert status["pattern_count"] > 0
        assert "by_type" in status
        assert "by_severity" in status
        assert "tool_name" in status["by_type"]
        assert status["last_update"] != ""


# ── BlocklistUpdater ─────────────────────────────────────────


class TestBlocklistUpdater:
    """Tests for the BlocklistUpdater auto-update logic."""

    def test_get_tier_community(self):
        from navil.blocklist_updater import _get_tier

        with patch.dict(os.environ, {}, clear=True):
            assert _get_tier() == "community"

    def test_get_tier_pro(self):
        from navil.blocklist_updater import _get_tier

        with patch.dict(os.environ, {"NAVIL_API_KEY": "test-key"}, clear=True):
            assert _get_tier() == "pro"

    def test_get_tier_explicit(self):
        from navil.blocklist_updater import _get_tier

        with patch.dict(os.environ, {"NAVIL_API_KEY": "key", "NAVIL_TIER": "enterprise"}, clear=True):
            assert _get_tier() == "enterprise"

    def test_should_delay_community(self):
        from navil.blocklist_updater import BlocklistUpdater

        mgr = BlocklistManager()
        with patch.dict(os.environ, {}, clear=True):
            updater = BlocklistUpdater(blocklist_manager=mgr)
            # Community tier with no previous fetch should not delay
            assert updater._should_delay() is False

    def test_should_delay_community_after_fetch(self):
        import time

        from navil.blocklist_updater import BlocklistUpdater

        mgr = BlocklistManager()
        with patch.dict(os.environ, {}, clear=True):
            updater = BlocklistUpdater(blocklist_manager=mgr)
            updater._last_fetch = time.time()  # just fetched
            assert updater._should_delay() is True

    def test_should_not_delay_pro(self):
        import time

        from navil.blocklist_updater import BlocklistUpdater

        mgr = BlocklistManager()
        with patch.dict(os.environ, {"NAVIL_API_KEY": "key"}, clear=True):
            updater = BlocklistUpdater(blocklist_manager=mgr, api_key="key")
            updater._last_fetch = time.time()  # just fetched
            assert updater._should_delay() is False

    def test_update_blocklist_sync(self):
        from navil.blocklist_updater import update_blocklist_sync

        r = fakeredis.FakeRedis()
        result = update_blocklist_sync(redis_client=r)

        assert result["loaded"] > 0
        assert result["version"] >= 1
        assert result["saved_to_redis"] is True
        assert result["pattern_count"] > 0

        # Verify data landed in Redis
        assert r.get(REDIS_PATTERNS_KEY) is not None
        assert int(r.get(REDIS_VERSION_KEY)) >= 1

    def test_update_blocklist_sync_no_redis(self):
        from navil.blocklist_updater import update_blocklist_sync

        result = update_blocklist_sync(redis_client=None)

        assert result["loaded"] > 0
        assert result["saved_to_redis"] is False


# ── Anomaly Detector Blocklist Integration ───────────────────


class TestAnomalyDetectorBlocklist:
    """Tests for blocklist integration in the anomaly detector."""

    def test_blocklist_loaded_on_first_detection(self):
        from navil.anomaly_detector import BehavioralAnomalyDetector

        detector = BehavioralAnomalyDetector()
        assert detector._blocklist is None
        assert detector._blocklist_loaded is False

        # Record an invocation to trigger detection
        detector.record_invocation(
            agent_name="test-agent",
            tool_name="inject_backdoor",
            action="execute",
            duration_ms=100,
        )

        # After first detection, blocklist should be loaded
        assert detector._blocklist_loaded is True
        assert detector._blocklist is not None

    def test_blocklist_match_generates_alert(self):
        from navil.anomaly_detector import BehavioralAnomalyDetector

        detector = BehavioralAnomalyDetector()

        detector.record_invocation(
            agent_name="test-agent",
            tool_name="inject_backdoor",
            action="execute",
            duration_ms=100,
        )

        blocklist_alerts = [a for a in detector.alerts if a.anomaly_type == "BLOCKLIST"]
        assert len(blocklist_alerts) >= 1
        alert = blocklist_alerts[0]
        assert alert.severity == "CRITICAL"
        assert "inject_backdoor" in alert.description

    def test_blocklist_match_generates_finding(self):
        from navil.anomaly_detector import BehavioralAnomalyDetector

        detector = BehavioralAnomalyDetector()

        detector.record_invocation(
            agent_name="test-agent",
            tool_name="inject_backdoor",
            action="execute",
            duration_ms=100,
        )

        assert len(detector.findings) >= 1
        finding = detector.findings[0]
        assert finding.source == "blocklist"
        assert "BLOCKLIST-" in finding.id

    def test_safe_tool_no_blocklist_alert(self):
        from navil.anomaly_detector import BehavioralAnomalyDetector

        detector = BehavioralAnomalyDetector()

        detector.record_invocation(
            agent_name="test-agent",
            tool_name="safe_normal_tool",
            action="read",
            duration_ms=50,
        )

        blocklist_alerts = [a for a in detector.alerts if a.anomaly_type == "BLOCKLIST"]
        assert len(blocklist_alerts) == 0


# ── Redis Hot-Loading Keys ───────────────────────────────────


class TestRedisHotLoading:
    """Verify Redis key structure is correct for Rust proxy hot-loading."""

    def test_version_key_increments(self):
        r = fakeredis.FakeRedis()
        mgr = BlocklistManager(redis_client=r)
        mgr.load_from_file()

        mgr.save_to_redis()
        v1 = int(r.get(REDIS_VERSION_KEY))

        mgr.save_to_redis()
        v2 = int(r.get(REDIS_VERSION_KEY))

        assert v2 == v1 + 1

    def test_patterns_key_valid_json(self):
        r = fakeredis.FakeRedis()
        mgr = BlocklistManager(redis_client=r)
        mgr.load_from_file()
        mgr.save_to_redis()

        raw = r.get(REDIS_PATTERNS_KEY)
        patterns = json.loads(raw)

        assert isinstance(patterns, list)
        assert len(patterns) > 0
        # Each pattern must have the fields the Rust proxy expects
        for p in patterns:
            assert "pattern_id" in p
            assert "pattern_type" in p
            assert "value" in p
            assert "severity" in p
            assert "confidence" in p

    def test_reload_from_redis_matches_original(self):
        """Save to Redis, then reload and verify patterns match."""
        r = fakeredis.FakeRedis()

        mgr1 = BlocklistManager(redis_client=r)
        mgr1.load_from_file()
        original_count = mgr1.pattern_count
        mgr1.save_to_redis()

        mgr2 = BlocklistManager(redis_client=r)
        loaded = mgr2.load_from_redis()

        assert loaded == original_count
        assert mgr2.version == mgr1.version
