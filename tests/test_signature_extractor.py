"""Tests for the Signature Extractor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from navil.honeypot.signature_extractor import SignatureExtractor


# -- Helpers -----------------------------------------------------------------


def _make_record(
    tool_name: str,
    source_ip: str = "1.2.3.4",
    arguments: dict | None = None,
    ts_offset_s: int = 0,
    user_agent: str = "",
) -> dict:
    """Create a test honeypot record."""
    ts = datetime.now(timezone.utc) + timedelta(seconds=ts_offset_s)
    return {
        "timestamp": ts.isoformat(),
        "tool_name": tool_name,
        "arguments": arguments or {},
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_headers": {},
        "method": "tools/call",
    }


# -- Signature Extraction ---------------------------------------------------


class TestSignatureExtractor:
    """Tests for the signature extractor."""

    def test_empty_records(self):
        extractor = SignatureExtractor()
        entries = extractor.analyze([])
        assert len(entries) == 0

    def test_extract_suspicious_tool_names(self):
        """Should detect tools with suspicious keywords."""
        records = [_make_record("inject_backdoor", ts_offset_s=i) for i in range(5)]
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        tool_entries = [e for e in entries if e.pattern_type == "tool_name"]
        assert len(tool_entries) >= 1
        assert any(e.value == "inject_backdoor" for e in tool_entries)

    def test_minimum_observations_enforced(self):
        """Should not create entries for tools seen fewer than MIN_OBSERVATIONS times."""
        records = [_make_record("inject_backdoor")]  # Only 1 observation
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        tool_entries = [e for e in entries if e.value == "inject_backdoor"]
        assert len(tool_entries) == 0

    def test_extract_sequence_patterns(self):
        """Should detect suspicious tool call sequences."""
        records = []
        # Create 4 IPs each doing read_file -> exec_command
        for i in range(4):
            ip = f"10.0.0.{i}"
            records.append(_make_record("read_file", ip, ts_offset_s=i * 10))
            records.append(_make_record("exec_command", ip, ts_offset_s=i * 10 + 1))

        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        seq_entries = [e for e in entries if e.pattern_type == "tool_sequence"]
        assert len(seq_entries) >= 1

    def test_extract_argument_patterns(self):
        """Should detect sensitive argument patterns."""
        records = [
            _make_record("read_file", arguments={"path": "~/.ssh/id_rsa"}, ts_offset_s=i)
            for i in range(5)
        ]
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        arg_entries = [e for e in entries if e.pattern_type == "argument_pattern"]
        assert len(arg_entries) >= 1

    def test_confidence_threshold(self):
        """All extracted entries should meet minimum confidence threshold."""
        records = [_make_record("inject_backdoor", ts_offset_s=i) for i in range(5)]
        extractor = SignatureExtractor(min_confidence=0.7)
        entries = extractor.analyze(records)

        for entry in entries:
            assert entry.confidence >= 0.7, (
                f"Entry {entry.pattern_id} has confidence {entry.confidence} < 0.7"
            )

    def test_custom_confidence_threshold(self):
        """Should respect custom minimum confidence threshold."""
        records = [_make_record("inject_backdoor", ts_offset_s=i) for i in range(5)]
        # Very high threshold
        extractor = SignatureExtractor(min_confidence=0.99)
        entries = extractor.analyze(records)
        # Some entries might still pass if they have very high confidence
        for entry in entries:
            assert entry.confidence >= 0.99

    def test_unique_pattern_ids(self):
        """All generated pattern IDs should be unique."""
        records = []
        for tool in ["inject_backdoor", "exfil_data", "keylogger"]:
            records.extend(_make_record(tool, ts_offset_s=i) for i in range(5))

        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        ids = [e.pattern_id for e in entries]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_entries_are_blocklist_entries(self):
        """All results should be BlocklistEntry instances."""
        from navil.blocklist import BlocklistEntry

        records = [_make_record("inject_backdoor", ts_offset_s=i) for i in range(5)]
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        for entry in entries:
            assert isinstance(entry, BlocklistEntry)

    def test_tools_list_ignored(self):
        """The __tools_list__ meta-tool should not generate signatures."""
        records = [_make_record("__tools_list__", ts_offset_s=i) for i in range(10)]
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        tool_entries = [e for e in entries if e.value == "__tools_list__"]
        assert len(tool_entries) == 0

    def test_severity_assignment(self):
        """High-confidence entries should get CRITICAL severity."""
        records = [_make_record("inject_backdoor", ts_offset_s=i) for i in range(20)]
        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        tool_entries = [e for e in entries if e.pattern_type == "tool_name"]
        assert len(tool_entries) >= 1
        # With inject + backdoor keywords and 20 observations, confidence should be high
        for e in tool_entries:
            assert e.severity in ("HIGH", "CRITICAL")

    def test_multiple_sensitive_patterns(self):
        """Should detect multiple sensitive argument patterns independently."""
        records = []
        for i in range(5):
            records.append(
                _make_record("read_file", arguments={"path": "~/.ssh/id_rsa"}, ts_offset_s=i)
            )
            records.append(
                _make_record(
                    "read_file", arguments={"path": "~/.aws/credentials"}, ts_offset_s=i + 100
                )
            )

        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        arg_entries = [e for e in entries if e.pattern_type == "argument_pattern"]
        # Should detect both .ssh/ and .aws/ patterns
        assert len(arg_entries) >= 2

    def test_read_then_exec_sequence_boosted(self):
        """Read-then-exec sequences should get confidence boost."""
        records = []
        for i in range(5):
            ip = f"10.0.0.{i}"
            records.append(_make_record("read_file", ip, ts_offset_s=i * 10))
            records.append(_make_record("exec_command", ip, ts_offset_s=i * 10 + 1))

        extractor = SignatureExtractor()
        entries = extractor.analyze(records)

        seq_entries = [e for e in entries if e.pattern_type == "tool_sequence"]
        # Should have the read_file,exec_command sequence
        matching = [e for e in seq_entries if "read_file" in e.value and "exec_command" in e.value]
        assert len(matching) >= 1
        # Confidence should be boosted above baseline
        for e in matching:
            assert e.confidence >= 0.8  # boosted by read+exec combination


# -- Timing Patterns ---------------------------------------------------------


class TestTimingPatterns:
    """Tests for timing pattern analysis."""

    def test_periodic_pattern_detection(self):
        """Should detect periodic call patterns."""
        records = [
            _make_record("status", source_ip="10.0.0.1", ts_offset_s=i * 10) for i in range(10)
        ]
        extractor = SignatureExtractor()
        timing = extractor.extract_timing_patterns(records)

        assert "10.0.0.1" in timing
        info = timing["10.0.0.1"]
        assert info["call_count"] == 10
        assert info["is_periodic"] is True

    def test_non_periodic_pattern(self):
        """Should detect non-periodic patterns."""
        import random

        random.seed(42)
        records = [
            _make_record("tool", source_ip="10.0.0.2", ts_offset_s=random.randint(0, 1000))
            for _ in range(10)
        ]
        extractor = SignatureExtractor()
        timing = extractor.extract_timing_patterns(records)

        if "10.0.0.2" in timing:
            # Random intervals should not be periodic
            assert timing["10.0.0.2"]["is_periodic"] is False

    def test_insufficient_records(self):
        """Should skip IPs with fewer than 3 records."""
        records = [
            _make_record("tool", source_ip="10.0.0.3", ts_offset_s=0),
            _make_record("tool", source_ip="10.0.0.3", ts_offset_s=10),
        ]
        extractor = SignatureExtractor()
        timing = extractor.extract_timing_patterns(records)
        assert "10.0.0.3" not in timing

    def test_timing_statistics(self):
        """Should calculate correct timing statistics."""
        records = [
            _make_record("tool", source_ip="10.0.0.1", ts_offset_s=i * 5) for i in range(5)
        ]
        extractor = SignatureExtractor()
        timing = extractor.extract_timing_patterns(records)

        assert "10.0.0.1" in timing
        info = timing["10.0.0.1"]
        assert info["call_count"] == 5
        assert info["mean_interval_s"] == pytest.approx(5.0, abs=0.5)
        assert info["min_interval_s"] == pytest.approx(5.0, abs=0.5)


# -- User-Agent Patterns ----------------------------------------------------


class TestUserAgentPatterns:
    """Tests for user-agent pattern analysis."""

    def test_user_agent_extraction(self):
        """Should group interactions by user agent."""
        records = [
            _make_record("read_file", user_agent="bot-a/1.0", ts_offset_s=i) for i in range(3)
        ] + [
            _make_record("exec_command", user_agent="bot-b/2.0", ts_offset_s=i + 10)
            for i in range(2)
        ]

        extractor = SignatureExtractor()
        ua_patterns = extractor.extract_user_agent_patterns(records)

        assert "bot-a/1.0" in ua_patterns
        assert ua_patterns["bot-a/1.0"]["call_count"] == 3
        assert "bot-b/2.0" in ua_patterns
        assert ua_patterns["bot-b/2.0"]["call_count"] == 2

    def test_user_agent_top_tools(self):
        """Should track which tools each user agent targets."""
        records = [
            _make_record("read_file", user_agent="attacker/1.0", ts_offset_s=0),
            _make_record("read_file", user_agent="attacker/1.0", ts_offset_s=1),
            _make_record("exec_command", user_agent="attacker/1.0", ts_offset_s=2),
        ]
        extractor = SignatureExtractor()
        ua_patterns = extractor.extract_user_agent_patterns(records)

        info = ua_patterns["attacker/1.0"]
        assert info["unique_tools"] == 2
        # read_file should be the top tool (2 calls vs 1)
        top = info["top_tools"]
        assert top[0][0] == "read_file"
        assert top[0][1] == 2

    def test_empty_user_agent_skipped(self):
        """Records without user agent should be excluded from UA analysis."""
        records = [
            _make_record("tool", user_agent="", ts_offset_s=i) for i in range(5)
        ]
        extractor = SignatureExtractor()
        ua_patterns = extractor.extract_user_agent_patterns(records)
        assert len(ua_patterns) == 0

    def test_user_agent_source_ips(self):
        """Should track source IPs per user agent."""
        records = [
            _make_record("tool", source_ip="10.0.0.1", user_agent="scanner/1.0", ts_offset_s=0),
            _make_record("tool", source_ip="10.0.0.2", user_agent="scanner/1.0", ts_offset_s=1),
            _make_record("tool", source_ip="10.0.0.1", user_agent="scanner/1.0", ts_offset_s=2),
        ]
        extractor = SignatureExtractor()
        ua_patterns = extractor.extract_user_agent_patterns(records)

        info = ua_patterns["scanner/1.0"]
        assert set(info["source_ips"]) == {"10.0.0.1", "10.0.0.2"}
