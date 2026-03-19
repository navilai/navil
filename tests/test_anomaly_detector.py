"""Tests for the BehavioralAnomalyDetector module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from navil.anomaly_detector import AnomalyType, BehavioralAnomalyDetector


@pytest.fixture
def detector() -> BehavioralAnomalyDetector:
    return BehavioralAnomalyDetector(baseline_window_hours=24)


def test_record_invocation(detector: BehavioralAnomalyDetector) -> None:
    """Recording an invocation should add it to the list."""
    detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    assert len(detector.invocations) == 1


def test_baseline_builds_on_first_invocation(detector: BehavioralAnomalyDetector) -> None:
    """Baseline should be built on first invocation."""
    detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    baseline = detector.get_baseline("agent-a")
    assert "avg_duration_ms" in baseline


def test_default_baseline_for_new_agent(detector: BehavioralAnomalyDetector) -> None:
    """New agents should get a default baseline."""
    baseline = detector.get_baseline("agent-x")
    assert baseline["invocation_count"] == 0


def test_rug_pull_detection(detector: BehavioralAnomalyDetector) -> None:
    """Rug-pull: agent suddenly uses 4+ new tools."""
    # Build baseline with one tool
    for _ in range(10):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    # Force baseline rebuild
    detector._build_baseline("agent-a")
    # Now access many new tools rapidly
    for tool in [
        "admin_panel",
        "credential_manager",
        "system_config",
        "user_management",
        "secret_vault",
    ]:
        detector.record_invocation("agent-a", tool, "read", duration_ms=50)
    alerts = detector.get_alerts(agent_name="agent-a")
    rug_pull_alerts = [a for a in alerts if a["anomaly_type"] == AnomalyType.RUG_PULL.value]
    assert len(rug_pull_alerts) >= 1


def test_data_exfiltration_detection(detector: BehavioralAnomalyDetector) -> None:
    """Data exfiltration: accessing 5x normal data volume."""
    # Build baseline with small data access
    for _ in range(10):
        detector.record_invocation(
            "agent-a", "logs", "read", duration_ms=50, data_accessed_bytes=100
        )
    detector._build_baseline("agent-a")
    # Now access huge data
    for _ in range(10):
        detector.record_invocation(
            "agent-a", "logs", "read", duration_ms=50, data_accessed_bytes=10000
        )
    alerts = detector.get_alerts(agent_name="agent-a")
    exfil_alerts = [a for a in alerts if a["anomaly_type"] == AnomalyType.DATA_EXFILTRATION.value]
    assert len(exfil_alerts) >= 1


def test_rate_spike_detection(detector: BehavioralAnomalyDetector) -> None:
    """Rate spike: 3x normal invocation rate in 30 minutes."""
    for _ in range(10):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    detector._build_baseline("agent-a")
    # Rapid burst
    for _ in range(50):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=10)
    alerts = detector.get_alerts(agent_name="agent-a")
    rate_alerts = [a for a in alerts if a["anomaly_type"] == AnomalyType.RATE_SPIKE.value]
    assert len(rate_alerts) >= 1


def test_privilege_escalation_detection(detector: BehavioralAnomalyDetector) -> None:
    """Accessing sensitive tools without baseline history should alert."""
    for _ in range(10):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    detector._build_baseline("agent-a")
    detector.record_invocation("agent-a", "admin_panel", "read", duration_ms=50)
    alerts = detector.get_alerts(agent_name="agent-a")
    priv_alerts = [a for a in alerts if a["anomaly_type"] == AnomalyType.PRIVILEGE_ESCALATION.value]
    assert len(priv_alerts) >= 1


def test_alerts_filter_by_severity(detector: BehavioralAnomalyDetector) -> None:
    """Filter alerts by severity level."""
    for _ in range(10):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    detector._build_baseline("agent-a")
    detector.record_invocation("agent-a", "admin_panel", "read", duration_ms=50)
    critical = detector.get_alerts(severity="CRITICAL")
    assert all(a["severity"] == "CRITICAL" for a in critical)


def test_no_alerts_for_normal_behavior(detector: BehavioralAnomalyDetector) -> None:
    """Normal behavior should not generate alerts after baseline is established."""
    # Build baseline with invocations timestamped 2 hours ago (outside 30-min window)
    old_time = datetime.now(timezone.utc) - timedelta(hours=2)
    with patch("navil.anomaly_detector.datetime") as mock_dt:
        mock_dt.now.return_value = old_time
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
        for _ in range(100):
            detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    detector._build_baseline("agent-a")
    detector.alerts.clear()

    # Now record a few normal invocations at current time — within baseline rate
    for _ in range(3):
        detector.record_invocation("agent-a", "logs", "read", duration_ms=50)
    alerts = detector.get_alerts(agent_name="agent-a")
    assert len(alerts) == 0


# ── New threshold boundary tests ─────────────────────────────────


class TestDefenseEvasionThreshold:
    """Defense evasion should use 50KB threshold (not 5KB)."""

    def test_5kb_payload_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """A 5KB payload should NOT trigger defense evasion (below 50KB threshold)."""
        detector.record_invocation(
            "agent-a", "tool", "run", duration_ms=100, arguments_size_bytes=5000
        )
        alerts = detector.get_alerts(agent_name="agent-a")
        de_alerts = [a for a in alerts if a["anomaly_type"] == "DEFENSE_EVASION"]
        assert len(de_alerts) == 0

    def test_49kb_payload_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """A 49KB payload should NOT trigger defense evasion."""
        detector.record_invocation(
            "agent-a", "tool", "run", duration_ms=100, arguments_size_bytes=49000
        )
        alerts = detector.get_alerts(agent_name="agent-a")
        de_alerts = [a for a in alerts if a["anomaly_type"] == "DEFENSE_EVASION"]
        assert len(de_alerts) == 0

    def test_60kb_payload_triggers_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """A 60KB payload should trigger defense evasion (above 50KB threshold)."""
        detector.record_invocation(
            "agent-a", "tool", "run", duration_ms=100, arguments_size_bytes=60000
        )
        alerts = detector.get_alerts(agent_name="agent-a")
        de_alerts = [a for a in alerts if a["anomaly_type"] == "DEFENSE_EVASION"]
        assert len(de_alerts) >= 1


class TestLateralMovementThreshold:
    """Lateral movement should use 8-server threshold (not 3)."""

    def test_4_servers_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """4 servers in 5 min should NOT trigger lateral movement."""
        for i in range(4):
            detector.record_invocation(
                "agent-a",
                "query",
                "call",
                duration_ms=50,
                target_server=f"http://server-{i}:3000",
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        lm_alerts = [a for a in alerts if a["anomaly_type"] == "LATERAL_MOVEMENT"]
        assert len(lm_alerts) == 0

    def test_7_servers_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """7 servers in 5 min should NOT trigger lateral movement."""
        for i in range(7):
            detector.record_invocation(
                "agent-a",
                "query",
                "call",
                duration_ms=50,
                target_server=f"http://server-{i}:3000",
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        lm_alerts = [a for a in alerts if a["anomaly_type"] == "LATERAL_MOVEMENT"]
        assert len(lm_alerts) == 0

    def test_9_servers_triggers_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """9 servers in 5 min should trigger lateral movement (above 8 threshold)."""
        for i in range(9):
            detector.record_invocation(
                "agent-a",
                "query",
                "call",
                duration_ms=50,
                target_server=f"http://server-{i}:3000",
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        lm_alerts = [a for a in alerts if a["anomaly_type"] == "LATERAL_MOVEMENT"]
        assert len(lm_alerts) >= 1


class TestReconnaissanceThreshold:
    """Reconnaissance should use 20-call threshold (not 5)."""

    def test_7_list_calls_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """7 tools/list calls should NOT trigger reconnaissance."""
        for _ in range(7):
            detector.record_invocation(
                "agent-a",
                "__tools_list__",
                "tools/list",
                duration_ms=10,
                is_list_tools=True,
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        recon_alerts = [a for a in alerts if a["anomaly_type"] == "RECONNAISSANCE"]
        assert len(recon_alerts) == 0

    def test_20_list_calls_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """20 tools/list calls should NOT trigger reconnaissance (at threshold, not above)."""
        for _ in range(20):
            detector.record_invocation(
                "agent-a",
                "__tools_list__",
                "tools/list",
                duration_ms=10,
                is_list_tools=True,
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        recon_alerts = [a for a in alerts if a["anomaly_type"] == "RECONNAISSANCE"]
        assert len(recon_alerts) == 0

    def test_25_list_calls_triggers_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """25 tools/list calls should trigger reconnaissance (above 20 threshold)."""
        for _ in range(25):
            detector.record_invocation(
                "agent-a",
                "__tools_list__",
                "tools/list",
                duration_ms=10,
                is_list_tools=True,
            )
        alerts = detector.get_alerts(agent_name="agent-a")
        recon_alerts = [a for a in alerts if a["anomaly_type"] == "RECONNAISSANCE"]
        assert len(recon_alerts) >= 1


class TestPersistenceIntervalException:
    """Persistence should only flag sub-60-second intervals."""

    def test_90s_intervals_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """90-second intervals should NOT trigger persistence (legitimate monitoring)."""
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        for i in range(8):
            ts = base + timedelta(seconds=i * 90)
            detector.record_invocation(
                "agent-a",
                "heartbeat",
                "ping",
                duration_ms=5,
                data_accessed_bytes=0,
                success=True,
                timestamp=ts.isoformat(),
            )
        detector._detect_persistence("agent-a")
        alerts = [a for a in detector.alerts if a.anomaly_type == "PERSISTENCE"]
        assert len(alerts) == 0

    def test_20s_intervals_triggers_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """20-second intervals should trigger persistence (sub-minute)."""
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        for i in range(8):
            ts = base + timedelta(seconds=i * 20)
            detector.record_invocation(
                "agent-a",
                "heartbeat",
                "ping",
                duration_ms=5,
                data_accessed_bytes=0,
                success=True,
                timestamp=ts.isoformat(),
            )
        detector._detect_persistence("agent-a")
        alerts = [a for a in detector.alerts if a.anomaly_type == "PERSISTENCE"]
        assert len(alerts) >= 1


class TestC2BeaconingMinimumCount:
    """C2 beaconing should require at least 10 beacons."""

    def test_5_beacons_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """5 beacons should NOT trigger C2 beaconing (below 10 minimum)."""
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        for i in range(5):
            ts = base + timedelta(seconds=i * 10)
            detector.record_invocation(
                "agent-a",
                "status",
                "check",
                duration_ms=20,
                data_accessed_bytes=0,
                success=True,
                response_size_bytes=256,
                timestamp=ts.isoformat(),
            )
        detector._detect_command_and_control("agent-a")
        alerts = [a for a in detector.alerts if a.anomaly_type == "COMMAND_AND_CONTROL"]
        assert len(alerts) == 0

    def test_8_beacons_no_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """8 beacons should NOT trigger C2 beaconing (below 10 minimum)."""
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        for i in range(8):
            ts = base + timedelta(seconds=i * 10)
            detector.record_invocation(
                "agent-a",
                "status",
                "check",
                duration_ms=20,
                data_accessed_bytes=0,
                success=True,
                response_size_bytes=256,
                timestamp=ts.isoformat(),
            )
        detector._detect_command_and_control("agent-a")
        alerts = [a for a in detector.alerts if a.anomaly_type == "COMMAND_AND_CONTROL"]
        assert len(alerts) == 0

    def test_12_beacons_triggers_alert(self, detector: BehavioralAnomalyDetector) -> None:
        """12 beacons should trigger C2 beaconing (above 10 minimum)."""
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        for i in range(12):
            ts = base + timedelta(seconds=i * 10)
            detector.record_invocation(
                "agent-a",
                "status",
                "check",
                duration_ms=20,
                data_accessed_bytes=0,
                success=True,
                response_size_bytes=256,
                timestamp=ts.isoformat(),
            )
        detector._detect_command_and_control("agent-a")
        alerts = [a for a in detector.alerts if a.anomaly_type == "COMMAND_AND_CONTROL"]
        assert len(alerts) >= 1
