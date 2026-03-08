"""Tests for the seed-database command and seeding logic."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.seed import (
    MockMCPServer,
    SeedStats,
    _fuzz_int,
    _gen_c2_beaconing,
    _gen_data_exfiltration,
    _gen_defense_evasion,
    _gen_lateral_movement,
    _gen_normal_traffic,
    _gen_persistence,
    _gen_privilege_escalation,
    _gen_rate_spike,
    _gen_reconnaissance,
    _gen_rug_pull,
    _gen_supply_chain,
    _inject_invocations,
    seed_database,
)

# ── Mock MCP Server ──────────────────────────────────────────────


class TestMockMCPServer:
    """Test the mock MCP server used during seeding."""

    def test_server_starts_and_stops(self) -> None:
        server = MockMCPServer()
        server.start()
        assert server.port > 0
        server.stop()

    def test_server_context_manager(self) -> None:
        with MockMCPServer() as server:
            assert server.port > 0
            assert server.url.startswith("http://127.0.0.1:")

    def test_server_responds_to_tools_list(self) -> None:
        import urllib.request

        with MockMCPServer() as server:
            req = urllib.request.Request(
                server.url,
                data=json.dumps({"method": "tools/list"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            assert "tools" in data
            assert len(data["tools"]) > 0

    def test_server_responds_to_tools_call(self) -> None:
        import urllib.request

        with MockMCPServer() as server:
            req = urllib.request.Request(
                server.url,
                data=json.dumps({
                    "method": "tools/call",
                    "params": {"name": "read_file", "args": {"path": "/tmp/test"}},
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            assert "result" in data


# ── Fuzzing Utilities ────────────────────────────────────────────


class TestFuzzing:
    """Test mathematical fuzzing functions."""

    def test_fuzz_int_within_bounds(self) -> None:
        for _ in range(200):
            val = _fuzz_int(100, 50, lo=0, hi=500)
            assert 0 <= val <= 500

    def test_fuzz_int_mean_approximately_correct(self) -> None:
        values = [_fuzz_int(100, 10) for _ in range(1000)]
        mean = sum(values) / len(values)
        assert 80 < mean < 120  # Wide band for randomness

    def test_fuzz_int_respects_lo_bound(self) -> None:
        for _ in range(100):
            val = _fuzz_int(1, 100, lo=50)
            assert val >= 50


# ── Scenario Generators ─────────────────────────────────────────


class TestScenarioGenerators:
    """Test that each scenario generator produces valid invocation dicts."""

    def test_gen_normal_traffic(self) -> None:
        invocations = _gen_normal_traffic("agent-1", 0)
        assert len(invocations) >= 5
        for inv in invocations:
            assert "agent_name" in inv
            assert "tool_name" in inv
            assert inv["duration_ms"] > 0

    def test_gen_reconnaissance(self) -> None:
        invocations = _gen_reconnaissance("agent-1", 0)
        assert len(invocations) >= 6
        for inv in invocations:
            assert inv["is_list_tools"] is True

    def test_gen_persistence(self) -> None:
        invocations = _gen_persistence("agent-1", 0)
        assert len(invocations) >= 6
        for inv in invocations:
            assert "_raw_timestamp" in inv

    def test_gen_defense_evasion(self) -> None:
        invocations = _gen_defense_evasion("agent-1", 0)
        assert len(invocations) == 1
        assert invocations[0]["arguments_size_bytes"] > 5000

    def test_gen_lateral_movement(self) -> None:
        invocations = _gen_lateral_movement("agent-1", 0)
        assert len(invocations) >= 4
        servers = {inv["target_server"] for inv in invocations}
        assert len(servers) >= 4

    def test_gen_c2_beaconing(self) -> None:
        invocations = _gen_c2_beaconing("agent-1", 0)
        assert len(invocations) >= 6
        for inv in invocations:
            assert "_raw_timestamp" in inv

    def test_gen_supply_chain(self) -> None:
        invocations = _gen_supply_chain("agent-1", 0)
        assert len(invocations) == 1
        assert "_register_server" in invocations[0]

    def test_gen_rug_pull(self) -> None:
        invocations = _gen_rug_pull("agent-1", 0)
        assert len(invocations) >= 3
        for inv in invocations:
            assert inv.get("_needs_baseline") is True

    def test_gen_data_exfiltration(self) -> None:
        invocations = _gen_data_exfiltration("agent-1", 0)
        assert len(invocations) == 1
        assert invocations[0]["data_accessed_bytes"] > 5000

    def test_gen_privilege_escalation(self) -> None:
        invocations = _gen_privilege_escalation("agent-1", 0)
        assert len(invocations) == 1
        assert invocations[0]["action"] == "admin"

    def test_gen_rate_spike(self) -> None:
        invocations = _gen_rate_spike("agent-1", 0)
        assert len(invocations) >= 30


# ── Injection ────────────────────────────────────────────────────


class TestInjection:
    """Test invocation injection into anomaly detector."""

    def test_inject_normal_invocations(self) -> None:
        det = BehavioralAnomalyDetector()
        invocations = _gen_normal_traffic("test-agent", 0)
        count = _inject_invocations(det, invocations)
        assert count == len(invocations)
        assert len(det.invocations) == count

    def test_inject_with_raw_timestamp(self) -> None:
        det = BehavioralAnomalyDetector()
        invocations = _gen_persistence("test-agent", 0)
        count = _inject_invocations(det, invocations)
        assert count >= 6
        # Raw timestamp invocations are appended directly
        assert len(det.invocations) == count

    def test_inject_with_server_registration(self) -> None:
        det = BehavioralAnomalyDetector()
        invocations = _gen_supply_chain("test-agent", 0)
        _inject_invocations(det, invocations)
        assert "http://mcp-server:3000" in det.registered_tools

    def test_inject_with_baseline_creation(self) -> None:
        det = BehavioralAnomalyDetector()
        invocations = _gen_rug_pull("test-agent", 0)
        _inject_invocations(det, invocations)
        assert "test-agent" in det.baselines


# ── SeedStats ────────────────────────────────────────────────────


class TestSeedStats:
    """Test SeedStats dataclass."""

    def test_to_dict(self) -> None:
        stats = SeedStats(
            iterations=100,
            total_invocations=5000,
            total_alerts=42,
            alerts_by_type={"RECONNAISSANCE": 20, "RATE_SPIKE": 22},
            scenarios_run={"reconnaissance": 100},
            elapsed_seconds=1.234,
        )
        d = stats.to_dict()
        assert d["iterations"] == 100
        assert d["total_invocations"] == 5000
        assert d["total_alerts"] == 42
        assert d["elapsed_seconds"] == 1.23


# ── Full Seed ────────────────────────────────────────────────────


class TestSeedDatabase:
    """Test the full seed_database function."""

    def test_seed_small_run(self) -> None:
        """Run a minimal seed to verify end-to-end works."""
        stats = seed_database(
            iterations=3,
            show_progress=False,
            mock_server=False,
        )
        assert stats.iterations == 3
        assert stats.total_invocations > 0
        assert stats.elapsed_seconds > 0
        # Should have run all non-policy scenarios
        assert len(stats.scenarios_run) == 10

    def test_seed_with_mock_server(self) -> None:
        """Verify seed works with mock server running."""
        stats = seed_database(
            iterations=2,
            show_progress=False,
            mock_server=True,
        )
        assert stats.iterations == 2
        assert stats.total_invocations > 0

    def test_seed_with_provided_detector(self) -> None:
        """Verify seed populates a provided detector."""
        det = BehavioralAnomalyDetector()
        stats = seed_database(
            iterations=3,
            detector=det,
            show_progress=False,
            mock_server=False,
        )
        assert stats.total_invocations > 0
        # The shared detector should have invocations from baseline feeding
        assert len(det.invocations) > 0

    def test_seed_generates_alerts(self) -> None:
        """Verify that attack scenarios actually fire alerts."""
        stats = seed_database(
            iterations=5,
            show_progress=False,
            mock_server=False,
        )
        assert stats.total_alerts > 0
        assert len(stats.alerts_by_type) > 0

    def test_seed_stats_alerts_by_type(self) -> None:
        """Verify multiple alert types are represented."""
        stats = seed_database(
            iterations=10,
            show_progress=False,
            mock_server=False,
        )
        # At minimum, we expect reconnaissance and defense_evasion to fire
        # (they don't need baselines)
        assert len(stats.alerts_by_type) >= 2


# ── CLI Integration ──────────────────────────────────────────────


class TestCLIIntegration:
    """Test the CLI entry point for seed-database."""

    def test_cli_seed_database_executes(self) -> None:
        """Verify the CLI command runs end-to-end."""
        from navil.cli import main

        with patch("sys.argv", ["navil", "seed-database", "-n", "2", "--quiet", "--no-server"]):
            exit_code = main()
        assert exit_code == 0

    def test_cli_seed_database_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verify JSON output mode works."""
        from navil.cli import main

        with patch("sys.argv", ["navil", "seed-database", "-n", "2", "--quiet", "--no-server", "--json"]):
            exit_code = main()
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["iterations"] == 2
        assert data["total_invocations"] > 0
