# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""Seed the BehavioralAnomalyDetector with synthetic baseline data.

Runs all 11 SAFE-MCP attack scenarios N times with mathematical fuzzing
(varied payload sizes, durations, response sizes, and JSON depth) to
populate the anomaly detector with realistic statistical baselines.

Usage (CLI):
    navil seed-database --iterations 1000

Programmatic:
    from navil.seed import seed_database
    stats = seed_database(iterations=1000)
"""

from __future__ import annotations

import hashlib
import logging
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from navil.anomaly_detector import BehavioralAnomalyDetector
from navil.pentest import SCENARIOS

logger = logging.getLogger(__name__)

# ── Mock MCP Server ──────────────────────────────────────────────

_MOCK_TOOLS = [
    {"name": "read_file", "description": "Read a file from disk"},
    {"name": "write_file", "description": "Write a file to disk"},
    {"name": "list_files", "description": "List directory contents"},
    {"name": "query_db", "description": "Run a database query"},
    {"name": "send_email", "description": "Send an email message"},
    {"name": "admin_panel", "description": "Access admin dashboard"},
    {"name": "network_scan", "description": "Scan network ports"},
    {"name": "status", "description": "Health check endpoint"},
]


class _MockMCPHandler(BaseHTTPRequestHandler):
    """Minimal MCP-over-HTTP handler for seeding."""

    def do_POST(self) -> None:  # noqa: N802
        import json

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len else b""

        try:
            req = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            req = {}

        method = req.get("method", "")

        resp: dict[str, Any]
        if method == "tools/list":
            resp = {"tools": _MOCK_TOOLS}
        elif method == "tools/call":
            # Echo back a synthetic result whose size is proportional to input
            arg_size = len(json.dumps(req.get("params", {})))
            resp = {"result": "x" * max(arg_size, 64)}
        else:
            resp = {"error": f"unknown method: {method}"}

        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stderr logging."""
        pass


class MockMCPServer:
    """Background-threaded mock MCP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = HTTPServer((host, port), _MockMCPHandler)
        self.host = host
        self.port = self._server.server_address[1]
        self.url = f"http://{self.host}:{self.port}"
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("Mock MCP server started at %s", self.url)

    def stop(self) -> None:
        self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Mock MCP server stopped")

    def __enter__(self) -> MockMCPServer:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()


# ── Fuzzing Utilities ────────────────────────────────────────────

# Normal-distribution parameters for each fuzzed dimension.
# Each scenario class has different "typical" ranges.

_NORMAL_TOOLS = ["read_file", "write_file", "list_files", "query_db", "send_email"]
_SENSITIVE_TOOLS = ["admin_panel", "network_scan", "credential_dump", "exfil_data"]
_RECON_TOOLS = ["__tools_list__"]

_MCP_SERVERS = [
    "http://mcp-alpha:3000",
    "http://mcp-beta:3000",
    "http://mcp-gamma:3000",
    "http://mcp-delta:3000",
    "http://mcp-epsilon:3000",
]


def _fuzz_int(mean: float, std: float, lo: int = 0, hi: int = 1_000_000) -> int:
    """Sample from a clipped Gaussian."""
    return max(lo, min(hi, int(random.gauss(mean, std))))


def _fuzz_float(mean: float, std: float, lo: float = 0.0, hi: float = 1e6) -> float:
    return max(lo, min(hi, random.gauss(mean, std)))


def _random_hash() -> str:
    """Generate a random SHA-256-like hex string."""
    return hashlib.sha256(random.randbytes(32)).hexdigest()


# ── Progress Bar ─────────────────────────────────────────────────


def _progress_bar(current: int, total: int, width: int = 40, label: str = "") -> None:
    """Print a single-line progress bar to stderr."""
    pct = current / total if total else 1.0
    filled = int(width * pct)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    line = f"\r  {label} [{bar}] {current}/{total} ({pct:.0%})"
    sys.stderr.write(line)
    sys.stderr.flush()


# ── Scenario Generators ─────────────────────────────────────────
# Each generator yields (invocation_kwargs, build_baseline_first) tuples
# to be fed into a BehavioralAnomalyDetector.


def _gen_normal_traffic(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Generate normal benign traffic to establish baselines."""
    invocations = []
    n_calls = _fuzz_int(15, 5, lo=5, hi=40)
    for _ in range(n_calls):
        tool = random.choice(_NORMAL_TOOLS)
        invocations.append(
            {
                "agent_name": agent,
                "tool_name": tool,
                "action": random.choice(["read", "write", "list", "query"]),
                "duration_ms": _fuzz_int(50, 20, lo=5),
                "data_accessed_bytes": _fuzz_int(200, 100, lo=0),
                "success": random.random() > 0.02,  # 98% success rate
                "arguments_size_bytes": _fuzz_int(150, 80, lo=10),
                "response_size_bytes": _fuzz_int(500, 200, lo=20),
                "arguments_hash": _random_hash(),
            }
        )
    return invocations


def _gen_reconnaissance(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Excessive tools/list probing."""
    n_probes = _fuzz_int(8, 3, lo=6, hi=20)
    return [
        {
            "agent_name": agent,
            "tool_name": "__tools_list__",
            "action": "tools/list",
            "duration_ms": _fuzz_int(10, 5, lo=2),
            "is_list_tools": True,
            "arguments_size_bytes": _fuzz_int(20, 10, lo=5),
            "response_size_bytes": _fuzz_int(800, 200, lo=100),
        }
        for _ in range(n_probes)
    ]


def _gen_persistence(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Bot-like periodic reconnection."""
    interval_s = _fuzz_int(30, 5, lo=15, hi=60)
    n_beats = _fuzz_int(8, 2, lo=6, hi=15)
    base = datetime.now(timezone.utc) - timedelta(minutes=15)
    invocations = []
    for i in range(n_beats):
        ts = base + timedelta(seconds=i * interval_s)
        invocations.append(
            {
                "_raw_timestamp": ts.isoformat(),
                "agent_name": agent,
                "tool_name": "heartbeat",
                "action": "ping",
                "duration_ms": _fuzz_int(5, 2, lo=1),
                "response_size_bytes": _fuzz_int(64, 20, lo=10),
            }
        )
    return invocations


def _gen_defense_evasion(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Large encoded payload."""
    return [
        {
            "agent_name": agent,
            "tool_name": random.choice(["execute", "eval", "run_script"]),
            "action": "run",
            "duration_ms": _fuzz_int(200, 80, lo=50),
            "arguments_size_bytes": _fuzz_int(7000, 2000, lo=5001),
            "response_size_bytes": _fuzz_int(300, 100, lo=50),
            "arguments_hash": _random_hash(),
        }
    ]


def _gen_lateral_movement(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Cross-server tool chaining."""
    n_servers = _fuzz_int(5, 1, lo=4, hi=8)
    servers = random.sample(_MCP_SERVERS, min(n_servers, len(_MCP_SERVERS)))
    # Pad with extra fake servers if needed
    while len(servers) < n_servers:
        servers.append(f"http://mcp-extra-{random.randint(1, 99)}:3000")
    return [
        {
            "agent_name": agent,
            "tool_name": random.choice(["query", "fetch", "invoke"]),
            "action": "tools/call",
            "duration_ms": _fuzz_int(80, 30, lo=10),
            "target_server": server,
            "data_accessed_bytes": _fuzz_int(300, 100, lo=0),
            "arguments_size_bytes": _fuzz_int(200, 80, lo=20),
            "response_size_bytes": _fuzz_int(500, 200, lo=50),
        }
        for server in servers
    ]


def _gen_c2_beaconing(agent: str, iteration: int) -> list[dict[str, Any]]:
    """C2 beaconing with consistent intervals and small payloads."""
    interval_s = _fuzz_int(10, 2, lo=5, hi=20)
    n_beacons = _fuzz_int(8, 2, lo=6, hi=15)
    resp_bytes = _fuzz_int(256, 30, lo=100, hi=500)
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    return [
        {
            "_raw_timestamp": (base + timedelta(seconds=i * interval_s)).isoformat(),
            "agent_name": agent,
            "tool_name": "status",
            "action": "check",
            "duration_ms": _fuzz_int(20, 5, lo=5),
            "response_size_bytes": _fuzz_int(resp_bytes, 20, lo=50),
        }
        for i in range(n_beacons)
    ]


def _gen_supply_chain(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Calling unregistered tools on a known server."""
    bad_tool = random.choice(["inject_backdoor", "shadow_deploy", "exfil_creds", "keylogger"])
    return [
        {
            "_register_server": ("http://mcp-server:3000", ["read", "write", "list"]),
            "agent_name": agent,
            "tool_name": bad_tool,
            "action": "tools/call",
            "duration_ms": _fuzz_int(100, 40, lo=20),
            "target_server": "http://mcp-server:3000",
            "arguments_size_bytes": _fuzz_int(300, 100, lo=50),
            "response_size_bytes": _fuzz_int(200, 80, lo=20),
        }
    ]


def _gen_rug_pull(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Sudden shift to new tools not in baseline."""
    new_tools = random.sample(
        _SENSITIVE_TOOLS + ["shadow_api", "dump_memory", "proxy_chain"],
        k=_fuzz_int(4, 1, lo=3, hi=6),
    )
    return [
        {
            "_needs_baseline": True,
            "agent_name": agent,
            "tool_name": tool,
            "action": "execute",
            "duration_ms": _fuzz_int(100, 40, lo=20),
            "data_accessed_bytes": _fuzz_int(500, 200, lo=50),
            "arguments_size_bytes": _fuzz_int(250, 100, lo=30),
            "response_size_bytes": _fuzz_int(400, 150, lo=50),
        }
        for tool in new_tools
    ]


def _gen_data_exfiltration(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Data volume spike exceeding baseline."""
    return [
        {
            "_needs_baseline": True,
            "agent_name": agent,
            "tool_name": "read_data",
            "action": "read",
            "duration_ms": _fuzz_int(80, 30, lo=10),
            "data_accessed_bytes": _fuzz_int(8000, 2000, lo=5500),
            "arguments_size_bytes": _fuzz_int(100, 30, lo=20),
            "response_size_bytes": _fuzz_int(8000, 2000, lo=5000),
        }
    ]


def _gen_privilege_escalation(agent: str, iteration: int) -> list[dict[str, Any]]:
    """First-time access to sensitive admin tools."""
    sensitive = random.choice(_SENSITIVE_TOOLS)
    return [
        {
            "_needs_baseline": True,
            "agent_name": agent,
            "tool_name": sensitive,
            "action": "admin",
            "duration_ms": _fuzz_int(60, 25, lo=10),
            "data_accessed_bytes": _fuzz_int(200, 80, lo=0),
            "arguments_size_bytes": _fuzz_int(150, 60, lo=20),
            "response_size_bytes": _fuzz_int(300, 100, lo=50),
        }
    ]


def _gen_rate_spike(agent: str, iteration: int) -> list[dict[str, Any]]:
    """Sudden burst of rapid calls."""
    n_calls = _fuzz_int(45, 10, lo=30, hi=80)
    return [
        {
            "_needs_baseline": True,
            "agent_name": agent,
            "tool_name": "query",
            "action": "read",
            "duration_ms": _fuzz_int(10, 5, lo=1),
            "data_accessed_bytes": _fuzz_int(20, 10, lo=0),
            "arguments_size_bytes": _fuzz_int(50, 20, lo=5),
            "response_size_bytes": _fuzz_int(100, 40, lo=10),
        }
        for _ in range(n_calls)
    ]


# Map scenario names to their generators
_SCENARIO_GENERATORS: dict[str, Any] = {
    "reconnaissance": _gen_reconnaissance,
    "persistence": _gen_persistence,
    "defense_evasion": _gen_defense_evasion,
    "lateral_movement": _gen_lateral_movement,
    "c2_beaconing": _gen_c2_beaconing,
    "supply_chain": _gen_supply_chain,
    "rug_pull": _gen_rug_pull,
    "data_exfiltration": _gen_data_exfiltration,
    "privilege_escalation": _gen_privilege_escalation,
    "rate_spike": _gen_rate_spike,
}


# ── Core Seeding Logic ───────────────────────────────────────────


@dataclass
class SeedStats:
    """Statistics from a seed run."""

    iterations: int = 0
    total_invocations: int = 0
    total_alerts: int = 0
    alerts_by_type: dict[str, int] = field(default_factory=dict)
    scenarios_run: dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "total_invocations": self.total_invocations,
            "total_alerts": self.total_alerts,
            "alerts_by_type": self.alerts_by_type,
            "scenarios_run": self.scenarios_run,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }


def _inject_baseline(detector: BehavioralAnomalyDetector, agent: str) -> int:
    """Inject normal baseline traffic into the detector. Returns invocation count."""
    baseline_time = datetime.now(timezone.utc) - timedelta(hours=2)
    n_baseline = _fuzz_int(15, 5, lo=8, hi=25)
    for i in range(n_baseline):
        ts = baseline_time + timedelta(minutes=i * 6)
        detector.record_invocation(
            agent_name=agent,
            tool_name=random.choice(_NORMAL_TOOLS),
            action="read",
            duration_ms=_fuzz_int(50, 20, lo=5),
            data_accessed_bytes=_fuzz_int(100, 50, lo=0),
            success=True,
            arguments_size_bytes=_fuzz_int(80, 30, lo=10),
            response_size_bytes=_fuzz_int(200, 80, lo=20),
            timestamp=ts.isoformat(),
        )
    detector._build_baseline(agent)
    return n_baseline


def _inject_invocations(
    detector: BehavioralAnomalyDetector,
    invocations: list[dict[str, Any]],
) -> int:
    """Inject a list of fuzzed invocations into the detector. Returns count."""
    count = 0
    for inv in invocations:
        # Handle special directives
        raw_ts = inv.pop("_raw_timestamp", None)
        needs_baseline = inv.pop("_needs_baseline", False)
        register = inv.pop("_register_server", None)

        if register:
            server_url, tools = register
            detector.register_server_tools(server_url, tools)

        if needs_baseline and not detector.baselines.get(inv["agent_name"]):
            _inject_baseline(detector, inv["agent_name"])

        if raw_ts:
            # Use record_invocation with explicit timestamp for timestamp-sensitive scenarios
            detector.record_invocation(
                agent_name=inv["agent_name"],
                tool_name=inv["tool_name"],
                action=inv.get("action", "unknown"),
                duration_ms=inv.get("duration_ms", 10),
                data_accessed_bytes=inv.get("data_accessed_bytes", 0),
                success=inv.get("success", True),
                location=inv.get("location"),
                target_server=inv.get("target_server"),
                arguments_hash=inv.get("arguments_hash"),
                arguments_size_bytes=inv.get("arguments_size_bytes", 0),
                response_size_bytes=inv.get("response_size_bytes", 0),
                is_list_tools=inv.get("is_list_tools", False),
                timestamp=raw_ts,
            )
        else:
            # Use record_invocation for full detection pipeline
            detector.record_invocation(
                agent_name=inv["agent_name"],
                tool_name=inv["tool_name"],
                action=inv.get("action", "unknown"),
                duration_ms=inv.get("duration_ms", 10),
                data_accessed_bytes=inv.get("data_accessed_bytes", 0),
                success=inv.get("success", True),
                location=inv.get("location"),
                target_server=inv.get("target_server"),
                arguments_hash=inv.get("arguments_hash"),
                arguments_size_bytes=inv.get("arguments_size_bytes", 0),
                response_size_bytes=inv.get("response_size_bytes", 0),
                is_list_tools=inv.get("is_list_tools", False),
            )
        count += 1
    return count


def _run_persistence_detectors(
    detector: BehavioralAnomalyDetector, agent: str, scenario: str
) -> None:
    """Trigger time-based detectors that need explicit invocation."""
    if scenario == "persistence":
        detector._detect_persistence(agent)
    elif scenario == "c2_beaconing":
        detector._detect_command_and_control(agent)


def seed_database(
    iterations: int = 1000,
    detector: BehavioralAnomalyDetector | None = None,
    show_progress: bool = True,
    mock_server: bool = True,
    full: bool = False,
) -> SeedStats:
    """Seed the anomaly detector with synthetic attack data.

    Args:
        iterations: Number of times to run each scenario.
        detector: Detector to seed. Creates a new one if None.
        show_progress: Show CLI progress bar.
        mock_server: Start a mock MCP server (for realism; not strictly required).
        full: If True, also run parameterized scenarios from public_attacks.yaml.

    Returns:
        SeedStats with summary of what was generated.
    """
    stats = SeedStats(iterations=iterations)
    t0 = time.monotonic()

    if detector is None:
        from navil.adaptive.feedback import FeedbackLoop
        from navil.adaptive.pattern_store import PatternStore

        detector = BehavioralAnomalyDetector(
            feedback_loop=FeedbackLoop(),
            pattern_store=PatternStore(),
        )

    scenarios = [s for s in SCENARIOS if s in _SCENARIO_GENERATORS]
    # policy_bypass is pentest-only (needs PolicyEngine), skip in seeding
    total_steps = len(scenarios) * iterations

    server_ctx: Any = None
    if mock_server:
        server_ctx = MockMCPServer()
        server_ctx.start()

    try:
        step = 0
        for scenario_name in scenarios:
            gen_fn = _SCENARIO_GENERATORS[scenario_name]
            stats.scenarios_run[scenario_name] = 0

            for i in range(iterations):
                # Fresh detector per iteration to avoid cross-contamination
                det = BehavioralAnomalyDetector()

                # Unique agent name per iteration for variety
                agent = f"seed-agent-{scenario_name}-{i % 50}"

                # Generate and inject fuzzed attack invocations
                attack_invocations = gen_fn(agent, i)
                count = _inject_invocations(det, attack_invocations)

                # Trigger time-based detectors
                _run_persistence_detectors(det, agent, scenario_name)

                stats.total_invocations += count
                stats.scenarios_run[scenario_name] += 1

                # Count alerts generated
                for alert in det.alerts:
                    stats.total_alerts += 1
                    atype = alert.anomaly_type
                    stats.alerts_by_type[atype] = stats.alerts_by_type.get(atype, 0) + 1

                # Also feed a subset of invocations into the shared detector
                # for cumulative baseline building
                if i % 10 == 0:
                    for inv_kwargs in attack_invocations:
                        # Clean special keys
                        clean = {k: v for k, v in inv_kwargs.items() if not k.startswith("_")}
                        if clean.get("agent_name"):
                            detector.record_invocation(**clean)

                step += 1
                if show_progress:
                    _progress_bar(step, total_steps, label=f"{scenario_name:<22}")

        # Also inject a large batch of normal traffic into the shared detector
        for i in range(iterations // 10):
            agent = f"seed-normal-{i % 20}"
            normal = _gen_normal_traffic(agent, i)
            for inv in normal:
                detector.record_invocation(**inv)
                stats.total_invocations += 1

        # ── Full mode: run parameterized scenarios from public_attacks.yaml ──
        if full:
            from navil.safemcp.generator import AttackVariantGenerator

            variant_gen = AttackVariantGenerator()
            variant_gen.load()
            expanded_generators = variant_gen.generate_scenario_generators()

            expanded_steps = len(expanded_generators) * iterations
            exp_step = 0
            for scenario_name, gen_fn in expanded_generators.items():
                stats.scenarios_run.setdefault(scenario_name, 0)
                for i in range(iterations):
                    det = BehavioralAnomalyDetector()
                    agent = f"seed-expanded-{scenario_name[:16]}-{i % 50}"
                    attack_invocations = gen_fn(agent, i)
                    count = _inject_invocations(det, attack_invocations)
                    stats.total_invocations += count
                    stats.scenarios_run[scenario_name] += 1

                    for alert in det.alerts:
                        stats.total_alerts += 1
                        atype = alert.anomaly_type
                        stats.alerts_by_type[atype] = stats.alerts_by_type.get(atype, 0) + 1

                    if i % 10 == 0:
                        for inv_kwargs in attack_invocations:
                            clean = {k: v for k, v in inv_kwargs.items() if not k.startswith("_")}
                            if clean.get("agent_name"):
                                detector.record_invocation(**clean)

                    exp_step += 1
                    if show_progress:
                        _progress_bar(
                            exp_step, expanded_steps, label=f"[expanded] {scenario_name[:22]:<22}"
                        )

        if show_progress:
            sys.stderr.write("\n")
            sys.stderr.flush()

    finally:
        if server_ctx is not None:
            server_ctx.stop()

    stats.elapsed_seconds = time.monotonic() - t0
    return stats


def export_scenarios(include_expanded: bool = True) -> list[dict[str, Any]]:
    """Export all scenario definitions to a JSON-serializable list.

    Args:
        include_expanded: If True, include parameterized scenarios from
                          public_attacks.yaml in addition to built-in ones.

    Returns:
        List of scenario definition dicts.
    """
    base_scenarios: list[dict[str, Any]] = []
    for name, _gen_fn in _SCENARIO_GENERATORS.items():
        base_scenarios.append(
            {
                "name": name,
                "source": "builtin",
                "category": name.upper(),
                "description": SCENARIOS.get(name, {}).get("description", ""),
            }
        )

    if include_expanded:
        from navil.safemcp.generator import AttackVariantGenerator

        variant_gen = AttackVariantGenerator()
        variant_gen.load()
        for entry in variant_gen.export_scenarios():
            entry["source"] = "public_attacks_catalog"
            base_scenarios.append(entry)

    return base_scenarios
