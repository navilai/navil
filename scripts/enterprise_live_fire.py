#!/usr/bin/env python3
"""Enterprise Live Fire — The War Game.

Fires realistic MCP traffic at the Navil cloud backend to populate the
dashboard with rich, accurate threat telemetry.  Simulates three Virtual
MCPs — each with a baseline of normal traffic followed by a distinct
attack payload — all sent concurrently via asyncio.

Usage:
    export NAVIL_API_KEY="navil_live_..."       # from seed_enterprise_drill.py
    export NAVIL_BACKEND_URL="https://api.navil.ai"  # or http://localhost:8000
    python scripts/enterprise_live_fire.py

Virtual MCPs:
    1. Postgres MCP   — 50 normal queries → SQL Injection (DROP TABLE)
    2. FileSystem MCP — 50 normal reads   → Path Traversal (../../../../etc/shadow)
    3. GitHub MCP     — 50 normal commits → Indirect Prompt Injection in PR body

Each virtual MCP fires traffic through two ingestion paths:
    - POST /v1/telemetry   — Raw event telemetry (populates dashboard timeline)
    - POST /v1/telemetry/sync — Anomaly sync events (populates threat feed)

Environment:
    NAVIL_API_KEY       — API key from seed_enterprise_drill.py (required)
    NAVIL_BACKEND_URL   — Cloud backend URL (default: http://localhost:8000)
    FIRE_RATE           — Events per second per MCP (default: 25)
    DRY_RUN             — Set to "1" to print payloads without sending
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required.  pip install httpx")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("NAVIL_API_KEY", "")
BACKEND_URL = os.environ.get("NAVIL_BACKEND_URL", "http://localhost:8000").rstrip("/")
FIRE_RATE = int(os.environ.get("FIRE_RATE", "25"))  # events/sec/MCP
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")

# Recognized anomaly types (must match cloud backend schema)
ANOMALY_TYPES = {
    "RECONNAISSANCE",
    "PERSISTENCE",
    "DEFENSE_EVASION",
    "LATERAL_MOVEMENT",
    "COMMAND_AND_CONTROL",
    "SUPPLY_CHAIN",
    "RUG_PULL",
    "DATA_EXFILTRATION",
    "PRIVILEGE_ESCALATION",
    "RATE_SPIKE",
    "POLICY",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(offset_seconds: int = 0) -> str:
    """ISO 8601 timestamp with optional offset from now.

    Uses naive UTC (no +00:00 suffix) for asyncpg compatibility — the cloud
    backend's ``sync_events.timestamp`` column is TIMESTAMP WITHOUT TIME ZONE.
    """
    dt = datetime.utcnow() + timedelta(seconds=offset_seconds)
    return dt.isoformat()


def _event_uuid(agent: str, tool: str, ts: str, anomaly: str = "") -> str:
    """Deterministic UUID5 for deduplication (matches cloud sync logic)."""
    seed = f"{agent}:{tool}:{ts}:{anomaly}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _agent_id(name: str) -> str:
    """HMAC-like anonymized agent ID (matches telemetry sync format)."""
    return hashlib.sha256(f"e2e-drill:{name}".encode()).hexdigest()


def _banner(msg: str) -> None:
    width = 64
    print(f"\n{'━' * width}")
    print(f"  {msg}")
    print(f"{'━' * width}")


def _phase(phase: str, mcp: str) -> None:
    print(f"  [{mcp:14s}] {phase}")


# ---------------------------------------------------------------------------
# Telemetry event builders
# ---------------------------------------------------------------------------


def build_raw_event(
    event_type: str,
    data: dict[str, Any],
    agent_id: str | None = None,
) -> dict:
    """Build a raw telemetry event for POST /v1/telemetry."""
    return {
        "agent_id": agent_id,
        "events": [{"type": event_type, "data": data}],
    }


def build_sync_event(
    agent_name: str,
    tool_name: str,
    anomaly_type: str,
    severity: str,
    confidence: float,
    ts: str | None = None,
    duration_ms: int = 50,
    payload_bytes: int = 256,
    response_bytes: int = 1024,
    action: str = "tools/call",
    statistical_deviation: float | None = None,
) -> dict:
    """Build a sync event for POST /v1/telemetry/sync."""
    timestamp = ts or _ts()
    aid = _agent_id(agent_name)
    return {
        "event_uuid": _event_uuid(aid, tool_name, timestamp, anomaly_type),
        "agent_id": aid,
        "tool_name": tool_name,
        "anomaly_type": anomaly_type,
        "severity": severity,
        "confidence": confidence,
        "statistical_deviation": statistical_deviation,
        "payload_bytes": payload_bytes,
        "response_bytes": response_bytes,
        "duration_ms": duration_ms,
        "timestamp": timestamp,
        "action": action,
    }


# ---------------------------------------------------------------------------
# Virtual MCP Scenarios
# ---------------------------------------------------------------------------


class VirtualMCP:
    """Base class for a simulated MCP server's traffic pattern."""

    name: str = "base"
    agent_name: str = "agent-base"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.stats = {"sent": 0, "errors": 0, "attacks": 0}

    async def _post_telemetry(self, payload: dict) -> None:
        """Send raw telemetry event."""
        if DRY_RUN:
            print(f"    [DRY-RUN] POST /v1/telemetry: {json.dumps(payload)[:120]}")
            self.stats["sent"] += 1
            return
        try:
            resp = await self.client.post(f"{BACKEND_URL}/v1/telemetry", json=payload)
            if resp.status_code < 300:
                self.stats["sent"] += 1
            else:
                self.stats["errors"] += 1
                if self.stats["errors"] <= 3:
                    print(f"    [WARN] /v1/telemetry {resp.status_code}: {resp.text[:100]}")
        except httpx.HTTPError as exc:
            self.stats["errors"] += 1
            if self.stats["errors"] <= 3:
                print(f"    [ERR] /v1/telemetry: {exc}")

    async def _post_sync(self, events: list[dict]) -> None:
        """Send anomaly sync events."""
        payload = {"events": events}
        if DRY_RUN:
            print(f"    [DRY-RUN] POST /v1/telemetry/sync: {len(events)} events")
            self.stats["sent"] += len(events)
            return
        try:
            resp = await self.client.post(f"{BACKEND_URL}/v1/telemetry/sync", json=payload)
            if resp.status_code < 300:
                self.stats["sent"] += len(events)
            else:
                self.stats["errors"] += 1
                if self.stats["errors"] <= 3:
                    print(f"    [WARN] /v1/telemetry/sync {resp.status_code}: {resp.text[:100]}")
        except httpx.HTTPError as exc:
            self.stats["errors"] += 1
            if self.stats["errors"] <= 3:
                print(f"    [ERR] /v1/telemetry/sync: {exc}")

    async def fire_normal(self, count: int = 50) -> None:
        """Override in subclass — send normal baseline traffic."""
        raise NotImplementedError

    async def fire_attack(self) -> None:
        """Override in subclass — send the attack payload."""
        raise NotImplementedError

    async def run(self) -> dict:
        """Execute the full scenario: baseline then attack."""
        _phase("Baseline traffic (50 normal calls)...", self.name)
        await self.fire_normal(50)
        _phase("Attack payload...", self.name)
        await self.fire_attack()
        _phase(
            f"Done — sent={self.stats['sent']} "
            f"attacks={self.stats['attacks']} "
            f"errors={self.stats['errors']}",
            self.name,
        )
        return self.stats


class PostgresMCP(VirtualMCP):
    """Virtual Postgres MCP — normal queries followed by SQL Injection."""

    name = "Postgres MCP"
    agent_name = "postgres-data-agent"

    NORMAL_QUERIES = [
        "SELECT id, name, email FROM users WHERE active = true LIMIT 100",
        "SELECT COUNT(*) FROM orders WHERE created_at > NOW() - INTERVAL '24 hours'",
        "SELECT product_name, price FROM products WHERE category = 'electronics'",
        "SELECT AVG(response_time_ms) FROM api_metrics WHERE endpoint = '/api/v1/users'",
        "SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name",
        "INSERT INTO audit_log (action, user_id, timestamp) VALUES ('login', 42, NOW())",
        "UPDATE users SET last_login = NOW() WHERE id = 42",
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        "SELECT pg_database_size('navil')",
        "SELECT * FROM pg_stat_activity WHERE state = 'active'",
    ]

    async def fire_normal(self, count: int = 50) -> None:
        for i in range(count):
            random.choice(self.NORMAL_QUERIES)
            _ts(offset_seconds=-count + i)

            # Raw telemetry event
            await self._post_telemetry(
                build_raw_event(
                    event_type="tool_call",
                    data={
                        "tool_name": "query",
                        "action": "tools/call",
                        "duration_ms": random.randint(5, 80),
                        "success": True,
                        "agent_name": self.agent_name,
                    },
                    agent_id=_agent_id(self.agent_name),
                )
            )

            # Throttle to FIRE_RATE
            if (i + 1) % FIRE_RATE == 0:
                await asyncio.sleep(0.05)

    async def fire_attack(self) -> None:
        """SQL Injection — DROP TABLE followed by exfiltration attempt."""
        attack_ts = _ts()

        # 1. The injection payload
        sqli_event = build_raw_event(
            event_type="anomaly.critical",
            data={
                "tool_name": "query",
                "action": "blocked",
                "duration_ms": 2,
                "success": False,
                "agent_name": self.agent_name,
                "query_preview": "'; DROP TABLE users; --",
                "anomaly_type": "PRIVILEGE_ESCALATION",
            },
            agent_id=_agent_id(self.agent_name),
        )
        await self._post_telemetry(sqli_event)
        self.stats["attacks"] += 1

        # 2. Follow-up: suspicious UNION-based data exfiltration
        exfil_event = build_raw_event(
            event_type="anomaly.high",
            data={
                "tool_name": "query",
                "action": "blocked",
                "duration_ms": 1,
                "success": False,
                "agent_name": self.agent_name,
                "query_preview": "UNION SELECT password_hash FROM users",
                "anomaly_type": "DATA_EXFILTRATION",
            },
            agent_id=_agent_id(self.agent_name),
        )
        await self._post_telemetry(exfil_event)
        self.stats["attacks"] += 1

        # 3. Sync the anomalies to the threat feed
        sync_events = [
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="query",
                anomaly_type="PRIVILEGE_ESCALATION",
                severity="CRITICAL",
                confidence=0.98,
                ts=attack_ts,
                duration_ms=2,
                payload_bytes=48,
                response_bytes=0,
                statistical_deviation=450.0,
            ),
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="query",
                anomaly_type="DATA_EXFILTRATION",
                severity="CRITICAL",
                confidence=0.95,
                ts=_ts(1),
                duration_ms=1,
                payload_bytes=64,
                response_bytes=0,
                statistical_deviation=380.0,
            ),
            # Rate spike from the rapid-fire queries
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="query",
                anomaly_type="RATE_SPIKE",
                severity="MEDIUM",
                confidence=0.72,
                ts=_ts(2),
                duration_ms=5,
                payload_bytes=256,
                statistical_deviation=120.0,
            ),
        ]
        await self._post_sync(sync_events)


class FileSystemMCP(VirtualMCP):
    """Virtual FileSystem MCP — normal file reads then Path Traversal."""

    name = "FileSystem MCP"
    agent_name = "filesystem-reader"

    NORMAL_FILES = [
        "/app/src/index.ts",
        "/app/src/components/Dashboard.tsx",
        "/app/package.json",
        "/app/tsconfig.json",
        "/app/README.md",
        "/app/src/utils/helpers.ts",
        "/app/src/api/routes.ts",
        "/app/.env.example",
        "/app/docker-compose.yml",
        "/app/src/styles/theme.css",
        "/app/tests/unit/auth.test.ts",
        "/app/src/middleware/cors.ts",
    ]

    async def fire_normal(self, count: int = 50) -> None:
        for i in range(count):
            random.choice(self.NORMAL_FILES)
            file_size = random.randint(200, 15000)

            await self._post_telemetry(
                build_raw_event(
                    event_type="tool_call",
                    data={
                        "tool_name": "read_file",
                        "action": "tools/call",
                        "duration_ms": random.randint(2, 30),
                        "success": True,
                        "agent_name": self.agent_name,
                        "file_size": file_size,
                    },
                    agent_id=_agent_id(self.agent_name),
                )
            )

            if (i + 1) % FIRE_RATE == 0:
                await asyncio.sleep(0.05)

    async def fire_attack(self) -> None:
        """Path Traversal — attempt to read /etc/shadow and sensitive files."""
        attack_ts = _ts()

        # 1. Classic path traversal
        traversal_paths = [
            "../../../../etc/shadow",
            "../../../../etc/passwd",
            "../../../.env",
            "../../../../root/.ssh/id_rsa",
            "../../../../proc/self/environ",
        ]

        for i, path in enumerate(traversal_paths):
            event = build_raw_event(
                event_type="anomaly.critical" if i == 0 else "anomaly.high",
                data={
                    "tool_name": "read_file",
                    "action": "blocked",
                    "duration_ms": 1,
                    "success": False,
                    "agent_name": self.agent_name,
                    "file_path": path,
                    "anomaly_type": "PRIVILEGE_ESCALATION",
                },
                agent_id=_agent_id(self.agent_name),
            )
            await self._post_telemetry(event)
            self.stats["attacks"] += 1

        # 2. Sync the anomalies
        sync_events = [
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="read_file",
                anomaly_type="PRIVILEGE_ESCALATION",
                severity="CRITICAL",
                confidence=0.99,
                ts=attack_ts,
                payload_bytes=len("../../../../etc/shadow"),
                response_bytes=0,
                statistical_deviation=500.0,
            ),
            # Defense evasion: the path encoding trick
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="read_file",
                anomaly_type="DEFENSE_EVASION",
                severity="HIGH",
                confidence=0.88,
                ts=_ts(1),
                payload_bytes=len("../../../../proc/self/environ"),
                response_bytes=0,
                statistical_deviation=200.0,
            ),
            # Reconnaissance: scanning multiple sensitive paths
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="read_file",
                anomaly_type="RECONNAISSANCE",
                severity="MEDIUM",
                confidence=0.75,
                ts=_ts(2),
                payload_bytes=512,
                statistical_deviation=150.0,
            ),
            # Data exfiltration attempt on /etc/shadow
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="read_file",
                anomaly_type="DATA_EXFILTRATION",
                severity="CRITICAL",
                confidence=0.96,
                ts=_ts(3),
                payload_bytes=128,
                response_bytes=4096,
                statistical_deviation=420.0,
            ),
        ]
        await self._post_sync(sync_events)


class GitHubMCP(VirtualMCP):
    """Virtual GitHub MCP — normal commits then Indirect Prompt Injection."""

    name = "GitHub MCP"
    agent_name = "github-review-agent"

    NORMAL_OPERATIONS = [
        ("list_commits", "tools/call", True),
        ("get_pull_request", "tools/call", True),
        ("list_issues", "tools/call", True),
        ("get_file_contents", "tools/call", True),
        ("create_comment", "tools/call", True),
        ("list_branches", "tools/call", True),
        ("get_diff", "tools/call", True),
        ("search_code", "tools/call", True),
    ]

    async def fire_normal(self, count: int = 50) -> None:
        for i in range(count):
            tool, action, success = random.choice(self.NORMAL_OPERATIONS)

            await self._post_telemetry(
                build_raw_event(
                    event_type="tool_call",
                    data={
                        "tool_name": tool,
                        "action": action,
                        "duration_ms": random.randint(20, 200),
                        "success": success,
                        "agent_name": self.agent_name,
                    },
                    agent_id=_agent_id(self.agent_name),
                )
            )

            if (i + 1) % FIRE_RATE == 0:
                await asyncio.sleep(0.05)

    async def fire_attack(self) -> None:
        """Indirect Prompt Injection hidden in a PR body."""
        attack_ts = _ts()

        # 1. The agent reads a PR that contains a prompt injection
        pr_read_event = build_raw_event(
            event_type="tool_call",
            data={
                "tool_name": "get_pull_request",
                "action": "tools/call",
                "duration_ms": 85,
                "success": True,
                "agent_name": self.agent_name,
            },
            agent_id=_agent_id(self.agent_name),
        )
        await self._post_telemetry(pr_read_event)

        # 2. Immediately after, the agent starts accessing unexpected tools
        #    (sign of a hijacked agent following injected instructions)

        # Lateral movement: agent starts talking to unfamiliar servers
        rogue_servers = [
            "http://evil-mcp.attacker.com:3000",
            "http://data-sink.malicious.io:8080",
            "http://c2-relay.darkweb.onion:9090",
        ]
        for server in rogue_servers:
            event = build_raw_event(
                event_type="anomaly.high",
                data={
                    "tool_name": "unknown_tool",
                    "action": "blocked",
                    "duration_ms": 5,
                    "success": False,
                    "agent_name": self.agent_name,
                    "target_server": server,
                    "anomaly_type": "LATERAL_MOVEMENT",
                },
                agent_id=_agent_id(self.agent_name),
            )
            await self._post_telemetry(event)
            self.stats["attacks"] += 1

        # 3. Supply chain: agent tries to call a tool not in its manifest
        supply_chain_event = build_raw_event(
            event_type="anomaly.critical",
            data={
                "tool_name": "exfiltrate_secrets",
                "action": "blocked",
                "duration_ms": 1,
                "success": False,
                "agent_name": self.agent_name,
                "anomaly_type": "SUPPLY_CHAIN",
            },
            agent_id=_agent_id(self.agent_name),
        )
        await self._post_telemetry(supply_chain_event)
        self.stats["attacks"] += 1

        # 4. Command & Control: periodic beacon after injection
        for _i in range(6):
            beacon_event = build_raw_event(
                event_type="anomaly.high",
                data={
                    "tool_name": "status_check",
                    "action": "blocked",
                    "duration_ms": 8,
                    "success": False,
                    "agent_name": self.agent_name,
                    "anomaly_type": "COMMAND_AND_CONTROL",
                },
                agent_id=_agent_id(self.agent_name),
            )
            await self._post_telemetry(beacon_event)
            self.stats["attacks"] += 1

        # 5. Sync the anomalies to threat feed
        sync_events = [
            # The initial prompt injection detection
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="get_pull_request",
                anomaly_type="DEFENSE_EVASION",
                severity="CRITICAL",
                confidence=0.92,
                ts=attack_ts,
                payload_bytes=8192,
                response_bytes=65536,
                statistical_deviation=340.0,
            ),
            # Lateral movement to rogue servers
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="unknown_tool",
                anomaly_type="LATERAL_MOVEMENT",
                severity="HIGH",
                confidence=0.94,
                ts=_ts(1),
                payload_bytes=128,
                response_bytes=0,
                statistical_deviation=280.0,
            ),
            # Supply chain: unregistered tool call
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="exfiltrate_secrets",
                anomaly_type="SUPPLY_CHAIN",
                severity="CRITICAL",
                confidence=0.99,
                ts=_ts(2),
                payload_bytes=64,
                response_bytes=0,
                statistical_deviation=500.0,
            ),
            # C2 beaconing pattern
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="status_check",
                anomaly_type="COMMAND_AND_CONTROL",
                severity="CRITICAL",
                confidence=0.87,
                ts=_ts(3),
                duration_ms=8,
                payload_bytes=32,
                response_bytes=256,
                statistical_deviation=190.0,
            ),
            # Persistence: the injected instruction creates a recurring task
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="create_scheduled_task",
                anomaly_type="PERSISTENCE",
                severity="HIGH",
                confidence=0.81,
                ts=_ts(4),
                payload_bytes=512,
                response_bytes=128,
                statistical_deviation=250.0,
            ),
            # Rug pull: tool description changed post-injection
            build_sync_event(
                agent_name=self.agent_name,
                tool_name="get_pull_request",
                anomaly_type="RUG_PULL",
                severity="HIGH",
                confidence=0.76,
                ts=_ts(5),
                payload_bytes=2048,
                response_bytes=8192,
                statistical_deviation=310.0,
            ),
        ]
        await self._post_sync(sync_events)


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------


async def main() -> None:
    if not API_KEY:
        print("ERROR: NAVIL_API_KEY is required.")
        print("  Run seed_enterprise_drill.py first, then export the key.")
        sys.exit(1)

    _banner("ENTERPRISE LIVE FIRE DRILL")
    print(f"  Backend:    {BACKEND_URL}")
    print(f"  API Key:    {API_KEY[:20]}...")
    print(f"  Fire Rate:  {FIRE_RATE} events/sec/MCP")
    print(f"  Dry Run:    {DRY_RUN}")
    print("  MCPs:       Postgres, FileSystem, GitHub")
    print("  Strategy:   50 normal calls → attack payload (per MCP)")

    # Validate connectivity
    _banner("Phase 0: Connectivity Check")
    async with httpx.AsyncClient(
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=30.0,
    ) as client:
        if not DRY_RUN:
            try:
                resp = await client.get(f"{BACKEND_URL}/v1/health")
                if resp.status_code == 200:
                    print(f"  Backend is healthy: {resp.json()}")
                else:
                    print(f"  WARNING: Health check returned {resp.status_code}")
                    print("  Continuing anyway...")
            except httpx.HTTPError as exc:
                print(f"  WARNING: Cannot reach backend: {exc}")
                print("  Continuing anyway (may fail)...")
        else:
            print("  [DRY-RUN] Skipping connectivity check")

        # ------------------------------------------------------------------
        # Phase 1: Fire all three MCPs concurrently
        # ------------------------------------------------------------------
        _banner("Phase 1: Baseline + Attack (concurrent)")
        start = time.monotonic()

        postgres = PostgresMCP(client)
        filesystem = FileSystemMCP(client)
        github = GitHubMCP(client)

        results = await asyncio.gather(
            postgres.run(),
            filesystem.run(),
            github.run(),
            return_exceptions=True,
        )

        elapsed = time.monotonic() - start

        # ------------------------------------------------------------------
        # Phase 2: Post-attack anomaly burst
        # ------------------------------------------------------------------
        _banner("Phase 2: Cross-MCP Correlation Events")
        print("  Sending cross-MCP correlation signals...")

        # These simulate the anomaly detector recognizing coordinated activity
        # across the three compromised MCPs — a hallmark of an organized attack.
        correlation_events = [
            build_sync_event(
                agent_name="orchestrator-agent",
                tool_name="__cross_mcp_correlation__",
                anomaly_type="LATERAL_MOVEMENT",
                severity="CRITICAL",
                confidence=0.97,
                ts=_ts(),
                payload_bytes=0,
                response_bytes=0,
                statistical_deviation=600.0,
            ),
            build_sync_event(
                agent_name="orchestrator-agent",
                tool_name="__rate_anomaly__",
                anomaly_type="RATE_SPIKE",
                severity="HIGH",
                confidence=0.85,
                ts=_ts(1),
                payload_bytes=0,
                statistical_deviation=180.0,
            ),
            build_sync_event(
                agent_name="orchestrator-agent",
                tool_name="__behavioral_deviation__",
                anomaly_type="RECONNAISSANCE",
                severity="MEDIUM",
                confidence=0.70,
                ts=_ts(2),
                payload_bytes=0,
                statistical_deviation=95.0,
            ),
        ]

        if not DRY_RUN:
            try:
                resp = await client.post(
                    f"{BACKEND_URL}/v1/telemetry/sync",
                    json={"events": correlation_events},
                )
                if resp.status_code < 300:
                    print(f"  Correlation events accepted: {resp.json()}")
                else:
                    print(f"  WARNING: {resp.status_code} {resp.text[:100]}")
            except httpx.HTTPError as exc:
                print(f"  ERROR: {exc}")
        else:
            print(f"  [DRY-RUN] Would send {len(correlation_events)} correlation events")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        _banner("DRILL COMPLETE")

        total_sent = 0
        total_attacks = 0
        total_errors = 0

        mcp_names = ["Postgres MCP", "FileSystem MCP", "GitHub MCP"]
        for _i, (name, result) in enumerate(zip(mcp_names, results, strict=False)):
            if isinstance(result, Exception):
                print(f"  {name:18s}  ERROR: {result}")
            else:
                total_sent += result["sent"]
                total_attacks += result["attacks"]
                total_errors += result["errors"]
                print(
                    f"  {name:18s}  "
                    f"sent={result['sent']:4d}  "
                    f"attacks={result['attacks']:2d}  "
                    f"errors={result['errors']:2d}"
                )

        print(f"\n  {'─' * 50}")
        print(f"  Total events sent:    {total_sent}")
        print(f"  Total attack payloads: {total_attacks}")
        print(f"  Total errors:          {total_errors}")
        print(f"  Elapsed time:          {elapsed:.1f}s")
        print(f"  Throughput:            {total_sent / max(elapsed, 0.1):.0f} events/sec")

        print(f"""
  ┌─────────────────────────────────────────────────────────────┐
  │  Dashboard should now show:                                  │
  │                                                              │
  │  Anomaly Types Triggered:                                    │
  │    - PRIVILEGE_ESCALATION  (SQL injection + path traversal)  │
  │    - DATA_EXFILTRATION     (shadow file + UNION query)       │
  │    - DEFENSE_EVASION       (prompt injection + path encode)  │
  │    - LATERAL_MOVEMENT      (rogue MCP servers)               │
  │    - SUPPLY_CHAIN          (unregistered tool call)          │
  │    - COMMAND_AND_CONTROL   (post-injection beaconing)        │
  │    - PERSISTENCE           (scheduled task creation)         │
  │    - RUG_PULL              (tool description mutation)       │
  │    - RECONNAISSANCE        (sensitive path scanning)         │
  │    - RATE_SPIKE            (rapid-fire queries)              │
  │                                                              │
  │  10 / 13 recognized anomaly types exercised                  │
  │                                                              │
  │  Check: {BACKEND_URL.replace("/api", "")}/dashboard
  └─────────────────────────────────────────────────────────────┘
""")


if __name__ == "__main__":
    asyncio.run(main())
