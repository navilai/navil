"""Parameterized SAFE-MCP scenario generator.

Reads each attack from public_attacks.yaml and generates 5-10 variants per
attack by parameterizing tool names, timing patterns, payload sizes, agent
names, and target resources.  Each variant is a valid scenario that can be
fed to the anomaly detector via the same injection path used by seed.py.

Output format is compatible with the existing ``_SCENARIO_GENERATORS`` dict
in ``navil.seed`` (each generator returns a ``list[dict[str, Any]]``).
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────

_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "public_attacks.yaml")

# Tool name substitution pools (grouped by purpose)
_TOOL_POOLS: dict[str, list[str]] = {
    "read": ["read_file", "cat_file", "get_contents", "fetch_file", "load_file"],
    "write": ["write_file", "save_file", "put_contents", "store_file", "update_file"],
    "list": ["list_files", "ls", "dir_contents", "enumerate_files", "browse_dir"],
    "execute": ["execute", "eval", "run_script", "exec_command", "shell_run"],
    "query": ["query_db", "sql_query", "db_read", "run_query", "fetch_rows"],
    "network": ["fetch_url", "http_get", "curl", "web_request", "api_call"],
    "admin": ["admin_panel", "admin_console", "control_panel", "management_ui"],
    "sensitive": ["credential_dump", "exfil_data", "network_scan", "keylogger"],
    "invoke": ["invoke", "call", "dispatch", "execute_remote", "trigger"],
}

_TARGET_PATHS: list[str] = [
    ".env", "~/.ssh/id_rsa", "~/.aws/credentials", "/etc/shadow",
    "~/.bashrc", "~/.gitconfig", "config/secrets.yaml", ".env.local",
    "~/.kube/config", "~/.docker/config.json", "/etc/passwd",
    "~/.ssh/known_hosts", "~/.npmrc", "~/.pypirc",
]

_EXFIL_URLS: list[str] = [
    "https://evil.com/exfil", "https://attacker.io/collect",
    "https://c2.badactor.net/data", "https://exfil.malware.xyz/upload",
]

_MCP_SERVERS: list[str] = [
    "http://mcp-alpha:3000", "http://mcp-beta:3000",
    "http://mcp-gamma:3000", "http://mcp-delta:3000",
    "http://mcp-epsilon:3000", "http://mcp-zeta:3000",
    "http://mcp-eta:3000", "http://mcp-theta:3000",
]

_AGENT_PREFIXES: list[str] = [
    "agent", "bot", "assistant", "worker", "task-runner",
    "copilot", "helper", "auto", "daemon", "service",
]

# Sensitive tools the detector flags for privilege escalation / rug pull
_SENSITIVE_TOOLS = ["admin_panel", "credential_dump", "network_scan", "exfil_data"]


def _random_hash() -> str:
    return hashlib.sha256(random.randbytes(32)).hexdigest()


def _fuzz_int(mean: float, std: float, lo: int = 0, hi: int = 1_000_000) -> int:
    return max(lo, min(hi, int(random.gauss(mean, std))))


def _random_agent() -> str:
    prefix = random.choice(_AGENT_PREFIXES)
    return f"{prefix}-{random.randint(1000, 9999)}"


# ── Catalog loader ───────────────────────────────────────────────


def load_attack_catalog(path: str | None = None) -> list[dict[str, Any]]:
    """Load the public attack catalog YAML.  Returns a list of attack dicts."""
    import yaml  # type: ignore[import-untyped]

    catalog_path = path or _CATALOG_PATH
    resolved = str(Path(catalog_path).resolve())

    with open(resolved) as fh:
        data = yaml.safe_load(fh)

    attacks: list[dict[str, Any]] = data.get("attacks", [])
    logger.debug("Loaded %d attacks from %s", len(attacks), resolved)
    return attacks


# ── Per-category variant generators ─────────────────────────────
# Each function takes a parsed attack dict and returns a list of
# ``list[dict[str, Any]]`` (one list of invocations per variant).


def _variants_reconnaissance(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate variants of reconnaissance (tools/list enumeration) attacks."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        n_probes = _fuzz_int(8, 3, lo=6, hi=20)
        invocations = [
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
        variants.append(invocations)
    return variants


def _variants_data_exfiltration(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate data exfiltration variants with different file paths and volumes."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        read_tool = random.choice(_TOOL_POOLS["read"])
        data_bytes = _fuzz_int(8000, 2000, lo=5500)
        invocations = [
            {
                "_needs_baseline": True,
                "agent_name": agent,
                "tool_name": read_tool,
                "action": "read",
                "duration_ms": _fuzz_int(80, 30, lo=10),
                "data_accessed_bytes": data_bytes,
                "arguments_size_bytes": _fuzz_int(100, 30, lo=20),
                "response_size_bytes": _fuzz_int(data_bytes, 500, lo=5000),
            }
        ]
        variants.append(invocations)
    return variants


def _variants_defense_evasion(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate defense evasion variants with varying payload sizes."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        exec_tool = random.choice(_TOOL_POOLS["execute"])
        payload = _fuzz_int(7000, 2000, lo=5001)
        invocations = [
            {
                "agent_name": agent,
                "tool_name": exec_tool,
                "action": "run",
                "duration_ms": _fuzz_int(200, 80, lo=50),
                "arguments_size_bytes": payload,
                "response_size_bytes": _fuzz_int(300, 100, lo=50),
                "arguments_hash": _random_hash(),
            }
        ]
        variants.append(invocations)
    return variants


def _variants_lateral_movement(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate lateral movement variants with different server sets."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        n_servers = _fuzz_int(5, 1, lo=4, hi=8)
        servers = random.sample(_MCP_SERVERS, min(n_servers, len(_MCP_SERVERS)))
        invoke_tools = _TOOL_POOLS["invoke"]
        invocations = [
            {
                "agent_name": agent,
                "tool_name": random.choice(invoke_tools),
                "action": "tools/call",
                "duration_ms": _fuzz_int(80, 30, lo=10),
                "target_server": server,
                "data_accessed_bytes": _fuzz_int(300, 100, lo=0),
                "arguments_size_bytes": _fuzz_int(200, 80, lo=20),
                "response_size_bytes": _fuzz_int(500, 200, lo=50),
            }
            for server in servers
        ]
        variants.append(invocations)
    return variants


def _variants_supply_chain(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate supply chain attack variants with unregistered tool calls."""
    bad_tools = ["inject_backdoor", "shadow_deploy", "exfil_creds", "keylogger",
                 "rootkit_install", "covert_tunnel", "data_siphon"]
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        bad_tool = random.choice(bad_tools)
        invocations = [
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
        variants.append(invocations)
    return variants


def _variants_rug_pull(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate rug pull variants — sudden shift to new sensitive tools."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        new_tools = random.sample(
            _SENSITIVE_TOOLS + ["shadow_api", "dump_memory", "proxy_chain"],
            k=_fuzz_int(4, 1, lo=3, hi=6),
        )
        invocations = [
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
        variants.append(invocations)
    return variants


def _variants_privilege_escalation(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate privilege escalation variants."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        sensitive = random.choice(_SENSITIVE_TOOLS)
        invocations = [
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
        variants.append(invocations)
    return variants


def _variants_persistence(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate persistence variants — periodic reconnection patterns."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        interval_s = _fuzz_int(30, 5, lo=15, hi=60)
        n_beats = _fuzz_int(8, 2, lo=6, hi=15)
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        invocations = [
            {
                "_raw_timestamp": (base + timedelta(seconds=i * interval_s)).isoformat(),
                "agent_name": agent,
                "tool_name": "heartbeat",
                "action": "ping",
                "duration_ms": _fuzz_int(5, 2, lo=1),
                "response_size_bytes": _fuzz_int(64, 20, lo=10),
            }
            for i in range(n_beats)
        ]
        variants.append(invocations)
    return variants


def _variants_c2(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate C2 beaconing variants."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        interval_s = _fuzz_int(10, 2, lo=5, hi=20)
        n_beacons = _fuzz_int(8, 2, lo=6, hi=15)
        resp_bytes = _fuzz_int(256, 30, lo=100, hi=500)
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        invocations = [
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
        variants.append(invocations)
    return variants


def _variants_rate_spike(attack: dict[str, Any], n: int = 7) -> list[list[dict[str, Any]]]:
    """Generate rate spike variants — burst of rapid calls."""
    variants: list[list[dict[str, Any]]] = []
    for _ in range(n):
        agent = _random_agent()
        n_calls = _fuzz_int(45, 10, lo=30, hi=80)
        invocations = [
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
        variants.append(invocations)
    return variants


# ── Category dispatcher ──────────────────────────────────────────

_CATEGORY_TO_GENERATOR: dict[str, Any] = {
    "RECONNAISSANCE": _variants_reconnaissance,
    "DATA_EXFILTRATION": _variants_data_exfiltration,
    "DEFENSE_EVASION": _variants_defense_evasion,
    "LATERAL_MOVEMENT": _variants_lateral_movement,
    "SUPPLY_CHAIN": _variants_supply_chain,
    "RUG_PULL": _variants_rug_pull,
    "PRIVILEGE_ESCALATION": _variants_privilege_escalation,
    "PERSISTENCE": _variants_persistence,
    "COMMAND_AND_CONTROL": _variants_c2,
    "RATE_SPIKE": _variants_rate_spike,
}


# ── Public API ───────────────────────────────────────────────────


class AttackVariantGenerator:
    """Generates parameterized attack scenario variants from the public catalog.

    Each attack in the catalog produces 5-10 variants with randomized:
      - Tool names (substituted from equivalent pools)
      - Timing patterns (fast burst vs slow trickle)
      - Payload sizes (small vs large)
      - Agent names (randomized)
      - Target resources (different file paths, URLs, etc.)
    """

    def __init__(self, catalog_path: str | None = None, variants_per_attack: int = 7) -> None:
        self.catalog_path = catalog_path
        self.variants_per_attack = max(5, min(10, variants_per_attack))
        self._attacks: list[dict[str, Any]] = []
        self._loaded = False

    def load(self) -> None:
        """Load the attack catalog."""
        self._attacks = load_attack_catalog(self.catalog_path)
        self._loaded = True

    @property
    def attacks(self) -> list[dict[str, Any]]:
        if not self._loaded:
            self.load()
        return self._attacks

    @property
    def attack_names(self) -> list[str]:
        return [a["name"] for a in self.attacks]

    def generate_variants(self, attack_name: str | None = None) -> dict[str, list[list[dict[str, Any]]]]:
        """Generate variants for one or all attacks.

        Args:
            attack_name: If given, generate variants only for this attack.
                         Otherwise, generate for all attacks in catalog.

        Returns:
            Dict mapping attack name to list of scenario variant invocations.
            Each variant is a list[dict[str, Any]] compatible with seed.py's
            ``_inject_invocations`` function.
        """
        result: dict[str, list[list[dict[str, Any]]]] = {}

        for attack in self.attacks:
            name = attack["name"]
            if attack_name and name != attack_name:
                continue

            category = attack.get("category", "")
            gen_fn = _CATEGORY_TO_GENERATOR.get(category)
            if gen_fn is None:
                logger.warning("No variant generator for category %s (attack: %s)", category, name)
                continue

            variants = gen_fn(attack, n=self.variants_per_attack)
            result[name] = variants

        return result

    def generate_scenario_generators(self) -> dict[str, Any]:
        """Return a dict of scenario_name -> generator_fn compatible with seed.py.

        Each generator_fn has signature (agent: str, iteration: int) -> list[dict[str, Any]].
        """
        generators: dict[str, Any] = {}

        for attack in self.attacks:
            name = attack["name"]
            category = attack.get("category", "")
            gen_fn = _CATEGORY_TO_GENERATOR.get(category)
            if gen_fn is None:
                continue

            # Create a closure that captures the attack dict
            def _make_gen(atk: dict[str, Any], fn: Any) -> Any:
                def _gen(agent: str, iteration: int) -> list[dict[str, Any]]:
                    variants = fn(atk, n=1)
                    if not variants:
                        return []
                    invocations = variants[0]
                    # Override agent name to use the provided one
                    for inv in invocations:
                        inv["agent_name"] = agent
                    return invocations
                return _gen

            generators[name] = _make_gen(attack, gen_fn)

        return generators

    def export_scenarios(self) -> list[dict[str, Any]]:
        """Export all attack definitions as JSON-serializable dicts."""
        output: list[dict[str, Any]] = []
        for attack in self.attacks:
            entry = {
                "name": attack["name"],
                "description": attack.get("description", ""),
                "category": attack.get("category", ""),
                "severity": attack.get("severity", ""),
                "attack_steps": attack.get("attack_steps", []),
                "indicators": attack.get("indicators", []),
                "source_reference": attack.get("source_reference", ""),
            }
            output.append(entry)
        return output


def generate_all_variants(
    catalog_path: str | None = None,
    variants_per_attack: int = 7,
) -> dict[str, list[list[dict[str, Any]]]]:
    """Convenience function: load catalog and generate all variants.

    Returns dict mapping attack_name -> list of variant invocation lists.
    """
    gen = AttackVariantGenerator(catalog_path, variants_per_attack)
    gen.load()
    return gen.generate_variants()
