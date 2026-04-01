"""Pool-to-SafeMCP converter.

Maps the 200 base attack vectors (IDs 101-300) from the mega pool to
SafeMCP generator functions, producing invocation lists compatible with
``navil.seed._inject_invocations``.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from navil.safemcp.generator import (
    _TOOL_POOLS,
    _fuzz_int,
    _random_agent,
    _random_hash,
)

# ── Catalog class ID mappings ────────────────────────────────────

CATALOG_TO_SLUG = {
    "AC-01": "multimodal_smuggling",
    "AC-02": "handshake_hijacking",
    "AC-03": "rag_memory_poisoning",
    "AC-04": "supply_chain",
    "AC-05": "privilege_escalation",
    "AC-06": "defense_evasion",
    "AC-07": "agent_collusion",
    "AC-08": "cognitive_exploitation",
    "AC-09": "temporal_stateful",
    "AC-10": "output_weaponization",
    "AC-11": "code_execution",
}

SLUG_TO_CATALOG = {v: k for k, v in CATALOG_TO_SLUG.items()}

# ── Timing templates ─────────────────────────────────────────────

_TIMING_TEMPLATES: dict[str, dict[str, Any]] = {
    "burst": {
        "interval_range": (0.05, 0.5),  # seconds between calls
        "count_range": (3, 8),
    },
    "sequential": {
        "interval_range": (1.0, 5.0),
        "count_range": (2, 6),
    },
    "slow_trickle": {
        "interval_range": (10.0, 60.0),
        "count_range": (2, 5),
    },
}


# ── Vector group definitions ─────────────────────────────────────

_VECTOR_GROUPS: list[dict[str, Any]] = [
    {
        "id_range": (101, 115),
        "class_name": "Multi-Modal Smuggling",
        "category": "multimodal_smuggling",
        "catalog_class_id": "AC-01",
        "tool_pool": "execute",
        "timing": "burst",
        "payload_range": (4000, 9000),
        "response_range": (200, 800),
    },
    {
        "id_range": (116, 130),
        "class_name": "Handshake Hijacking",
        "category": "handshake_hijacking",
        "catalog_class_id": "AC-02",
        "tool_pool": "network",
        "timing": "sequential",
        "payload_range": (500, 3000),
        "response_range": (300, 1500),
    },
    {
        "id_range": (131, 150),
        "class_name": "RAG/Memory Poisoning",
        "category": "rag_memory_poisoning",
        "catalog_class_id": "AC-03",
        "tool_pool": "query",
        "timing": "slow_trickle",
        "payload_range": (2000, 8000),
        "response_range": (1000, 5000),
    },
    {
        "id_range": (151, 170),
        "class_name": "Supply Chain/Discovery",
        "category": "supply_chain",
        "catalog_class_id": "AC-04",
        "tool_pool": "admin",
        "timing": "burst",
        "payload_range": (1000, 5000),
        "response_range": (200, 1000),
    },
    {
        "id_range": (171, 190),
        "class_name": "Privilege Escalation",
        "category": "privilege_escalation",
        "catalog_class_id": "AC-05",
        "tool_pool": "sensitive",
        "timing": "sequential",
        "payload_range": (500, 3000),
        "response_range": (300, 2000),
    },
    {
        "id_range": (191, 200),
        "class_name": "Anti-Forensics",
        "category": "defense_evasion",
        "catalog_class_id": "AC-06",
        "tool_pool": "execute",
        "timing": "slow_trickle",
        "payload_range": (3000, 7000),
        "response_range": (100, 500),
    },
    {
        "id_range": (201, 220),
        "class_name": "Agent Collusion & Multi-Agent Attacks",
        "category": "agent_collusion",
        "catalog_class_id": "AC-07",
        "tool_pool": "network",
        "timing": "burst",
        "payload_range": (1000, 4000),
        "response_range": (500, 2000),
    },
    {
        "id_range": (221, 240),
        "class_name": "Cognitive Architecture Exploitation",
        "category": "cognitive_exploitation",
        "catalog_class_id": "AC-08",
        "tool_pool": "query",
        "timing": "sequential",
        "payload_range": (3000, 10000),
        "response_range": (2000, 8000),
    },
    {
        "id_range": (241, 260),
        "class_name": "Temporal & Stateful Attacks",
        "category": "temporal_stateful",
        "catalog_class_id": "AC-09",
        "tool_pool": "admin",
        "timing": "slow_trickle",
        "payload_range": (500, 3000),
        "response_range": (200, 1500),
    },
    {
        "id_range": (261, 280),
        "class_name": "Output Manipulation & Weaponization",
        "category": "output_weaponization",
        "catalog_class_id": "AC-10",
        "tool_pool": "execute",
        "timing": "burst",
        "payload_range": (2000, 8000),
        "response_range": (3000, 12000),
    },
    {
        "id_range": (281, 300),
        "class_name": "Infrastructure & Runtime Attacks",
        "category": "code_execution",
        "catalog_class_id": "AC-11",
        "tool_pool": "admin",
        "timing": "sequential",
        "payload_range": (1000, 5000),
        "response_range": (500, 3000),
    },
]


def _build_vector_map() -> dict[int, dict[str, Any]]:
    """Build the VECTOR_TO_SAFEMCP mapping from group definitions."""
    mapping: dict[int, dict[str, Any]] = {}
    for group in _VECTOR_GROUPS:
        lo, hi = group["id_range"]
        count = hi - lo + 1
        payload_lo, payload_hi = group["payload_range"]
        response_lo, response_hi = group["response_range"]
        for idx, vid in enumerate(range(lo, hi + 1)):
            # Vary payload/response ranges per vector within the group
            frac = idx / max(count - 1, 1)
            p_lo = int(payload_lo + frac * (payload_hi - payload_lo) * 0.3)
            p_hi = int(payload_lo + (0.7 + frac * 0.3) * (payload_hi - payload_lo))
            r_lo = int(response_lo + frac * (response_hi - response_lo) * 0.3)
            r_hi = int(response_lo + (0.7 + frac * 0.3) * (response_hi - response_lo))
            mapping[vid] = {
                "category": group["category"],
                "catalog_class_id": group["catalog_class_id"],
                "class_name": group["class_name"],
                "tool_pool": group["tool_pool"],
                "timing": group["timing"],
                "payload_range": (p_lo, max(p_lo + 100, p_hi)),
                "response_range": (r_lo, max(r_lo + 50, r_hi)),
            }
    return mapping


VECTOR_TO_SAFEMCP: dict[int, dict[str, Any]] = _build_vector_map()


# ── Invocation builder ───────────────────────────────────────────


def _build_invocations(
    vector_cfg: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a single invocation list from a vector config."""
    timing_cfg = _TIMING_TEMPLATES[vector_cfg["timing"]]
    pool_key = vector_cfg["tool_pool"]
    tools = _TOOL_POOLS[pool_key]

    count_lo, count_hi = timing_cfg["count_range"]
    n_calls = random.randint(count_lo, count_hi)
    interval_lo, interval_hi = timing_cfg["interval_range"]

    agent = _random_agent()
    base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(5, 30))

    payload_lo, payload_hi = vector_cfg["payload_range"]
    response_lo, response_hi = vector_cfg["response_range"]

    invocations: list[dict[str, Any]] = []
    elapsed = 0.0
    for _i in range(n_calls):
        interval = random.uniform(interval_lo, interval_hi)
        elapsed += interval
        ts = base_time + timedelta(seconds=elapsed)

        invocations.append(
            {
                "agent_name": agent,
                "tool_name": random.choice(tools),
                "action": random.choice(["call", "list", "read"]),
                "duration_ms": _fuzz_int(50, 20, lo=5, hi=500),
                "arguments_size_bytes": _fuzz_int(
                    (payload_lo + payload_hi) / 2,
                    (payload_hi - payload_lo) / 4,
                    lo=payload_lo,
                    hi=payload_hi,
                ),
                "response_size_bytes": _fuzz_int(
                    (response_lo + response_hi) / 2,
                    (response_hi - response_lo) / 4,
                    lo=response_lo,
                    hi=response_hi,
                ),
                "_raw_timestamp": ts.isoformat(),
                "arguments_hash": _random_hash(),
            }
        )

    return invocations


# ── Public API ───────────────────────────────────────────────────


def convert_vector(vector_id: int, count: int = 5) -> list[list[dict[str, Any]]]:
    """Convert a single vector ID to SafeMCP-compatible invocation lists.

    Args:
        vector_id: Attack vector ID (101-300).
        count: Number of variant invocation lists to generate.

    Returns:
        List of invocation lists, each compatible with ``_inject_invocations``.

    Raises:
        KeyError: If vector_id is not in the mapping.
    """
    if vector_id not in VECTOR_TO_SAFEMCP:
        raise KeyError(f"Unknown vector ID: {vector_id}. Valid range is 101-300.")

    cfg = VECTOR_TO_SAFEMCP[vector_id]
    return [_build_invocations(cfg) for _ in range(count)]


def convert_all(count_per_vector: int = 5) -> dict[int, list[list[dict[str, Any]]]]:
    """Convert all 200 vectors to SafeMCP-compatible invocation lists.

    Args:
        count_per_vector: Number of variant invocation lists per vector.

    Returns:
        Dict mapping vector_id -> list of invocation lists.
    """
    result: dict[int, list[list[dict[str, Any]]]] = {}
    for vid in sorted(VECTOR_TO_SAFEMCP):
        result[vid] = convert_vector(vid, count=count_per_vector)
    return result


def get_catalog_class_id(vector_id: int) -> str:
    """Return the threat catalog class ID (e.g. 'AC-01') for a vector."""
    return VECTOR_TO_SAFEMCP[vector_id]["catalog_class_id"]


def get_vector_category(vector_id: int) -> str:
    """Return the category for a given vector ID."""
    return VECTOR_TO_SAFEMCP[vector_id]["category"]


def get_vector_class(vector_id: int) -> str:
    """Return the attack class name for a given vector ID."""
    return VECTOR_TO_SAFEMCP[vector_id]["class_name"]


def get_vectors_for_category(category: str) -> list[int]:
    """Return all vector IDs that map to a given category."""
    return [vid for vid, cfg in VECTOR_TO_SAFEMCP.items() if cfg["category"] == category]
