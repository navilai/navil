"""Red team command -- monthly synthetic red team using LLM-generated attack hypotheses.

Usage:
  navil redteam --generate                — generate and fire hypotheses
  navil redteam --generate --count 30     — generate 30 hypotheses
  navil redteam --generate --dry-run      — generate but don't fire
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

from navil.safemcp.categories import ALL_CATEGORIES

# ── Constants ─────────────────────────────────────────────────

MAX_HYPOTHESES = 50

REDTEAM_SYSTEM_PROMPT = """\
You are a security researcher generating novel attack hypotheses \
for MCP (Model Context Protocol) servers.
Your goal is to identify potential attack vectors that may not be \
covered by existing detection rules.

SAFETY CONSTRAINTS:
- Generate only DESCRIPTIONS of hypothetical attacks, never actual exploit code.
- Each hypothesis should describe the attack concept, not provide implementation details.
- Focus on detection gaps and novel threat categories.

You must respond with a JSON array of hypothesis objects. Each object has:
- "hypothesis": string describing the attack concept
- "category": one of the valid categories listed below
- "novelty_rationale": why this attack is novel or under-detected
- "expected_detection": either "missed" or "blocked"

Valid categories: {categories}

Respond ONLY with a JSON array. No explanation, no markdown code fences."""

REDTEAM_USER_PROMPT = """\
Generate {count} novel attack hypotheses for MCP server security testing.

Current coverage state:
{coverage_state}

Focus on:
1. Categories with low or no coverage data
2. Novel combinations of existing attack techniques
3. Emerging threats from recent AI/LLM security research
4. Cross-category attack chains"""


# ── Hypothesis parsing ───────────────────────────────────────


def parse_hypotheses(response: str) -> list[dict[str, str]]:
    """Parse LLM response into a list of hypothesis dicts.

    Tries direct JSON parsing first, then falls back to extract_json
    for responses wrapped in markdown fences or prose.
    """
    # Strip markdown code fences
    cleaned = response.strip()
    if "```" in cleaned:
        m = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(1).strip()

    # Try direct parse first (handles arrays correctly)
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        # Fall back to extract_json for object extraction
        from navil.llm import extract_json

        raw = extract_json(response)
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []

    if isinstance(data, dict):
        # Handle case where LLM wraps in {"hypotheses": [...]}
        data = data.get("hypotheses", data.get("results", [data]))
    if not isinstance(data, list):
        return []

    valid: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        hypothesis = item.get("hypothesis", "")
        category = item.get("category", "")
        novelty = item.get("novelty_rationale", "")
        expected = item.get("expected_detection", "")

        if not hypothesis or not category:
            continue

        # Sanitize: strip control characters (keep newline and tab),
        # terminal escape sequences, and code-like content
        hypothesis = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", hypothesis)
        hypothesis = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", hypothesis)
        novelty = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", novelty)
        novelty = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", novelty)

        # Validate category
        if category not in ALL_CATEGORIES:
            # Try to fuzzy match
            for valid_cat in ALL_CATEGORIES:
                if valid_cat in category or category in valid_cat:
                    category = valid_cat
                    break
            else:
                continue

        # Validate expected_detection
        if expected not in ("missed", "blocked"):
            expected = "missed"

        valid.append(
            {
                "hypothesis": hypothesis,
                "category": category,
                "novelty_rationale": novelty,
                "expected_detection": expected,
            }
        )

    return valid


# ── Prediction comparison ────────────────────────────────────


def compare_prediction(predicted: str, actual_blocked: bool) -> str:
    """Compare LLM prediction against actual result.

    Returns one of:
        'REAL GAP' — predicted missed AND actually missed
        'COVERAGE OK' — predicted missed AND actually blocked
        'SURPRISE GAP' — predicted blocked AND actually missed (high priority)
        'EXPECTED BLOCK' — predicted blocked AND actually blocked
    """
    if predicted == "missed" and not actual_blocked:
        return "REAL GAP"
    elif predicted == "missed" and actual_blocked:
        return "COVERAGE OK"
    elif predicted == "blocked" and not actual_blocked:
        return "SURPRISE GAP"
    else:
        return "EXPECTED BLOCK"


# ── Coverage state ───────────────────────────────────────────


def _get_coverage_state() -> str:
    """Get current coverage state as a string for the LLM prompt."""
    lines: list[str] = []
    for cat in ALL_CATEGORIES:
        display = cat.replace("_", " ").title()
        lines.append(f"  - {display}: no coverage data available")
    return "\n".join(lines)


# ── Scenario conversion and firing ───────────────────────────


def _hypothesis_to_invocations(hypothesis: dict[str, str]) -> list[dict[str, Any]]:
    """Convert a hypothesis to a list of invocations for the anomaly detector."""
    import random

    from navil.safemcp.generator import _TOOL_POOLS, _random_agent, _random_hash

    category = hypothesis["category"]

    # Pick tool pool based on category
    pool_map = {
        "prompt_injection": "execute",
        "data_exfiltration": "read",
        "credential_access": "sensitive",
        "privilege_escalation": "sensitive",
        "reconnaissance": "list",
        "command_and_control": "network",
        "supply_chain": "admin",
        "denial_of_service": "network",
        "lateral_movement": "network",
        "persistence": "admin",
        "defense_evasion": "execute",
        "resource_hijacking": "execute",
        "code_execution": "execute",
        "social_engineering": "invoke",
        "configuration_tampering": "admin",
        "information_disclosure": "read",
        "multimodal_smuggling": "execute",
        "handshake_hijacking": "network",
        "rag_memory_poisoning": "query",
        "agent_collusion": "network",
        "cognitive_exploitation": "query",
        "temporal_stateful": "admin",
        "output_weaponization": "execute",
        "tool_schema_injection": "invoke",
        "context_window_manipulation": "query",
        "model_supply_chain": "admin",
        "cross_tenant_leakage": "network",
        "delegation_abuse": "invoke",
        "feedback_loop_poisoning": "query",
        "covert_channel": "network",
    }

    pool_key = pool_map.get(category, "execute")
    tools = _TOOL_POOLS[pool_key]
    agent = _random_agent()

    invocations: list[dict[str, Any]] = []
    n_calls = random.randint(3, 7)
    base_time = datetime.now(timezone.utc)

    for i in range(n_calls):
        ts = base_time + timedelta(seconds=i * random.uniform(0.1, 2.0))
        invocations.append(
            {
                "agent_name": agent,
                "tool_name": random.choice(tools),
                "action": random.choice(["call", "list", "read"]),
                "duration_ms": random.randint(10, 300),
                "arguments_size_bytes": random.randint(500, 5000),
                "response_size_bytes": random.randint(100, 3000),
                "_raw_timestamp": ts.isoformat(),
                "arguments_hash": _random_hash(),
            }
        )

    return invocations


def _fire_hypothesis(
    detector: Any,
    invocations: list[dict[str, Any]],
) -> bool:
    """Fire a hypothesis scenario through the detector. Returns True if blocked."""
    alerts_before = len(detector.alerts)

    for inv in invocations:
        detector.record_invocation(
            agent_name=inv.get("agent_name", "redteam-agent"),
            tool_name=inv.get("tool_name", "unknown"),
            action=inv.get("action", "call"),
            duration_ms=inv.get("duration_ms", 100),
            arguments_hash=inv.get("arguments_hash"),
            arguments_size_bytes=inv.get("arguments_size_bytes", 0),
            response_size_bytes=inv.get("response_size_bytes", 0),
            timestamp=inv.get("_raw_timestamp"),
        )

    alerts_after = len(detector.alerts)
    return alerts_after > alerts_before


# ── Command handler ──────────────────────────────────────────


def _redteam_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil redteam`."""
    if not args.generate:
        print("Use --generate to run hypothesis generation.", file=sys.stderr)
        return 1

    count = min(args.count, MAX_HYPOTHESES)
    dry_run = args.dry_run

    print(f"Navil Red Team — generating {count} attack hypotheses")
    print()

    # Build coverage state
    coverage_state = _get_coverage_state()

    # Call LLM
    try:
        from navil.llm.client import LLMClient

        llm = LLMClient(max_tokens=4096, temperature=0.7)
    except Exception as exc:
        print(f"Error initializing LLM client: {exc}", file=sys.stderr)
        print("Install LLM dependencies: pip install navil[llm]", file=sys.stderr)
        return 1

    system_prompt = REDTEAM_SYSTEM_PROMPT.format(categories=", ".join(ALL_CATEGORIES))
    user_prompt = REDTEAM_USER_PROMPT.format(count=count, coverage_state=coverage_state)

    print("Calling LLM for hypothesis generation...")
    try:
        response = llm.complete(system_prompt, user_prompt)
    except Exception as exc:
        print(f"LLM call failed: {exc}", file=sys.stderr)
        return 1

    hypotheses = parse_hypotheses(response)
    if not hypotheses:
        print("No valid hypotheses generated.", file=sys.stderr)
        return 1

    print(f"Generated {len(hypotheses)} valid hypotheses")
    print()

    if dry_run:
        # Print hypotheses without firing
        for i, h in enumerate(hypotheses, 1):
            print(f"  {i}. [{h['category']}] {h['hypothesis']}")
            print(f"     Expected: {h['expected_detection']}")
            print(f"     Rationale: {h['novelty_rationale']}")
            print()
        return 0

    # Fire hypotheses through detector
    from navil.anomaly_detector import BehavioralAnomalyDetector

    detector = BehavioralAnomalyDetector()
    results: list[dict[str, Any]] = []

    print("Firing hypotheses through anomaly detector...")
    for i, h in enumerate(hypotheses, 1):
        invocations = _hypothesis_to_invocations(h)
        blocked = _fire_hypothesis(detector, invocations)
        comparison = compare_prediction(h["expected_detection"], blocked)

        result = {
            "hypothesis": h["hypothesis"],
            "category": h["category"],
            "novelty_rationale": h["novelty_rationale"],
            "predicted": h["expected_detection"],
            "actual": "blocked" if blocked else "missed",
            "comparison": comparison,
        }
        results.append(result)

        # Print result with priority indicator
        priority = ""
        if comparison == "SURPRISE GAP":
            priority = " [HIGH PRIORITY]"
        elif comparison == "REAL GAP":
            priority = " [GAP]"
        print(f"  {i}. {comparison}{priority}: {h['hypothesis'][:60]}...")

    # Summary
    print()
    real_gaps = sum(1 for r in results if r["comparison"] == "REAL GAP")
    surprise_gaps = sum(1 for r in results if r["comparison"] == "SURPRISE GAP")
    coverage_ok = sum(1 for r in results if r["comparison"] == "COVERAGE OK")
    expected_blocks = sum(1 for r in results if r["comparison"] == "EXPECTED BLOCK")

    print("Summary:")
    print(f"  REAL GAP:       {real_gaps}")
    print(f"  SURPRISE GAP:   {surprise_gaps}")
    print(f"  COVERAGE OK:    {coverage_ok}")
    print(f"  EXPECTED BLOCK: {expected_blocks}")

    # Store results
    import tempfile

    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir, exist_ok=True)
    results_path = os.path.join(data_dir, "redteam_results.yaml")

    existing: dict[str, list[dict[str, Any]]] = {"runs": []}
    if os.path.exists(results_path):
        with open(results_path) as f:
            loaded = yaml.safe_load(f)
            if loaded and isinstance(loaded, dict):
                existing = loaded

    run_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "real_gaps": real_gaps,
        "surprise_gaps": surprise_gaps,
        "results": results,
    }
    existing["runs"].append(run_record)

    # Atomic write: write to temp file then rename to prevent partial writes
    fd, tmp_path = tempfile.mkstemp(dir=data_dir, suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(existing, f, default_flow_style=False, sort_keys=False)
        os.replace(tmp_path, results_path)
    except BaseException:
        os.unlink(tmp_path)
        raise

    print(f"\nResults saved to {results_path}")
    return 0


# ── Registration ─────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the redteam subcommand."""
    redteam_parser = subparsers.add_parser(
        "redteam",
        help="Synthetic red team using LLM-generated attack hypotheses",
    )
    redteam_parser.add_argument(
        "--generate",
        action="store_true",
        help="Run hypothesis generation",
    )
    redteam_parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of hypotheses to generate (default: 20, max: 50)",
    )
    redteam_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate hypotheses but don't fire them",
    )
    redteam_parser.set_defaults(func=lambda cli, args: _redteam_command(cli, args))
