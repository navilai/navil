"""`navil policy test` — validate a policy against a fixture of tool calls.

Reads a JSONL fixture where each line is a tool-call event with an
``expected_decision`` of ``allow``, ``deny``, or ``require_approval``.
Loads the given policy file and runs each fixture call through the
policy engine, then prints a pass/fail report.

This is the runner that makes the Policy Template Library executable —
without it the templates and fixtures are just documentation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from navil.policy_engine import PolicyEngine

# Decision label normalization
_DECISION_ALLOW = "allow"
_DECISION_DENY = "deny"
_DECISION_APPROVAL = "require_approval"
_VALID_DECISIONS = {_DECISION_ALLOW, _DECISION_DENY, _DECISION_APPROVAL}


def register_subcommand(policy_subparsers: argparse._SubParsersAction) -> None:
    """Attach `test` to the existing `navil policy` subparser."""
    p = policy_subparsers.add_parser(
        "test",
        help="Validate a policy against a fixture of tool calls",
        description=(
            "Runs each tool call in a JSONL fixture through the given policy "
            "and checks the actual decision matches expected_decision. Used "
            "to validate Policy Template Library entries."
        ),
    )
    p.add_argument(
        "--policy",
        required=True,
        metavar="FILE",
        help="Path to the navil.yaml policy file to test.",
    )
    p.add_argument(
        "--fixture",
        required=True,
        metavar="FILE",
        help="Path to a JSONL fixture file. One tool-call event per line.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the summary line.",
    )
    p.set_defaults(func=lambda cli, args: _run(cli, args))


def _classify_decision(allowed: bool, reason: str, tool: str, approval_set: set[str]) -> str:
    """Map a policy engine decision to allow / deny / require_approval.

    The engine itself only returns binary (allow, deny). The
    ``require_approval`` policy section is honored by the runner: if a
    tool is allowed by the engine AND listed in require_approval, the
    runner classifies it as approval-required.
    """
    if not allowed:
        if "approval" in reason.lower():
            return _DECISION_APPROVAL
        return _DECISION_DENY
    if tool in approval_set:
        return _DECISION_APPROVAL
    return _DECISION_ALLOW


def _run(_cli: Any, args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    fixture_path = Path(args.fixture)

    if not policy_path.exists():
        print(f"  ✗ Policy file not found: {policy_path}", file=sys.stderr)
        return 2
    if not fixture_path.exists():
        print(f"  ✗ Fixture file not found: {fixture_path}", file=sys.stderr)
        return 2

    # Load policy via PolicyEngine so the test honors the same loader
    # that runtime uses (includes scope expansion, allowlist parsing, etc.)
    engine = PolicyEngine(policy_file=str(policy_path))

    # Read fixture JSONL
    cases: list[dict[str, Any]] = []
    with fixture_path.open() as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"  ✗ Malformed JSON on line {lineno}: {exc}",
                    file=sys.stderr,
                )
                return 2
            cases.append(obj)

    if not args.quiet:
        print()
        print("  navil policy test")
        print("  ───────────────────────────────────────────────────────")
        print(f"  Policy   : {policy_path}")
        print(f"  Fixture  : {fixture_path}")
        print(f"  Cases    : {len(cases)}")
        print()

    passed = 0
    failed_cases: list[dict[str, Any]] = []

    # Templates typically declare a single `default` agent that applies
    # to any caller. Production engines fall back to default for unknown
    # agent names; the runner mirrors that intent here so a fixture
    # using `agent: cursor` against a template with only `default`
    # behaves the same way it would in production.
    policy_agents = engine.policy.get("agents", {})

    # Approval-required tools come from the top-level require_approval
    # block. Templates that have approval rules per-agent are also
    # supported — fold the per-agent lists in.
    approval_set: set[str] = set(engine.policy.get("require_approval", []))
    for agent_def in policy_agents.values():
        approval_set.update(agent_def.get("require_approval", []))

    for _i, case in enumerate(cases, start=1):
        requested_agent = case.get("agent", "default")
        agent = requested_agent if requested_agent in policy_agents else "default"
        tool = case.get("tool", "")
        expected = case.get("expected_decision", "").lower()
        description = case.get("description", "")

        if expected not in _VALID_DECISIONS:
            failed_cases.append(
                {
                    **case,
                    "actual": "INVALID_FIXTURE",
                    "error": f"expected_decision must be one of {sorted(_VALID_DECISIONS)}",
                }
            )
            continue

        allowed, reason = engine.check_tool_call(
            agent_name=agent, tool_name=tool, action="tools/call"
        )
        actual = _classify_decision(allowed, reason, tool, approval_set)

        if actual == expected:
            passed += 1
            if not args.quiet:
                marker = {"allow": "✓", "deny": "✗", "require_approval": "⚠"}[expected]
                print(f"  {marker} [{actual:>16}] {agent}/{tool}")
        else:
            failed_cases.append(
                {
                    **case,
                    "actual": actual,
                    "reason": reason,
                }
            )
            if not args.quiet:
                print(f"  ✗ FAIL              {agent}/{tool}")
                print(f"      expected: {expected}")
                print(f"      actual  : {actual}")
                print(f"      reason  : {reason}")
                if description:
                    print(f"      desc    : {description}")

    total = len(cases)
    print()
    if failed_cases:
        print(f"  ✗ {len(failed_cases)}/{total} cases failed")
        if args.quiet:
            for fc in failed_cases:
                print(
                    f"    {fc.get('agent', '?')}/{fc.get('tool', '?')}: "
                    f"expected={fc.get('expected_decision')} "
                    f"actual={fc.get('actual')}"
                )
        print()
        return 1

    print(f"  ✓ {passed}/{total} cases passed")
    print()
    return 0


def register(subparsers: argparse._SubParsersAction, _cli_class: type) -> None:
    """Auto-discovery hook — attach `test` to the `policy` parent parser.

    Mirrors the policy_gen.py pattern: locate the existing `policy`
    subparser action and register `test` under it without touching
    policy.py.
    """
    choices = getattr(subparsers, "choices", {}) or {}
    policy_parser = choices.get("policy")
    if policy_parser is None:
        policy_parser = subparsers.add_parser(
            "policy", help="Evaluate and manage security policies"
        )

    policy_sub = None
    for action in policy_parser._actions:  # type: ignore[attr-defined]
        if isinstance(action, argparse._SubParsersAction):
            policy_sub = action
            break
    if policy_sub is None:
        policy_sub = policy_parser.add_subparsers(dest="policy_command")

    if "test" in (getattr(policy_sub, "choices", {}) or {}):
        return

    register_subcommand(policy_sub)
