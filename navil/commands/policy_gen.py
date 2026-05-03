"""`navil policy generate` — AI-reasoned least-privilege policy generation.

Reads the user's MCP configs and tool-call audit log, asks an LLM
(with the SAFE-MCP threat catalog cached) to reason about the agent's
real exposure surface, then emits ``./navil.yaml`` plus a
``./navil-policy.md`` rationale document a security team can defend.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from navil.llm.smart_policy import generate_policy


def register_subcommand(policy_subparsers: argparse._SubParsersAction) -> None:
    """Attach `generate` to the existing `navil policy` subparser."""
    p = policy_subparsers.add_parser(
        "generate",
        help="AI-reasoned least-privilege policy with per-rule rationale",
        description=(
            "Reads MCP configs + tool-call audit logs, calls Claude with "
            "the SAFE-MCP threat catalog as cached context, and emits a "
            "tight navil.yaml plus a rationale document."
        ),
    )
    p.add_argument(
        "--from-log",
        default=None,
        help=(
            "Path to a JSONL audit log "
            "({agent, tool, timestamp, decision} per line). "
            "Defaults to ~/.navil/tool_calls.jsonl if present."
        ),
    )
    p.add_argument(
        "--policy-out",
        default="navil.yaml",
        help="Output path for the policy YAML (default: ./navil.yaml)",
    )
    p.add_argument(
        "--rationale-out",
        default="navil-policy.md",
        help="Output path for the rationale doc (default: ./navil-policy.md)",
    )
    p.add_argument(
        "--model",
        default=None,
        help="Override the LLM model (default: project's standard Claude model)",
    )
    p.add_argument(
        "--engine",
        default=None,
        choices=[
            "sonnet-4-6",
            "opus-4-7",
            "haiku-4-5",
            "claude-sonnet-4-6",
            "claude-opus-4-7",
            "claude-haiku-4-5",
        ],
        help=(
            "Reasoning engine alias. "
            "sonnet-4-6 (default, fast), opus-4-7 (deepest reasoning), "
            "haiku-4-5 (cheapest). Overrides --model when set."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the policy + rationale; do not write files",
    )
    p.add_argument(
        "--explain",
        action="store_true",
        help="Print only the rationale doc; do not write or print YAML",
    )
    p.set_defaults(func=lambda cli, args: _run(cli, args))


_ENGINE_ALIASES = {
    "sonnet-4-6": "claude-sonnet-4-6",
    "opus-4-7": "claude-opus-4-7",
    "haiku-4-5": "claude-haiku-4-5",
    "claude-sonnet-4-6": "claude-sonnet-4-6",
    "claude-opus-4-7": "claude-opus-4-7",
    "claude-haiku-4-5": "claude-haiku-4-5",
}


def _run(_cli: Any, args: argparse.Namespace) -> int:
    audit_path: Path | None = Path(args.from_log) if args.from_log else None

    kwargs: dict[str, Any] = {"audit_log": audit_path}
    engine_value = getattr(args, "engine", None)
    if engine_value:
        kwargs["model"] = _ENGINE_ALIASES.get(engine_value, engine_value)
    elif args.model:
        kwargs["model"] = args.model

    result = generate_policy(**kwargs)

    method = result.get("method", "unknown")
    reason = result.get("reason")
    yaml_text: str = result.get("yaml", "")
    md_text: str = result.get("markdown", "")

    print(f"\n  Navil Smart Policy Generator [{method}]")
    print("=" * 60)
    if reason:
        print(f"  {reason}")

    if args.explain:
        print()
        print(md_text)
        return 0

    if args.dry_run:
        print("\n  --- navil.yaml (dry-run) ---")
        print(yaml_text)
        print("\n  --- navil-policy.md (dry-run) ---")
        print(md_text)
        return 0

    policy_path = Path(args.policy_out)
    rationale_path = Path(args.rationale_out)

    policy_path.parent.mkdir(parents=True, exist_ok=True)
    rationale_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(yaml_text, encoding="utf-8")
    rationale_path.write_text(md_text, encoding="utf-8")

    print(f"\n  Policy written to:    {policy_path}")
    print(f"  Rationale written to: {rationale_path}")
    return 0


def register(subparsers: argparse._SubParsersAction, _cli_class: type) -> None:
    """Auto-discovery hook.

    The ``policy`` parent parser is registered by ``commands/policy.py``.
    We attach ``generate`` to whichever copy of that parser already exists
    in the subparsers map; if it does not exist yet, we create it. This
    keeps the file purely additive — no edits to ``policy.py`` required.
    """
    # argparse stores registered choices on the action itself
    choices = getattr(subparsers, "choices", {}) or {}
    policy_parser = choices.get("policy")
    if policy_parser is None:
        policy_parser = subparsers.add_parser(
            "policy", help="Evaluate and manage security policies"
        )

    # Find or create the policy_command subparsers action
    policy_sub = None
    for action in policy_parser._actions:  # type: ignore[attr-defined]
        if isinstance(action, argparse._SubParsersAction):
            policy_sub = action
            break
    if policy_sub is None:
        policy_sub = policy_parser.add_subparsers(dest="policy_command")

    # Avoid re-registering if some other module already added `generate`
    if "generate" in (getattr(policy_sub, "choices", {}) or {}):
        return

    register_subcommand(policy_sub)
