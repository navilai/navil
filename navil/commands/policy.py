"""Policy commands -- evaluate security policies for MCP tool calls."""

from __future__ import annotations

import argparse


def _policy_check_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle policy check command."""
    tool_name = args.tool
    agent_name = args.agent
    action = args.action

    print("\nChecking Policy")
    print(f"Agent: {agent_name}, Tool: {tool_name}, Action: {action}")
    print("-" * 60)

    allowed, reason = cli.policy_engine.check_tool_call(
        agent_name=agent_name, tool_name=tool_name, action=action
    )

    status = "ALLOWED" if allowed else "DENIED"
    print(f"\nPolicy Decision: {status}")
    print(f"Reason: {reason}")

    return 0 if allowed else 1


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the policy subcommands."""
    policy_parser = subparsers.add_parser("policy", help="Evaluate security policies")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    check_parser = policy_subparsers.add_parser("check", help="Check policy decision")
    check_parser.add_argument("--tool", required=True, help="Tool name")
    check_parser.add_argument("--agent", required=True, help="Agent name")
    check_parser.add_argument("--action", required=True, help="Action (read/write/delete)")
    check_parser.set_defaults(func=lambda cli, args: _policy_check_command(cli, args))
