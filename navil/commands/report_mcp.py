"""Report command -- generate State of MCP security report from batch scan results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _state_of_mcp_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil report state-of-mcp <jsonl_path>`."""
    from navil.report.state_of_mcp import generate_state_of_mcp_report

    jsonl_path = Path(args.jsonl_path)
    if not jsonl_path.exists():
        print(f"Error: File not found: {jsonl_path}", file=sys.stderr)
        return 1

    report = generate_state_of_mcp_report(jsonl_path)

    if args.output:
        Path(args.output).write_text(report)
        print(f"Report written to: {args.output}")
    else:
        print(report)

    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the report state-of-mcp subcommand.

    Note: the top-level ``report`` command is already registered by export.py.
    This module adds the ``report-mcp`` command as a separate top-level command
    to avoid conflicts.
    """
    parser = subparsers.add_parser(
        "report-mcp",
        help="Generate State of MCP security report from batch scan results",
    )
    parser.add_argument(
        "jsonl_path",
        help="Path to JSONL file from scan-batch",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for Markdown report (default: stdout)",
    )
    parser.set_defaults(func=lambda cli, args: _state_of_mcp_command(cli, args))
