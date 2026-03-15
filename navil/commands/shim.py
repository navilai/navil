"""Shim and wrap commands -- stdio transport wrapping for MCP servers."""

from __future__ import annotations

import argparse
import logging
import os
import sys


def _shim_start(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    import asyncio
    import shlex

    from navil.shim import run_shim

    cmd = shlex.split(args.cmd)
    agent_name = args.agent or os.environ.get("NAVIL_AGENT_NAME", "stdio-agent")

    # Shim runs silently on stdout (that's the MCP transport channel).
    # All logging goes to stderr so it doesn't corrupt the JSON-RPC stream.
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.WARNING,
        format="%(asctime)s [navil-shim] %(levelname)s %(message)s",
        force=True,
    )

    try:
        return asyncio.run(
            run_shim(
                cmd=cmd,
                agent_name=agent_name,
                policy_path=args.policy,
                redis_url=args.redis_url,
            )
        )
    except KeyboardInterrupt:
        return 0


def _wrap_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    from navil.wrap import print_summary, wrap_config

    only = args.only.split(",") if args.only else None
    skip = args.skip.split(",") if args.skip else None

    try:
        result = wrap_config(
            args.config,
            only=only,
            skip=skip,
            policy_path=args.policy,
            agent_prefix=args.agent_prefix,
            undo=args.undo,
            dry_run=args.dry_run,
        )
        print_summary(result, undo=args.undo)
        return 0
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register shim and wrap subcommands."""
    # ── Shim command (stdio transport) ────────────────────────
    shim_parser = subparsers.add_parser(
        "shim",
        help="Wrap a stdio MCP server with Navil security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Wrap any MCP server binary
  navil shim --cmd "npx -y @modelcontextprotocol/server-filesystem /tmp"

  # With policy enforcement
  navil shim --cmd "python -m my_mcp_server" --agent my-agent --policy policy.yaml

  # OpenClaw integration (in openclaw.json):
  #   "mcpServers": {
  #     "filesystem": {
  #       "command": "navil",
  #       "args": ["shim", "--cmd", "npx -y @modelcontextprotocol/server-filesystem /tmp"]
  #     }
  #   }
        """,
    )
    shim_parser.add_argument(
        "--cmd",
        required=True,
        help="The MCP server command to wrap (e.g., 'npx -y @mcp/server-filesystem /tmp')",
    )
    shim_parser.add_argument(
        "--agent",
        default=None,
        help="Agent identity for policy/telemetry (default: NAVIL_AGENT_NAME env or 'stdio-agent')",
    )
    shim_parser.add_argument(
        "--policy",
        default=None,
        help="Path to policy YAML file for enforcement",
    )
    shim_parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL for telemetry (default: NAVIL_REDIS_URL env or none)",
    )
    shim_parser.set_defaults(func=_shim_start)

    # ── Wrap command (config patcher) ─────────────────────────
    wrap_parser = subparsers.add_parser(
        "wrap",
        help="Wrap all MCP servers in a config with navil shim",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  navil wrap openclaw.json                     # wrap all servers
  navil wrap openclaw.json --only filesystem,github  # wrap specific servers
  navil wrap openclaw.json --policy policy.yaml      # attach a policy
  navil wrap openclaw.json --dry-run                 # preview without modifying
  navil wrap openclaw.json --undo                    # restore original config
        """,
    )
    wrap_parser.add_argument("config", help="Path to MCP client config (e.g., openclaw.json)")
    wrap_parser.add_argument(
        "--only",
        default=None,
        help="Comma-separated list of server names to wrap (default: all)",
    )
    wrap_parser.add_argument(
        "--skip",
        default=None,
        help="Comma-separated list of server names to skip",
    )
    wrap_parser.add_argument("--policy", default=None, help="Path to policy YAML file")
    wrap_parser.add_argument(
        "--agent-prefix",
        default=None,
        help="Agent name prefix (default: 'navil', produces 'navil-<server>')",
    )
    wrap_parser.add_argument(
        "--undo", action="store_true", help="Restore original config from backup"
    )
    wrap_parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without modifying files"
    )
    wrap_parser.set_defaults(func=_wrap_command)
