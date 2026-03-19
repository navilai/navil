"""OpenAPI commands — wrap, serve, and scan OpenAPI specs.

Provides the ``navil openapi`` subcommand group:

    navil openapi wrap <spec.yaml>              # Generate MCP config from OpenAPI
    navil openapi wrap <spec.yaml> --output .    # Write to specific directory
    navil openapi wrap <spec.yaml> --dry-run     # Preview without writing
    navil openapi wrap <spec.yaml> --filter "GET*"  # Only wrap GET endpoints
    navil openapi serve <spec.yaml>              # Start as MCP server directly
    navil openapi scan <spec.yaml>               # Scan OpenAPI spec for security issues
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _openapi_wrap(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle ``navil openapi wrap``."""
    from navil.openapi_bridge import openapi_to_mcp_config, write_mcp_config

    spec_path = args.spec
    filter_pattern = args.filter
    output_dir = args.output
    dry_run = args.dry_run
    api_name = args.name
    policy = args.policy

    try:
        result = openapi_to_mcp_config(
            spec_path,
            filter_pattern=filter_pattern,
            api_name=api_name,
            policy_path=policy,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Print summary
    print("\nOpenAPI -> MCP Bridge", file=sys.stderr)
    print(f"{'─' * 50}", file=sys.stderr)
    print(f"  Spec:       {spec_path}", file=sys.stderr)
    print(f"  API name:   {result['server_name']}", file=sys.stderr)
    print(f"  Base URL:   {result['base_url']}", file=sys.stderr)
    print(f"  Tools:      {result['tools_count']}", file=sys.stderr)

    if result["security_schemes"]:
        schemes = ", ".join(result["security_schemes"])
        print(f"  Security:   {schemes}", file=sys.stderr)
    else:
        print("  Security:   (none detected)", file=sys.stderr)

    if dry_run:
        print("\n  [dry-run] MCP config preview:\n", file=sys.stderr)
        print(json.dumps(result["mcp_config"], indent=2))
        return 0

    config_file = write_mcp_config(result, output_dir)
    print(f"\n  Bridge config: {result['bridge_config_path']}", file=sys.stderr)
    print(f"  MCP config:    {config_file}", file=sys.stderr)
    print(
        f"\n  Add the contents of {config_file} to your MCP client config "
        f"(claude_desktop_config.json, openclaw.json, etc.)\n",
        file=sys.stderr,
    )
    return 0


def _openapi_serve(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle ``navil openapi serve`` — run the MCP bridge server directly."""
    import asyncio
    import logging

    from navil.openapi_bridge import _extract_security_requirements, load_spec, spec_to_tools

    spec_path = args.spec

    try:
        spec = load_spec(spec_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    tools = spec_to_tools(spec, filter_pattern=args.filter)
    servers = spec.get("servers", [])
    base_url = servers[0]["url"] if servers else "http://localhost"
    security_reqs = _extract_security_requirements(spec)

    config = {
        "spec_path": str(Path(spec_path).resolve()),
        "base_url": base_url,
        "tools": tools,
        "security": security_reqs,
    }

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.WARNING,
        format="%(asctime)s [navil-openapi] %(levelname)s %(message)s",
        force=True,
    )

    print(
        f"Starting OpenAPI MCP server for {spec_path} "
        f"({len(tools)} tools, base={base_url})",
        file=sys.stderr,
    )

    from navil.openapi_server import OpenAPIMCPServer

    server = OpenAPIMCPServer(config)
    return asyncio.run(server.run())


def _openapi_scan(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle ``navil openapi scan``."""
    from navil.openapi_scanner import scan_openapi

    spec_path = args.spec
    fmt = getattr(args, "format", "text")

    try:
        findings = scan_openapi(spec_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # ── SARIF output ──────────────────────────────────────────
    if fmt == "sarif":
        from navil.sarif import findings_to_sarif_str

        sarif_text = findings_to_sarif_str(findings)
        if args.output:
            Path(args.output).write_text(sarif_text)
        else:
            sys.stdout.write(sarif_text)
            if not sarif_text.endswith("\n"):
                sys.stdout.write("\n")
        return 0 if not findings else 1

    # ── JSON output ───────────────────────────────────────────
    if fmt == "json":

        def _default(obj):  # type: ignore[no-untyped-def]
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

        text = json.dumps([dataclasses.asdict(f) for f in findings], indent=2, default=_default)
        if args.output:
            Path(args.output).write_text(text)
        else:
            print(text)
        return 0 if not findings else 1

    # ── Text output (default) ─────────────────────────────────
    print(f"\nOpenAPI Security Scan: {spec_path}")
    print("─" * 60)

    if not findings:
        print("\n  No security issues found.\n")
        return 0

    print(f"\n  Found {len(findings)} issue(s):\n")

    # Group by severity
    by_severity: dict[str, list] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = by_severity.get(severity, [])
        if not group:
            continue
        print(f"  [{severity}] ({len(group)})")
        for finding in group:
            print(f"    - {finding.title}")
            print(f"      {finding.description}")
            if finding.remediation:
                print(f"      Fix: {finding.remediation}")
            print()

    if args.output:
        text = json.dumps([dataclasses.asdict(f) for f in findings], indent=2)
        Path(args.output).write_text(text)
        print(f"  Report saved to: {args.output}")

    return 1


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the ``navil openapi`` subcommand group."""
    openapi_parser = subparsers.add_parser(
        "openapi",
        help="Convert, serve, and scan OpenAPI specs as MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  navil openapi wrap petstore.yaml                  # Generate MCP config
  navil openapi wrap petstore.yaml --dry-run        # Preview without writing
  navil openapi wrap petstore.yaml --filter "GET*"  # Only GET endpoints
  navil openapi serve petstore.yaml                 # Start MCP server directly
  navil openapi scan petstore.yaml                  # Scan for security issues
        """,
    )

    openapi_sub = openapi_parser.add_subparsers(dest="openapi_command", help="OpenAPI action")

    # ── wrap ──────────────────────────────────────────────────
    wrap_parser = openapi_sub.add_parser(
        "wrap",
        help="Generate a Navil-wrapped MCP config from an OpenAPI spec",
    )
    wrap_parser.add_argument("spec", help="Path to OpenAPI spec (YAML or JSON)")
    wrap_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory for generated config files (default: same as spec)",
    )
    wrap_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the generated config without writing files",
    )
    wrap_parser.add_argument(
        "--filter",
        default=None,
        help="Fnmatch pattern to filter endpoints (e.g. 'GET*', '*/pets*')",
    )
    wrap_parser.add_argument(
        "--name",
        default=None,
        help="Override the API name in the MCP config",
    )
    wrap_parser.add_argument(
        "--policy",
        default=None,
        help="Path to Navil policy YAML to attach to the shim",
    )
    wrap_parser.set_defaults(func=_openapi_wrap)

    # ── serve ─────────────────────────────────────────────────
    serve_parser = openapi_sub.add_parser(
        "serve",
        help="Start an MCP server that proxies to the OpenAPI-described API",
    )
    serve_parser.add_argument("spec", help="Path to OpenAPI spec (YAML or JSON)")
    serve_parser.add_argument(
        "--filter",
        default=None,
        help="Fnmatch pattern to filter endpoints",
    )
    serve_parser.set_defaults(func=_openapi_serve)

    # ── scan ──────────────────────────────────────────────────
    scan_parser = openapi_sub.add_parser(
        "scan",
        help="Scan an OpenAPI spec for security issues",
    )
    scan_parser.add_argument("spec", help="Path to OpenAPI spec (YAML or JSON)")
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    scan_parser.set_defaults(func=_openapi_scan)

    # Default handler when no subcommand given
    openapi_parser.set_defaults(
        func=lambda cli, args: (openapi_parser.print_help(), 1)[1]
    )
