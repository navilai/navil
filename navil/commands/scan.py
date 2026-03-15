"""Scan command -- scan MCP configuration files for vulnerabilities."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path


def _write_output(text: str, output_path: str | None) -> None:
    """Write *text* to *output_path* (or stdout if None)."""
    if output_path:
        Path(output_path).write_text(text)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _scan_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle scan command."""
    config_path = args.config_path
    fmt = getattr(args, "format", "text")

    if not Path(config_path).exists():
        print(f"Error: Configuration file not found: {config_path}", file=sys.stderr)
        return 1

    result = cli.scanner.scan(config_path)

    # ── SARIF output ──────────────────────────────────────────
    if fmt == "sarif":
        from navil.sarif import findings_to_sarif_str

        findings = result.get("findings", [])
        sarif_text = findings_to_sarif_str(findings)
        _write_output(sarif_text, args.output)
        return 0 if result.get("security_score", 0) >= 60 else 1

    # ── JSON output ───────────────────────────────────────────
    if fmt == "json":

        def _default(obj):  # type: ignore[no-untyped-def]
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

        text = json.dumps(result, indent=2, default=_default)
        _write_output(text, args.output)
        return 0 if result.get("security_score", 0) >= 60 else 1

    # ── Text output (default) ─────────────────────────────────
    print(f"\nScanning MCP configuration: {config_path}")
    print("-" * 60)

    # Display results
    print(f"\nStatus: {result.get('status', 'unknown')}")
    print(f"Security Score: {result.get('security_score', 0)}/100")
    print(f"Total Vulnerabilities: {result.get('total_vulnerabilities', 0)}")

    # Show vulnerabilities by level
    vulns_by_level = result.get("vulnerabilities_by_level", {})
    if vulns_by_level:
        print("\nVulnerabilities by Severity:")
        for level, count in vulns_by_level.items():
            if count > 0:
                print(f"  {level}: {count}")

    # Show vulnerabilities
    vulns = result.get("vulnerabilities", [])
    if vulns:
        print("\nDetailed Vulnerabilities:")
        for i, vuln in enumerate(vulns, 1):
            print(f"\n  {i}. {vuln.get('title')}")
            print(f"     Risk Level: {vuln.get('risk_level')}")
            print(f"     Description: {vuln.get('description')}")
            print(f"     Remediation: {vuln.get('remediation')}")

    # Show recommendations
    print(f"\nRecommendation: {result.get('recommendation', 'N/A')}")

    # Save report if requested
    if args.output:
        output_path = Path(args.output)

        def _default_text(obj):  # type: ignore[no-untyped-def]
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=_default_text)
        print(f"\nReport saved to: {output_path}")

    return 0 if result.get("security_score", 0) >= 60 else 1


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:  # noqa: N802
    """Register the scan subcommand."""
    scan_parser = subparsers.add_parser("scan", help="Scan MCP configuration file")
    scan_parser.add_argument("config_path", help="Path to MCP configuration file (JSON)")
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "sarif", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: stdout)",
        default=None,
    )
    scan_parser.set_defaults(func=lambda cli, args: _scan_command(cli, args))
