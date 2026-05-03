"""navil audit-deps — MCP ecosystem dependency vulnerability scanner.

Discovers top MCP server packages on npm and PyPI, resolves their
dependency trees, queries OSV.dev for CVEs, maps findings to the
SAFE-MCP tactic taxonomy, and writes a Markdown report + JSON data
file to disk.

Usage:
    navil audit-deps
    navil audit-deps --top 50 --ecosystem npm --output ./report
    navil audit-deps --top 200 --quiet
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def register(subparsers: argparse._SubParsersAction, _cli_class: Any) -> None:  # noqa: SLF001
    """Register the audit-deps subcommand."""
    parser = subparsers.add_parser(
        "audit-deps",
        help="Scan MCP package dependencies for CVEs and map to SAFE-MCP tactics.",
        description=__doc__,
    )
    parser.add_argument(
        "--top",
        type=int,
        default=100,
        metavar="N",
        help="Number of packages to audit per ecosystem (default: 100).",
    )
    parser.add_argument(
        "--ecosystem",
        choices=["npm", "pypi", "all"],
        default="all",
        metavar="ECOSYSTEM",
        help="Registry to audit: npm, pypi, or all (default: all).",
    )
    parser.add_argument(
        "--output",
        default="./navil-report",
        metavar="DIR",
        help="Directory to write report.md and report.json (default: ./navil-report).",
    )
    parser.add_argument(
        "--no-transitive",
        action="store_true",
        help="Skip transitive dependency CVE lookup (faster, less complete).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output.",
    )
    parser.add_argument(
        "--stdio-flaw",
        action="store_true",
        help=(
            "Scan local MCP configs for the unpatched STDIO transport "
            "vulnerability (Ox disclosure, April 2026). Skips OSV CVE pipeline."
        ),
    )
    parser.set_defaults(func=_audit_deps_command)


def _audit_deps_command(_cli: Any, args: argparse.Namespace) -> int:
    """Entry point called by the CLI dispatcher."""
    if args.quiet:
        logging.getLogger("navil").setLevel(logging.WARNING)
    else:
        logging.getLogger("navil").setLevel(logging.INFO)

    if getattr(args, "stdio_flaw", False):
        return _stdio_flaw_command(args)

    ecosystems = ["npm", "pypi"] if args.ecosystem == "all" else [args.ecosystem]

    print("\n  navil audit-deps")
    print("  ─────────────────────────────────────────────────────────")
    print(f"  Ecosystems : {', '.join(ecosystems)}")
    print(f"  Top N      : {args.top} packages per ecosystem")
    print(f"  Transitive : {'no' if args.no_transitive else 'yes (1 level)'}")
    print(f"  Output     : {args.output}")
    print()

    try:
        from navil.report.dep_auditor import run_audit
        from navil.report.report_renderer import render_json, render_markdown
    except ImportError as exc:
        print(f"  ✗ Missing dependency: {exc}", file=sys.stderr)
        print("    Run: pip install httpx", file=sys.stderr)
        return 1

    print("  Discovering packages and resolving dependencies…")
    report = asyncio.run(
        run_audit(
            top_n=args.top,
            ecosystems=ecosystems,
            include_transitive=not args.no_transitive,
        )
    )

    # Write outputs
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "report.md"
    json_path = out_dir / "report.json"

    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(render_json(report), encoding="utf-8")

    pct = (report.packages_with_vulns / max(report.packages_audited, 1)) * 100

    print()
    print(f"  ✓ Packages audited     : {report.packages_audited}")
    print(f"  ✓ With CVEs            : {report.packages_with_vulns} ({pct:.0f}%)")
    print(f"  ✓ Total CVE instances  : {report.total_cves}")
    print(f"    Critical / High      : {report.critical_count} / {report.high_count}")

    if report.tactic_exposure:
        top_tactic = max(report.tactic_exposure, key=report.tactic_exposure.get)  # type: ignore[arg-type]
        print(
            f"  ✓ Top exposed tactic   : {top_tactic} ({report.tactic_exposure[top_tactic]} pkgs)"
        )

    print()
    print(f"  Report → {md_path}")
    print(f"  Data   → {json_path}")
    print()

    return 0


def _stdio_flaw_command(args: argparse.Namespace) -> int:
    """Run the local STDIO-flaw scan and write stdio-flaw.md / .json."""
    from navil.report import stdio_flaw

    print("\n  navil audit-deps --stdio-flaw")
    print("  ─────────────────────────────────────────────────────────")
    print("  Mode       : local STDIO transport flaw scan (no network)")
    print(f"  Output     : {args.output}")
    print()

    report = stdio_flaw.run_scan()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "stdio-flaw.md"
    json_path = out_dir / "stdio-flaw.json"
    md_path.write_text(stdio_flaw.render_markdown(report), encoding="utf-8")
    json_path.write_text(stdio_flaw.render_json(report), encoding="utf-8")

    print(f"  ✓ Configs scanned    : {report.configs_scanned}")
    print(f"  ✓ Servers examined   : {report.servers_examined}")
    print(f"  ✓ Servers flagged    : {report.servers_flagged}")
    if report.flagged:
        from collections import Counter

        counts = Counter(f.risk_class for f in report.flagged)
        for risk, n in counts.most_common():
            print(f"    {risk:<20}: {n}")
    print()
    print(f"  Report → {md_path}")
    print(f"  Data   → {json_path}")
    print()
    return 0
