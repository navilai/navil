"""Analyze command -- static analysis of MCP server source code."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path


def _write_output(text: str, output_path: str | None) -> None:
    """Write text to output_path (or stdout if None)."""
    if output_path:
        Path(output_path).write_text(text)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _analyze_command(cli: object, args: argparse.Namespace) -> int:
    """Handle the analyze command."""
    from navil.static_analysis.analyzer import StaticAnalyzer

    target_path = args.path
    fmt = getattr(args, "format", "text")
    severity = getattr(args, "severity", None)
    lang = getattr(args, "lang", None)
    checks = getattr(args, "checks", None)

    if not Path(target_path).exists():
        print(f"Error: Path not found: {target_path}", file=sys.stderr)
        return 1

    # Build language and check sets
    languages = {lang} if lang else None
    enabled_checks = set(checks.split(",")) if checks else None

    try:
        analyzer = StaticAnalyzer(
            enabled_checks=enabled_checks,
            languages=languages,
            severity_filter=severity,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    findings = analyzer.analyze_path(target_path)

    # ── SARIF output ──────────────────────────────────────────
    if fmt == "sarif":
        from navil.sarif import findings_to_sarif_str

        sarif_text = findings_to_sarif_str(findings)
        _write_output(sarif_text, args.output)
        return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0

    # ── JSON output ───────────────────────────────────────────
    if fmt == "json":

        def _default(obj: object) -> object:
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)  # type: ignore[arg-type]
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

        data = {
            "status": "completed",
            "path": str(target_path),
            "total_findings": len(findings),
            "findings": findings,
            "tree_sitter": analyzer.tree_sitter_available,
        }
        text = json.dumps(data, indent=2, default=_default)
        _write_output(text, args.output)
        return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0

    # ── Text output (default) ─────────────────────────────────
    mode = "tree-sitter" if analyzer.tree_sitter_available else "regex-only (fallback)"
    print(f"\nStatic analysis of: {target_path}")
    print(f"Analysis mode: {mode}")
    print("-" * 60)

    if not findings:
        print("\nNo security issues found.")
        if args.output:
            Path(args.output).write_text("No security issues found.\n")
        return 0

    print(f"\nTotal findings: {len(findings)}")

    # Group by severity
    by_severity: dict[str, list[object]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    print("\nFindings by Severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = len(by_severity.get(sev, []))
        if count > 0:
            print(f"  {sev}: {count}")

    print("\nDetailed Findings:")
    for i, f in enumerate(findings, 1):
        print(f"\n  {i}. [{f.severity}] {f.title}")
        print(f"     Location: {f.affected_field}")
        print(f"     ID: {f.id}")
        print(f"     Description: {f.description}")
        if f.evidence:
            # Truncate evidence for display
            evidence = f.evidence[:200] + "..." if len(f.evidence) > 200 else f.evidence
            print(f"     Evidence: {evidence}")
        print(f"     Remediation: {f.remediation}")

    # Save report if requested
    if args.output:
        output_path = Path(args.output)

        def _default_text(obj: object) -> object:
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)  # type: ignore[arg-type]
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

        data = {
            "status": "completed",
            "path": str(target_path),
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(output_path, "w") as fp:
            json.dump(data, fp, indent=2, default=_default_text)
        print(f"\nReport saved to: {output_path}")

    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    return 1 if has_critical else 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the analyze subcommand."""
    parser = subparsers.add_parser(
        "analyze",
        help="Static analysis of MCP server source code",
        description=(
            "Analyze MCP server source code for security vulnerabilities "
            "using tree-sitter AST analysis with regex fallback."
        ),
    )
    parser.add_argument(
        "path",
        help="Path to source file or directory to analyze",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "sarif", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: stdout)",
        default=None,
    )
    parser.add_argument(
        "--lang",
        choices=["python", "javascript", "typescript"],
        help="Analyze only this language (default: all supported)",
        default=None,
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity to report (default: all)",
        default=None,
    )
    parser.add_argument(
        "--checks",
        help=(
            "Comma-separated list of checks to run "
            "(default: all). Valid: subprocess,sql_injection,"
            "path_traversal,secrets,input_validation,"
            "deserialization,command_injection,error_handling,"
            "sensitive_logs,insecure_http"
        ),
        default=None,
    )
    parser.set_defaults(func=lambda cli, args: _analyze_command(cli, args))
