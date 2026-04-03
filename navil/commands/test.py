"""Test command -- fire threat pool scenarios through the anomaly detector and report coverage.

Usage:
  navil test                           — run default pool (200 base vectors)
  navil test --pool mega               — run mega pool (downloaded on first use)
  navil test --pool custom vectors.jsonl — run custom JSONL vectors
  navil test --categories prompt_injection,lateral_movement
  navil test --limit 50 --threshold 90
"""

from __future__ import annotations

import argparse
import math
import random
import sys
import time
from collections import defaultdict
from typing import Any

# ── ANSI helpers ──────────────────────────────────────────────


def _supports_color(no_color_flag: bool) -> bool:
    """Return True if stdout is a TTY and --no-color was not passed."""
    if no_color_flag:
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _color(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"\033[{code}m{text}\033[0m"


def _coverage_color(pct: float, use_color: bool) -> str:
    """Color a percentage string based on coverage thresholds."""
    s = f"{pct:.1f}%"
    if pct >= 90:
        return _color(s, "32", use_color)  # green
    elif pct >= 70:
        return _color(s, "33", use_color)  # yellow
    else:
        return _color(s, "31", use_color)  # red


# ── Stratified sampling ──────────────────────────────────────


def stratified_sample(
    items_by_category: dict[str, list[Any]],
    limit: int,
) -> dict[str, list[Any]]:
    """Sample proportionally across categories up to *limit* total items."""
    total = sum(len(v) for v in items_by_category.values())
    if total <= limit:
        return items_by_category

    result: dict[str, list[Any]] = {}
    allocated = 0
    categories = sorted(items_by_category.keys())

    for cat in categories:
        pool = items_by_category[cat]
        # Proportional allocation, at least 1 if the category has items
        n = max(1, math.floor(len(pool) / total * limit))
        n = min(n, len(pool), limit - allocated)
        result[cat] = random.sample(pool, n) if n < len(pool) else list(pool)
        allocated += n

    # Distribute remaining budget
    remaining = limit - allocated
    if remaining > 0:
        for cat in categories:
            pool = items_by_category[cat]
            already = len(result.get(cat, []))
            can_add = len(pool) - already
            if can_add > 0:
                extra = min(can_add, remaining)
                existing_set = set(id(x) for x in result[cat])
                extras = [x for x in pool if id(x) not in existing_set][:extra]
                result[cat].extend(extras)
                remaining -= extra
                if remaining <= 0:
                    break

    return result


# ── Pool loading ─────────────────────────────────────────────


def _load_default_pool(
    categories_filter: list[str] | None,
) -> dict[str, list[list[dict[str, Any]]]]:
    """Load the default pool (200 base vectors) via pool_converter."""
    from navil.safemcp.pool_converter import (
        VECTOR_TO_SAFEMCP,
        convert_vector,
    )

    items_by_cat: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
    for vid, cfg in sorted(VECTOR_TO_SAFEMCP.items()):
        cat = cfg["category"]
        if categories_filter and cat not in categories_filter:
            continue
        variants = convert_vector(vid, count=5)
        items_by_cat[cat].extend(variants)

    return dict(items_by_cat)


def _load_mega_pool() -> dict[str, list[list[dict[str, Any]]]]:
    """Load the mega pool (downloaded on first use)."""
    print("Mega pool download not yet configured. Use --pool default.", file=sys.stderr)
    sys.exit(1)


def _load_custom_pool(path: str) -> dict[str, list[list[dict[str, Any]]]]:
    """Load a custom JSONL pool from a file path."""
    import json
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        print(f"Error: Custom pool file not found: {path}", file=sys.stderr)
        sys.exit(1)

    items_by_cat: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            cat = record.get("category", "unknown")
            invocations = record.get("invocations", [])
            if invocations:
                items_by_cat[cat].append(invocations)

    return dict(items_by_cat)


# ── Scenario firing ──────────────────────────────────────────


def _fire_scenario(
    detector: Any,
    invocations: list[dict[str, Any]],
) -> bool:
    """Fire a single scenario through the anomaly detector.

    Returns True if the scenario was blocked (anomaly detected).
    """
    alerts_before = len(detector.alerts)

    for inv in invocations:
        detector.record_invocation(
            agent_name=inv.get("agent_name", "test-agent"),
            tool_name=inv.get("tool_name", "unknown"),
            action=inv.get("action", "call"),
            duration_ms=inv.get("duration_ms", 100),
            data_accessed_bytes=inv.get("data_accessed_bytes", 0),
            success=inv.get("success", True),
            arguments_hash=inv.get("arguments_hash"),
            arguments_size_bytes=inv.get("arguments_size_bytes", 0),
            response_size_bytes=inv.get("response_size_bytes", 0),
            timestamp=inv.get("_raw_timestamp"),
        )

    alerts_after = len(detector.alerts)
    return alerts_after > alerts_before


# ── Report formatting ────────────────────────────────────────


def format_report(
    results: dict[str, dict[str, int]],
    pool_name: str,
    total_vectors: int,
    total_variants: int,
    runtime_seconds: float,
    threshold: int | None,
    use_color: bool,
) -> tuple[str, int]:
    """Format the coverage report and compute exit code.

    Returns (report_text, exit_code).
    """
    lines: list[str] = []
    header = "Navil Test Report"
    lines.append(_color(header, "36", use_color))  # cyan
    lines.append(f"Pool: {pool_name} ({total_vectors} base vectors, {total_variants} variants)")
    lines.append(f"Runtime: {runtime_seconds:.1f}s")
    lines.append("")

    # Table header
    hdr = f"  {'Category':<36s} {'Total':>5s}  {'Blocked':>7s}  {'Missed':>6s}  {'Coverage':>10s}"
    lines.append(_color(hdr, "36", use_color))
    sep = "  " + "\u2500" * 68
    lines.append(sep)

    grand_total = 0
    grand_blocked = 0
    grand_missed = 0

    for cat in sorted(results.keys()):
        r = results[cat]
        total = r["total"]
        blocked = r["blocked"]
        missed = r["missed"]
        pct = (blocked / total * 100) if total > 0 else 0.0

        grand_total += total
        grand_blocked += blocked
        grand_missed += missed

        # Human-readable category name
        display_cat = cat.replace("_", " ").title()
        pct_str = _coverage_color(pct, use_color)
        lines.append(
            f"  {display_cat:<36s} {total:>5d}  {blocked:>7d}  {missed:>6d}  {pct_str:>10s}"
        )

    lines.append(sep)
    grand_pct = (grand_blocked / grand_total * 100) if grand_total > 0 else 0.0
    grand_pct_str = _coverage_color(grand_pct, use_color)
    lines.append(
        f"  {'TOTAL':<36s} {grand_total:>5d}  {grand_blocked:>7d}"
        f"  {grand_missed:>6d}  {grand_pct_str:>10s}"
    )

    # ── SAFE-MCP tactic breakdown ──────────────────────────────
    try:
        from navil.safemcp.pool_converter import safe_mcp_tactic_coverage

        tactic_cov = safe_mcp_tactic_coverage(results)
        lines.append("")
        lines.append(_color("  SAFE-MCP Tactic Coverage", "36", use_color))
        lines.append("  " + "\u2500" * 68)
        for tactic, pct in tactic_cov.items():
            bar_filled = int(pct / 10)  # 0-10 blocks
            bar = "\u2588" * bar_filled + "\u2591" * (10 - bar_filled)
            pct_str = _coverage_color(pct, use_color)
            lines.append(f"  {tactic:<28s}  {pct_str:>7s}  {bar}")
    except ImportError:
        pass

    exit_code = 0
    if threshold is not None:
        lines.append("")
        if grand_pct < threshold:
            exit_code = 1
            lines.append(f"Exit code: 1 (coverage {grand_pct:.1f}% < threshold {threshold}%)")
        else:
            lines.append(f"Exit code: 0 (coverage {grand_pct:.1f}% >= threshold {threshold}%)")

    return "\n".join(lines), exit_code


# ── Command handler ──────────────────────────────────────────


def _test_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil test`."""
    from navil.anomaly_detector import BehavioralAnomalyDetector

    use_color = _supports_color(getattr(args, "no_color", False))
    pool_name = args.pool
    categories_filter = None
    if args.categories:
        categories_filter = [c.strip() for c in args.categories.split(",")]

    # Load pool
    if pool_name == "mega":
        _load_mega_pool()
        return 1  # unreachable, _load_mega_pool exits
    elif pool_name == "custom":
        if not args.pool_path:
            print(
                "Error: --pool custom requires a JSONL file path via --pool-path", file=sys.stderr
            )
            return 1
        items_by_cat = _load_custom_pool(args.pool_path)
    else:
        items_by_cat = _load_default_pool(categories_filter)

    if not items_by_cat:
        print("No scenarios found for the given filters.", file=sys.stderr)
        return 1

    # Count totals before sampling (used for report header)

    # Stratified sampling if --limit is set
    limit = args.limit
    if limit and limit > 0:
        items_by_cat = stratified_sample(items_by_cat, limit)

    sampled_total = sum(len(v) for v in items_by_cat.values())

    # Count unique base vectors
    total_vectors = sum(len(v) for v in items_by_cat.values()) if pool_name == "custom" else 200

    # Create a fresh detector for testing
    detector = BehavioralAnomalyDetector()

    # Fire scenarios
    results: dict[str, dict[str, int]] = {}
    start_time = time.monotonic()

    for cat, scenarios in items_by_cat.items():
        blocked = 0
        missed = 0
        for scenario in scenarios:
            if _fire_scenario(detector, scenario):
                blocked += 1
            else:
                missed += 1
        results[cat] = {"total": len(scenarios), "blocked": blocked, "missed": missed}

    runtime = time.monotonic() - start_time

    # Format and print report
    threshold = args.threshold
    report, exit_code = format_report(
        results=results,
        pool_name=pool_name,
        total_vectors=total_vectors,
        total_variants=sampled_total,
        runtime_seconds=runtime,
        threshold=threshold,
        use_color=use_color,
    )
    print(report)
    return exit_code


# ── Registration ─────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the test subcommand."""
    test_parser = subparsers.add_parser(
        "test",
        help="Fire threat pool scenarios and produce a coverage report",
    )
    test_parser.add_argument(
        "--pool",
        choices=["default", "mega", "custom"],
        default="default",
        help="Threat pool to use (default: default)",
    )
    test_parser.add_argument(
        "--pool-path",
        default=None,
        help="Path to custom JSONL pool file (used with --pool custom)",
    )
    test_parser.add_argument(
        "--categories",
        default=None,
        help="Comma-separated list of categories to filter to",
    )
    test_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit total scenarios (default: all for default pool)",
    )
    test_parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Exit code 1 if coverage < N%% (for CI/CD)",
    )
    test_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    test_parser.set_defaults(func=lambda cli, args: _test_command(cli, args))
