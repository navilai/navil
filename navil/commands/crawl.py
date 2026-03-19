"""Crawl command -- discover MCP servers from public registries.

Extended commands:
  navil crawl registries         — discover MCP servers
  navil crawl schedule           — set up recurring scan
  navil crawl run-scan           — run a one-off full scan pipeline
  navil crawl history            — show scan history
  navil crawl diff <s1> <s2>     — compare two scans
  navil crawl trend              — show trend over recent scans
  navil crawl trend-report       — generate publishable trend report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import orjson


def _crawl_registries_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl registries`."""
    from navil.crawler.registry_crawler import RegistryCrawler

    limit = args.limit or 0
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Crawling registries (limit={limit or 'unlimited'})...")

    crawler = RegistryCrawler(limit=limit)
    results = asyncio.run(crawler.crawl())

    if not results:
        print("No servers discovered.", file=sys.stderr)
        return 1

    # Write each result as a JSON file
    for i, r in enumerate(results):
        fname = f"{r.source}_{i:04d}.json"
        path = output_dir / fname
        path.write_bytes(orjson.dumps(r.to_dict(), option=orjson.OPT_INDENT_2))

    print(f"Discovered {len(results)} servers, written to {output_dir}/")
    return 0


# ── Schedule command ──────────────────────────────────────────


def _schedule_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl schedule`."""
    from navil.crawler.scheduler import (
        generate_crontab_entry,
        generate_systemd_timer,
        run_async_scheduler,
        run_daemon,
    )

    interval = args.interval
    mode = args.mode

    if mode == "daemon":
        print(f"Starting scan daemon (interval={interval})...")
        print("Press Ctrl+C to stop.")
        run_daemon(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
            webhook_url=args.webhook,
        )
        return 0

    elif mode == "async":
        print(f"Starting async scan scheduler (interval={interval})...")
        print("Press Ctrl+C to stop.")

        # Set up Redis client if URL provided
        redis_client = None
        redis_url = getattr(args, "redis_url", None)
        if redis_url:
            try:
                import redis.asyncio as aioredis

                redis_client = aioredis.from_url(redis_url)
                print(f"Redis lock enabled: {redis_url}")
            except Exception as exc:
                print(f"Warning: Could not connect to Redis ({exc}). Running without lock.")

        try:
            asyncio.run(
                run_async_scheduler(
                    interval,
                    limit=args.limit,
                    timeout_per_scan=args.timeout,
                    webhook_url=args.webhook,
                    slack_webhook_url=getattr(args, "slack_webhook", None),
                    redis_client=redis_client,
                    feed_to_cloud=getattr(args, "feed_to_cloud", False),
                )
            )
        except KeyboardInterrupt:
            print("\nScheduler stopped.")
        return 0

    elif mode == "crontab":
        entry = generate_crontab_entry(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
        )
        print("Add this line to your crontab (crontab -e):")
        print()
        print(f"  {entry}")
        print()
        return 0

    elif mode == "systemd":
        units = generate_systemd_timer(
            interval,
            limit=args.limit,
            timeout_per_scan=args.timeout,
        )
        print("=== navil-scan.service ===")
        print(units["service"])
        print("=== navil-scan.timer ===")
        print(units["timer"])
        print("Install with:")
        print("  sudo cp navil-scan.service navil-scan.timer /etc/systemd/system/")
        print("  sudo systemctl enable --now navil-scan.timer")
        return 0

    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        return 1


# ── Run-scan command ──────────────────────────────────────────


def _run_scan_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl run-scan`."""
    from navil.crawler.scheduler import run_full_scan

    print("Running full scan pipeline (crawl + scan + store)...")
    result = run_full_scan(
        limit=args.limit,
        timeout_per_scan=args.timeout,
        webhook_url=getattr(args, "webhook", None),
    )

    if result.get("status") == "no_servers":
        print("No servers discovered from registries.", file=sys.stderr)
        return 1

    print("\nScan complete:")
    print(f"  Scan ID:    {result.get('scan_id')}")
    print(f"  Discovered: {result.get('servers_discovered', 0)} servers")
    stats = result.get("stats", {})
    print(f"  Successful: {stats.get('successful', 0)}")
    print(f"  Failed:     {stats.get('failed', 0)}")
    print(f"  Timed out:  {stats.get('timed_out', 0)}")
    print(f"  Elapsed:    {result.get('elapsed_seconds', 0):.1f}s")

    if args.json:
        print("\n" + json.dumps(result, indent=2))

    return 0


# ── History command ───────────────────────────────────────────


def _history_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl history`."""
    from navil.crawler.scan_history import ScanHistoryStore

    store = ScanHistoryStore()
    scans = store.get_scan_history(limit=args.limit)

    if not scans:
        print("No scan history found.")
        return 0

    if args.json:
        print(json.dumps([s.to_dict() for s in scans], indent=2))
        return 0

    print(
        f"{'ID':>4s}  {'Date':>10s}  {'Servers':>7s}  {'OK':>4s}  {'Fail':>4s}  {'Avg Score':>9s}"
    )
    print("-" * 50)
    for s in scans:
        ts = s.timestamp[:10] if len(s.timestamp) >= 10 else s.timestamp
        print(
            f"{s.scan_id:4d}  {ts:>10s}  {s.total_servers:7d}  "
            f"{s.successful:4d}  {s.failed:4d}  {s.avg_score:9.1f}"
        )

    return 0


# ── Diff command ──────────────────────────────────────────────


def _diff_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl diff <scan1> <scan2>`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.scan_diff import generate_scan_diff, render_scan_diff_markdown

    store = ScanHistoryStore()
    diff = generate_scan_diff(store, args.scan1, args.scan2)

    if "error" in diff:
        print(f"Error: {diff['error']}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        md = render_scan_diff_markdown(diff)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Diff report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Trend command ─────────────────────────────────────────────


def _trend_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl trend`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.trend_analyzer import TrendAnalyzer

    store = ScanHistoryStore()
    analyzer = TrendAnalyzer(store)

    if args.server:
        data = analyzer.analyze_server(args.server, last_n=args.last)
    else:
        data = analyzer.analyze(last_n=args.last)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        md = analyzer.render_markdown(data)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Trend report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Trend report command ─────────────────────────────────────


def _trend_report_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil crawl trend-report`."""
    from navil.crawler.scan_history import ScanHistoryStore
    from navil.report.trend_report import generate_trend_report, render_trend_report_markdown

    store = ScanHistoryStore()
    report = generate_trend_report(store, last_n=args.last)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        md = render_trend_report_markdown(report)
        if args.output:
            Path(args.output).write_text(md)
            print(f"Trend report written to: {args.output}")
        else:
            print(md)

    return 0


# ── Registration ──────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the crawl subcommand and its sub-subcommands."""
    crawl_parser = subparsers.add_parser("crawl", help="Crawl MCP registries and manage scans")
    crawl_sub = crawl_parser.add_subparsers(dest="crawl_command")

    # ── crawl registries ──────────────────────────────────────
    reg_parser = crawl_sub.add_parser("registries", help="Discover MCP servers from registries")
    reg_parser.add_argument(
        "--output",
        "-o",
        default="crawl_results",
        help="Output directory for crawl results (default: crawl_results/)",
    )
    reg_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max number of servers to discover (0 = unlimited)",
    )
    reg_parser.set_defaults(func=lambda cli, args: _crawl_registries_command(cli, args))

    # ── crawl schedule ────────────────────────────────────────
    sched_parser = crawl_sub.add_parser(
        "schedule",
        help="Set up recurring scan schedule",
    )
    sched_parser.add_argument(
        "--interval",
        choices=["hourly", "daily", "weekly", "monthly"],
        default="weekly",
        help="Scan interval (default: weekly)",
    )
    sched_parser.add_argument(
        "--mode",
        choices=["daemon", "async", "crontab", "systemd"],
        default="crontab",
        help="Output mode: daemon (sync loop), async (asyncio with Redis lock), "
        "crontab (print entry), systemd (print units)",
    )
    sched_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max servers per scan (0 = unlimited)",
    )
    sched_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per individual scan in seconds (default: 30)",
    )
    sched_parser.add_argument(
        "--webhook",
        default=None,
        help="Webhook URL to notify after each scan completes",
    )
    sched_parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL for distributed lock (e.g., redis://localhost:6379). "
        "Used with --mode async to prevent concurrent runs.",
    )
    sched_parser.add_argument(
        "--slack-webhook",
        default=None,
        help="Slack incoming webhook URL for error alerts",
    )
    sched_parser.add_argument(
        "--feed-to-cloud",
        action="store_true",
        help="Feed scan results to Navil cloud threat intel endpoint",
    )
    sched_parser.set_defaults(func=lambda cli, args: _schedule_command(cli, args))

    # ── crawl run-scan ────────────────────────────────────────
    run_parser = crawl_sub.add_parser(
        "run-scan",
        help="Run a one-off full scan pipeline (crawl + scan + store)",
    )
    run_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max servers to crawl (0 = unlimited)",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per scan in seconds (default: 30)",
    )
    run_parser.add_argument(
        "--webhook",
        default=None,
        help="Webhook URL to notify when scan completes",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Output full result as JSON",
    )
    run_parser.set_defaults(func=lambda cli, args: _run_scan_command(cli, args))

    # ── crawl history ─────────────────────────────────────────
    hist_parser = crawl_sub.add_parser(
        "history",
        help="Show scan history",
    )
    hist_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max number of scans to show (default: 20)",
    )
    hist_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    hist_parser.set_defaults(func=lambda cli, args: _history_command(cli, args))

    # ── crawl diff ────────────────────────────────────────────
    diff_parser = crawl_sub.add_parser(
        "diff",
        help="Compare two scan runs",
    )
    diff_parser.add_argument(
        "scan1",
        type=int,
        help="First (older) scan ID",
    )
    diff_parser.add_argument(
        "scan2",
        type=int,
        help="Second (newer) scan ID",
    )
    diff_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    diff_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for Markdown report",
    )
    diff_parser.set_defaults(func=lambda cli, args: _diff_command(cli, args))

    # ── crawl trend ───────────────────────────────────────────
    trend_parser = crawl_sub.add_parser(
        "trend",
        help="Show security trends over time",
    )
    trend_parser.add_argument(
        "--last",
        type=int,
        default=5,
        help="Number of recent scans to analyze (default: 5)",
    )
    trend_parser.add_argument(
        "--server",
        default=None,
        help="Show trend for a specific server",
    )
    trend_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    trend_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for Markdown report",
    )
    trend_parser.set_defaults(func=lambda cli, args: _trend_command(cli, args))

    # ── crawl trend-report ────────────────────────────────────
    tr_parser = crawl_sub.add_parser(
        "trend-report",
        help="Generate publishable monthly trend report",
    )
    tr_parser.add_argument(
        "--last",
        type=int,
        default=0,
        help="Number of recent scans to include (0 = all)",
    )
    tr_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of Markdown",
    )
    tr_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path for report",
    )
    tr_parser.set_defaults(func=lambda cli, args: _trend_report_command(cli, args))
