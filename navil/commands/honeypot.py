"""Honeypot CLI commands -- manage decoy MCP servers for threat intelligence."""

from __future__ import annotations

import argparse
import json
import sys


def _honeypot_start(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Start honeypot containers."""
    from navil.honeypot.deploy import HoneypotDeployer

    deployer = HoneypotDeployer(
        compose_file=args.compose_file if hasattr(args, "compose_file") else None,
    )

    profiles = args.profiles.split(",") if args.profiles else None
    result = deployer.start(profiles=profiles, log_path=args.log_path)

    if result["status"] == "error":
        print(f"\n  Error: {result['message']}\n", file=sys.stderr)
        return 1

    print(f"\n  Honeypot Started")
    print(f"  {'Profiles:':<20} {', '.join(result['profiles'])}")
    print(f"  {'Compose file:':<20} {result['compose_file']}")
    print(f"  {'Log directory:':<20} {result['log_dir']}")
    print()
    return 0


def _honeypot_stop(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Stop honeypot containers."""
    from navil.honeypot.deploy import HoneypotDeployer

    deployer = HoneypotDeployer(
        compose_file=args.compose_file if hasattr(args, "compose_file") else None,
    )

    profiles = args.profiles.split(",") if args.profiles else None
    result = deployer.stop(profiles=profiles)

    if result["status"] == "error":
        print(f"\n  Error: {result['message']}\n", file=sys.stderr)
        return 1

    print(f"\n  Honeypot Stopped: {', '.join(result['profiles'])}\n")
    return 0


def _honeypot_status(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show honeypot container status."""
    from navil.honeypot.deploy import HoneypotDeployer

    deployer = HoneypotDeployer(
        compose_file=args.compose_file if hasattr(args, "compose_file") else None,
    )

    result = deployer.status()

    if result["status"] == "error":
        print(f"\n  Error: {result['message']}\n", file=sys.stderr)
        return 1

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        if result.get("format") == "json":
            containers = result.get("containers", [])
            if not containers:
                print("\n  No honeypot containers running.\n")
                return 0
            print(f"\n  Honeypot Containers ({len(containers)} running):\n")
            for c in containers:
                name = c.get("Name", c.get("name", "?"))
                state = c.get("State", c.get("state", "?"))
                status_str = c.get("Status", c.get("status", "?"))
                print(f"    {name:<30} {state:<12} {status_str}")
            print()
        else:
            print(f"\n{result.get('output', 'No output')}\n")

    return 0


def _honeypot_logs(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show honeypot container logs."""
    from navil.honeypot.deploy import HoneypotDeployer

    deployer = HoneypotDeployer(
        compose_file=args.compose_file if hasattr(args, "compose_file") else None,
    )

    profiles = args.profiles.split(",") if args.profiles else None
    result = deployer.logs(profiles=profiles, tail=args.tail)

    if result["status"] == "error":
        print(f"\n  Error: {result['message']}\n", file=sys.stderr)
        return 1

    print(result.get("output", ""))
    return 0


def _honeypot_analyze(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Analyze collected honeypot data and extract signatures."""
    from navil.honeypot.collector import HoneypotCollector
    from navil.honeypot.signature_extractor import SignatureExtractor

    collector = HoneypotCollector()

    # Load data from JSONL file
    if not args.input:
        print("\n  Error: --input required (path to honeypot JSONL data)\n", file=sys.stderr)
        return 1

    try:
        loaded = collector.load_jsonl(args.input)
    except FileNotFoundError:
        print(f"\n  Error: file not found: {args.input}\n", file=sys.stderr)
        return 1

    if loaded == 0:
        print("\n  No records found in input file.\n")
        return 0

    extractor = SignatureExtractor(
        min_confidence=args.min_confidence,
    )
    entries = extractor.analyze(collector.records)

    if args.json_output:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        print(f"\n  Honeypot Signature Analysis")
        print(f"  {'Records analyzed:':<24} {loaded:>8}")
        print(f"  {'Signatures extracted:':<24} {len(entries):>8}")
        print(f"  {'Min confidence:':<24} {args.min_confidence:>8.2f}")
        print()

        if entries:
            print(f"  {'ID':<16} {'Type':<18} {'Severity':<10} {'Conf':<6} Value")
            sep = "-"
            print(f"  {sep * 16} {sep * 18} {sep * 10} {sep * 6} {sep * 30}")
            for e in entries:
                value_short = e.value[:30] + ("..." if len(e.value) > 30 else "")
                print(
                    f"  {e.pattern_id:<16} {e.pattern_type:<18} "
                    f"{e.severity:<10} {e.confidence:<6.2f} {value_short}"
                )
            print()

        # Timing analysis
        timing = extractor.extract_timing_patterns(collector.records)
        if timing:
            print(f"  Timing Patterns:")
            for ip, info in timing.items():
                periodic_mark = "[PERIODIC]" if info["is_periodic"] else ""
                print(
                    f"    {ip:<16} calls={info['call_count']:<4} "
                    f"mean={info['mean_interval_s']:.1f}s "
                    f"std={info['std_interval_s']:.1f}s {periodic_mark}"
                )
            print()

    # Export signatures to file if requested
    if args.output:
        from navil.blocklist import BlocklistManager

        mgr = BlocklistManager()
        mgr.merge(entries)
        mgr.save_to_file(args.output)
        print(f"  Signatures exported to {args.output}\n")

    return 0


def _honeypot_profiles(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """List available honeypot profiles."""
    from navil.honeypot.server import HoneypotMCPServer

    print("\n  Available Honeypot Profiles:\n")

    for profile_name in ["dev_tools", "cloud_creds", "db_admin"]:
        server = HoneypotMCPServer(profile=profile_name)
        tools = server.tool_names
        print(f"  {profile_name}")
        for tool in tools:
            desc = server.tools[tool].get("description", "")
            desc_short = desc[:60] + ("..." if len(desc) > 60 else "")
            print(f"    - {tool:<24} {desc_short}")
        print()

    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the honeypot subcommand group."""
    hp_parser = subparsers.add_parser(
        "honeypot",
        help="Manage honeypot decoy MCP servers for threat intelligence",
    )
    hp_sub = hp_parser.add_subparsers(dest="honeypot_command", help="Honeypot operation")

    # Common arguments
    def _add_common(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--compose-file",
            default=None,
            help="Path to docker-compose file (default: docker-compose.honeypot.yaml)",
        )

    # start
    start_parser = hp_sub.add_parser("start", help="Start honeypot containers")
    start_parser.add_argument(
        "--profiles",
        default=None,
        help="Comma-separated profiles to start (default: all). "
        "Options: dev_tools,cloud_creds,db_admin",
    )
    start_parser.add_argument(
        "--log-path",
        default=None,
        help="Override JSONL log path for the collector",
    )
    _add_common(start_parser)
    start_parser.set_defaults(func=_honeypot_start)

    # stop
    stop_parser = hp_sub.add_parser("stop", help="Stop honeypot containers")
    stop_parser.add_argument(
        "--profiles",
        default=None,
        help="Comma-separated profiles to stop (default: all)",
    )
    _add_common(stop_parser)
    stop_parser.set_defaults(func=_honeypot_stop)

    # status
    status_parser = hp_sub.add_parser("status", help="Show honeypot container status")
    status_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output JSON"
    )
    _add_common(status_parser)
    status_parser.set_defaults(func=_honeypot_status)

    # logs
    logs_parser = hp_sub.add_parser("logs", help="Show honeypot container logs")
    logs_parser.add_argument(
        "--profiles",
        default=None,
        help="Comma-separated profiles to get logs for",
    )
    logs_parser.add_argument(
        "--tail", type=int, default=50, help="Number of log lines to show"
    )
    _add_common(logs_parser)
    logs_parser.set_defaults(func=_honeypot_logs)

    # analyze
    analyze_parser = hp_sub.add_parser(
        "analyze", help="Analyze collected honeypot data and extract signatures"
    )
    analyze_parser.add_argument(
        "--input", "-i", required=True, help="Path to honeypot JSONL data file"
    )
    analyze_parser.add_argument(
        "--output", "-o", default=None, help="Export signatures to blocklist JSON file"
    )
    analyze_parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (default: 0.7)",
    )
    analyze_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output raw JSON"
    )
    analyze_parser.set_defaults(func=_honeypot_analyze)

    # profiles
    profiles_parser = hp_sub.add_parser("profiles", help="List available honeypot profiles")
    profiles_parser.set_defaults(func=_honeypot_profiles)

    # Default handler for bare "navil honeypot"
    hp_parser.set_defaults(func=lambda cli, args: (hp_parser.print_help(), 0)[1])
