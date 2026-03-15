"""Seed-database command -- populate anomaly detector with synthetic baselines."""

from __future__ import annotations

import argparse


def _seed_database(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    from navil.pentest import SCENARIOS as _SCENARIOS
    from navil.seed import seed_database

    # Handle --export: write scenario definitions to JSON and exit
    if args.export:
        import json as _json

        from navil.seed import export_scenarios

        scenarios = export_scenarios(include_expanded=True)
        output = _json.dumps(scenarios, indent=2)
        if args.export != "-":
            with open(args.export, "w") as fh:
                fh.write(output)
            print(f"Exported {len(scenarios)} scenario definitions to {args.export}")
        else:
            print(output)
        return 0

    scenario_count = len(_SCENARIOS) - 1
    mode = "full (builtin + expanded)" if args.full else "builtin"

    if not args.quiet:
        print(
            f"\n  Navil Seed Database"
            f"\n  Mode: {mode}"
            f"\n  Running {scenario_count}+ scenarios \u00d7 {args.iterations} iterations"
            f"\n  with mathematical fuzzing (Gaussian payload/rate/depth variance)\n"
        )

    stats = seed_database(
        iterations=args.iterations,
        detector=cli.anomaly_detector,
        show_progress=not args.quiet,
        mock_server=not args.no_server,
        full=args.full,
    )

    if args.json_output:
        import json as _json

        print(_json.dumps(stats.to_dict(), indent=2))
    else:
        print("\n  Seeding complete!")
        print(f"  {'Iterations:':<24} {stats.iterations:>10,}")
        print(f"  {'Total invocations:':<24} {stats.total_invocations:>10,}")
        print(f"  {'Total alerts fired:':<24} {stats.total_alerts:>10,}")
        print(f"  {'Elapsed time:':<24} {stats.elapsed_seconds:>9.1f}s")
        print()
        if stats.alerts_by_type:
            print("  Alerts by type:")
            for atype, count in sorted(
                stats.alerts_by_type.items(), key=lambda x: x[1], reverse=True
            ):
                print(f"    {atype:<28} {count:>8,}")
        print()

    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the seed-database subcommand."""
    seed_parser = subparsers.add_parser(
        "seed-database",
        help="Populate anomaly detector with synthetic SAFE-MCP attack baselines",
    )
    seed_parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=1000,
        help="Number of times to run each scenario (default: 1000)",
    )
    seed_parser.add_argument(
        "--full",
        action="store_true",
        help="Run all 50+ scenarios (original + parameterized from public_attacks.yaml)",
    )
    seed_parser.add_argument(
        "--export",
        nargs="?",
        const="-",
        default=None,
        metavar="FILE",
        help="Export all scenario definitions to JSON file (use - for stdout)",
    )
    seed_parser.add_argument(
        "--no-server",
        action="store_true",
        help="Skip starting the mock MCP server",
    )
    seed_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output raw JSON stats instead of formatted summary",
    )
    seed_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress bar",
    )
    seed_parser.set_defaults(func=_seed_database)
