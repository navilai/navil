"""Blocklist CLI commands — manage threat signature patterns."""

from __future__ import annotations

import argparse
import json


def _blocklist_update(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Fetch and merge latest blocklist."""
    from navil.blocklist_updater import update_blocklist_sync

    result = update_blocklist_sync(
        redis_client=getattr(cli, "redis", None),
        file_path=None,
    )

    print(f"\n  Blocklist Update")
    print(f"  {'Patterns loaded:':<24} {result['loaded']:>8}")
    print(f"  {'Total patterns:':<24} {result['pattern_count']:>8}")
    print(f"  {'Version:':<24} {result['version']:>8}")
    print(f"  {'Saved to Redis:':<24} {'yes' if result['saved_to_redis'] else 'no':>8}")
    print()
    return 0


def _blocklist_list(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """List all loaded blocklist patterns."""
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    # Load blocklist
    loaded = 0
    if getattr(cli, "redis", None) is not None:
        loaded = mgr.load_from_redis()
    if loaded == 0:
        try:
            mgr.load_from_file()
        except FileNotFoundError:
            print("\n  No blocklist loaded. Run 'navil blocklist update' first.\n")
            return 1

    entries = mgr.entries

    if args.json_output:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        if not entries:
            print("\n  No patterns loaded.\n")
            return 0

        # Optional filter by type
        if args.type:
            entries = [e for e in entries if e.pattern_type == args.type]

        # Optional filter by severity
        if args.severity:
            entries = [e for e in entries if e.severity == args.severity.upper()]

        print(f"\n  Blocklist Patterns ({len(entries)} total):\n")
        for entry in entries:
            print(f"  [{entry.severity:<8}] {entry.pattern_id}")
            print(f"    Type:        {entry.pattern_type}")
            print(f"    Value:       {entry.value}")
            print(f"    Confidence:  {entry.confidence:.2f}")
            print(f"    Source:      {entry.source}")
            print(f"    Description: {entry.description}")
            print()

    return 0


def _blocklist_add(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Manually add a pattern to the blocklist."""
    from navil.blocklist import BlocklistEntry, BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    # Load existing blocklist first
    if getattr(cli, "redis", None) is not None:
        mgr.load_from_redis()
    else:
        try:
            mgr.load_from_file()
        except FileNotFoundError:
            pass  # Start fresh

    entry = BlocklistEntry(
        pattern_id=args.pattern_id,
        pattern_type=args.type,
        value=args.value,
        severity=args.severity.upper(),
        description=args.description or "",
        confidence=float(args.confidence),
        source="manual",
    )

    added = mgr.add_entry(entry)
    if not added:
        print(f"\n  Pattern {args.pattern_id} already exists with equal or higher confidence.\n")
        return 0

    # Push to Redis if available
    saved = False
    if getattr(cli, "redis", None) is not None:
        saved = mgr.save_to_redis()

    print(f"\n  Added pattern: {entry.pattern_id}")
    print(f"    Type:        {entry.pattern_type}")
    print(f"    Value:       {entry.value}")
    print(f"    Severity:    {entry.severity}")
    print(f"    Confidence:  {entry.confidence:.2f}")
    if saved:
        print(f"    Pushed to Redis (v{mgr.version})")
    print()
    return 0


def _blocklist_version(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show current blocklist version."""
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    # Try Redis first, then file
    loaded = 0
    if getattr(cli, "redis", None) is not None:
        loaded = mgr.load_from_redis()
    if loaded == 0:
        try:
            mgr.load_from_file()
        except FileNotFoundError:
            print("\n  No blocklist loaded. Run 'navil blocklist update' first.\n")
            return 1

    if args.json_output:
        print(json.dumps({"version": mgr.version, "pattern_count": mgr.pattern_count}))
    else:
        print(f"\n  Blocklist version: {mgr.version}")
        print(f"  Pattern count:     {mgr.pattern_count}")
        if mgr.last_update:
            print(f"  Last update:       {mgr.last_update[:19]}")
        print()
    return 0


def _blocklist_status(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show blocklist status."""
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    # Try Redis first, then file
    loaded = 0
    if getattr(cli, "redis", None) is not None:
        loaded = mgr.load_from_redis()
    if loaded == 0:
        try:
            mgr.load_from_file()
        except FileNotFoundError:
            print("\n  No blocklist loaded. Run 'navil blocklist update' first.\n")
            return 1

    status = mgr.status()

    if args.json_output:
        print(json.dumps(status, indent=2))
    else:
        print(f"\n  Blocklist Status")
        print(f"  {'Version:':<24} {status['version']:>8}")
        print(f"  {'Pattern count:':<24} {status['pattern_count']:>8}")
        print(f"  {'Last update:':<24} {status['last_update'][:19]:>24}")
        print()
        if status["by_type"]:
            print("  By type:")
            for ptype, count in sorted(status["by_type"].items()):
                print(f"    {ptype:<28} {count:>6}")
        if status["by_severity"]:
            print("  By severity:")
            for sev, count in sorted(status["by_severity"].items()):
                print(f"    {sev:<28} {count:>6}")
        print()

    return 0


def _blocklist_load(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Load blocklist from local JSON file."""
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    try:
        loaded = mgr.load_from_file(args.file)
    except FileNotFoundError:
        print(f"\n  Error: file not found: {args.file}\n")
        return 1
    except json.JSONDecodeError:
        print(f"\n  Error: invalid JSON in {args.file}\n")
        return 1

    # Optionally push to Redis
    saved = False
    if getattr(cli, "redis", None) is not None:
        saved = mgr.save_to_redis()

    print(f"\n  Loaded {loaded} patterns from {args.file}")
    if saved:
        print(f"  Pushed to Redis (v{mgr.version})")
    print()
    return 0


def _blocklist_search(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Search for matching blocklist entries."""
    from navil.blocklist import BlocklistManager

    mgr = BlocklistManager(redis_client=getattr(cli, "redis", None))

    # Load blocklist
    loaded = 0
    if getattr(cli, "redis", None) is not None:
        loaded = mgr.load_from_redis()
    if loaded == 0:
        try:
            mgr.load_from_file()
        except FileNotFoundError:
            print("\n  No blocklist loaded. Run 'navil blocklist update' first.\n")
            return 1

    results = mgr.search(args.pattern)

    if args.json_output:
        print(json.dumps([e.to_dict() for e in results], indent=2))
    else:
        if not results:
            print(f"\n  No matches for '{args.pattern}'\n")
            return 0

        print(f"\n  Found {len(results)} matching pattern(s):\n")
        for entry in results:
            print(f"  [{entry.severity}] {entry.pattern_id}")
            print(f"    Type:        {entry.pattern_type}")
            print(f"    Value:       {entry.value}")
            print(f"    Confidence:  {entry.confidence:.2f}")
            print(f"    Description: {entry.description}")
            print()

    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the blocklist subcommand group."""
    bl_parser = subparsers.add_parser(
        "blocklist",
        help="Manage threat signature blocklist",
    )
    bl_sub = bl_parser.add_subparsers(dest="blocklist_command", help="Blocklist operation")

    # update
    update_parser = bl_sub.add_parser("update", help="Fetch and merge latest blocklist")
    update_parser.set_defaults(func=_blocklist_update)

    # list
    list_parser = bl_sub.add_parser("list", help="List all loaded patterns")
    list_parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    list_parser.add_argument("--type", choices=["tool_name", "tool_sequence", "argument_pattern"],
                             help="Filter by pattern type")
    list_parser.add_argument("--severity", help="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)")
    list_parser.set_defaults(func=_blocklist_list)

    # add
    add_parser = bl_sub.add_parser("add", help="Manually add a pattern")
    add_parser.add_argument("pattern_id", help="Unique pattern identifier (e.g. BL-CUSTOM-001)")
    add_parser.add_argument("--type", required=True,
                            choices=["tool_name", "tool_sequence", "argument_pattern"],
                            help="Pattern type")
    add_parser.add_argument("--value", required=True, help="Pattern value (tool name, sequence, or regex)")
    add_parser.add_argument("--severity", default="HIGH",
                            choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            help="Severity level (default: HIGH)")
    add_parser.add_argument("--confidence", type=float, default=0.8,
                            help="Confidence score 0.0-1.0 (default: 0.8)")
    add_parser.add_argument("--description", default="", help="Description of the pattern")
    add_parser.set_defaults(func=_blocklist_add)

    # version
    version_parser = bl_sub.add_parser("version", help="Show current blocklist version")
    version_parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    version_parser.set_defaults(func=_blocklist_version)

    # status
    status_parser = bl_sub.add_parser("status", help="Show blocklist version and stats")
    status_parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    status_parser.set_defaults(func=_blocklist_status)

    # load
    load_parser = bl_sub.add_parser("load", help="Load blocklist from local JSON file")
    load_parser.add_argument("file", help="Path to blocklist JSON file")
    load_parser.set_defaults(func=_blocklist_load)

    # search
    search_parser = bl_sub.add_parser("search", help="Search for matching entries")
    search_parser.add_argument("pattern", help="Search pattern (matches ID, value, description)")
    search_parser.add_argument("--json", action="store_true", dest="json_output", help="Output JSON")
    search_parser.set_defaults(func=_blocklist_search)

    # Default handler for bare "navil blocklist"
    bl_parser.set_defaults(func=lambda cli, args: (bl_parser.print_help(), 0)[1])
