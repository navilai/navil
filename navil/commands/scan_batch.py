"""Scan-batch command -- bulk-scan crawled MCP server entries."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _scan_batch_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle `navil scan-batch <input_dir>`."""
    from navil.crawler.batch_scanner import scan_batch

    input_dir = Path(args.input_dir)
    if not input_dir.is_dir():
        print(f"Error: Not a directory: {input_dir}", file=sys.stderr)
        return 1

    output = args.output
    timeout = args.timeout

    print(f"Batch scanning crawl results in {input_dir}...")
    print(f"Output: {output} | Timeout per scan: {timeout}s")

    stats = scan_batch(input_dir, output, timeout_per_scan=timeout)

    print(f"\nBatch scan complete:")
    print(f"  Total:      {stats.total}")
    print(f"  Successful: {stats.successful}")
    print(f"  Failed:     {stats.failed}")
    print(f"  Timed out:  {stats.timed_out}")
    print(f"\nResults written to: {output}")

    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the scan-batch subcommand."""
    parser = subparsers.add_parser(
        "scan-batch",
        help="Batch-scan crawl results directory",
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing crawl result JSON files",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="scan_results.jsonl",
        help="Output JSONL file (default: scan_results.jsonl)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per scan in seconds (default: 30)",
    )
    parser.set_defaults(func=lambda cli, args: _scan_batch_command(cli, args))
