"""navil rank-tracker — Google keyword ranking tracker for navil.ai.

Checks Google search rankings for a list of target keywords, records
positions to a CSV log, and prints a human-readable diff vs. the last run.

Usage:
    navil rank-tracker
    navil rank-tracker --domain navil.ai --top 30 --quiet
    navil rank-tracker --keywords "MCP security" "agent governance"
    navil rank-tracker --output /tmp/my_ranks.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import random
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_KEYWORDS = [
    "ai agent security",
    "MCP governance",
    "LLM tool call monitoring",
    "Claude Code security",
    "agent governance tool",
    "MCP server security",
    "production AI agent monitoring",
    "AI agent runtime protection",
    "best AI agent security tool",
    "MCP governance comparison",
    "MCP proxy",
    "agent policy engine",
    "MCP security 2026",
    "Claude Code MCP security",
    "open source agent governance",
]

DEFAULT_DOMAIN = "navil.ai"
DEFAULT_TOP = 30
DEFAULT_CSV = Path.home() / ".navil" / "rank_tracker.csv"
CSV_FIELDS = ["date", "keyword", "position", "url", "domain"]

_USERAGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------


def _search_with_googlesearch(keyword: str, num: int, domain: str) -> tuple[int | str, str]:
    """Use the googlesearch-python package to find domain rank for keyword."""
    from googlesearch import search  # type: ignore[import]

    for pos, url in enumerate(search(keyword, num_results=num, lang="en"), start=1):
        if domain in url:
            return pos, url
    return "not found", ""


def _search_with_requests(keyword: str, num: int, domain: str) -> tuple[int | str, str]:
    """Fallback: scrape Google HTML search results."""
    import re
    import urllib.parse

    import requests  # type: ignore[import]
    from requests.exceptions import RequestException

    query = urllib.parse.quote_plus(keyword)
    url = f"https://www.google.com/search?q={query}&num={num}&hl=en"
    headers = {"User-Agent": _USERAGENT}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except RequestException as exc:
        logger.warning("requests error for %r: %s", keyword, exc)
        return "not found", ""

    # Extract result URLs from href="/url?q=..." patterns
    raw_urls = re.findall(r'/url\?q=(https?://[^&"]+)', resp.text)
    seen: list[str] = []
    for raw in raw_urls:
        decoded = urllib.parse.unquote(raw)
        # Skip Google-internal URLs
        if "google.com" in decoded:
            continue
        if decoded not in seen:
            seen.append(decoded)

    for pos, result_url in enumerate(seen[:num], start=1):
        if domain in result_url:
            return pos, result_url

    return "not found", ""


def _check_keyword(
    keyword: str,
    domain: str,
    top: int,
    use_googlesearch: bool,
) -> tuple[int | str, str]:
    """Return (position, url) for domain in keyword results."""
    if use_googlesearch:
        return _search_with_googlesearch(keyword, top, domain)
    return _search_with_requests(keyword, top, domain)


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------


def _load_previous_run(csv_path: Path, domain: str) -> dict[str, tuple[str, str]]:
    """Return {keyword: (position, url)} for the most recent run in the CSV."""
    if not csv_path.exists():
        return {}

    rows_by_keyword: dict[str, list[dict]] = {}
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("domain") == domain:
                rows_by_keyword.setdefault(row["keyword"], []).append(row)

    result: dict[str, tuple[str, str]] = {}
    for kw, rows in rows_by_keyword.items():
        # Sort by date descending, pick latest
        rows.sort(key=lambda r: r["date"], reverse=True)
        latest = rows[0]
        result[kw] = (latest["position"], latest["url"])
    return result


def _append_results(csv_path: Path, rows: list[dict]) -> None:
    """Append result rows to the CSV, creating file/dir as needed."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _position_str(pos: int | str) -> str:
    return str(pos) if pos != "not found" else "—"


def _change_indicator(prev: str | None, curr: int | str) -> str:
    if prev is None:
        return "NEW"
    prev_int = None if prev == "not found" else int(prev)
    curr_int = None if curr == "not found" else int(curr)  # type: ignore[arg-type]
    if prev_int is None and curr_int is None:
        return "—"
    if prev_int is None:
        return "NEW"
    if curr_int is None:
        return "▼ lost"
    diff = prev_int - curr_int  # positive = moved up (lower rank number)
    if diff > 0:
        return f"▲ +{diff}"
    if diff < 0:
        return f"▼ {diff}"
    return "="


def _print_report(
    domain: str,
    keywords: list[str],
    top: int,
    results: list[dict],
    prev_run: dict[str, tuple[str, str]],
    quiet: bool,
) -> None:
    sep = "─" * 56
    print("\n  navil rank-tracker")
    print(f"  {sep}")
    print(f"  Domain    : {domain}")
    print(f"  Keywords  : {len(keywords)}")
    print(f"  Checking  : Google (top {top} results per keyword)")
    print()

    kw_col = 36
    pos_col = 10
    hdr = f"  {'Keyword':<{kw_col}} {'Position':>{pos_col}}   Change"
    print(hdr)
    print(f"  {sep}")

    for row in results:
        kw = row["keyword"]
        pos = row["position"]
        prev_pos = prev_run.get(kw, (None, ""))[0]
        change = _change_indicator(prev_pos, pos)

        if quiet and change == "=":
            continue  # suppress unchanged

        pos_display = _position_str(pos)
        print(f"  {kw:<{kw_col}} {pos_display:>{pos_col}}   {change}")

    print()


# ---------------------------------------------------------------------------
# Core command
# ---------------------------------------------------------------------------


def _rank_tracker_command(_cli: Any, args: argparse.Namespace) -> int:
    keywords: list[str] = args.keywords or DEFAULT_KEYWORDS
    domain: str = args.domain
    top: int = args.top
    quiet: bool = args.quiet
    csv_path = Path(args.output).expanduser()

    # Detect which search backend is available
    use_googlesearch = False
    try:
        import googlesearch  # type: ignore[import]  # noqa: F401

        use_googlesearch = True
    except ImportError:
        pass

    if not use_googlesearch:
        try:
            import requests  # type: ignore[import]  # noqa: F401
        except ImportError:
            print(
                "Error: neither googlesearch-python nor requests is installed.\n"
                "Install one with:\n"
                "  pip install googlesearch-python\n"
                "or:\n"
                "  pip install requests",
                file=sys.stderr,
            )
            return 1

    # Load previous run for diff
    prev_run = _load_previous_run(csv_path, domain)

    today = str(date.today())
    results: list[dict] = []

    if not quiet:
        backend = "googlesearch-python" if use_googlesearch else "requests (HTML scrape)"
        print(f"  Using backend: {backend}")

    for i, kw in enumerate(keywords):
        if not quiet:
            print(f"  Checking ({i + 1}/{len(keywords)}): {kw} ...", end="\r", flush=True)

        pos, url = _check_keyword(kw, domain, top, use_googlesearch)

        results.append(
            {
                "date": today,
                "keyword": kw,
                "position": pos,
                "url": url,
                "domain": domain,
            }
        )

        # Polite delay between requests
        if i < len(keywords) - 1:
            time.sleep(random.uniform(2, 3))

    if not quiet:
        # Clear the "Checking..." line
        print(" " * 60, end="\r")

    _append_results(csv_path, results)
    _print_report(domain, keywords, top, results, prev_run, quiet)
    print(f"  Results saved → {csv_path}")
    print()

    return 0


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def register(subparsers: argparse._SubParsersAction, _cli_class: Any) -> None:  # noqa: SLF001
    """Register the rank-tracker subcommand."""
    parser = subparsers.add_parser(
        "rank-tracker",
        help="Track Google keyword rankings for navil.ai and log positions to CSV.",
        description=__doc__,
    )
    parser.add_argument(
        "--keywords",
        nargs="+",
        metavar="KEYWORD",
        default=None,
        help="Keywords to check (default: built-in list of 15 target keywords).",
    )
    parser.add_argument(
        "--domain",
        default=DEFAULT_DOMAIN,
        metavar="DOMAIN",
        help=f"Domain to track rankings for (default: {DEFAULT_DOMAIN}).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP,
        metavar="N",
        help=f"Number of Google results to check per keyword (default: {DEFAULT_TOP}).",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_CSV),
        metavar="FILE",
        help=f"CSV file to append results to (default: {DEFAULT_CSV}).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print keywords where position changed or is new.",
    )
    parser.set_defaults(func=_rank_tracker_command)
