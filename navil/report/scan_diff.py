"""Scan diff — compare two scan runs and produce a human-readable diff.

Generates both structured data (dict) and Markdown output showing:
  - New vulnerabilities found
  - Vulnerabilities fixed
  - Score changes per server
  - New servers in registry
  - Servers removed from registry
  - Summary statistics
"""

from __future__ import annotations

import logging
from typing import Any

from navil.crawler.scan_history import ScanHistoryStore

logger = logging.getLogger(__name__)


def generate_scan_diff(
    store: ScanHistoryStore,
    scan_id_1: int,
    scan_id_2: int,
) -> dict[str, Any]:
    """Generate a structured diff between two scan runs.

    Delegates to ``ScanHistoryStore.compare_scans()`` for the raw data,
    then enriches the result with additional analysis.

    Args:
        store: The scan history store to read from.
        scan_id_1: The older scan ID.
        scan_id_2: The newer scan ID.

    Returns:
        Dict with diff data. Contains an "error" key if either scan is missing.
    """
    diff = store.compare_scans(scan_id_1, scan_id_2)

    if "error" in diff:
        return diff

    # Enrich with score bucket analysis
    score_changes = diff.get("score_changes", [])
    if score_changes:
        big_improvements = [sc for sc in score_changes if sc["delta"] >= 20]
        big_regressions = [sc for sc in score_changes if sc["delta"] <= -20]
        diff["notable_improvements"] = big_improvements
        diff["notable_regressions"] = big_regressions

    return diff


def render_scan_diff_markdown(diff: dict[str, Any]) -> str:
    """Render a scan diff as Markdown.

    Args:
        diff: The diff dict from :func:`generate_scan_diff`.

    Returns:
        Markdown string.
    """
    if "error" in diff:
        return f"**Error:** {diff['error']}\n"

    lines: list[str] = []

    scan_1 = diff.get("scan_1", {})
    scan_2 = diff.get("scan_2", {})
    summary = diff.get("summary", {})

    lines.append("# Scan Comparison Report")
    lines.append("")
    lines.append(f"**Scan {scan_1.get('scan_id', '?')}** ({scan_1.get('timestamp', '?')[:10]})")
    lines.append("  vs  ")
    lines.append(f"**Scan {scan_2.get('scan_id', '?')}** ({scan_2.get('timestamp', '?')[:10]})")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Average score change | {summary.get('avg_score_change', 0):+.1f} |")
    lines.append(f"| Servers improved | {summary.get('servers_improved', 0)} |")
    lines.append(f"| Servers degraded | {summary.get('servers_degraded', 0)} |")
    lines.append(f"| Servers added | {summary.get('servers_added', 0)} |")
    lines.append(f"| Servers removed | {summary.get('servers_removed', 0)} |")
    lines.append(f"| New vulnerabilities | {summary.get('new_vulnerability_count', 0)} |")
    lines.append(f"| Fixed vulnerabilities | {summary.get('fixed_vulnerability_count', 0)} |")
    lines.append("")

    # Score changes
    score_changes = diff.get("score_changes", [])
    if score_changes:
        lines.append("## Score Changes")
        lines.append("")
        lines.append("| Server | Old Score | New Score | Change |")
        lines.append("|--------|-----------|-----------|--------|")
        # Sort by delta
        sorted_changes = sorted(score_changes, key=lambda x: x["delta"])
        for sc in sorted_changes:
            sign = "+" if sc["delta"] > 0 else ""
            lines.append(
                f"| {sc['server_name']} | {sc['old_score']} | "
                f"{sc['new_score']} | {sign}{sc['delta']} |"
            )
        lines.append("")

    # Notable improvements
    notable_improvements = diff.get("notable_improvements", [])
    if notable_improvements:
        lines.append("## Notable Improvements (score +20 or more)")
        lines.append("")
        for s in notable_improvements:
            lines.append(
                f"- **{s['server_name']}**: {s['old_score']} -> {s['new_score']} "
                f"(+{s['delta']})"
            )
        lines.append("")

    # Notable regressions
    notable_regressions = diff.get("notable_regressions", [])
    if notable_regressions:
        lines.append("## Notable Regressions (score -20 or more)")
        lines.append("")
        for s in notable_regressions:
            lines.append(
                f"- **{s['server_name']}**: {s['old_score']} -> {s['new_score']} "
                f"({s['delta']})"
            )
        lines.append("")

    # New servers
    new_servers = diff.get("new_servers", [])
    if new_servers:
        lines.append(f"## New Servers ({len(new_servers)})")
        lines.append("")
        for s in new_servers[:30]:
            lines.append(f"- {s}")
        if len(new_servers) > 30:
            lines.append(f"- *...and {len(new_servers) - 30} more*")
        lines.append("")

    # Removed servers
    removed_servers = diff.get("removed_servers", [])
    if removed_servers:
        lines.append(f"## Removed Servers ({len(removed_servers)})")
        lines.append("")
        for s in removed_servers[:30]:
            lines.append(f"- {s}")
        if len(removed_servers) > 30:
            lines.append(f"- *...and {len(removed_servers) - 30} more*")
        lines.append("")

    # New vulnerabilities
    new_vulns = diff.get("new_vulnerabilities", [])
    if new_vulns:
        lines.append(f"## New Vulnerabilities ({len(new_vulns)})")
        lines.append("")
        for v in new_vulns[:30]:
            lines.append(f"- {v}")
        if len(new_vulns) > 30:
            lines.append(f"- *...and {len(new_vulns) - 30} more*")
        lines.append("")

    # Fixed vulnerabilities
    fixed_vulns = diff.get("fixed_vulnerabilities", [])
    if fixed_vulns:
        lines.append(f"## Fixed Vulnerabilities ({len(fixed_vulns)})")
        lines.append("")
        for v in fixed_vulns[:30]:
            lines.append(f"- {v}")
        if len(fixed_vulns) > 30:
            lines.append(f"- *...and {len(fixed_vulns) - 30} more*")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Navil Scan Diff*")
    lines.append("")

    return "\n".join(lines)
