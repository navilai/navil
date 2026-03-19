"""Trend report generator — publishable monthly trend report.

"State of MCP Security — Month over Month"

Generates a comprehensive report combining:
  - Total servers scanned, average score
  - Top 10 most common vulnerability types
  - Notable improvements / regressions
  - New attack patterns detected
  - Comparison charts (text-based for CLI, data for dashboard)
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from navil.crawler.scan_history import ScanHistoryStore
from navil.report.trend_analyzer import TrendAnalyzer

logger = logging.getLogger(__name__)


def generate_trend_report(
    store: ScanHistoryStore,
    *,
    last_n: int = 0,
) -> dict[str, Any]:
    """Generate a comprehensive trend report.

    Args:
        store: The scan history store.
        last_n: Number of recent scans to include (0 = all).

    Returns:
        Dict with all report data, suitable for JSON export.
    """
    analyzer = TrendAnalyzer(store)
    trend_data = analyzer.analyze(last_n=last_n)

    scans = store.get_scan_history(limit=last_n)
    if not scans:
        return {
            "report_type": "trend",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "message": "No scan history available.",
        }

    # Most recent scan for current state
    latest_scan = scans[0]  # scans are most-recent-first
    latest_results = store.get_scan_results(latest_scan.scan_id)

    # Current vulnerability landscape
    vuln_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    scores: list[int] = []

    for r in latest_results:
        if r.status == "success":
            scores.append(r.score)
            vulns = json.loads(r.vulnerabilities_json)
            for v in vulns:
                if isinstance(v, dict):
                    vuln_counter[v.get("id", "UNKNOWN")] += 1
                    severity_counter[v.get("risk_level", "UNKNOWN")] += 1

    # Score distribution
    score_buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for s in scores:
        if s <= 20:
            score_buckets["0-20"] += 1
        elif s <= 40:
            score_buckets["21-40"] += 1
        elif s <= 60:
            score_buckets["41-60"] += 1
        elif s <= 80:
            score_buckets["61-80"] += 1
        else:
            score_buckets["81-100"] += 1

    report: dict[str, Any] = {
        "report_type": "trend",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "latest_scan": {
            "scan_id": latest_scan.scan_id,
            "timestamp": latest_scan.timestamp,
            "total_servers": latest_scan.total_servers,
            "successful": latest_scan.successful,
            "avg_score": round(latest_scan.avg_score, 1),
        },
        "score_distribution": score_buckets,
        "top_vulnerabilities": [{"type": t, "count": c} for t, c in vuln_counter.most_common(10)],
        "severity_breakdown": dict(severity_counter),
        "trend_data": trend_data,
    }

    # If we have previous scans, compute month-over-month
    if len(scans) >= 2:
        previous_scan = scans[1]
        diff = store.compare_scans(previous_scan.scan_id, latest_scan.scan_id)
        report["month_over_month"] = {
            "previous_scan_id": previous_scan.scan_id,
            "avg_score_change": diff.get("summary", {}).get("avg_score_change", 0),
            "new_servers": len(diff.get("new_servers", [])),
            "removed_servers": len(diff.get("removed_servers", [])),
            "new_vulnerabilities": len(diff.get("new_vulnerabilities", [])),
            "fixed_vulnerabilities": len(diff.get("fixed_vulnerabilities", [])),
        }

    return report


def render_trend_report_markdown(report: dict[str, Any]) -> str:
    """Render a trend report as publishable Markdown.

    Args:
        report: The report dict from :func:`generate_trend_report`.

    Returns:
        Markdown string.
    """
    lines: list[str] = []

    generated = report.get("generated_at", "")
    date_str = generated[:10] if len(generated) >= 10 else generated

    lines.append("# State of MCP Security -- Month over Month")
    lines.append("")
    lines.append(f"*Report generated on {date_str} by Navil*")
    lines.append("")

    if report.get("message"):
        lines.append(f"_{report['message']}_")
        lines.append("")
        return "\n".join(lines)

    # Latest scan summary
    latest = report.get("latest_scan", {})
    lines.append("## Current State")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total servers scanned | {latest.get('total_servers', 0)} |")
    lines.append(f"| Successful scans | {latest.get('successful', 0)} |")
    lines.append(f"| Average security score | {latest.get('avg_score', 0)} / 100 |")
    lines.append(f"| Scan date | {latest.get('timestamp', '?')[:10]} |")
    lines.append("")

    # Month over month
    mom = report.get("month_over_month")
    if mom:
        lines.append("## Month-over-Month Changes")
        lines.append("")
        asc = mom.get("avg_score_change", 0)
        direction = "improved" if asc > 0 else "declined" if asc < 0 else "unchanged"
        lines.append(f"- Average score **{direction}** by {abs(asc):.1f} points")
        lines.append(f"- {mom.get('new_servers', 0)} new servers added to registry")
        lines.append(f"- {mom.get('removed_servers', 0)} servers removed")
        lines.append(f"- {mom.get('new_vulnerabilities', 0)} new vulnerabilities detected")
        lines.append(f"- {mom.get('fixed_vulnerabilities', 0)} vulnerabilities fixed")
        lines.append("")

    # Score distribution
    dist = report.get("score_distribution", {})
    if dist:
        lines.append("## Score Distribution")
        lines.append("")
        lines.append("```")
        max_count = max(dist.values()) if dist.values() else 1
        for bucket, count in dist.items():
            bar_len = int((count / max(max_count, 1)) * 40)
            bar = "#" * bar_len
            lines.append(f"  {bucket:>6s} | {bar:<40s} {count}")
        lines.append("```")
        lines.append("")

    # Top vulnerabilities
    top_vulns = report.get("top_vulnerabilities", [])
    if top_vulns:
        lines.append("## Top 10 Most Common Vulnerability Types")
        lines.append("")
        lines.append("| Rank | Vulnerability | Count |")
        lines.append("|------|--------------|-------|")
        for i, tv in enumerate(top_vulns[:10], 1):
            lines.append(f"| {i} | {tv['type']} | {tv['count']} |")
        lines.append("")

    # Severity breakdown
    severity = report.get("severity_breakdown", {})
    if severity:
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity:
                lines.append(f"| {sev} | {severity[sev]} |")
        lines.append("")

    # Trend data highlights
    trend = report.get("trend_data", {})

    # Most improved
    improved = trend.get("most_improved", [])
    if improved:
        lines.append("## Notable Improvements")
        lines.append("")
        lines.append("| Server | Previous | Current | Change |")
        lines.append("|--------|----------|---------|--------|")
        for s in improved[:5]:
            lines.append(
                f"| {s['server_name']} | {s['old_score']} | " f"{s['new_score']} | +{s['delta']} |"
            )
        lines.append("")

    # Most degraded
    degraded = trend.get("most_degraded", [])
    if degraded:
        lines.append("## Notable Regressions")
        lines.append("")
        lines.append("| Server | Previous | Current | Change |")
        lines.append("|--------|----------|---------|--------|")
        for s in degraded[:5]:
            lines.append(
                f"| {s['server_name']} | {s['old_score']} | " f"{s['new_score']} | {s['delta']} |"
            )
        lines.append("")

    # Repeat offenders
    offenders = trend.get("repeat_offenders", [])
    if offenders:
        lines.append("## Repeat Offenders")
        lines.append("")
        lines.append("*Servers consistently scoring below 50 across multiple scans.*")
        lines.append("")
        lines.append("| Server | Avg Score | Latest Score | Scans Below 50 |")
        lines.append("|--------|-----------|-------------|----------------|")
        for o in offenders[:10]:
            lines.append(
                f"| {o['server_name']} | {o['avg_score']} | "
                f"{o['latest_score']} | {o['scans_below_50']}/{o['scans_appeared']} |"
            )
        lines.append("")

    # New vulnerability types
    new_types = trend.get("new_vulnerability_types", [])
    if new_types:
        lines.append("## New Attack Patterns Detected")
        lines.append("")
        lines.append("The following vulnerability types appeared for the first time:")
        lines.append("")
        for vt in new_types:
            lines.append(f"- `{vt}`")
        lines.append("")

    # Score trend chart (text-based)
    score_trend = trend.get("score_trend", [])
    if len(score_trend) >= 2:
        lines.append("## Score Trend")
        lines.append("")
        lines.append("```")
        max_score = 100
        for st in score_trend:
            ts = st["timestamp"][:10] if len(st["timestamp"]) >= 10 else st["timestamp"]
            bar_len = int((st["avg_score"] / max_score) * 40)
            bar = "#" * bar_len
            lines.append(f"  {ts} | {bar:<40s} {st['avg_score']:.1f}")
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Report generated by [Navil](https://github.com/ivanlkf/navil) -- ")
    lines.append("Supply Chain Security for MCP Servers*")
    lines.append("")

    return "\n".join(lines)
