"""Trend analyzer — analyzes security trends across historical scans.

Reads from :class:`~navil.crawler.scan_history.ScanHistoryStore` and computes:
  - Average security score over time
  - Most improved / most degraded servers
  - New vulnerabilities appearing across the ecosystem
  - Vulnerability type distribution changes
  - New servers added / servers removed
  - Repeat offenders (servers that remain vulnerable across multiple scans)
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any

from navil.crawler.scan_history import ScanHistoryStore

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """Analyze security trends across multiple scan runs."""

    def __init__(self, store: ScanHistoryStore) -> None:
        self._store = store

    def analyze(self, last_n: int = 0) -> dict[str, Any]:
        """Run full trend analysis across recent scans.

        Args:
            last_n: Number of most recent scans to analyze (0 = all).

        Returns:
            Dict with trend data suitable for reporting or JSON export.
        """
        scans = self._store.get_scan_history(limit=last_n)

        if not scans:
            return self._empty_result("No scan history available.")

        if len(scans) == 1:
            return self._baseline_result(scans[0])

        # Reverse to chronological order (oldest first)
        scans = list(reversed(scans))

        result: dict[str, Any] = {
            "scan_count": len(scans),
            "date_range": {
                "first": scans[0].timestamp,
                "last": scans[-1].timestamp,
            },
        }

        # Score trend
        result["score_trend"] = [
            {
                "scan_id": s.scan_id,
                "timestamp": s.timestamp,
                "avg_score": round(s.avg_score, 1),
                "total_servers": s.total_servers,
                "successful": s.successful,
            }
            for s in scans
        ]

        # Compare first and last scans for overall movement
        first_scan = scans[0]
        last_scan = scans[-1]
        result["overall_score_change"] = round(last_scan.avg_score - first_scan.avg_score, 1)

        # Per-server analysis across scans
        result.update(self._analyze_server_trends(scans))

        # Vulnerability distribution changes
        result.update(self._analyze_vulnerability_trends(scans))

        # Repeat offenders
        result["repeat_offenders"] = self._find_repeat_offenders(scans)

        # Server churn (added / removed)
        result["server_churn"] = self._analyze_server_churn(scans)

        return result

    def analyze_server(self, server_name: str, last_n: int = 0) -> dict[str, Any]:
        """Analyze trend for a specific server.

        Args:
            server_name: The server to analyze.
            last_n: Max data points to include (0 = all).

        Returns:
            Dict with per-server trend data.
        """
        trend = self._store.get_server_trend(server_name, limit=last_n)

        if not trend:
            return {
                "server_name": server_name,
                "message": f"No history found for server '{server_name}'.",
                "data_points": 0,
            }

        scores = [t["score"] for t in trend if t["status"] == "success"]
        vuln_counts = [t["vulnerability_count"] for t in trend if t["status"] == "success"]

        result: dict[str, Any] = {
            "server_name": server_name,
            "data_points": len(trend),
            "history": trend,
        }

        if scores:
            result["current_score"] = scores[-1]
            result["score_change"] = scores[-1] - scores[0] if len(scores) > 1 else 0
            result["avg_score"] = round(sum(scores) / len(scores), 1)
            result["min_score"] = min(scores)
            result["max_score"] = max(scores)
        else:
            result["current_score"] = 0
            result["score_change"] = 0

        if vuln_counts:
            result["current_vuln_count"] = vuln_counts[-1]
            result["vuln_count_change"] = (
                vuln_counts[-1] - vuln_counts[0] if len(vuln_counts) > 1 else 0
            )
        else:
            result["current_vuln_count"] = 0
            result["vuln_count_change"] = 0

        # Determine trend direction
        if len(scores) >= 2:
            if scores[-1] > scores[0]:
                result["trend"] = "improving"
            elif scores[-1] < scores[0]:
                result["trend"] = "degrading"
            else:
                result["trend"] = "stable"
        else:
            result["trend"] = "baseline"

        return result

    # ── Internal helpers ──────────────────────────────────────

    def _empty_result(self, message: str) -> dict[str, Any]:
        return {"scan_count": 0, "message": message}

    def _baseline_result(self, scan: Any) -> dict[str, Any]:
        """Return a baseline result when only one scan exists."""
        results = self._store.get_scan_results(scan.scan_id)

        # Collect vulnerability types
        vuln_counter: Counter[str] = Counter()
        for r in results:
            vulns = json.loads(r.vulnerabilities_json)
            for v in vulns:
                vid = v.get("id", "UNKNOWN") if isinstance(v, dict) else str(v)
                vuln_counter[vid] += 1

        return {
            "scan_count": 1,
            "message": "Only one scan available — this is the baseline.",
            "baseline": {
                "scan_id": scan.scan_id,
                "timestamp": scan.timestamp,
                "total_servers": scan.total_servers,
                "successful": scan.successful,
                "avg_score": round(scan.avg_score, 1),
                "top_vulnerabilities": vuln_counter.most_common(10),
            },
        }

    def _analyze_server_trends(self, scans: list[Any]) -> dict[str, Any]:
        """Find most improved and most degraded servers."""
        if len(scans) < 2:
            return {"most_improved": [], "most_degraded": []}

        first_id = scans[0].scan_id
        last_id = scans[-1].scan_id

        first_results = {r.server_name: r for r in self._store.get_scan_results(first_id)}
        last_results = {r.server_name: r for r in self._store.get_scan_results(last_id)}

        common = set(first_results.keys()) & set(last_results.keys())

        changes: list[dict[str, Any]] = []
        for name in common:
            r1 = first_results[name]
            r2 = last_results[name]
            if r1.status == "success" and r2.status == "success":
                delta = r2.score - r1.score
                if delta != 0:
                    changes.append(
                        {
                            "server_name": name,
                            "old_score": r1.score,
                            "new_score": r2.score,
                            "delta": delta,
                        }
                    )

        # Sort by delta
        changes.sort(key=lambda x: x["delta"], reverse=True)

        return {
            "most_improved": changes[:10],
            "most_degraded": list(reversed(changes[-10:])) if len(changes) >= 1 else [],
        }

    def _analyze_vulnerability_trends(self, scans: list[Any]) -> dict[str, Any]:
        """Analyze how vulnerability types change across scans."""
        if len(scans) < 2:
            return {"vuln_distribution_change": {}}

        first_id = scans[0].scan_id
        last_id = scans[-1].scan_id

        def _count_vulns(scan_id: int) -> Counter[str]:
            counter: Counter[str] = Counter()
            for r in self._store.get_scan_results(scan_id):
                vulns = json.loads(r.vulnerabilities_json)
                for v in vulns:
                    vid = v.get("id", "UNKNOWN") if isinstance(v, dict) else str(v)
                    counter[vid] += 1
            return counter

        first_vulns = _count_vulns(first_id)
        last_vulns = _count_vulns(last_id)

        # Compute distribution change
        all_types = set(first_vulns.keys()) | set(last_vulns.keys())
        distribution_change: list[dict[str, Any]] = []
        for vtype in sorted(all_types):
            old_count = first_vulns.get(vtype, 0)
            new_count = last_vulns.get(vtype, 0)
            distribution_change.append(
                {
                    "vulnerability_type": vtype,
                    "old_count": old_count,
                    "new_count": new_count,
                    "delta": new_count - old_count,
                }
            )

        # New vulnerability types
        new_types = sorted(set(last_vulns.keys()) - set(first_vulns.keys()))

        # Top vulnerability types in latest scan
        top_vulns = last_vulns.most_common(10)

        return {
            "vuln_distribution_change": distribution_change,
            "new_vulnerability_types": new_types,
            "top_vulnerability_types": [{"type": t, "count": c} for t, c in top_vulns],
        }

    def _find_repeat_offenders(self, scans: list[Any]) -> list[dict[str, Any]]:
        """Find servers that remain vulnerable across multiple scans.

        A repeat offender is a server that has score < 50 in at least
        half of the scans it appears in.
        """
        # Track scores per server across all scans
        server_scores: dict[str, list[int]] = {}

        for scan in scans:
            for r in self._store.get_scan_results(scan.scan_id):
                if r.status == "success":
                    server_scores.setdefault(r.server_name, []).append(r.score)

        offenders: list[dict[str, Any]] = []
        for name, scores in server_scores.items():
            if len(scores) < 2:
                continue
            low_score_count = sum(1 for s in scores if s < 50)
            if low_score_count >= len(scores) // 2 + 1:  # majority of scans
                offenders.append(
                    {
                        "server_name": name,
                        "scans_appeared": len(scores),
                        "scans_below_50": low_score_count,
                        "avg_score": round(sum(scores) / len(scores), 1),
                        "latest_score": scores[-1],
                    }
                )

        offenders.sort(key=lambda x: x["avg_score"])
        return offenders

    def _analyze_server_churn(self, scans: list[Any]) -> dict[str, Any]:
        """Analyze servers added and removed between first and last scan."""
        if len(scans) < 2:
            return {"added": [], "removed": []}

        first_id = scans[0].scan_id
        last_id = scans[-1].scan_id

        first_names = {r.server_name for r in self._store.get_scan_results(first_id)}
        last_names = {r.server_name for r in self._store.get_scan_results(last_id)}

        return {
            "added": sorted(last_names - first_names),
            "removed": sorted(first_names - last_names),
        }

    # ── Markdown rendering ────────────────────────────────────

    def render_markdown(self, data: dict[str, Any]) -> str:
        """Render trend analysis data as a Markdown report."""
        lines: list[str] = []
        lines.append("# MCP Security Trend Analysis")
        lines.append("")

        if data.get("message"):
            lines.append(f"*{data['message']}*")
            lines.append("")

        if data.get("scan_count", 0) == 0:
            return "\n".join(lines)

        # Baseline mode
        if "baseline" in data:
            bl = data["baseline"]
            lines.append(f"**Baseline scan** (ID: {bl['scan_id']}, {bl['timestamp']})")
            lines.append("")
            lines.append(f"- Total servers: {bl['total_servers']}")
            lines.append(f"- Successful scans: {bl['successful']}")
            lines.append(f"- Average score: {bl['avg_score']}")
            lines.append("")
            if bl.get("top_vulnerabilities"):
                lines.append("### Top Vulnerability Types")
                lines.append("")
                lines.append("| Type | Count |")
                lines.append("|------|-------|")
                for vtype, count in bl["top_vulnerabilities"]:
                    lines.append(f"| {vtype} | {count} |")
                lines.append("")
            return "\n".join(lines)

        # Full trend report
        dr = data.get("date_range", {})
        lines.append(f"**Period:** {dr.get('first', '?')} to {dr.get('last', '?')}")
        lines.append(f"**Scans analyzed:** {data.get('scan_count', 0)}")
        lines.append(f"**Overall score change:** {data.get('overall_score_change', 0):+.1f}")
        lines.append("")

        # Score trend table
        score_trend = data.get("score_trend", [])
        if score_trend:
            lines.append("## Score Trend")
            lines.append("")
            lines.append("| Scan ID | Date | Avg Score | Servers |")
            lines.append("|---------|------|-----------|---------|")
            for st in score_trend:
                ts = st["timestamp"][:10] if len(st["timestamp"]) >= 10 else st["timestamp"]
                lines.append(
                    f"| {st['scan_id']} | {ts} | {st['avg_score']} | {st['total_servers']} |"
                )
            lines.append("")

        # Most improved
        improved = data.get("most_improved", [])
        if improved:
            lines.append("## Most Improved Servers")
            lines.append("")
            lines.append("| Server | Old Score | New Score | Change |")
            lines.append("|--------|-----------|-----------|--------|")
            for s in improved[:10]:
                lines.append(
                    f"| {s['server_name']} | {s['old_score']}"
                    f" | {s['new_score']} | {s['delta']:+d} |"
                )
            lines.append("")

        # Most degraded
        degraded = data.get("most_degraded", [])
        if degraded:
            lines.append("## Most Degraded Servers")
            lines.append("")
            lines.append("| Server | Old Score | New Score | Change |")
            lines.append("|--------|-----------|-----------|--------|")
            for s in degraded[:10]:
                lines.append(
                    f"| {s['server_name']} | {s['old_score']}"
                    f" | {s['new_score']} | {s['delta']:+d} |"
                )
            lines.append("")

        # Repeat offenders
        offenders = data.get("repeat_offenders", [])
        if offenders:
            lines.append("## Repeat Offenders")
            lines.append("")
            lines.append("*Servers scoring below 50 in a majority of scans.*")
            lines.append("")
            lines.append("| Server | Scans | Below 50 | Avg Score | Latest |")
            lines.append("|--------|-------|----------|-----------|--------|")
            for o in offenders[:15]:
                lines.append(
                    f"| {o['server_name']} | {o['scans_appeared']} | "
                    f"{o['scans_below_50']} | {o['avg_score']} | {o['latest_score']} |"
                )
            lines.append("")

        # New vulnerability types
        new_types = data.get("new_vulnerability_types", [])
        if new_types:
            lines.append("## New Vulnerability Types Detected")
            lines.append("")
            for vt in new_types:
                lines.append(f"- {vt}")
            lines.append("")

        # Top vulnerability types
        top_vulns = data.get("top_vulnerability_types", [])
        if top_vulns:
            lines.append("## Top Vulnerability Types (Latest Scan)")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for tv in top_vulns:
                lines.append(f"| {tv['type']} | {tv['count']} |")
            lines.append("")

        # Server churn
        churn = data.get("server_churn", {})
        added = churn.get("added", [])
        removed = churn.get("removed", [])
        if added or removed:
            lines.append("## Server Churn")
            lines.append("")
            if added:
                lines.append(f"**New servers ({len(added)}):** {', '.join(added[:20])}")
                if len(added) > 20:
                    lines.append(f"  *(and {len(added) - 20} more)*")
            if removed:
                lines.append(f"**Removed servers ({len(removed)}):** {', '.join(removed[:20])}")
                if len(removed) > 20:
                    lines.append(f"  *(and {len(removed) - 20} more)*")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by Navil Trend Analyzer*")
        lines.append("")

        return "\n".join(lines)
