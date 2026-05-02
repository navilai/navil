"""Renders an AuditReport to Markdown and JSON.

The Markdown output is the draft of the "State of MCP Security"
publication.  JSON is the structured data file for future charting.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from navil.report.dep_auditor import AuditedPackage, AuditReport

_SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "NONE": "✅",
    "UNKNOWN": "⚪",
}


def render_markdown(report: AuditReport) -> str:
    lines: list[str] = []
    a = lines.append

    pct_vuln = (report.packages_with_vulns / max(report.packages_audited, 1)) * 100

    a("# The Security Surface of the Agent-Readable Web")
    a(f"> State of MCP Security — {_fmt_date(report.generated_at)}")
    a("")
    a("**Navil** scanned the top MCP server packages across npm and PyPI,")
    a("cross-referenced every dependency against the OSV vulnerability database,")
    a("and mapped findings to the SAFE-MCP threat taxonomy.")
    a("")
    a("---")
    a("")
    a("## Executive Summary")
    a("")
    a(f"- **{report.packages_audited}** MCP packages audited ({', '.join(report.ecosystems)})")
    cve_pct = f"{pct_vuln:.0f}%"
    a(f"- **{report.packages_with_vulns}** ({cve_pct}) contain at least one known CVE")
    a(f"- **{report.total_cves}** total vulnerability instances found")
    sev_line = (
        f"- Severity: {report.critical_count} critical · {report.high_count} high"
        f" · {report.medium_count} medium · {report.low_count} low"
    )
    a(sev_line)
    a("")
    if report.tactic_exposure:
        top_tactic = max(report.tactic_exposure, key=report.tactic_exposure.get)  # type: ignore[arg-type]
        a(
            f"The most-exposed attack surface is **{top_tactic}**, affecting "
            f"{report.tactic_exposure[top_tactic]} packages."
        )
    a("")
    a("---")
    a("")
    a("## Methodology")
    a("")
    a(
        "1. **Discovery** — queried the npm registry for packages with `mcp-server` keyword "
        "and PyPI's simple index for packages matching `mcp`.  No manual curation."
    )
    a(
        "2. **Dependency resolution** — fetched each package's published `package.json` / "
        "`requires_dist` and extracted direct + first-level transitive dependencies."
    )
    a(
        "3. **CVE lookup** — batch-queried [OSV.dev](https://osv.dev) (the open vulnerability "
        "database aggregating NVD, GitHub Advisory, and others) for each package@version pair."
    )
    a(
        "4. **Tactic mapping** — matched CVE summaries and details against keyword sets derived "
        "from the [SAFE-MCP threat taxonomy](https://safe-mcp.org) to assign each finding to "
        "one or more attack tactic categories."
    )
    a("")
    a(
        "Limitations: version detection uses the latest published version of each package. "
        "Pinned or older deployments may have different (higher) exposure.  Transitive depth "
        "is capped at one level; deeper trees may surface additional CVEs."
    )
    a("")
    a("---")
    a("")
    a("## Findings by SAFE-MCP Tactic")
    a("")
    a("| Attack Tactic | Affected Packages | % of Audited |")
    a("|---|---|---|")
    for tactic, count in sorted(report.tactic_exposure.items(), key=lambda x: -x[1]):
        pct = (count / max(report.packages_audited, 1)) * 100
        a(f"| {tactic} | {count} | {pct:.1f}% |")
    a("")
    a("---")
    a("")
    a("## Most Common Vulnerable Dependencies")
    a("")
    a(
        "The following packages appeared as dependencies across multiple MCP servers "
        "and carried known CVEs — meaning a single upstream fix would reduce exposure "
        "across the entire ecosystem."
    )
    a("")
    a("| Dependency | MCP Packages Affected |")
    a("|---|---|")
    for dep in report.top_vulnerable_deps[:15]:
        a(f"| `{dep['name']}` | {dep['affected_packages']} |")
    a("")
    a("---")
    a("")
    a("## Package-Level Findings")
    a("")
    a("Packages with at least one high or critical severity CVE:")
    a("")

    high_risk = [p for p in report.packages if p.max_severity in ("CRITICAL", "HIGH")]
    high_risk.sort(key=lambda p: (-p.total_cves, p.name))

    for pkg in high_risk[:30]:
        icon = _SEV_EMOJI.get(pkg.max_severity, "⚪")
        a(f"### {icon} `{pkg.name}` v{pkg.version} ({pkg.ecosystem})")
        if pkg.description:
            a(f"_{pkg.description}_")
            a("")
        a(f"- **CVEs found:** {pkg.total_cves} ({pkg.max_severity} max severity)")
        if pkg.github_url:
            a(f"- **Source:** {pkg.github_url}")
        if pkg.tactic_exposure:
            tactics_str = ", ".join(sorted(pkg.tactic_exposure.keys()))
            a(f"- **Exposed tactics:** {tactics_str}")
        a("")
        # List direct package CVEs
        for vuln in pkg.vulns[:5]:
            icon2 = _SEV_EMOJI.get(vuln.severity, "⚪")
            a(f"  - {icon2} `{vuln.id}` ({vuln.severity}) — {vuln.summary[:120]}")
        # List dep CVEs (grouped)
        for dep_name, vulns in list(pkg.dep_vulns.items())[:5]:
            for vuln in vulns[:3]:
                icon2 = _SEV_EMOJI.get(vuln.severity, "⚪")
                short = vuln.summary[:80]
                a(f"  - {icon2} `{vuln.id}` via `{dep_name}` ({vuln.severity}) — {short}")
        a("")

    a("---")
    a("")
    a("## What This Means for Teams Running MCP Servers")
    a("")
    a("**For platform teams:** The findings show that MCP servers carry the same")
    a("supply-chain risk as any other Node/Python service — with one additional")
    a("dimension: an autonomous agent calling a vulnerable MCP server can be")
    a("manipulated into exfiltrating data, escalating privileges, or executing")
    a("arbitrary code through a compromised tool response, with no human reviewing")
    a("the interaction in real time.")
    a("")
    a("**For security teams:** Standard SCA tools will flag these CVEs at the")
    a("package level.  The gap is at the *runtime layer*: knowing which agents")
    a("can reach which servers, and enforcing policy on every tool call, not just")
    a("at deploy time.")
    a("")
    a("**For MCP server authors:** The most actionable step is keeping")
    a("dependencies pinned and running `npm audit` / `pip-audit` in CI.")
    a("The second most actionable step is scoping your server's tool list to")
    a("the minimum required — reducing the blast radius if a dependency is")
    a("compromised.")
    a("")
    a("---")
    a("")
    a("## About This Report")
    a("")
    a("Generated by [Navil](https://navil.ai) — production governance for AI agents.")
    a("Data from [OSV.dev](https://osv.dev) and [SAFE-MCP](https://safe-mcp.org).")
    a(f"Scan completed {_fmt_date(report.generated_at)} UTC.")
    a("")
    a("Report data available as structured JSON.")
    a("Methodology and raw data available on request.")

    return "\n".join(lines)


def render_json(report: AuditReport) -> str:
    """Render the report as structured JSON for archiving / charting."""

    def _pkg_dict(pkg: AuditedPackage) -> dict[str, Any]:
        return {
            "name": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "description": pkg.description,
            "github_url": pkg.github_url,
            "total_cves": pkg.total_cves,
            "max_severity": pkg.max_severity,
            "tactic_exposure": {t: ids for t, ids in pkg.tactic_exposure.items()},
            "direct_vulns": [
                {"id": v.id, "severity": v.severity, "summary": v.summary[:200]} for v in pkg.vulns
            ],
            "dep_vulns": {
                dep: [{"id": v.id, "severity": v.severity, "summary": v.summary[:200]} for v in vs]
                for dep, vs in pkg.dep_vulns.items()
            },
        }

    data: dict[str, Any] = {
        "generated_at": report.generated_at,
        "ecosystems": report.ecosystems,
        "summary": {
            "packages_audited": report.packages_audited,
            "packages_with_vulns": report.packages_with_vulns,
            "total_cves": report.total_cves,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
        },
        "tactic_exposure": report.tactic_exposure,
        "top_vulnerable_deps": report.top_vulnerable_deps,
        "packages": [_pkg_dict(p) for p in report.packages],
    }
    return json.dumps(data, indent=2)


def _fmt_date(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%B %d, %Y")
    except Exception:
        return iso
