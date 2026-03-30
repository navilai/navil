"""Risk scorer — assesses crawled MCP server scan results for threat potential.

Evaluates each scanned server on five dimensions:
  1. Package freshness (new packages are higher risk)
  2. Permission scope (broad permissions = higher risk)
  3. Vulnerability severity (CRITICAL/HIGH findings = higher risk)
  4. Supply chain indicators (npx, pip install, pipe-to-shell)
  5. Known-bad pattern matches (cross-reference with existing threat patterns)

Risk scores are normalized to [0.0, 1.0].  Scores above the configurable
threshold (default 0.7) are flagged for auto-promotion to the threat intel
channel.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Defaults ─────────────────────────────────────────────────

DEFAULT_HIGH_RISK_THRESHOLD = 0.7

# Weights for each risk dimension (must sum to 1.0)
_WEIGHTS = {
    "vulnerability_severity": 0.35,
    "permission_scope": 0.25,
    "supply_chain": 0.20,
    "known_bad_patterns": 0.15,
    "package_freshness": 0.05,
}

# Severity-to-weight mapping for vulnerability scoring
_SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.0,
}


# ── Data types ───────────────────────────────────────────────


@dataclass
class RiskBreakdown:
    """Per-dimension risk scores for a single server."""

    vulnerability_severity: float = 0.0
    permission_scope: float = 0.0
    supply_chain: float = 0.0
    known_bad_patterns: float = 0.0
    package_freshness: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass
class RiskAssessment:
    """Complete risk assessment for a scanned server."""

    server_name: str
    source: str
    url: str
    risk_score: float
    is_high_risk: bool
    breakdown: RiskBreakdown
    high_risk_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["breakdown"] = self.breakdown.to_dict()
        return d


# ── Scoring functions ────────────────────────────────────────


def _score_vulnerability_severity(scan_result: dict[str, Any]) -> float:
    """Score based on severity of detected vulnerabilities.

    Uses the worst-case severity and the count of CRITICAL/HIGH findings.
    """
    findings = scan_result.get("findings", [])
    if not findings:
        return 0.0

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Worst-case severity
    worst = 0.0
    for sev, _count in severity_counts.items():
        score = _SEVERITY_SCORES.get(sev, 0.0)
        worst = max(worst, score)

    # Density bonus: many CRITICAL/HIGH findings compound risk
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
    density_bonus = min(critical_high * 0.05, 0.2)  # cap at 0.2

    return min(worst + density_bonus, 1.0)


def _score_permission_scope(scan_result: dict[str, Any]) -> float:
    """Score based on excessive permissions detected in the scan."""
    findings = scan_result.get("findings", [])
    if not findings:
        return 0.0

    permission_ids = {
        "PERM-EXCESSIVE",
        "EXFIL-READ_SEND",
        "PRIV-EXEC",
        "CRED-API_KEY",
        "CRED-PASSWORD",
        "SENSITIVE-DATA",
    }
    matched = 0
    for f in findings:
        fid = f.get("id", "") if isinstance(f, dict) else ""
        if any(fid.startswith(pid) for pid in permission_ids):
            matched += 1

    if matched == 0:
        return 0.0
    # 1 match = 0.4, 2 = 0.6, 3+ = 0.8, 5+ = 1.0
    return min(0.2 + matched * 0.2, 1.0)


def _score_supply_chain(scan_result: dict[str, Any]) -> float:
    """Score based on supply chain risk indicators."""
    findings = scan_result.get("findings", [])
    if not findings:
        return 0.0

    supply_chain_ids = {"SUPPLY-CHAIN", "SOURCE-UNVERIFIED"}
    matched = 0
    for f in findings:
        fid = f.get("id", "") if isinstance(f, dict) else ""
        if any(fid.startswith(sid) for sid in supply_chain_ids):
            matched += 1

    if matched == 0:
        return 0.0
    return min(0.3 + matched * 0.2, 1.0)


def _score_known_bad_patterns(scan_result: dict[str, Any]) -> float:
    """Score based on known malicious pattern matches."""
    findings = scan_result.get("findings", [])
    if not findings:
        return 0.0

    malicious_ids = {"MALICIOUS", "PROMPT-INJECTION", "BACKDOOR"}
    matched = 0
    for f in findings:
        fid = f.get("id", "") if isinstance(f, dict) else ""
        if any(fid.startswith(mid) for mid in malicious_ids):
            matched += 1

    if matched == 0:
        return 0.0
    # Any malicious pattern match is very high risk
    return min(0.7 + matched * 0.1, 1.0)


def _score_package_freshness(scan_result: dict[str, Any]) -> float:
    """Score based on package freshness signals.

    Currently uses a heuristic: if the scan result contains metadata
    suggesting a new/unknown package, assign moderate risk.
    This is a placeholder for future npm/PyPI age checking.
    """
    # For now, check if the source is "npm" or "pypi" (registry packages
    # have higher baseline supply-chain risk than curated lists)
    return 0.0  # Conservative default; enhanced when we add API age checks


# ── Main scorer ──────────────────────────────────────────────


def score_server_risk(
    scan_record: dict[str, Any],
    *,
    threshold: float = DEFAULT_HIGH_RISK_THRESHOLD,
) -> RiskAssessment:
    """Calculate the composite risk score for a single scan record.

    Args:
        scan_record: A dict from the batch scanner JSONL output.
            Expected keys: server_name, source, url, status, scan.
        threshold: Risk score above which the server is flagged.

    Returns:
        RiskAssessment with composite score and per-dimension breakdown.
    """
    server_name = scan_record.get("server_name", "unknown")
    source = scan_record.get("source", "")
    url = scan_record.get("url", "")
    status = scan_record.get("status", "")

    # Non-successful scans get a moderate risk score (we can't assess them)
    if status != "success":
        return RiskAssessment(
            server_name=server_name,
            source=source,
            url=url,
            risk_score=0.3,
            is_high_risk=False,
            breakdown=RiskBreakdown(),
            high_risk_findings=["scan_failed"],
        )

    scan_result = scan_record.get("scan", {})

    # Calculate per-dimension scores
    breakdown = RiskBreakdown(
        vulnerability_severity=_score_vulnerability_severity(scan_result),
        permission_scope=_score_permission_scope(scan_result),
        supply_chain=_score_supply_chain(scan_result),
        known_bad_patterns=_score_known_bad_patterns(scan_result),
        package_freshness=_score_package_freshness(scan_result),
    )

    # Weighted composite
    composite = (
        breakdown.vulnerability_severity * _WEIGHTS["vulnerability_severity"]
        + breakdown.permission_scope * _WEIGHTS["permission_scope"]
        + breakdown.supply_chain * _WEIGHTS["supply_chain"]
        + breakdown.known_bad_patterns * _WEIGHTS["known_bad_patterns"]
        + breakdown.package_freshness * _WEIGHTS["package_freshness"]
    )

    # Collect high-risk finding IDs for the assessment
    high_risk_finding_ids: list[str] = []
    for f in scan_result.get("findings", []):
        if isinstance(f, dict):
            sev = f.get("severity", "INFO")
            if sev in ("CRITICAL", "HIGH"):
                high_risk_finding_ids.append(f.get("id", "UNKNOWN"))

    return RiskAssessment(
        server_name=server_name,
        source=source,
        url=url,
        risk_score=round(composite, 4),
        is_high_risk=composite >= threshold,
        breakdown=breakdown,
        high_risk_findings=high_risk_finding_ids,
    )


def score_batch(
    scan_records: list[dict[str, Any]],
    *,
    threshold: float = DEFAULT_HIGH_RISK_THRESHOLD,
) -> list[RiskAssessment]:
    """Score a batch of scan records and return assessments.

    Args:
        scan_records: List of dicts from batch scanner JSONL.
        threshold: Risk score threshold for high-risk flagging.

    Returns:
        List of RiskAssessment objects, sorted by risk_score descending.
    """
    assessments = [score_server_risk(record, threshold=threshold) for record in scan_records]
    assessments.sort(key=lambda a: a.risk_score, reverse=True)
    return assessments
