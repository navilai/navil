"""Check #4: Hardcoded secrets detection.

Detects API keys, passwords, tokens, and other secrets hardcoded in source code.
Complements the config scanner's credential detection.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    make_finding,
)
from navil.types import Finding

CHECK_ID_PREFIX = "SA-SECRET"

# Patterns for detecting hardcoded secrets (regex-based, language-agnostic)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "AWS-KEY",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        "AWS Access Key ID",
    ),
    (
        "PRIVATE-KEY",
        re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"),
        "Private key",
    ),
    (
        "JWT",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."),
        "JSON Web Token",
    ),
    (
        "GITHUB-TOKEN",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "GitHub token",
    ),
    (
        "SLACK-TOKEN",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "Slack token",
    ),
    (
        "GENERIC-API-KEY",
        re.compile(
            r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]"""
        ),
        "API key",
    ),
    (
        "GENERIC-PASSWORD",
        re.compile(
            r"""(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['"]([^\s'"]{8,})['"]"""
        ),
        "Hardcoded password",
    ),
    (
        "GENERIC-TOKEN",
        re.compile(
            r"""(?i)(?:secret|token|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{20,})['"]"""
        ),
        "Hardcoded token/secret",
    ),
    (
        "CONNECTION-STRING",
        re.compile(
            r"""(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'"]{10,}"""
        ),
        "Database connection string with credentials",
    ),
]

# Lines that are likely not real secrets (common false-positive patterns)
_FALSE_POSITIVE_PATTERNS = re.compile(
    r"(?i)(example|placeholder|your[_-]?|changeme|xxx|dummy|test|fake|sample|TODO|FIXME"
    r"|replace[_-]?with|insert[_-]?your|<[^>]+>|\$\{|\{\{)",
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run hardcoded secrets detection (always regex-based)."""
    findings: list[Finding] = []

    for secret_type, pattern, label in _SECRET_PATTERNS:
        for match in pattern.finditer(ctx.source_text):
            matched_text = match.group(0)

            # Skip false positives
            if _FALSE_POSITIVE_PATTERNS.search(matched_text):
                continue

            # Skip if inside a comment
            line_no = ctx.source_text[: match.start()].count("\n") + 1
            line_text = ctx.lines[line_no - 1] if line_no <= len(ctx.lines) else ""
            stripped = line_text.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Redact the secret in evidence
            if len(matched_text) > 16:
                redacted = matched_text[:8] + "..." + matched_text[-4:]
            else:
                redacted = "***"

            findings.append(
                make_finding(
                    check_id=f"{CHECK_ID_PREFIX}-{secret_type}",
                    title=f"Hardcoded {label} detected",
                    description=(
                        f"A {label.lower()} appears to be hardcoded in source code. "
                        "Hardcoded secrets can be extracted from version control "
                        "history and are a major credential leakage risk."
                    ),
                    severity="CRITICAL",
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation=(
                        "Move secrets to environment variables or a secrets manager "
                        "(e.g., AWS Secrets Manager, HashiCorp Vault). Never commit "
                        "secrets to source control."
                    ),
                    evidence=f"Detected {label}: {redacted}",
                )
            )

    return findings
