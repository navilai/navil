"""Check #10: Insecure HTTP URLs.

Detects http:// URLs in production code (not test code) that should
be using https:// for secure communication.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    get_code_snippet,
    make_finding,
)
from navil.types import Finding

CHECK_ID = "SA-INSECURE-HTTP"

# Match http:// URLs but exclude localhost, 127.0.0.1, and common safe patterns
_HTTP_URL = re.compile(
    r"""(?:['"`])"""  # opening quote
    r"(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]|example\.com|example\.org)"
    r"[^\s'\"`,;)}\]]+)"  # the URL itself
    r"""(?:['"`])""",  # closing quote
)

# Test file indicators
_TEST_INDICATORS = re.compile(
    r"(?i)(test_|_test\.py|\.test\.|spec\.|\.spec\.|\btest\b|fixture|mock)",
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run insecure HTTP detection (always regex-based)."""
    findings: list[Finding] = []

    # Skip test files
    if _TEST_INDICATORS.search(ctx.file_path):
        return findings

    for match in _HTTP_URL.finditer(ctx.source_text):
        url = match.group(1)
        line_no = ctx.source_text[: match.start()].count("\n") + 1
        line_text = ctx.lines[line_no - 1] if line_no <= len(ctx.lines) else ""

        # Skip if in a comment
        stripped = line_text.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        snippet = get_code_snippet(ctx.lines, line_no)
        findings.append(
            make_finding(
                check_id=CHECK_ID,
                title="Insecure HTTP URL",
                description=(
                    f"HTTP URL found in source code: {url[:60]}... "
                    "HTTP transmits data in plaintext and is vulnerable "
                    "to man-in-the-middle attacks."
                ),
                severity="MEDIUM",
                file_path=ctx.file_path,
                line_no=line_no,
                remediation=(
                    "Replace http:// with https:// for all production URLs "
                    "to ensure encrypted communication."
                ),
                evidence=snippet,
                confidence=0.85,
            )
        )

    return findings
