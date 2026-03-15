"""Check #6: Unsafe deserialization detection.

Detects dangerous deserialization patterns such as pickle, yaml.load()
without SafeLoader, and similar patterns. These are DETECTION TARGETS
for the security scanner -- not functions we use ourselves.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    call_has_keyword,
    find_nodes_by_type,
    get_code_snippet,
    is_call_to,
    line_number,
    make_finding,
)
from navil.types import Finding

CHECK_ID = "SA-DESERIALIZE"

# Regex fallback patterns for detecting dangerous deserialization in scanned code
_PY_UNSAFE_DESER = re.compile(
    r"(?:pickle|cPickle|shelve|marshal)\.(loads?|Unpickler)\s*\("
)
_PY_YAML_UNSAFE = re.compile(r"yaml\.(load|unsafe_load|full_load)\s*\(")


def run(ctx: SourceContext) -> list[Finding]:
    """Run unsafe deserialization detection."""
    if ctx.use_tree_sitter:
        return _check_tree_sitter(ctx)
    return _check_regex(ctx)


def _check_tree_sitter(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    if ctx.language == "python":
        findings.extend(_check_python_ts(ctx))

    return findings


def _check_python_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []
    call_nodes = find_nodes_by_type(ctx.root_node, "call")

    # Modules and methods that perform unsafe deserialization
    unsafe_targets = [
        ("pickle", "loads", "CRITICAL"),
        ("pickle", "load", "CRITICAL"),
        ("pickle", "Unpickler", "CRITICAL"),
        ("cPickle", "loads", "CRITICAL"),
        ("cPickle", "load", "CRITICAL"),
        ("shelve", "open", "HIGH"),
        ("marshal", "loads", "HIGH"),
        ("marshal", "load", "HIGH"),
    ]

    for node in call_nodes:
        for module, method, severity in unsafe_targets:
            if is_call_to(node, module, method):
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title=f"Unsafe deserialization: {module}.{method}()",
                        description=(
                            f"{module}.{method}() can execute arbitrary code during "
                            "deserialization. Never use with untrusted data."
                        ),
                        severity=severity,
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Use JSON or other safe serialization formats. "
                            "If the current format is required, restrict the "
                            "unpickler or use a safe loader."
                        ),
                        evidence=snippet,
                    )
                )

        # yaml.load() without SafeLoader
        if is_call_to(node, "yaml", "load"):
            has_safe = call_has_keyword(node, "Loader", "SafeLoader")
            has_safe_full = call_has_keyword(node, "Loader", "yaml.SafeLoader")
            if not has_safe and not has_safe_full:
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title="Unsafe YAML loading: yaml.load() without SafeLoader",
                        description=(
                            "yaml.load() without Loader=SafeLoader can execute "
                            "arbitrary Python code embedded in YAML data."
                        ),
                        severity="CRITICAL",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Use yaml.safe_load() or "
                            "yaml.load(data, Loader=SafeLoader)."
                        ),
                        evidence=snippet,
                    )
                )

        # yaml.unsafe_load / yaml.full_load
        for method in ("unsafe_load", "full_load"):
            if is_call_to(node, "yaml", method):
                snippet = get_code_snippet(ctx.lines, line_number(node))
                sev = "CRITICAL" if method == "unsafe_load" else "HIGH"
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title=f"Unsafe YAML loading: yaml.{method}()",
                        description=(
                            f"yaml.{method}() can execute arbitrary code. "
                            "Use yaml.safe_load() instead."
                        ),
                        severity=sev,
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation="Use yaml.safe_load() instead.",
                        evidence=snippet,
                    )
                )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    if ctx.language != "python":
        return findings

    for match in _PY_UNSAFE_DESER.finditer(ctx.source_text):
        line_no = ctx.source_text[: match.start()].count("\n") + 1
        snippet = get_code_snippet(ctx.lines, line_no)
        findings.append(
            make_finding(
                check_id=CHECK_ID,
                title="Unsafe deserialization detected",
                description="Dangerous deserialization pattern found in source code.",
                severity="CRITICAL",
                file_path=ctx.file_path,
                line_no=line_no,
                remediation="Use JSON instead for untrusted data.",
                evidence=snippet,
                confidence=0.85,
            )
        )

    for match in _PY_YAML_UNSAFE.finditer(ctx.source_text):
        # Quick check: if SafeLoader is nearby, skip
        region = ctx.source_text[match.start() : match.start() + 200]
        if "SafeLoader" in region:
            continue
        line_no = ctx.source_text[: match.start()].count("\n") + 1
        snippet = get_code_snippet(ctx.lines, line_no)
        findings.append(
            make_finding(
                check_id=CHECK_ID,
                title="Unsafe YAML loading",
                description="yaml.load() without SafeLoader detected.",
                severity="CRITICAL",
                file_path=ctx.file_path,
                line_no=line_no,
                remediation="Use yaml.safe_load() or specify Loader=SafeLoader.",
                evidence=snippet,
                confidence=0.85,
            )
        )

    return findings
