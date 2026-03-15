"""Check #9: Sensitive data in logs.

Detects logging statements that include passwords, tokens, keys,
or other sensitive data that should not appear in log output.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    find_nodes_by_type,
    get_code_snippet,
    is_call_to,
    line_number,
    make_finding,
    node_text,
)
from navil.types import Finding

CHECK_ID = "SA-SENSITIVE-LOG"

# Sensitive variable name patterns
_SENSITIVE_NAMES = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey"
    r"|auth[_-]?token|access[_-]?token|private[_-]?key|credentials?"
    r"|session[_-]?id|cookie|bearer|authorization)",
)

# Regex fallback: logging/print with sensitive variable names
_PY_LOG_SENSITIVE = re.compile(
    r"(?:logging\.(?:info|debug|warning|error|critical)|logger\.(?:info|debug|warning|error|critical)|print)\s*\("
    r"[^)]*(?:password|passwd|secret|token|api_key|apikey|private_key|credentials?)",
    re.IGNORECASE,
)
_JS_LOG_SENSITIVE = re.compile(
    r"console\.(?:log|info|warn|error|debug)\s*\("
    r"[^)]*(?:password|passwd|secret|token|apiKey|api_key|privateKey|credentials?)",
    re.IGNORECASE,
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run sensitive data in logs detection."""
    if ctx.use_tree_sitter:
        return _check_tree_sitter(ctx)
    return _check_regex(ctx)


def _check_tree_sitter(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    if ctx.language == "python":
        findings.extend(_check_python_ts(ctx))
    elif ctx.language in ("javascript", "typescript"):
        findings.extend(_check_js_ts(ctx))

    return findings


def _check_python_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    # Python logging/print functions to check
    log_targets = [
        ("logging", "info"),
        ("logging", "debug"),
        ("logging", "warning"),
        ("logging", "error"),
        ("logging", "critical"),
        ("logger", "info"),
        ("logger", "debug"),
        ("logger", "warning"),
        ("logger", "error"),
        ("logger", "critical"),
        (None, "print"),
    ]

    call_nodes = find_nodes_by_type(ctx.root_node, "call")

    for node in call_nodes:
        for module, method in log_targets:
            if not is_call_to(node, module, method):
                continue

            # Check arguments for sensitive variable names
            args = node.child_by_field_name("arguments")
            if args is None:
                continue

            args_text = node_text(args)
            if _SENSITIVE_NAMES.search(args_text):
                snippet = get_code_snippet(ctx.lines, line_number(node))
                log_func = f"{module}.{method}" if module else method
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title="Sensitive data in log output",
                        description=(
                            f"Logging call {log_func}() appears to include "
                            "sensitive data (passwords, tokens, keys). "
                            "This can leak credentials in log files."
                        ),
                        severity="HIGH",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Remove sensitive data from log statements. "
                            "Log only non-sensitive identifiers or redacted values. "
                            "Use structured logging with sensitive field masking."
                        ),
                        evidence=snippet,
                        confidence=0.75,
                    )
                )
                break  # One finding per call node

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    call_nodes = find_nodes_by_type(ctx.root_node, "call_expression")

    for node in call_nodes:
        func = node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            continue

        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if not obj or not prop:
            continue

        if node_text(obj) != "console":
            continue
        if node_text(prop) not in ("log", "info", "warn", "error", "debug"):
            continue

        # Check arguments for sensitive names
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        args_text = node_text(args)
        if _SENSITIVE_NAMES.search(args_text):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Sensitive data in console output",
                    description=(
                        "console.log() or similar appears to include "
                        "sensitive data. This can leak credentials."
                    ),
                    severity="HIGH",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Remove sensitive data from console output. "
                        "Use structured logging with field masking."
                    ),
                    evidence=snippet,
                    confidence=0.75,
                )
            )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    if ctx.language == "python":
        pattern = _PY_LOG_SENSITIVE
    elif ctx.language in ("javascript", "typescript"):
        pattern = _JS_LOG_SENSITIVE
    else:
        return findings

    for match in pattern.finditer(ctx.source_text):
        line_no = ctx.source_text[: match.start()].count("\n") + 1
        snippet = get_code_snippet(ctx.lines, line_no)
        findings.append(
            make_finding(
                check_id=CHECK_ID,
                title="Sensitive data in log output",
                description="Log statement may contain sensitive data.",
                severity="HIGH",
                file_path=ctx.file_path,
                line_no=line_no,
                remediation="Remove sensitive data from log statements.",
                evidence=snippet,
                confidence=0.7,
            )
        )

    return findings
