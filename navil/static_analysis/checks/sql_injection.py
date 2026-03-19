"""Check #2: SQL injection detection.

Detects string concatenation and f-strings used in SQL queries
instead of parameterized queries.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    find_nodes_by_type,
    get_code_snippet,
    line_number,
    make_finding,
    node_text,
)
from navil.types import Finding

CHECK_ID = "SA-SQLI"

# SQL keywords that indicate a query context
_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b",
    re.IGNORECASE,
)

# Regex fallback: f-string or format string with SQL keywords
_PY_FSTRING_SQL = re.compile(
    r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{',
    re.IGNORECASE,
)
_PY_FORMAT_SQL = re.compile(
    r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["\']\.format\s*\(',
    re.IGNORECASE,
)
_PY_PERCENT_SQL = re.compile(
    r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*%s.*["\']\s*%\s*',
    re.IGNORECASE,
)
_PY_CONCAT_SQL = re.compile(
    r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["\']\s*\+',
    re.IGNORECASE,
)

# JS/TS: template literal with SQL
_JS_TEMPLATE_SQL = re.compile(
    r"`.*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$\{",
    re.IGNORECASE,
)
_JS_CONCAT_SQL = re.compile(
    r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["\']\s*\+',
    re.IGNORECASE,
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run SQL injection detection."""
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

    # Look for f-strings and concatenated strings containing SQL keywords
    for node_type in ("string", "concatenated_string", "binary_operator"):
        for node in find_nodes_by_type(ctx.root_node, node_type):
            text = node_text(node)
            if _SQL_KEYWORDS.search(text):
                # f-string with interpolation
                if node.type == "string" and text.startswith("f") and "{" in text:
                    snippet = get_code_snippet(ctx.lines, line_number(node))
                    findings.append(
                        make_finding(
                            check_id=CHECK_ID,
                            title="SQL injection via f-string",
                            description=(
                                "SQL query constructed using an f-string with "
                                "variable interpolation. This is vulnerable to "
                                "SQL injection attacks."
                            ),
                            severity="CRITICAL",
                            file_path=ctx.file_path,
                            line_no=line_number(node),
                            remediation=(
                                "Use parameterized queries: "
                                "cursor.execute('SELECT * FROM t WHERE id = ?', (id,))"
                            ),
                            evidence=snippet,
                        )
                    )

                # String concatenation with +
                if node.type == "binary_operator":
                    op = node.child_by_field_name("operator")
                    if op and node_text(op) == "+":
                        snippet = get_code_snippet(ctx.lines, line_number(node))
                        findings.append(
                            make_finding(
                                check_id=CHECK_ID,
                                title="SQL injection via string concatenation",
                                description=(
                                    "SQL query constructed using string concatenation. "
                                    "This is vulnerable to SQL injection attacks."
                                ),
                                severity="CRITICAL",
                                file_path=ctx.file_path,
                                line_no=line_number(node),
                                remediation=(
                                    "Use parameterized queries instead of string concatenation."
                                ),
                                evidence=snippet,
                            )
                        )

    # Check for .format() on SQL strings
    for node in find_nodes_by_type(ctx.root_node, "call"):
        func = node.child_by_field_name("function")
        if func and func.type == "attribute":
            attr = func.child_by_field_name("attribute")
            obj = func.child_by_field_name("object")
            if attr and node_text(attr) == "format" and obj:
                obj_text = node_text(obj)
                if _SQL_KEYWORDS.search(obj_text):
                    snippet = get_code_snippet(ctx.lines, line_number(node))
                    findings.append(
                        make_finding(
                            check_id=CHECK_ID,
                            title="SQL injection via str.format()",
                            description=(
                                "SQL query constructed using str.format(). "
                                "This is vulnerable to SQL injection attacks."
                            ),
                            severity="CRITICAL",
                            file_path=ctx.file_path,
                            line_no=line_number(node),
                            remediation=("Use parameterized queries instead of str.format()."),
                            evidence=snippet,
                        )
                    )

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    # Template literals with SQL keywords and interpolation
    for node in find_nodes_by_type(ctx.root_node, "template_string"):
        text = node_text(node)
        if _SQL_KEYWORDS.search(text) and "${" in text:
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="SQL injection via template literal",
                    description=(
                        "SQL query constructed using a template literal with "
                        "variable interpolation. This is vulnerable to SQL injection."
                    ),
                    severity="CRITICAL",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Use parameterized queries: db.query('SELECT * FROM t WHERE id = $1', [id])"
                    ),
                    evidence=snippet,
                )
            )

    # String concatenation with SQL
    for node in find_nodes_by_type(ctx.root_node, "binary_expression"):
        text = node_text(node)
        if _SQL_KEYWORDS.search(text):
            op = node.child_by_field_name("operator")
            if op and node_text(op) == "+":
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title="SQL injection via string concatenation",
                        description=(
                            "SQL query constructed via string concatenation. "
                            "Vulnerable to SQL injection."
                        ),
                        severity="CRITICAL",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation="Use parameterized queries.",
                        evidence=snippet,
                    )
                )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    if ctx.language == "python":
        patterns = [
            (_PY_FSTRING_SQL, "SQL injection via f-string"),
            (_PY_FORMAT_SQL, "SQL injection via str.format()"),
            (_PY_PERCENT_SQL, "SQL injection via % formatting"),
            (_PY_CONCAT_SQL, "SQL injection via string concatenation"),
        ]
    elif ctx.language in ("javascript", "typescript"):
        patterns = [
            (_JS_TEMPLATE_SQL, "SQL injection via template literal"),
            (_JS_CONCAT_SQL, "SQL injection via string concatenation"),
        ]
    else:
        return findings

    for pattern, title in patterns:
        for match in pattern.finditer(ctx.source_text):
            line_no = ctx.source_text[: match.start()].count("\n") + 1
            snippet = get_code_snippet(ctx.lines, line_no)
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title=title,
                    description=f"Detected {title.lower()} in source code.",
                    severity="CRITICAL",
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation="Use parameterized queries instead of string interpolation.",
                    evidence=snippet,
                    confidence=0.8,
                )
            )

    return findings
