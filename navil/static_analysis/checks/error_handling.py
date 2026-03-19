"""Check #8: Missing or poor error handling.

Detects bare except: blocks and MCP tool handlers without
any error handling, which can leak sensitive information or
cause unexpected behavior.
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

CHECK_ID = "SA-ERROR-HANDLING"

# Regex fallback
_PY_BARE_EXCEPT = re.compile(r"^\s*except\s*:", re.MULTILINE)
_PY_BROAD_EXCEPT = re.compile(r"^\s*except\s+Exception\s*:", re.MULTILINE)


def run(ctx: SourceContext) -> list[Finding]:
    """Run error handling detection."""
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

    # 1. Bare except: blocks
    for node in find_nodes_by_type(ctx.root_node, "except_clause"):
        # A bare except has no exception type specified
        # In tree-sitter, bare `except:` has no named children that are types
        text = node_text(node)
        # Check if it's a bare except (no exception type after 'except')
        stripped = text.strip()
        if stripped.startswith("except:") or stripped.startswith("except :"):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=f"{CHECK_ID}-BARE-EXCEPT",
                    title="Bare except: clause",
                    description=(
                        "A bare except: catches all exceptions including "
                        "SystemExit and KeyboardInterrupt, which can mask "
                        "critical errors and make debugging difficult."
                    ),
                    severity="MEDIUM",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Catch specific exceptions: except ValueError: or "
                        "except (TypeError, ValueError):. At minimum use "
                        "except Exception: to avoid catching SystemExit."
                    ),
                    evidence=snippet,
                )
            )

    # 2. Tool handlers without try/except
    for node in find_nodes_by_type(ctx.root_node, "function_definition"):
        func_name = node.child_by_field_name("name")
        if func_name is None:
            continue

        name = node_text(func_name)
        if not re.search(r"(?i)(tool|handler|handle)", name):
            continue

        body = node.child_by_field_name("body")
        if body is None:
            continue

        # Check if function body contains any try statement
        has_try = any(child.type == "try_statement" for child in body.children)
        if not has_try:
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=f"{CHECK_ID}-NO-TRY",
                    title="Tool handler without error handling",
                    description=(
                        f"Tool handler '{name}' has no try/except block. "
                        "Unhandled exceptions in tool handlers can expose "
                        "internal details or crash the server."
                    ),
                    severity="LOW",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Wrap tool handler logic in try/except to catch and "
                        "handle errors gracefully. Return user-friendly error "
                        "messages without exposing internal details."
                    ),
                    evidence=snippet,
                    confidence=0.6,
                )
            )

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    # Check for empty catch blocks
    for node in find_nodes_by_type(ctx.root_node, "catch_clause"):
        body = node.child_by_field_name("body")
        if body is not None:
            # Empty catch block
            named_children = [c for c in body.named_children if c.type != "comment"]
            if len(named_children) == 0:
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=f"{CHECK_ID}-EMPTY-CATCH",
                        title="Empty catch block",
                        description=(
                            "An empty catch block silently swallows errors, "
                            "making it impossible to diagnose failures."
                        ),
                        severity="MEDIUM",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Log the error or re-throw it. Never silently " "ignore exceptions."
                        ),
                        evidence=snippet,
                    )
                )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    if ctx.language == "python":
        for match in _PY_BARE_EXCEPT.finditer(ctx.source_text):
            line_no = ctx.source_text[: match.start()].count("\n") + 1
            snippet = get_code_snippet(ctx.lines, line_no)
            findings.append(
                make_finding(
                    check_id=f"{CHECK_ID}-BARE-EXCEPT",
                    title="Bare except: clause",
                    description="Bare except: catches all exceptions.",
                    severity="MEDIUM",
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation="Catch specific exceptions instead of bare except.",
                    evidence=snippet,
                    confidence=0.9,
                )
            )

    return findings
