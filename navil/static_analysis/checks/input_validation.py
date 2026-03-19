"""Check #5: Missing input validation in MCP tool handlers.

Detects MCP tool handler functions that use arguments/parameters without
performing any validation or type checking first.
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

CHECK_ID = "SA-INPUT-VALIDATION"

# Heuristic patterns that indicate an MCP tool handler
_HANDLER_INDICATORS = re.compile(
    r"(?i)(tool_handler|handle_tool|tool_call|handle_call|mcp_tool"
    r"|@tool|@server\.tool|def\s+\w*tool\w*|def\s+\w*handler\w*)",
)

# Patterns that indicate validation is being performed
_VALIDATION_PATTERNS = re.compile(
    r"(?i)(isinstance\s*\(|assert\s+|validate|schema|pydantic"
    r"|if\s+.*\bnot\b\s+.*arguments|if\s+.*arguments\s*\.\s*get"
    r"|raise\s+(ValueError|TypeError|KeyError|ValidationError)"
    r"|\.validate\(|jsonschema|try\s*:\s*\n.*arguments)",
    re.DOTALL,
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run missing input validation detection."""
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

    # Find function definitions that look like tool handlers
    for node in find_nodes_by_type(ctx.root_node, "function_definition"):
        func_name = node.child_by_field_name("name")
        if func_name is None:
            continue

        name = node_text(func_name)
        # Heuristic: function name contains 'tool', 'handler', 'handle'
        if not re.search(r"(?i)(tool|handler|handle)", name):
            continue

        # Check parameters for 'arguments' or 'params'
        params = node.child_by_field_name("parameters")
        if params is None:
            continue

        param_text = node_text(params)
        if not re.search(r"(?i)(arguments|params|request|args)", param_text):
            continue

        # Check function body for validation patterns
        body = node.child_by_field_name("body")
        if body is None:
            continue

        body_text = node_text(body)
        if not _VALIDATION_PATTERNS.search(body_text):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Missing input validation in tool handler",
                    description=(
                        f"Tool handler function '{name}' appears to use "
                        "arguments without validation. MCP tool handlers should "
                        "validate all input before processing."
                    ),
                    severity="MEDIUM",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Add input validation at the start of the handler: "
                        "check types, required fields, and value ranges. "
                        "Consider using pydantic or jsonschema for validation."
                    ),
                    evidence=snippet,
                    confidence=0.7,
                )
            )

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []

    # Find function/method declarations that look like handlers
    func_types = ("function_declaration", "method_definition", "arrow_function")
    for node in find_nodes_by_type(ctx.root_node, *func_types):
        # Get function name
        name_node = node.child_by_field_name("name")
        if name_node is None:
            # Arrow functions may be assigned to a variable
            parent = node.parent
            if parent and parent.type == "variable_declarator":
                name_node = parent.child_by_field_name("name")
            if name_node is None:
                continue

        name = node_text(name_node)
        if not re.search(r"(?i)(tool|handler|handle)", name):
            continue

        # Check body for validation
        body = node.child_by_field_name("body")
        if body is None:
            continue

        body_text = node_text(body)
        validation_js = re.compile(
            r"(?i)(typeof\s|instanceof\s|\.validate\(|zod\.|joi\.|ajv\."
            r"|if\s*\(!|throw\s+new\s+(TypeError|Error|ValidationError))",
        )
        if not validation_js.search(body_text):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Missing input validation in tool handler",
                    description=(
                        f"Tool handler '{name}' does not appear to validate "
                        "its input arguments. All MCP tool inputs should be "
                        "validated before processing."
                    ),
                    severity="MEDIUM",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Add input validation using typeof checks, Zod schemas, "
                        "or Joi validation before processing arguments."
                    ),
                    evidence=snippet,
                    confidence=0.7,
                )
            )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    # Find handler-like functions
    handler_pattern = re.compile(
        r"(?:def|function|const|let|var)\s+(\w*(?:tool|handler|handle)\w*)\s*[(\s=]",
        re.IGNORECASE,
    )

    for match in handler_pattern.finditer(ctx.source_text):
        func_name = match.group(1)
        start_pos = match.start()
        # Look ahead ~500 chars for the function body
        body_region = ctx.source_text[start_pos : start_pos + 500]

        if not _VALIDATION_PATTERNS.search(body_region):
            line_no = ctx.source_text[:start_pos].count("\n") + 1
            snippet = get_code_snippet(ctx.lines, line_no)
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Missing input validation in tool handler",
                    description=(f"Tool handler '{func_name}' may lack input validation."),
                    severity="MEDIUM",
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation="Add input validation before processing arguments.",
                    evidence=snippet,
                    confidence=0.6,
                )
            )

    return findings
