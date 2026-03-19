"""Check #7: Command injection via tool arguments.

Detects MCP tool arguments passed directly to shell commands
without sanitization, enabling command injection attacks.
These are DETECTION TARGETS for the scanner.
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

CHECK_ID = "SA-CMD-INJECTION"

# Regex fallback: f-string or format string passed to subprocess/os calls
_PY_CMD_FSTRING = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.(?:system|popen))"
    r"\s*\(\s*f['\"]",
)
_PY_CMD_FORMAT = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.(?:system|popen))"
    r"\s*\([^)]*\.format\s*\(",
)
_JS_CMD_TEMPLATE = re.compile(
    r"child_process\.\w+\s*\(\s*`",
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run command injection detection."""
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
    call_nodes = find_nodes_by_type(ctx.root_node, "call")

    dangerous_cmd_targets = [
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
        ("os", "system"),
        ("os", "popen"),
    ]

    for node in call_nodes:
        for module, method in dangerous_cmd_targets:
            if not is_call_to(node, module, method):
                continue

            args = node.child_by_field_name("arguments")
            if args is None:
                continue

            # Check first positional argument for f-string or format string
            first_arg = None
            for child in args.named_children:
                if child.type != "keyword_argument":
                    first_arg = child
                    break

            if first_arg is None:
                continue

            text = node_text(first_arg)
            is_interpolated = False

            # f-string with variable interpolation
            if first_arg.type == "string" and text.startswith("f") and "{" in text:
                is_interpolated = True

            # .format() call on string
            if first_arg.type == "call":
                func = first_arg.child_by_field_name("function")
                if func and func.type == "attribute":
                    attr = func.child_by_field_name("attribute")
                    if attr and node_text(attr) == "format":
                        is_interpolated = True

            # String concatenation with variable
            if first_arg.type == "binary_operator":
                op = first_arg.child_by_field_name("operator")
                if op and node_text(op) == "+":
                    is_interpolated = True

            if is_interpolated:
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title="Command injection: user input in shell command",
                        description=(
                            f"User-controlled input is interpolated into a "
                            f"{module}.{method}() command string. This enables "
                            "command injection attacks."
                        ),
                        severity="CRITICAL",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Pass arguments as a list instead of a string: "
                            "subprocess.run(['cmd', user_input]). "
                            "Use shlex.quote() if shell=True is required."
                        ),
                        evidence=snippet,
                    )
                )

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

        if node_text(obj) != "child_process":
            continue
        method_name = node_text(prop)
        if method_name not in ("exec", "execSync"):
            continue

        # Check if first argument is a template literal with interpolation
        args = node.child_by_field_name("arguments")
        if args is None:
            continue

        first_arg = args.named_children[0] if args.named_children else None
        if first_arg is None:
            continue

        if first_arg.type == "template_string" and "${" in node_text(first_arg):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Command injection: user input in shell command",
                    description=(
                        "Template literal with interpolation passed to "
                        "child_process, enabling command injection."
                    ),
                    severity="CRITICAL",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Use child_process.execFile() or spawn() with "
                        "arguments as an array instead."
                    ),
                    evidence=snippet,
                )
            )

        # String concatenation
        if first_arg.type == "binary_expression":
            op_node = first_arg.child_by_field_name("operator")
            if op_node and node_text(op_node) == "+":
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=CHECK_ID,
                        title="Command injection: concatenated command string",
                        description=(
                            "String concatenation in child_process command "
                            "enables command injection."
                        ),
                        severity="CRITICAL",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Use child_process.execFile() with arguments as a separate array."
                        ),
                        evidence=snippet,
                    )
                )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []

    if ctx.language == "python":
        patterns = [
            (_PY_CMD_FSTRING, "Command injection via f-string in subprocess call"),
            (_PY_CMD_FORMAT, "Command injection via .format() in subprocess call"),
        ]
    elif ctx.language in ("javascript", "typescript"):
        patterns = [
            (_JS_CMD_TEMPLATE, "Command injection via template literal"),
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
                    remediation="Pass command arguments as a list, not a string.",
                    evidence=snippet,
                    confidence=0.8,
                )
            )

    return findings
