"""Check #3: Path traversal detection.

Detects user input passed to file operations (open(), Path(), os.path.join())
without proper sanitization, which can lead to arbitrary file access.
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

CHECK_ID = "SA-PATH-TRAVERSAL"

# Regex fallback
_PY_OPEN_FSTRING = re.compile(r"open\s*\(\s*f['\"]")
_PY_OPEN_FORMAT = re.compile(r"open\s*\([^)]*\.format\s*\(")
_PY_OPEN_CONCAT = re.compile(r"open\s*\([^)]*\+")
_PY_PATH_FSTRING = re.compile(r"Path\s*\(\s*f['\"]")
_PY_OS_PATH_JOIN_VAR = re.compile(r"os\.path\.join\s*\(")
_JS_FS_METHODS = re.compile(
    r"fs\.(readFile|writeFile|readFileSync|writeFileSync|unlink|readdir"
    r"|mkdir|rmdir|rename|access|stat|open)\s*\(",
)


def run(ctx: SourceContext) -> list[Finding]:
    """Run path traversal detection."""
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


def _has_unsanitized_input(node: object, ctx: SourceContext) -> bool:
    """Heuristic: check if a call's arguments contain variable interpolation.

    Looks for f-strings, .format(), concatenation with variables, or raw
    variable references that likely come from user input.
    """
    text = node_text(node)
    # f-string in arguments
    if "f'" in text or 'f"' in text:
        return True
    # .format() in arguments
    if ".format(" in text:
        return True
    # string concatenation with +
    return bool("+" in text and ("'" in text or '"' in text))


def _check_python_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []
    call_nodes = find_nodes_by_type(ctx.root_node, "call")

    for node in call_nodes:
        # open() with variable/f-string argument
        if is_call_to(node, None, "open") and _has_unsanitized_input(node, ctx):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Potential path traversal in open()",
                    description=(
                        "File path passed to open() includes variable interpolation. "
                        "If the variable comes from user input, this enables path "
                        "traversal attacks (e.g., ../../etc/passwd)."
                    ),
                    severity="HIGH",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Validate and sanitize file paths before use. "
                        "Use os.path.realpath() and verify the resolved path "
                        "is within the expected directory."
                    ),
                    evidence=snippet,
                )
            )

        # Path() with variable/f-string
        if is_call_to(node, None, "Path") and _has_unsanitized_input(node, ctx):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title="Potential path traversal in Path()",
                    description=(
                        "Path() constructed with variable interpolation. "
                        "User input can escape the intended directory."
                    ),
                    severity="HIGH",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Validate paths with Path.resolve() and check that "
                        "the result is within the allowed base directory."
                    ),
                    evidence=snippet,
                )
            )

        # os.path.join() -- always flag when user input may be involved
        if is_call_to(node, "os.path", "join"):
            args = node.child_by_field_name("arguments")
            if args and args.named_child_count > 1:
                # Check if any argument is a variable (not a string literal)
                for arg in args.named_children:
                    if arg.type == "identifier":
                        snippet = get_code_snippet(ctx.lines, line_number(node))
                        findings.append(
                            make_finding(
                                check_id=CHECK_ID,
                                title="Potential path traversal in os.path.join()",
                                description=(
                                    "os.path.join() called with a variable argument. "
                                    "If this variable contains '../', it can escape "
                                    "the base directory."
                                ),
                                severity="MEDIUM",
                                file_path=ctx.file_path,
                                line_no=line_number(node),
                                remediation=(
                                    "Use os.path.realpath() on the result and verify "
                                    "it starts with the expected base path."
                                ),
                                evidence=snippet,
                                confidence=0.7,
                            )
                        )
                        break

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []
    call_nodes = find_nodes_by_type(ctx.root_node, "call_expression")

    for node in call_nodes:
        func = node.child_by_field_name("function")
        if func is None:
            continue

        # fs.readFile(), fs.writeFile(), etc.
        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj and prop and node_text(obj) == "fs":
                method = node_text(prop)
                fs_methods = {
                    "readFile",
                    "writeFile",
                    "readFileSync",
                    "writeFileSync",
                    "unlink",
                    "unlinkSync",
                    "readdir",
                    "readdirSync",
                    "mkdir",
                    "mkdirSync",
                    "rmdir",
                    "rmdirSync",
                    "rename",
                    "renameSync",
                    "access",
                    "accessSync",
                }
                if method in fs_methods:
                    args = node.child_by_field_name("arguments")
                    if args:
                        first_arg = args.named_children[0] if args.named_children else None
                        if first_arg and first_arg.type in (
                            "identifier",
                            "template_string",
                            "binary_expression",
                        ):
                            snippet = get_code_snippet(ctx.lines, line_number(node))
                            findings.append(
                                make_finding(
                                    check_id=CHECK_ID,
                                    title=f"Potential path traversal in fs.{method}()",
                                    description=(
                                        f"fs.{method}() called with a variable or "
                                        "interpolated path. This can be exploited "
                                        "for path traversal."
                                    ),
                                    severity="HIGH",
                                    file_path=ctx.file_path,
                                    line_no=line_number(node),
                                    remediation=(
                                        "Validate and sanitize file paths. Use "
                                        "path.resolve() and verify the result is "
                                        "within the expected directory."
                                    ),
                                    evidence=snippet,
                                )
                            )

        # path.join() with variable
        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj and prop and node_text(obj) == "path" and node_text(prop) == "join":
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in args.named_children:
                        if arg.type == "identifier":
                            snippet = get_code_snippet(ctx.lines, line_number(node))
                            findings.append(
                                make_finding(
                                    check_id=CHECK_ID,
                                    title="Potential path traversal in path.join()",
                                    description=(
                                        "path.join() called with a variable argument "
                                        "that may contain '../' sequences."
                                    ),
                                    severity="MEDIUM",
                                    file_path=ctx.file_path,
                                    line_no=line_number(node),
                                    remediation=(
                                        "Validate the resolved path is within "
                                        "the expected base directory."
                                    ),
                                    evidence=snippet,
                                    confidence=0.7,
                                )
                            )
                            break

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex fallback."""
    findings: list[Finding] = []
    patterns: list[tuple[re.Pattern[str], str]] = []

    if ctx.language == "python":
        patterns = [
            (_PY_OPEN_FSTRING, "Potential path traversal in open() with f-string"),
            (_PY_OPEN_FORMAT, "Potential path traversal in open() with .format()"),
            (_PY_OPEN_CONCAT, "Potential path traversal in open() with concatenation"),
            (_PY_PATH_FSTRING, "Potential path traversal in Path() with f-string"),
        ]
    elif ctx.language in ("javascript", "typescript"):
        patterns = [
            (_JS_FS_METHODS, "Potential path traversal in fs method"),
        ]

    for pattern, title in patterns:
        for match in pattern.finditer(ctx.source_text):
            line_no = ctx.source_text[: match.start()].count("\n") + 1
            snippet = get_code_snippet(ctx.lines, line_no)
            findings.append(
                make_finding(
                    check_id=CHECK_ID,
                    title=title,
                    description=f"Detected {title.lower()} in source code.",
                    severity="HIGH",
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation="Validate and sanitize file paths before use.",
                    evidence=snippet,
                    confidence=0.7,
                )
            )

    return findings
