"""Check #1: Unsafe subprocess/exec calls.

Detects dangerous patterns like subprocess.run(shell=True), os.system(),
and code-evaluation functions in Python and JS/TS.
These are DETECTION TARGETS -- patterns this scanner flags in user code.
"""

from __future__ import annotations

import re

from navil.static_analysis.utils import (
    SourceContext,
    call_has_keyword,
    find_nodes_by_type,
    get_code_snippet,
    is_bare_call,
    is_call_to,
    line_number,
    make_finding,
    node_text,
)
from navil.types import Finding

CHECK_ID_PREFIX = "SA-EXEC"

# Regex fallback patterns
_PY_SUBPROCESS_SHELL = re.compile(
    r"subprocess\.(run|call|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True",
    re.DOTALL,
)
_PY_OS_SYSTEM = re.compile(r"os\.(system|popen)\s*\(")
_PY_CODE_EVAL = re.compile(r"\b(eval|exec)\s*\(")
_JS_CHILD_PROC = re.compile(r"child_process\.\w+\s*\(")
_JS_CODE_EVAL = re.compile(r"\beval\s*\(")


def run(ctx: SourceContext) -> list[Finding]:
    """Run unsafe subprocess/exec detection."""
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

    for node in call_nodes:
        # subprocess.run/call/Popen with shell=True
        for method in ("run", "call", "Popen", "check_output", "check_call"):
            if is_call_to(node, "subprocess", method):
                if call_has_keyword(node, "shell", "True"):
                    snippet = get_code_snippet(ctx.lines, line_number(node))
                    findings.append(
                        make_finding(
                            check_id=f"{CHECK_ID_PREFIX}-SUBPROCESS-SHELL",
                            title="Subprocess call with shell=True",
                            description=(
                                f"subprocess.{method}() called with shell=True enables "
                                "shell injection attacks. User-controlled input in the "
                                "command string can run arbitrary commands."
                            ),
                            severity="CRITICAL",
                            file_path=ctx.file_path,
                            line_no=line_number(node),
                            remediation=(
                                "Use subprocess with shell=False (default) and pass "
                                "arguments as a list: subprocess.run(['cmd', 'arg1'])"
                            ),
                            evidence=snippet,
                        )
                    )
                break

        # os.system() / os.popen()
        for method in ("system", "popen"):
            if is_call_to(node, "os", method):
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=f"{CHECK_ID_PREFIX}-OS-SYSTEM",
                        title=f"os.{method}() call detected",
                        description=(
                            f"os.{method}() runs commands through the shell "
                            "and is vulnerable to command injection."
                        ),
                        severity="CRITICAL",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            "Replace os.system()/os.popen() with subprocess.run() "
                            "using shell=False and a list of arguments."
                        ),
                        evidence=snippet,
                    )
                )
                break

        # Dangerous code-evaluation functions
        for func_name in ("eval", "exec"):
            if is_call_to(node, None, func_name):
                snippet = get_code_snippet(ctx.lines, line_number(node))
                findings.append(
                    make_finding(
                        check_id=f"{CHECK_ID_PREFIX}-CODE-EVAL",
                        title=f"{func_name}() call detected",
                        description=(
                            f"{func_name}() runs arbitrary code and is a major "
                            "security risk if used with untrusted input."
                        ),
                        severity="HIGH",
                        file_path=ctx.file_path,
                        line_no=line_number(node),
                        remediation=(
                            f"Avoid {func_name}(). Use safer alternatives like "
                            "ast.literal_eval() for data parsing or structured "
                            "dispatch patterns."
                        ),
                        evidence=snippet,
                    )
                )
                break

    return findings


def _check_js_ts(ctx: SourceContext) -> list[Finding]:
    findings: list[Finding] = []
    call_nodes = find_nodes_by_type(ctx.root_node, "call_expression")

    for node in call_nodes:
        # child_process member calls
        func = node.child_by_field_name("function")
        if func and func.type == "member_expression":
            obj_node = func.child_by_field_name("object")
            prop_node = func.child_by_field_name("property")
            if obj_node and prop_node:
                obj_name = node_text(obj_node)
                method_name = node_text(prop_node)
                if obj_name == "child_process" and method_name in ("exec", "execSync"):
                    snippet = get_code_snippet(ctx.lines, line_number(node))
                    findings.append(
                        make_finding(
                            check_id=f"{CHECK_ID_PREFIX}-CHILD-PROCESS",
                            title=f"child_process.{method_name}() call detected",
                            description=(
                                f"child_process.{method_name}() runs commands in a shell "
                                "and is vulnerable to command injection."
                            ),
                            severity="CRITICAL",
                            file_path=ctx.file_path,
                            line_no=line_number(node),
                            remediation=(
                                "Use child_process.execFile() or spawn() "
                                "which do not invoke a shell by default."
                            ),
                            evidence=snippet,
                        )
                    )

        # Bare eval() call
        if is_bare_call(node, "eval"):
            snippet = get_code_snippet(ctx.lines, line_number(node))
            findings.append(
                make_finding(
                    check_id=f"{CHECK_ID_PREFIX}-CODE-EVAL",
                    title="eval() call detected",
                    description=(
                        "eval() runs arbitrary code and is a major "
                        "security risk if used with untrusted input."
                    ),
                    severity="HIGH",
                    file_path=ctx.file_path,
                    line_no=line_number(node),
                    remediation=(
                        "Avoid eval(). Use JSON.parse() for data parsing, "
                        "or use a safer alternative pattern."
                    ),
                    evidence=snippet,
                )
            )

    return findings


def _check_regex(ctx: SourceContext) -> list[Finding]:
    """Regex-based fallback when tree-sitter is not available."""
    findings: list[Finding] = []

    patterns: list[tuple[re.Pattern[str], str, str, str, str]] = []

    if ctx.language == "python":
        patterns = [
            (
                _PY_SUBPROCESS_SHELL,
                f"{CHECK_ID_PREFIX}-SUBPROCESS-SHELL",
                "Subprocess call with shell=True",
                "CRITICAL",
                "Use subprocess with shell=False and pass arguments as a list.",
            ),
            (
                _PY_OS_SYSTEM,
                f"{CHECK_ID_PREFIX}-OS-SYSTEM",
                "os.system()/os.popen() call detected",
                "CRITICAL",
                "Replace with subprocess.run() using shell=False.",
            ),
            (
                _PY_CODE_EVAL,
                f"{CHECK_ID_PREFIX}-CODE-EVAL",
                "Code evaluation function call detected",
                "HIGH",
                "Avoid dynamic code evaluation. Use ast.literal_eval() or structured dispatch.",
            ),
        ]
    elif ctx.language in ("javascript", "typescript"):
        patterns = [
            (
                _JS_CHILD_PROC,
                f"{CHECK_ID_PREFIX}-CHILD-PROCESS",
                "child_process call detected",
                "CRITICAL",
                "Use child_process.execFile() or spawn() instead.",
            ),
            (
                _JS_CODE_EVAL,
                f"{CHECK_ID_PREFIX}-CODE-EVAL",
                "eval() call detected",
                "HIGH",
                "Avoid eval(). Use JSON.parse() or safer alternatives.",
            ),
        ]

    for pattern, check_id, title, severity, remediation in patterns:
        for match in pattern.finditer(ctx.source_text):
            line_no = ctx.source_text[: match.start()].count("\n") + 1
            snippet = get_code_snippet(ctx.lines, line_no)
            findings.append(
                make_finding(
                    check_id=check_id,
                    title=title,
                    description=f"Detected {title.lower()} in source code.",
                    severity=severity,
                    file_path=ctx.file_path,
                    line_no=line_no,
                    remediation=remediation,
                    evidence=snippet,
                    confidence=0.8,
                )
            )

    return findings
