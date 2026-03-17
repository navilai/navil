"""
Tree-sitter helpers and fallback utilities for static analysis.

Provides:
- Tree-sitter parser initialization (with graceful fallback flag)
- AST walking helpers
- Code snippet extraction
- Common pattern matching utilities
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from navil.types import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter availability
# ---------------------------------------------------------------------------
TREE_SITTER_AVAILABLE = False

try:
    import tree_sitter

    TREE_SITTER_AVAILABLE = True
except ImportError:
    tree_sitter = None  # type: ignore[assignment]

# Language detection by file extension
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


@dataclass
class SourceContext:
    """Context object passed to each security check.

    Attributes:
        file_path: Absolute path to the source file being analyzed.
        source: Raw source code bytes.
        source_text: Source code as a string.
        lines: Source split into lines (for line-number lookup).
        language: Detected language (python / javascript / typescript).
        tree: Parsed tree-sitter tree (None in fallback mode).
        root_node: Root AST node (None in fallback mode).
        use_tree_sitter: Whether tree-sitter is available and parsing succeeded.
    """

    file_path: str
    source: bytes
    source_text: str
    lines: list[str]
    language: str
    tree: Any = None
    root_node: Any = None
    use_tree_sitter: bool = False


# ---------------------------------------------------------------------------
# AST walking
# ---------------------------------------------------------------------------


def walk_tree(node: Any) -> list[Any]:
    """Return all descendant nodes via depth-first traversal."""
    result: list[Any] = []
    _walk_recursive(node, result)
    return result


def _walk_recursive(node: Any, acc: list[Any]) -> None:
    acc.append(node)
    for child in node.children:
        _walk_recursive(child, acc)


def find_nodes_by_type(root: Any, *types: str) -> list[Any]:
    """Return all descendant nodes whose type is in the given set."""
    return [n for n in walk_tree(root) if n.type in types]


def node_text(node: Any) -> str:
    """Extract the UTF-8 text of a tree-sitter node."""
    return node.text.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Call-site helpers
# ---------------------------------------------------------------------------


def is_call_to(node: Any, obj: str | None, attr: str) -> bool:
    """Check if a call node invokes obj.attr() or just attr().

    For obj=None matches a bare function call.
    For obj='subprocess' matches subprocess.run(), etc.
    """
    if node.type != "call":
        return False

    func = node.child_by_field_name("function")
    if func is None:
        return False

    # Simple function call
    if obj is None and func.type == "identifier":
        return node_text(func) == attr

    # Attribute call: module.function()
    if func.type == "attribute":
        obj_node = func.child_by_field_name("object")
        attr_node = func.child_by_field_name("attribute")
        if obj_node is None or attr_node is None:
            return False
        return node_text(obj_node) == obj and node_text(attr_node) == attr

    return False


def call_has_keyword(node: Any, keyword: str, value: str | None = None) -> bool:
    """Check if a call node has a keyword argument with the given name.

    If value is provided, also checks that the keyword argument value matches.
    """
    if node.type != "call":
        return False
    args = node.child_by_field_name("arguments")
    if args is None:
        return False
    for child in args.children:
        if child.type == "keyword_argument":
            name_node = child.child_by_field_name("name")
            if name_node and node_text(name_node) == keyword:
                if value is None:
                    return True
                val_node = child.child_by_field_name("value")
                if val_node and node_text(val_node) == value:
                    return True
    return False


# ---------------------------------------------------------------------------
# JS/TS call helpers
# ---------------------------------------------------------------------------


def is_member_call(node: Any, obj: str, method: str) -> bool:
    """Check if node is a member expression call like obj.method() in JS/TS."""
    if node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return False
    obj_node = func.child_by_field_name("object")
    prop_node = func.child_by_field_name("property")
    if obj_node is None or prop_node is None:
        return False
    return node_text(obj_node) == obj and node_text(prop_node) == method


def is_bare_call(node: Any, func_name: str) -> bool:
    """Check if node is a bare function call like func_name() in JS/TS."""
    if node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    if func is None:
        return False
    return func.type == "identifier" and node_text(func) == func_name


# ---------------------------------------------------------------------------
# Line number helpers
# ---------------------------------------------------------------------------


def line_number(node: Any) -> int:
    """Return the 1-based line number of a tree-sitter node."""
    return node.start_point[0] + 1


def get_code_snippet(lines: list[str], line_no: int, context: int = 0) -> str:
    """Return context lines around 1-based line_no."""
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    return "\n".join(lines[start:end]).strip()


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def make_finding(
    *,
    check_id: str,
    title: str,
    description: str,
    severity: str,
    file_path: str,
    line_no: int,
    remediation: str,
    evidence: str = "",
    confidence: float = 0.9,
) -> Finding:
    """Convenience wrapper to build a Finding with file:line affected_field."""
    return Finding(
        id=check_id,
        title=title,
        description=description,
        severity=severity,
        source="static_analysis",
        affected_field=f"{file_path}:{line_no}",
        remediation=remediation,
        evidence=evidence,
        confidence=confidence,
    )
