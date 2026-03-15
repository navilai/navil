"""JavaScript language support for tree-sitter parsing."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_parser: Any = None
_language: Any = None


def get_language() -> Any:
    """Return the tree-sitter Language object for JavaScript."""
    global _language
    if _language is None:
        import tree_sitter
        import tree_sitter_javascript as tsjavascript

        _language = tree_sitter.Language(tsjavascript.language())
    return _language


def get_parser() -> Any:
    """Return a cached tree-sitter Parser for JavaScript."""
    global _parser
    if _parser is None:
        import tree_sitter

        _parser = tree_sitter.Parser(get_language())
    return _parser


def parse(source: bytes) -> Any:
    """Parse JavaScript source bytes and return the tree."""
    return get_parser().parse(source)


# JS-specific dangerous patterns -- DETECTION TARGETS for the scanner.
# child_process.exec is a command injection risk we want to detect.
DANGEROUS_MEMBER_CALLS: list[tuple[str, str]] = [
    ("child_process", "exec"),
    ("child_process", "execSync"),
]

DANGEROUS_BARE_CALLS: list[str] = [
    "eval",
    "Function",
    "setTimeout",  # when used with string arg
    "setInterval",  # when used with string arg
]

SQL_METHODS: list[str] = [
    "query",
    "execute",
    "raw",
    "prepare",
]

LOG_METHODS: list[str] = [
    "log",
    "info",
    "warn",
    "error",
    "debug",
]
