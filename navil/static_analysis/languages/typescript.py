"""TypeScript language support for tree-sitter parsing."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_parser: Any = None
_language: Any = None


def get_language() -> Any:
    """Return the tree-sitter Language object for TypeScript."""
    global _language
    if _language is None:
        import tree_sitter
        import tree_sitter_typescript as tstypescript

        _language = tree_sitter.Language(tstypescript.language_typescript())
    return _language


def get_parser() -> Any:
    """Return a cached tree-sitter Parser for TypeScript."""
    global _parser
    if _parser is None:
        import tree_sitter

        _parser = tree_sitter.Parser(get_language())
    return _parser


def parse(source: bytes) -> Any:
    """Parse TypeScript source bytes and return the tree."""
    return get_parser().parse(source)


# TypeScript reuses the same dangerous patterns as JavaScript.
# See javascript.py for DANGEROUS_MEMBER_CALLS, DANGEROUS_BARE_CALLS, etc.
