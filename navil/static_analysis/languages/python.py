"""Python language support for tree-sitter parsing."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_parser: Any = None
_language: Any = None


def get_language() -> Any:
    """Return the tree-sitter Language object for Python."""
    global _language
    if _language is None:
        import tree_sitter
        import tree_sitter_python as tspython

        _language = tree_sitter.Language(tspython.language())
    return _language


def get_parser() -> Any:
    """Return a cached tree-sitter Parser for Python."""
    global _parser
    if _parser is None:
        import tree_sitter

        _parser = tree_sitter.Parser(get_language())
    return _parser


def parse(source: bytes) -> Any:
    """Parse Python source bytes and return the tree."""
    return get_parser().parse(source)


# Python-specific dangerous function names grouped by category.
# These are DETECTION TARGETS for the security scanner -- patterns to flag
# when found in scanned source code, not functions we call ourselves.

DANGEROUS_EXEC_FUNCTIONS: dict[str, list[tuple[str | None, str]]] = {
    # (object_name_or_None, function_name)
    "subprocess_shell": [
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
    ],
    "os_system": [
        ("os", "system"),
        ("os", "popen"),
    ],
    "code_execution": [
        (None, "exec"),
        (None, "compile"),
    ],
    "code_eval": [
        (None, "eval"),
    ],
}

UNSAFE_DESERIALIZE: list[tuple[str | None, str]] = [
    ("pickle", "loads"),
    ("pickle", "load"),
    ("pickle", "Unpickler"),
    ("cPickle", "loads"),
    ("cPickle", "load"),
    ("shelve", "open"),
    ("marshal", "loads"),
    ("marshal", "load"),
    # yaml.load without SafeLoader
    ("yaml", "load"),
    ("yaml", "unsafe_load"),
    ("yaml", "full_load"),
]

PATH_FUNCTIONS: list[tuple[str | None, str]] = [
    (None, "open"),
    ("os.path", "join"),
    ("os", "open"),
    ("os", "listdir"),
    ("os", "remove"),
    ("os", "unlink"),
    ("os", "rename"),
    ("os", "makedirs"),
    ("shutil", "copy"),
    ("shutil", "move"),
    ("shutil", "rmtree"),
]

SQL_EXECUTE_METHODS: list[str] = [
    "execute",
    "executemany",
    "executescript",
]

LOG_FUNCTIONS: list[tuple[str | None, str]] = [
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
