"""
Main StaticAnalyzer class.

Orchestrates tree-sitter-based source code scanning of MCP server
implementations to detect security vulnerabilities.

Falls back to regex-only analysis when tree-sitter is not available.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from navil.static_analysis.checks import (
    command_injection,
    deserialization,
    error_handling,
    input_validation,
    insecure_http,
    path_traversal,
    secrets,
    sensitive_logs,
    sql_injection,
    subprocess_check,
)
from navil.static_analysis.utils import (
    EXTENSION_TO_LANGUAGE,
    TREE_SITTER_AVAILABLE,
    SourceContext,
)
from navil.types import Finding

logger = logging.getLogger(__name__)

# Registry of all checks with their module, name, and default enabled state
_ALL_CHECKS: list[tuple[str, Any]] = [
    ("subprocess", subprocess_check),
    ("sql_injection", sql_injection),
    ("path_traversal", path_traversal),
    ("secrets", secrets),
    ("input_validation", input_validation),
    ("deserialization", deserialization),
    ("command_injection", command_injection),
    ("error_handling", error_handling),
    ("sensitive_logs", sensitive_logs),
    ("insecure_http", insecure_http),
]


class StaticAnalyzer:
    """Tree-sitter-based source code analyzer for MCP server implementations.

    Usage::

        analyzer = StaticAnalyzer()
        findings = analyzer.analyze_path("/path/to/mcp-server/")

        # Or analyze a single file:
        findings = analyzer.analyze_file("/path/to/server.py")

    Configuration:

    - ``enabled_checks``: set of check names to run (default: all).
          Valid names: subprocess, sql_injection, path_traversal, secrets,
          input_validation, deserialization, command_injection,
          error_handling, sensitive_logs, insecure_http
    - ``languages``: set of languages to analyze (default: all supported).
    - ``severity_filter``: minimum severity to include in results.
    """

    def __init__(
        self,
        *,
        enabled_checks: set[str] | None = None,
        languages: set[str] | None = None,
        severity_filter: str | None = None,
    ) -> None:
        self._enabled_checks = enabled_checks or {name for name, _ in _ALL_CHECKS}
        self._languages = languages or {"python", "javascript", "typescript"}
        self._severity_filter = severity_filter
        self._severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        # Validate check names
        valid_names = {name for name, _ in _ALL_CHECKS}
        invalid = self._enabled_checks - valid_names
        if invalid:
            raise ValueError(
                f"Unknown check name(s): {invalid}. "
                f"Valid names: {sorted(valid_names)}"
            )

        # Build active check list
        self._checks = [
            (name, module)
            for name, module in _ALL_CHECKS
            if name in self._enabled_checks
        ]

        self._use_tree_sitter = TREE_SITTER_AVAILABLE
        if not self._use_tree_sitter:
            logger.warning(
                "tree-sitter not available; falling back to regex-only analysis. "
                "Install tree-sitter, tree-sitter-python, tree-sitter-javascript, "
                "and tree-sitter-typescript for full AST-based analysis."
            )

    @property
    def tree_sitter_available(self) -> bool:
        """Whether tree-sitter is available for AST-based analysis."""
        return self._use_tree_sitter

    def analyze_path(self, path: str) -> list[Finding]:
        """Analyze all supported source files under *path*.

        *path* can be a file or directory. If a directory, it is walked
        recursively. Unparseable files are skipped with a warning.

        Returns:
            List of Finding objects sorted by severity (CRITICAL first).
        """
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        if target.is_file():
            file_findings = self._analyze_single_file(target)
            return self._filter_and_sort(file_findings)

        # Directory: collect all supported files
        findings: list[Finding] = []
        for file_path in sorted(target.rglob("*")):
            if not file_path.is_file():
                continue
            ext = file_path.suffix.lower()
            if ext not in EXTENSION_TO_LANGUAGE:
                continue
            lang = EXTENSION_TO_LANGUAGE[ext]
            if lang not in self._languages:
                continue

            # Skip common non-production directories
            parts = file_path.parts
            skip_dirs = {
                "node_modules", ".git", "__pycache__", ".tox", ".mypy_cache",
                ".pytest_cache", "dist", "build", ".venv", "venv", "env",
            }
            if any(part in skip_dirs for part in parts):
                continue

            findings.extend(self._analyze_single_file(file_path))

        return self._filter_and_sort(findings)

    def analyze_file(self, file_path: str) -> list[Finding]:
        """Analyze a single source file.

        Returns:
            List of Finding objects sorted by severity.
        """
        target = Path(file_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        findings = self._analyze_single_file(target)
        return self._filter_and_sort(findings)

    def _analyze_single_file(self, file_path: Path) -> list[Finding]:
        """Analyze one file, returning raw (unfiltered) findings."""
        ext = file_path.suffix.lower()
        language = EXTENSION_TO_LANGUAGE.get(ext)
        if language is None:
            return []

        try:
            source = file_path.read_bytes()
        except (OSError, PermissionError) as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        source_text = source.decode("utf-8", errors="replace")
        lines = source_text.splitlines()

        # Build context
        ctx = SourceContext(
            file_path=str(file_path),
            source=source,
            source_text=source_text,
            lines=lines,
            language=language,
        )

        # Parse with tree-sitter if available
        if self._use_tree_sitter:
            try:
                tree = self._parse(source, language)
                if tree is not None:
                    ctx.tree = tree
                    ctx.root_node = tree.root_node
                    ctx.use_tree_sitter = True
                else:
                    logger.warning(
                        "tree-sitter parse returned None for %s; using regex fallback",
                        file_path,
                    )
            except Exception as exc:
                logger.warning(
                    "tree-sitter parse failed for %s: %s; using regex fallback",
                    file_path,
                    exc,
                )

        # Run all enabled checks
        findings: list[Finding] = []
        for check_name, check_module in self._checks:
            try:
                results = check_module.run(ctx)
                findings.extend(results)
            except Exception as exc:
                logger.warning(
                    "Check '%s' failed on %s: %s",
                    check_name,
                    file_path,
                    exc,
                )

        return findings

    def _parse(self, source: bytes, language: str) -> Any:
        """Parse source bytes with the appropriate tree-sitter parser."""
        if language == "python":
            from navil.static_analysis.languages.python import parse

            return parse(source)
        elif language == "javascript":
            from navil.static_analysis.languages.javascript import parse

            return parse(source)
        elif language == "typescript":
            from navil.static_analysis.languages.typescript import parse

            return parse(source)
        return None

    def _filter_and_sort(self, findings: list[Finding]) -> list[Finding]:
        """Apply severity filter and sort by severity (CRITICAL first)."""
        if self._severity_filter:
            min_idx = self._severity_order.index(self._severity_filter.upper())
            findings = [
                f
                for f in findings
                if self._severity_order.index(f.severity) >= min_idx
            ]

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
        findings.sort(
            key=lambda f: -self._severity_order.index(f.severity)
            if f.severity in self._severity_order
            else 0
        )
        return findings
