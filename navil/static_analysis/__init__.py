"""
Static analysis subsystem for Navil.

Provides tree-sitter-based source code scanning of MCP server implementations
to detect security vulnerabilities such as command injection, SQL injection,
path traversal, hardcoded secrets, and more.

Falls back to regex-only analysis when tree-sitter is not available.
"""

from __future__ import annotations

from navil.static_analysis.analyzer import StaticAnalyzer

__all__ = ["StaticAnalyzer"]
