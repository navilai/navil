"""MCP config auto-discovery — find all MCP client configs on the system.

Searches standard locations for Cursor, Claude Desktop, OpenClaw, Continue.dev,
and project-local configs. Returns a list of discovered configs with metadata.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

# Standard MCP config locations by client
_STANDARD_PATHS: list[tuple[str, str]] = [
    # (path template, client name)
    ("~/.cursor/mcp.json", "Cursor"),
    ("./.mcp.json", "Project-local"),
]

# Platform-specific paths
if platform.system() == "Darwin":
    _STANDARD_PATHS.extend(
        [
            (
                "~/Library/Application Support/Claude/claude_desktop_config.json",
                "Claude Desktop",
            ),
        ]
    )
else:
    _STANDARD_PATHS.extend(
        [
            ("~/.config/claude/claude_desktop_config.json", "Claude Desktop"),
        ]
    )

# Additional paths that exist on all platforms
_STANDARD_PATHS.extend(
    [
        ("openclaw.json", "OpenClaw"),
        (".continue/config.json", "Continue.dev"),
    ]
)


def _count_servers(config: dict[str, Any]) -> int:
    """Count mcpServers entries in a parsed config."""
    servers = config.get("mcpServers", {})
    if isinstance(servers, dict):
        return len(servers)
    return 0


def _try_parse_config(path: Path) -> dict[str, Any] | None:
    """Try to parse a JSON config file, returning None on failure."""
    try:
        text = path.read_text(encoding="utf-8")
        config = json.loads(text)
        if isinstance(config, dict) and _count_servers(config) > 0:
            return config
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        pass
    return None


def discover_configs(
    extra_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Auto-discover MCP client config files on the system.

    Searches standard locations for known MCP clients, plus any paths
    specified in the ``NAVIL_MCP_CONFIG`` environment variable or
    passed explicitly via *extra_paths*.

    Returns a list of dicts, each with::

        {
            "path": str,           # absolute path to the config file
            "client_name": str,    # e.g. "Cursor", "Claude Desktop"
            "server_count": int,   # number of mcpServers entries
        }

    Results are sorted by server count descending (most servers first).
    """
    seen_paths: set[str] = set()
    results: list[dict[str, Any]] = []

    def _check(raw_path: str, client_name: str) -> None:
        path = Path(os.path.expanduser(raw_path)).resolve()
        key = str(path)
        if key in seen_paths:
            return
        seen_paths.add(key)

        if not path.exists():
            return

        config = _try_parse_config(path)
        if config is None:
            return

        count = _count_servers(config)
        if count > 0:
            results.append(
                {
                    "path": str(path),
                    "client_name": client_name,
                    "server_count": count,
                }
            )

    # 1. Explicit extra paths (highest priority)
    if extra_paths:
        for p in extra_paths:
            _check(p, "Custom")

    # 2. Environment variable
    env_path = os.environ.get("NAVIL_MCP_CONFIG")
    if env_path:
        _check(env_path, "NAVIL_MCP_CONFIG")

    # 3. Standard locations
    for raw_path, client_name in _STANDARD_PATHS:
        _check(raw_path, client_name)

    # Sort by server count descending
    results.sort(key=lambda r: r["server_count"], reverse=True)
    return results


def prompt_for_config() -> str | None:
    """Prompt the user for a config path when none were discovered.

    Returns the path string, or None if stdin is not a TTY.
    """
    if not (hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
        return None

    print(
        "\n  No MCP config files found in standard locations.",
        file=sys.stderr,
    )
    print(
        "  Where is your MCP client config? (e.g., ~/.cursor/mcp.json)",
        file=sys.stderr,
    )
    try:
        path = input("  Path: ").strip()
        return path if path else None
    except (EOFError, KeyboardInterrupt):
        return None
