"""MCP STDIO transport vulnerability scanner.

Detects the class of vulnerability disclosed by Ox researchers in April 2026:
the MCP STDIO transport executes arbitrary OS commands regardless of whether
they spawn a valid MCP server. Anthropic declined to patch — so detection at
the user's config level is the actual mitigation.

Pure local scan: no network calls. Reads MCP client config files via
``navil.discovery.discover_configs`` and inspects each server's launch
command against a heuristic allow-list of known-good launchers.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from navil.discovery import discover_configs

logger = logging.getLogger(__name__)


# ── Risk classes ──────────────────────────────────────────────────

RISK_SHELL_WRAPPER = "SHELL_WRAPPER"
RISK_UNPINNED_NPX = "UNPINNED_NPX"
RISK_UNTRUSTED_AUTHOR = "UNTRUSTED_AUTHOR"
RISK_REMOTE_PIPE = "REMOTE_PIPE"
RISK_UNKNOWN_BINARY = "UNKNOWN_BINARY"

_MITIGATION: dict[str, str] = {
    RISK_SHELL_WRAPPER: (
        "Replace the shell wrapper with a direct binary path; "
        "wrap with `navil secure` to enforce at runtime."
    ),
    RISK_UNPINNED_NPX: "Pin the npm package version (e.g. `npx -y pkg@1.2.3`).",
    RISK_UNTRUSTED_AUTHOR: (
        "Move to a vetted publisher (e.g. @modelcontextprotocol/*) or a local audited binary."
    ),
    RISK_REMOTE_PIPE: (
        "Never pipe remote scripts into a shell. Vendor the script and "
        "review it locally before execution."
    ),
    RISK_UNKNOWN_BINARY: (
        "Verify the binary path and pin its version; "
        "wrap with `navil secure` to enforce at runtime."
    ),
}

# Trusted publisher scopes for npm packages.
_TRUSTED_NPM_SCOPES: tuple[str, ...] = (
    "@modelcontextprotocol/",
    "@anthropic-ai/",
    "@anthropic/",
)

# Shell wrapper executables that almost always indicate arbitrary OS exec.
_SHELL_WRAPPERS: frozenset[str] = frozenset(
    {"bash", "sh", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"}
)

# Remote-fetch executables.
_REMOTE_FETCHERS: frozenset[str] = frozenset({"curl", "wget", "fetch", "http"})

# Known-good launcher executables (need additional checks below).
_LAUNCHER_BINS: frozenset[str] = frozenset(
    {"npx", "uvx", "uv", "python", "python3", "node", "deno", "bun"}
)

_SEMVER_RE = re.compile(r"@\d|@\^|@~|@>|@<|@=")


# ── Data types ────────────────────────────────────────────────────


@dataclass
class FlaggedServer:
    config_path: str
    client_name: str
    server_name: str
    command: str
    args: list[str]
    full_command: str
    risk_class: str
    mitigation: str


@dataclass
class StdioFlawReport:
    generated_at: str
    configs_scanned: int
    servers_examined: int
    servers_flagged: int
    flagged: list[FlaggedServer] = field(default_factory=list)


# ── Detection logic ───────────────────────────────────────────────


def _basename(cmd: str) -> str:
    """Return the basename of an executable path, lowercased."""
    if not cmd:
        return ""
    # Strip path separators.
    name = cmd.replace("\\", "/").rsplit("/", 1)[-1]
    return name.lower()


def _truncate(text: str, limit: int = 120) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _classify(command: str, args: list[str]) -> str | None:
    """Return a risk class for a stdio launch command, or None if known-good."""
    bin_name = _basename(command)
    joined_args = " ".join(args)
    full = f"{command} {joined_args}".strip()

    # 1. Shell wrappers — always suspect.
    if bin_name in _SHELL_WRAPPERS:
        return RISK_SHELL_WRAPPER

    # 2. Remote pipes — curl/wget into a shell.
    if bin_name in _REMOTE_FETCHERS:
        return RISK_REMOTE_PIPE
    if "|" in full and any(s in full for s in ("curl ", "wget ", "http://", "https://")):
        return RISK_REMOTE_PIPE

    # 3. npx — known launcher, but version + scope must check out.
    if bin_name == "npx":
        return _classify_npx(args)

    # 4. uvx / uv tool run — pinned form is fine.
    if bin_name in {"uvx", "uv"}:
        return _classify_uvx(args)

    # 5. python -m <module> — pinned-by-environment, accept.
    if bin_name in {"python", "python3"}:
        if "-m" in args:
            return None
        return RISK_UNKNOWN_BINARY

    # 6. node / deno / bun running a local script: accept if path-like local file.
    if bin_name in {"node", "deno", "bun"}:
        if args and args[0].startswith(("/", "./", "../")):
            return None
        return RISK_UNKNOWN_BINARY

    # 7. Direct absolute path — accept (user vetted it).
    if command.startswith("/") or command.startswith("./") or command.startswith("../"):
        return None

    # 8. Bare binary name on PATH — unknown territory.
    return RISK_UNKNOWN_BINARY


def _classify_npx(args: list[str]) -> str | None:
    """Return risk class for npx args, or None if known-good."""
    # Strip flag tokens like -y, --yes, --package=...
    pkg_token: str | None = None
    for a in args:
        if a.startswith("-"):
            continue
        pkg_token = a
        break

    if pkg_token is None:
        return RISK_UNPINNED_NPX

    # Extract the package spec (everything before any extra positional args).
    pkg = pkg_token

    # Trusted scope?
    is_trusted_scope = any(pkg.startswith(s) for s in _TRUSTED_NPM_SCOPES)

    # Pinned version? Look for `@<digit>` or other comparator AFTER the scope.
    # For scoped packages: @scope/name@1.2.3 → second '@' indicates version.
    if pkg.startswith("@"):
        # scoped package
        rest = pkg[1:]
        has_version = "@" in rest
    else:
        has_version = "@" in pkg

    if is_trusted_scope and has_version:
        return None
    if is_trusted_scope and not has_version:
        # Trusted publisher but no version pin — still risky (supply-chain).
        return RISK_UNPINNED_NPX
    if not has_version:
        return RISK_UNPINNED_NPX
    # Has a version but unscoped / untrusted author.
    if not is_trusted_scope and not pkg.startswith("@"):
        return RISK_UNTRUSTED_AUTHOR
    return RISK_UNTRUSTED_AUTHOR


def _classify_uvx(args: list[str]) -> str | None:
    """Return risk class for uvx/uv args, or None if known-good."""
    # `uv tool run <pkg>` or `uvx <pkg>`
    positional = [a for a in args if not a.startswith("-")]
    # Drop subcommand tokens for `uv` (e.g. tool run).
    if positional and positional[0] == "tool":
        positional = positional[2:] if len(positional) > 2 else []
    if not positional:
        return RISK_UNPINNED_NPX
    pkg = positional[0]
    if "==" in pkg or _SEMVER_RE.search(pkg):
        return None
    return RISK_UNPINNED_NPX


def _is_stdio_transport(server: dict[str, Any]) -> bool:
    """Return True if the server entry uses stdio transport.

    Stdio is the default when no transport/url is specified and a `command`
    field is present. Servers using sse/http transports usually expose a
    `url` field instead of `command`.
    """
    transport = server.get("transport") or server.get("type")
    remote_transports = {"sse", "http", "streamable-http", "websocket", "ws"}
    if isinstance(transport, str) and transport.lower() in remote_transports:
        return False
    if "url" in server and "command" not in server:
        return False
    return "command" in server


def _examine_config(config_path: str, client_name: str) -> tuple[int, list[FlaggedServer]]:
    """Read a single config file and return (servers_examined, flagged_list)."""
    examined = 0
    flagged: list[FlaggedServer] = []
    try:
        text = Path(config_path).read_text(encoding="utf-8")
        config = json.loads(text)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.debug("skipping %s: %s", config_path, exc)
        return 0, []

    servers = config.get("mcpServers", {})
    if not isinstance(servers, dict):
        return 0, []

    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        if not _is_stdio_transport(server):
            continue
        examined += 1

        command = str(server.get("command", "")).strip()
        raw_args = server.get("args", [])
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
        full_command = f"{command} {' '.join(args)}".strip()

        risk = _classify(command, args)
        if risk is None:
            continue

        flagged.append(
            FlaggedServer(
                config_path=config_path,
                client_name=client_name,
                server_name=str(server_name),
                command=command,
                args=args,
                full_command=_truncate(full_command),
                risk_class=risk,
                mitigation=_MITIGATION[risk],
            )
        )

    return examined, flagged


# ── Public entry points ───────────────────────────────────────────


def run_scan(extra_paths: list[str] | None = None) -> StdioFlawReport:
    """Discover MCP configs and scan for STDIO-flaw exposure.

    Pure local — no network calls. Returns a structured report.
    """
    configs = discover_configs(extra_paths=extra_paths)
    total_examined = 0
    flagged: list[FlaggedServer] = []

    for entry in configs:
        examined, found = _examine_config(entry["path"], entry["client_name"])
        total_examined += examined
        flagged.extend(found)

    return StdioFlawReport(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        configs_scanned=len(configs),
        servers_examined=total_examined,
        servers_flagged=len(flagged),
        flagged=flagged,
    )


# ── Renderers ─────────────────────────────────────────────────────

_PREAMBLE = (
    "This scan detects the MCP STDIO transport class of vulnerability "
    "disclosed by Ox researchers in April 2026 (~200,000 servers affected, "
    "150M+ downloads). Anthropic declined to patch."
)


def render_markdown(report: StdioFlawReport) -> str:
    lines: list[str] = []
    lines.append("# navil audit-deps --stdio-flaw")
    lines.append("")
    lines.append(f"_Generated: {report.generated_at}_")
    lines.append("")
    lines.append("> " + _PREAMBLE)
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Configs scanned : **{report.configs_scanned}**")
    lines.append(f"- Servers examined: **{report.servers_examined}**")
    lines.append(f"- Servers flagged : **{report.servers_flagged}**")
    lines.append("")

    if not report.flagged:
        lines.append("No STDIO-flaw exposure detected. ✓")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Flagged servers")
    lines.append("")
    lines.append("| Config | Server | Risk | Command | Mitigation |")
    lines.append("|---|---|---|---|---|")
    for f in report.flagged:
        cmd_cell = f"`{f.full_command}`".replace("|", "\\|")
        lines.append(
            f"| `{f.config_path}` | `{f.server_name}` | **{f.risk_class}** | "
            f"{cmd_cell} | {f.mitigation} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_json(report: StdioFlawReport) -> str:
    payload: dict[str, Any] = {
        "generated_at": report.generated_at,
        "configs_scanned": report.configs_scanned,
        "servers_examined": report.servers_examined,
        "servers_flagged": report.servers_flagged,
        "flagged": [asdict(f) for f in report.flagged],
        "preamble": _PREAMBLE,
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"
