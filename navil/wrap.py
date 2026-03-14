"""
navil wrap — one-command OpenClaw / Claude Desktop config patcher.

Reads an MCP client config (openclaw.json, claude_desktop_config.json, etc.),
wraps every MCP server entry with ``navil shim``, and writes the secured
config back.  The original file is backed up as ``<name>.backup.json``.

Usage:
    navil wrap openclaw.json                  # wrap all servers
    navil wrap openclaw.json --only fs,git    # wrap specific servers
    navil wrap openclaw.json --policy p.yaml  # attach a policy to every shim
    navil wrap openclaw.json --undo           # restore the backup
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any


def _is_already_wrapped(entry: dict[str, Any]) -> bool:
    """Return True if this mcpServers entry already uses navil shim."""
    cmd = entry.get("command", "")
    args = entry.get("args", [])
    # Direct command match
    if cmd == "navil" and args and args[0] == "shim":
        return True
    # Full path match (e.g. /usr/local/bin/navil)
    return cmd.endswith("/navil") and bool(args) and args[0] == "shim"


def _build_original_command(entry: dict[str, Any]) -> str:
    """Reconstruct the original command string from command + args."""
    import shlex

    parts = [entry["command"]] + entry.get("args", [])
    return " ".join(shlex.quote(p) for p in parts)


def _wrap_entry(
    entry: dict[str, Any],
    server_name: str,
    policy_path: str | None = None,
    agent_prefix: str | None = None,
) -> dict[str, Any]:
    """Wrap a single mcpServers entry with navil shim."""
    original_cmd = _build_original_command(entry)
    agent_name = f"{agent_prefix or 'navil'}-{server_name}"

    new_args = ["shim", "--cmd", original_cmd, "--agent", agent_name]
    if policy_path:
        new_args.extend(["--policy", policy_path])

    wrapped = dict(entry)
    wrapped["command"] = "navil"
    wrapped["args"] = new_args
    # Preserve env, cwd, etc. — they pass through to the child process

    return wrapped


def _unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Reverse a navil shim wrap back to the original command."""
    import shlex

    args = entry.get("args", [])
    if not args or args[0] != "shim":
        return entry  # not wrapped

    # Parse --cmd value from args
    original_cmd = None
    i = 1
    while i < len(args):
        if args[i] == "--cmd" and i + 1 < len(args):
            original_cmd = args[i + 1]
            break
        i += 1

    if not original_cmd:
        return entry  # malformed, leave as-is

    parts = shlex.split(original_cmd)
    unwrapped = dict(entry)
    unwrapped["command"] = parts[0]
    unwrapped["args"] = parts[1:] if len(parts) > 1 else []
    return unwrapped


def wrap_config(
    config_path: str,
    *,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    policy_path: str | None = None,
    agent_prefix: str | None = None,
    undo: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Patch an MCP client config to wrap servers with navil shim.

    Returns a summary dict with keys:
        wrapped: list of server names that were wrapped
        skipped: list of server names that were skipped (already wrapped or filtered)
        total: total server count
        output_path: path where the config was written
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    backup_path = path.with_suffix(".backup.json")

    # —— Undo mode ——
    if undo:
        if backup_path.exists():
            shutil.copy2(backup_path, path)
            return {"restored": True, "backup": str(backup_path), "output_path": str(path)}
        # No backup → try to unwrap in-place
        config = json.loads(path.read_text())
        servers = config.get("mcpServers", {})
        unwrapped_names = []
        for name, entry in servers.items():
            if _is_already_wrapped(entry):
                servers[name] = _unwrap_entry(entry)
                unwrapped_names.append(name)
        config["mcpServers"] = servers
        if not dry_run:
            path.write_text(json.dumps(config, indent=2) + "\n")
        return {"unwrapped": unwrapped_names, "output_path": str(path)}

    # —— Normal wrap mode ——
    config = json.loads(path.read_text())
    servers = config.get("mcpServers", {})

    if not servers:
        raise ValueError(f"No mcpServers found in {config_path}")

    # Back up original
    if not dry_run and not backup_path.exists():
        shutil.copy2(path, backup_path)

    wrapped_names: list[str] = []
    skipped_names: list[str] = []

    for name, entry in servers.items():
        # Filter logic
        if only and name not in only:
            skipped_names.append(name)
            continue
        if skip and name in skip:
            skipped_names.append(name)
            continue
        if _is_already_wrapped(entry):
            skipped_names.append(name)
            continue

        servers[name] = _wrap_entry(entry, name, policy_path=policy_path, agent_prefix=agent_prefix)
        wrapped_names.append(name)

    config["mcpServers"] = servers

    if not dry_run:
        path.write_text(json.dumps(config, indent=2) + "\n")

    return {
        "wrapped": wrapped_names,
        "skipped": skipped_names,
        "total": len(servers),
        "output_path": str(path),
        "backup_path": str(backup_path) if not dry_run else None,
    }


def print_summary(result: dict[str, Any], undo: bool = False) -> None:
    """Pretty-print the wrap/unwrap result to stderr."""
    if undo:
        if result.get("restored"):
            print(f"✓ Restored from backup: {result['backup']}", file=sys.stderr)
        elif result.get("unwrapped"):
            names = ", ".join(result["unwrapped"])
            print(f"✓ Unwrapped {len(result['unwrapped'])} server(s): {names}", file=sys.stderr)
        else:
            print("Nothing to undo.", file=sys.stderr)
        return

    wrapped = result.get("wrapped", [])
    skipped = result.get("skipped", [])

    if wrapped:
        count = len(wrapped)
        total = result["total"]
        print(f"\n✓ Wrapped {count}/{total} MCP server(s) with navil shim:\n", file=sys.stderr)
        for name in wrapped:
            print(f"  → {name}", file=sys.stderr)
    if skipped:
        names = ", ".join(skipped)
        print(f"\n  Skipped {len(skipped)}: {names} (already wrapped or filtered)", file=sys.stderr)
    if result.get("backup_path"):
        print(f"\n  Backup saved: {result['backup_path']}", file=sys.stderr)
    print(f"  Config written: {result['output_path']}\n", file=sys.stderr)

    if wrapped:
        print(
            "Your MCP servers are now protected. "
            "Run your agent as usual — navil shim is transparent.",
            file=sys.stderr,
        )
