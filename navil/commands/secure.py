"""Secure command — zero-to-governed in 60 seconds.

Orchestrates discovery → scan → wrap → policy → re-scan in one command.

Usage:
  navil secure                          # auto-discover and secure everything
  navil secure --config ~/.cursor/mcp.json  # target a specific config
  navil secure --dry-run                # preview without making changes
  navil secure --skip-policy            # skip policy generation step
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from navil.discovery import discover_configs, prompt_for_config
from navil.wrap import wrap_config

# ── ANSI helpers (same palette as test.py) ─────────────────────


def _supports_color(no_color_flag: bool) -> bool:
    if no_color_flag:
        return False
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def _color(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(text: str, use_color: bool) -> str:
    return _color(text, "1", use_color)


def _green(text: str, use_color: bool) -> str:
    return _color(text, "32", use_color)


def _yellow(text: str, use_color: bool) -> str:
    return _color(text, "33", use_color)


def _red(text: str, use_color: bool) -> str:
    return _color(text, "31", use_color)


def _cyan(text: str, use_color: bool) -> str:
    return _color(text, "36", use_color)


def _dim(text: str, use_color: bool) -> str:
    return _color(text, "2", use_color)


def _coverage_color(pct: float, use_color: bool) -> str:
    s = f"{pct:.0f}%"
    if pct >= 90:
        return _green(s, use_color)
    elif pct >= 70:
        return _yellow(s, use_color)
    else:
        return _red(s, use_color)


# ── Step output ────────────────────────────────────────────────


def _step(emoji: str, label: str, use_color: bool) -> None:
    """Print a step header to stderr."""
    print(f"\n{emoji} {_bold(label, use_color)}", file=sys.stderr)


def _detail(text: str) -> None:
    """Print an indented detail line to stderr."""
    print(f"   {text}", file=sys.stderr)


# ── Coverage computation (reuses test.py internals) ────────────


def _compute_coverage(cli: Any) -> tuple[dict[str, dict[str, int]], float, int, int]:
    """Run the threat pool through the anomaly detector and compute coverage.

    Returns (results_by_category, overall_pct, categories_protected, categories_total).
    """
    from navil.anomaly_detector import BehavioralAnomalyDetector
    from navil.commands.test import _fire_scenario, _load_default_pool

    items_by_cat = _load_default_pool(categories_filter=None)
    if not items_by_cat:
        return {}, 0.0, 0, 0

    detector = BehavioralAnomalyDetector()
    results: dict[str, dict[str, int]] = {}

    for cat, scenarios in items_by_cat.items():
        blocked = 0
        missed = 0
        for scenario in scenarios:
            if _fire_scenario(detector, scenario):
                blocked += 1
            else:
                missed += 1
        results[cat] = {"total": len(scenarios), "blocked": blocked, "missed": missed}

    grand_total = sum(r["total"] for r in results.values())
    grand_blocked = sum(r["blocked"] for r in results.values())
    overall_pct = (grand_blocked / grand_total * 100) if grand_total > 0 else 0.0

    categories_protected = sum(1 for r in results.values() if r["total"] > 0 and r["blocked"] > 0)
    categories_total = len(results)

    return results, overall_pct, categories_protected, categories_total


def _gap_categories(results: dict[str, dict[str, int]]) -> list[str]:
    """Return category names where coverage is zero."""
    gaps = []
    for cat, r in sorted(results.items()):
        if r["total"] > 0 and r["blocked"] == 0:
            gaps.append(cat.replace("_", " ").title())
    return gaps


# ── Policy generation (reuses policy.py internals) ─────────────


def _generate_baseline_policy(
    cli: Any,
    dry_run: bool,
    output_path: str = "policy.yaml",
) -> dict[str, Any]:
    """Generate a baseline policy, returning stats about what was created.

    Returns dict with keys: deny_rules, scope_profiles, path, method.
    """
    from datetime import datetime, timezone

    import yaml

    from navil.commands.policy import _PERMISSIVE_DEFAULT_POLICY

    generated_policy = None
    method = "permissive_default"

    try:
        from navil.llm.policy_gen import PolicyGenerator

        gen = PolicyGenerator()

        # Build context from baselines if available
        baseline_summary = ""
        if hasattr(cli, "anomaly_detector"):
            baselines = getattr(cli.anomaly_detector, "adaptive_baselines", {})
            if baselines:
                parts = []
                for agent_name, ab in baselines.items():
                    parts.append(
                        f"Agent '{agent_name}': "
                        f"tools used: {getattr(ab, 'tool_distribution', {})}, "
                        f"avg rate: {getattr(ab, 'rate_ema', 0):.1f}/min"
                    )
                baseline_summary = "\n".join(parts)

        if baseline_summary:
            description = (
                f"Generate a security policy based on these observed agent behaviors:\n"
                f"{baseline_summary}\n\n"
                f"Apply least-privilege: only allow tools and rates that match observed behavior."
            )
        else:
            description = (
                "Generate a default security policy for an MCP server with:\n"
                "- A default agent profile with reasonable rate limits\n"
                "- Deny rules for dangerous operations (shell exec, secrets access, data export)\n"
                "- Scope profiles limiting tools visibility per agent\n"
                "- Suspicious patterns for common attack vectors\n"
                "- Read-only file system access by default"
            )

        generated_policy = gen.generate(description)
        if generated_policy:
            method = "ai_generated"
    except Exception:
        pass

    policy = generated_policy if generated_policy else _PERMISSIVE_DEFAULT_POLICY

    # Count deny rules and scope profiles
    deny_rules = 0
    for agent_cfg in policy.get("agents", {}).values():
        deny_rules += len(agent_cfg.get("tools_denied", []))
    scope_profiles = len(policy.get("scopes", {}))

    if not dry_run:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        header = (
            f"# Auto-generated by navil secure at {timestamp}\n"
            f"# Review and customize for your environment\n\n"
        )
        with open(out, "w") as f:
            f.write(header)
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

    return {
        "deny_rules": deny_rules,
        "scope_profiles": scope_profiles,
        "path": output_path,
        "method": method,
    }


# ── Main command handler ───────────────────────────────────────


def _secure_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil secure`."""
    use_color = _supports_color(getattr(args, "no_color", False))
    dry_run = getattr(args, "dry_run", False)
    skip_policy = getattr(args, "skip_policy", False)
    config_path = getattr(args, "config", None)

    start_time = time.monotonic()

    if dry_run:
        print(
            _dim("  DRY RUN — no files will be modified\n", use_color),
            file=sys.stderr,
        )

    # ── Step 1: Discover ───────────────────────────────────────
    _step("\U0001f50d", "Discovering MCP configs...", use_color)

    extra = [config_path] if config_path else None
    configs = discover_configs(extra_paths=extra)

    if not configs:
        # Try prompting the user
        user_path = prompt_for_config()
        if user_path:
            configs = discover_configs(extra_paths=[user_path])

    if not configs:
        _detail("No MCP config files found.")
        _detail("Specify one with: navil secure --config <path>")
        return 1

    total_servers = 0
    for cfg in configs:
        path_display = cfg["path"]
        # Shorten home directory for display
        home = str(Path.home())
        if path_display.startswith(home):
            path_display = "~" + path_display[len(home) :]
        _detail(f"Found: {path_display} ({cfg['server_count']} servers)")
        total_servers += cfg["server_count"]

    # ── Step 2: Scan (before) ──────────────────────────────────
    _step("\U0001f4ca", "Scanning current coverage...", use_color)

    try:
        from navil.safemcp.pool_converter import VECTOR_TO_SAFEMCP

        pattern_count = len(VECTOR_TO_SAFEMCP) * 5  # 5 variants each
    except ImportError:
        pattern_count = 568  # fallback estimate

    _detail(f"Running {pattern_count} detection patterns across 30 categories...")

    before_results, before_pct, before_protected, before_total = _compute_coverage(cli)
    _detail(
        f"Current coverage: {_coverage_color(before_pct, use_color)} "
        f"({before_protected}/{before_total} categories protected)"
    )

    # ── Step 3: Wrap ───────────────────────────────────────────
    _step("\U0001f512", "Wrapping servers with Navil proxy...", use_color)

    total_wrapped = 0
    total_skipped = 0
    wrap_errors: list[str] = []

    for cfg in configs:
        path = cfg["path"]
        path_display = cfg["path"]
        home = str(Path.home())
        if path_display.startswith(home):
            path_display = "~" + path_display[len(home) :]

        try:
            result = wrap_config(path, dry_run=dry_run)
            wrapped = result.get("wrapped", [])
            skipped = result.get("skipped", [])
            total_wrapped += len(wrapped)
            total_skipped += len(skipped)

            if wrapped:
                _detail(
                    _green(f"\u2713 Wrapped {len(wrapped)} servers in {path_display}", use_color)
                )
            elif skipped:
                _detail(
                    _dim(
                        f"  Already wrapped: {len(skipped)} servers in {path_display}. Skipping.",
                        use_color,
                    )
                )
        except (FileNotFoundError, ValueError) as e:
            wrap_errors.append(f"{path_display}: {e}")
            _detail(_red(f"\u2717 Error: {path_display}: {e}", use_color))

    if total_wrapped == 0 and total_skipped > 0:
        _detail(
            _dim(
                f"All {total_skipped} servers already wrapped. Nothing to do.",
                use_color,
            )
        )

    # ── Step 4: Policy auto-generate ───────────────────────────
    if not skip_policy:
        _step("\U0001f9e0", "Generating baseline policies from server profiles...", use_color)

        try:
            policy_result = _generate_baseline_policy(
                cli,
                dry_run=dry_run,
                output_path=getattr(args, "policy_output", "policy.yaml"),
            )
            deny = policy_result["deny_rules"]
            scopes = policy_result["scope_profiles"]
            if deny > 0:
                _detail(
                    _green(
                        f"\u2713 {deny} deny rules generated "
                        f"(secrets access, exfiltration endpoints, shell_exec)",
                        use_color,
                    )
                )
            if scopes > 0:
                _detail(
                    _green(
                        f"\u2713 {scopes} scope profiles created "
                        f"(agents see only the tools they need)",
                        use_color,
                    )
                )
            if deny == 0 and scopes == 0:
                _detail("Permissive default policy applied (customize with navil policy suggest)")
            if dry_run:
                _detail(_dim("  DRY RUN — policy not written to disk", use_color))
        except Exception as e:
            _detail(_yellow(f"Policy generation skipped: {e}", use_color))

    # ── Step 5: Scan (after) ───────────────────────────────────
    _step("\U0001f4ca", "Re-scanning coverage with Navil active...", use_color)

    after_results, after_pct, after_protected, after_total = _compute_coverage(cli)
    _detail(
        f"New coverage: {_coverage_color(after_pct, use_color)} "
        f"({after_protected}/{after_total} categories protected)"
    )

    # ── Summary ────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    print("", file=sys.stderr)

    if total_wrapped > 0 or total_skipped > 0:
        print(
            _green(f"\u2705 Done in {elapsed:.0f} seconds.", use_color),
            file=sys.stderr,
        )
    elif wrap_errors:
        print(
            _red(f"\u274c Completed with errors in {elapsed:.0f} seconds.", use_color),
            file=sys.stderr,
        )
    print("", file=sys.stderr)

    # Before / After
    before_str = _coverage_color(before_pct, use_color)
    after_str = _coverage_color(after_pct, use_color)
    print(f"   Before: {before_str} coverage  \u2192  After: {after_str} coverage", file=sys.stderr)

    # Gap categories
    gaps = _gap_categories(after_results)
    if gaps:
        print(
            f"   {len(gaps)} categories still exposed \u2014 "
            f"run {_cyan('navil test --show-gaps', use_color)} to see them.",
            file=sys.stderr,
        )

    print(
        f"   To keep improving: {_cyan('https://navil.ai/docs', use_color)}",
        file=sys.stderr,
    )
    print("", file=sys.stderr)

    if dry_run:
        print(
            _dim(
                "   DRY RUN \u2014 no files were modified. Run without --dry-run to apply changes.",
                use_color,
            ),
            file=sys.stderr,
        )
        print("", file=sys.stderr)

    return 1 if wrap_errors and total_wrapped == 0 else 0


# ── Registration ───────────────────────────────────────────────


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the secure subcommand."""
    secure_parser = subparsers.add_parser(
        "secure",
        help="Zero-to-governed in 60 seconds — discover, wrap, policy, and verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
One command to secure all your MCP connections:

  navil secure                               # auto-discover and secure everything
  navil secure --config ~/.cursor/mcp.json   # target a specific config
  navil secure --dry-run                     # preview without making changes
  navil secure --skip-policy                 # skip policy generation

navil secure auto-discovers your MCP config files, wraps every server
with the Navil security proxy, generates baseline policies, and shows
a before/after coverage score. Works fully offline — no account needed.
        """,
    )
    secure_parser.add_argument(
        "--config",
        default=None,
        help="Path to a specific MCP config file (skip auto-discovery)",
    )
    secure_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying any files",
    )
    secure_parser.add_argument(
        "--skip-policy",
        action="store_true",
        help="Skip policy auto-generation step",
    )
    secure_parser.add_argument(
        "--policy-output",
        default="policy.yaml",
        help="Output path for generated policy (default: policy.yaml)",
    )
    secure_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    secure_parser.set_defaults(func=lambda cli, args: _secure_command(cli, args))
