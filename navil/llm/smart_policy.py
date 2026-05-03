# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Apache License, Version 2.0 (see LICENSE)
"""LLM-driven least-privilege policy generator with per-rule rationale.

Reads MCP configs + tool-call audit logs, aggregates usage stats, asks an
LLM to reason like a security researcher, and emits both a strict
``navil.yaml`` policy AND a ``navil-policy.md`` rationale document.

Design notes:
  * The SAFE-MCP threat catalog is large and static; we send it as a
    cached system block (Anthropic ``cache_control: ephemeral``) so
    subsequent invocations are cheap.
  * If no ``ANTHROPIC_API_KEY`` is set, the generator degrades gracefully
    to a rule-based default (the existing baseline).
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Models used elsewhere in the project. Keep the override env-var consistent.
DEFAULT_MODEL = os.environ.get("NAVIL_SMART_POLICY_MODEL", "claude-sonnet-4-20250514")

# Tools that imply elevated risk — used to flag rules in the prompt.
_SENSITIVE_TOOL_PATTERNS = [
    (re.compile(r"(?i)\bwrite\b|\bedit\b|\bcreate\b|\bdelete\b|\bremove\b"), "filesystem_write"),
    (re.compile(r"(?i)\bexec\b|\bshell\b|\brun_command\b|\bbash\b"), "code_execution"),
    (re.compile(r"(?i)\bfetch\b|\bhttp\b|\bcurl\b|\bnetwork\b|\bpost\b"), "network_egress"),
    (re.compile(r"(?i)\bsecret\b|\bcredential\b|\bkey\b|\btoken\b|\bauth\b"), "credential_access"),
    (re.compile(r"(?i)\bdb\b|\bsql\b|\bquery\b|\bdatabase\b"), "data_access"),
]


# ── SAFE-MCP catalog (static; cached on the LLM side) ──────────────
SAFE_MCP_CATALOG = """\
SAFE-MCP threat catalog (subset, agent-relevant):

AC-01 prompt_injection      — adversarial input bypasses agent intent.
AC-02 data_exfiltration     — tool call siphons sensitive context to attacker-controlled sink.
AC-03 credential_access     — tool reads .env, keychain, tokens, API keys.
AC-04 privilege_escalation  — agent gains capabilities beyond its declared scope.
AC-05 code_execution        — shell_exec/eval-class tools allow arbitrary RCE.
AC-06 supply_chain          — typosquatted/poisoned MCP package or dependency.
AC-07 lateral_movement      — agent calls tools across servers it should not see.
AC-08 tool_poisoning        — exposed-but-unused tool becomes attack surface.
AC-09 tool_schema_injection — malicious tool description manipulates the agent.
AC-10 cross_tenant_leakage  — one agent's data visible to another via shared scope.
AC-11 delegation_abuse      — sub-agent invoked with inflated authority.
AC-12 covert_channel        — encoded data exfil via legitimate-looking tool output.
AC-13 rag_memory_poisoning  — long-lived memory store contaminated.
AC-14 output_weaponization  — tool returns injected content that re-prompts agent.
AC-15 configuration_tampering — agent modifies its own policy/MCP config.
AC-16 denial_of_service     — runaway loops / token-burn / rate spikes.

Rule-writing principles for navil.yaml:
  1. Default-deny. Only allow tools observed in the audit log AND
     justified by a documented use case.
  2. For each agent, list ``tools_allowed`` explicitly — never use ``"*"``.
  3. Add ``tools_denied`` entries for sensitive patterns the agent did
     NOT exercise (these are the AC-08 tool-poisoning surface area).
  4. ``rate_limit_per_hour`` should be ~3x the observed peak (headroom
     without uncapped runaway).
  5. ``data_clearance`` — minimum tier that covers observed tool families.
  6. Each agent block MUST be preceded by a ``# rationale:`` comment that
     names the SAFE-MCP code(s) the rule mitigates and cites the usage
     stat that justified the decision.
"""


# ── Stats aggregation ──────────────────────────────────────────────


@dataclass
class AgentUsageStats:
    """Per-agent aggregated tool-call statistics."""

    agent: str
    total_calls: int = 0
    tool_counts: Counter[str] = field(default_factory=Counter)
    decisions: Counter[str] = field(default_factory=Counter)
    first_seen: str | None = None
    last_seen: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "total_calls": self.total_calls,
            "tool_counts": dict(self.tool_counts.most_common()),
            "decisions": dict(self.decisions),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def load_audit_log(path: Path) -> list[dict[str, Any]]:
    """Load a JSONL audit log. Each line: {agent, tool, timestamp, decision}.

    Returns an empty list for missing/empty/unreadable files.
    """
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    return records


def aggregate_usage(
    records: list[dict[str, Any]],
    exposed_tools_by_agent: dict[str, set[str]] | None = None,
) -> dict[str, AgentUsageStats]:
    """Aggregate records into per-agent stats."""
    out: dict[str, AgentUsageStats] = {}
    for rec in records:
        agent = str(rec.get("agent") or rec.get("agent_name") or "unknown")
        tool = str(rec.get("tool") or rec.get("tool_name") or "unknown")
        ts = rec.get("timestamp")
        decision = str(rec.get("decision") or "ALLOW")

        stats = out.setdefault(agent, AgentUsageStats(agent=agent))
        stats.total_calls += 1
        stats.tool_counts[tool] += 1
        stats.decisions[decision] += 1
        if ts:
            ts_str = str(ts)
            if stats.first_seen is None or ts_str < stats.first_seen:
                stats.first_seen = ts_str
            if stats.last_seen is None or ts_str > stats.last_seen:
                stats.last_seen = ts_str

    # Make sure every observed agent has an entry even if exposed-only
    if exposed_tools_by_agent:
        for agent in exposed_tools_by_agent:
            out.setdefault(agent, AgentUsageStats(agent=agent))
    return out


def _tools_from_mcp_config(config: dict[str, Any]) -> set[str]:
    """Extract MCP server names as a coarse 'exposed tool surface'."""
    servers = config.get("mcpServers", {})
    if isinstance(servers, dict):
        return set(servers.keys())
    return set()


def discover_exposed_tools() -> dict[str, set[str]]:
    """Read all discovered MCP configs and return server name sets per client."""
    try:
        from navil.discovery import discover_configs
    except Exception:
        return {}
    out: dict[str, set[str]] = {}
    for entry in discover_configs():
        path = Path(entry["path"])
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out[str(entry.get("client_name", path.name))] = _tools_from_mcp_config(cfg)
    return out


def _classify_sensitive(tool: str) -> list[str]:
    return [tag for pat, tag in _SENSITIVE_TOOL_PATTERNS if pat.search(tool)]


def build_analysis_context(
    stats: dict[str, AgentUsageStats],
    exposed: dict[str, set[str]],
) -> dict[str, Any]:
    """Compute the structured analysis the LLM will reason over."""
    all_exposed: set[str] = set().union(*exposed.values()) if exposed else set()
    used: set[str] = set()
    for s in stats.values():
        used.update(s.tool_counts.keys())

    never_called = sorted(all_exposed - used)
    rarely_called: list[str] = []
    sensitive_used: list[dict[str, Any]] = []

    for s in stats.values():
        for tool, count in s.tool_counts.items():
            if count <= 2 and s.total_calls >= 10:
                rarely_called.append(f"{s.agent}::{tool} ({count} calls)")
            tags = _classify_sensitive(tool)
            if tags:
                sensitive_used.append(
                    {"agent": s.agent, "tool": tool, "tags": tags, "count": count}
                )

    return {
        "agents": {a: s.as_dict() for a, s in stats.items()},
        "exposed_tools_by_client": {k: sorted(v) for k, v in exposed.items()},
        "never_called_but_exposed": never_called,
        "rarely_called": rarely_called,
        "sensitive_used": sensitive_used,
    }


# ── Rule-based fallback ───────────────────────────────────────────


def fallback_policy(context: dict[str, Any]) -> tuple[str, str]:
    """Deterministic policy generator used when no API key is present.

    Returns (yaml_text, rationale_md).
    """
    agents_block: dict[str, Any] = {}
    rationale_lines: list[str] = [
        "# Navil Policy Rationale (rule-based fallback)",
        "",
        "Generated without LLM (no ANTHROPIC_API_KEY). Each agent rule is",
        "derived directly from observed usage: only tools actually called",
        "are allowed; everything else is denied.",
        "",
    ]

    agents_data = context.get("agents", {})
    if not agents_data:
        agents_block["default"] = {
            "tools_allowed": [],
            "tools_denied": [],
            "rate_limit_per_hour": 60,
            "data_clearance": "PUBLIC",
        }
        rationale_lines.append(
            "- **default**: no audit log records observed. Default-deny "
            "with rate_limit=60 (SAFE-MCP AC-16)."
        )
    else:
        for agent_name, s in agents_data.items():
            tool_counts: dict[str, int] = s.get("tool_counts", {})
            tools_allowed = sorted(tool_counts.keys())
            peak = max(tool_counts.values()) if tool_counts else 0
            rate_limit = max(60, peak * 3)
            agents_block[agent_name] = {
                "tools_allowed": tools_allowed,
                "tools_denied": sorted(context.get("never_called_but_exposed", [])),
                "rate_limit_per_hour": rate_limit,
                "data_clearance": "INTERNAL",
            }
            rationale_lines.append(
                f"- **{agent_name}**: {len(tools_allowed)} tools allowed "
                f"(observed in audit log); {len(context.get('never_called_but_exposed', []))} "
                f"exposed-but-unused tools denied (SAFE-MCP AC-08); "
                f"rate_limit={rate_limit}/hr (3x observed peak {peak}, AC-16)."
            )

    policy = {
        "version": "1.0",
        "agents": agents_block,
        "scopes": {},
        "suspicious_patterns": [
            {
                "name": "credential_access_attempt",
                "tool": "*",
                "actions": ["read"],
                "alert_level": "HIGH",
            }
        ],
    }

    # Produce YAML with rationale comments inline
    yaml_lines = [
        "# Navil policy — rule-based fallback (no LLM)",
        "# rationale: see navil-policy.md for per-rule justification",
        "",
        yaml.dump(policy, default_flow_style=False, sort_keys=False),
    ]
    return "\n".join(yaml_lines), "\n".join(rationale_lines) + "\n"


# ── LLM call with prompt caching ──────────────────────────────────


def _build_user_prompt(context: dict[str, Any]) -> str:
    return (
        "Analyze the following MCP exposure + audit data and emit a "
        "least-privilege navil.yaml policy plus a rationale document.\n\n"
        "## Observed exposure & usage (JSON)\n"
        "```json\n"
        f"{json.dumps(context, indent=2, default=str)}\n"
        "```\n\n"
        "## Output format (STRICT)\n"
        "Respond with two fenced blocks, in this order:\n"
        "1. ```yaml ... ``` containing the full navil.yaml. Each agent "
        "entry MUST be preceded by a `# rationale: ...` comment naming "
        "the SAFE-MCP code(s) and citing the usage stat that justifies it.\n"
        "2. ```markdown ... ``` containing a 'Navil Policy Rationale' "
        "document a security team can defend in review: per-rule, what "
        "it blocks, what threat it maps to in SAFE-MCP, why this rule exists."
    )


_LLM_SYSTEM = (
    "You are a senior application-security engineer specialising in "
    "MCP-based agent systems. You reason about agent capabilities the "
    "way a security researcher reasons about code: every grant is a "
    "blast-radius decision, every unused exposed tool is a tool-poisoning "
    "vector. Your output is a defendable least-privilege policy."
)


def _call_anthropic(context: dict[str, Any], model: str) -> str:
    """Call the Anthropic API with prompt caching for the SAFE-MCP catalog."""
    import anthropic  # type: ignore[import-not-found]

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=4096,
        temperature=0.2,
        system=[
            {"type": "text", "text": _LLM_SYSTEM},
            {
                "type": "text",
                "text": SAFE_MCP_CATALOG,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        messages=[{"role": "user", "content": _build_user_prompt(context)}],
    )
    # Concatenate text blocks
    parts: list[str] = []
    for block in response.content:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)


def _split_yaml_and_md(text: str) -> tuple[str, str]:
    """Pull the yaml and markdown fenced blocks out of the LLM response."""
    yaml_match = re.search(r"```ya?ml\s*\n(.*?)```", text, re.DOTALL)
    md_match = re.search(r"```(?:markdown|md)\s*\n(.*?)```", text, re.DOTALL)
    yaml_text = yaml_match.group(1).strip() if yaml_match else ""
    md_text = md_match.group(1).strip() if md_match else ""
    if not md_text:
        # Fall back: anything after the YAML block is treated as rationale
        md_text = text[yaml_match.end() :].strip() if yaml_match else text.strip()
    return yaml_text, md_text


# ── Public API ────────────────────────────────────────────────────


def generate_policy(
    audit_log: Path | None = None,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """Generate a smart policy from observed MCP behaviour.

    Returns a dict with keys: ``yaml`` (str), ``markdown`` (str),
    ``method`` ("llm" or "fallback"), ``context`` (dict).

    Never raises for normal operation: missing logs / missing API key
    degrade to the rule-based fallback.
    """
    exposed = discover_exposed_tools()

    records: list[dict[str, Any]] = []
    if audit_log is not None:
        records = load_audit_log(audit_log)
    else:
        # Default location
        default = Path.home() / ".navil" / "tool_calls.jsonl"
        if default.exists():
            records = load_audit_log(default)

    stats = aggregate_usage(records, exposed_tools_by_agent=exposed)
    context = build_analysis_context(stats, exposed)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        yaml_text, md_text = fallback_policy(context)
        return {
            "yaml": yaml_text,
            "markdown": md_text,
            "method": "fallback",
            "context": context,
            "reason": "No ANTHROPIC_API_KEY in env; falling back to rule-based default",
        }

    try:
        raw = _call_anthropic(context, model=model)
        yaml_text, md_text = _split_yaml_and_md(raw)
        if not yaml_text:
            raise ValueError("LLM response missing yaml block")
        # Sanity check: parses as YAML
        yaml.safe_load(yaml_text)
        return {
            "yaml": yaml_text,
            "markdown": md_text or "(no rationale block returned by LLM)",
            "method": "llm",
            "context": context,
        }
    except Exception as exc:  # noqa: BLE001 — degrade on any LLM/network error
        yaml_text, md_text = fallback_policy(context)
        return {
            "yaml": yaml_text,
            "markdown": md_text,
            "method": "fallback",
            "context": context,
            "reason": f"LLM generation failed ({exc}); falling back to rule-based default",
        }
