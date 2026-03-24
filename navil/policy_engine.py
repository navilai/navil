"""
Runtime Policy Engine

Evaluates tool calls against security policies defined in YAML format.
Enforces least-privilege access, detects suspicious patterns, and logs all decisions.

Scope vs Policy Semantics (from eng review):
  - Scope = VISIBILITY: what tools an agent SEES in tools/list responses.
    Controlled by X-Navil-Scope header + scopes section in policy.yaml.
    Enforcement point: Rust proxy filters tools/list response.
  - Policy = PERMISSION: what tools an agent can CALL.
    Controlled by agents section in policy.yaml (tools_allowed/tools_denied).
    Enforcement point: Python PolicyEngine check_tool_call().
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Redis key prefix for scope definitions (read by Rust proxy)
SCOPE_REDIS_PREFIX = "navil:scope"


class PolicyDecision(Enum):
    """Policy evaluation outcome."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    ALERT = "ALERT"  # Allow but with alert


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""

    decision: str
    rule_matched: str
    reason: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    agent_name: str
    tool_name: str
    action: str
    timestamp: str


class PolicyEngine:
    """
    Runtime policy engine for evaluating tool calls.

    Features:
    - YAML-based policy definitions
    - Tool whitelisting/blacklisting
    - Rate limiting
    - Data sensitivity checking
    - Least-privilege enforcement
    - Suspicious pattern detection
    """

    def __init__(
        self,
        policy_file: str = "policy.yaml",
        auto_policy_file: str | None = None,
        redis_client: Any | None = None,
    ) -> None:
        """
        Initialize policy engine.

        Args:
            policy_file: Path to human-owned YAML policy file
            auto_policy_file: Path to machine-owned policy.auto.yaml (optional)
            redis_client: async Redis client for pushing scope defs to Rust proxy
        """
        self.policy_file = Path(policy_file)
        self.auto_policy_file = Path(auto_policy_file) if auto_policy_file else None
        self.redis = redis_client
        self.policy: dict[str, Any] = {}
        self.scopes: dict[str, list[str]] = {}  # scope_name -> [tool_names]
        self.decisions_log: list[PolicyEvaluationResult] = []
        self.rate_limits: dict[tuple[str, str], dict[str, int]] = {}
        self._rate_limit_lock = threading.Lock()
        self._load_policy()

    def _load_policy(self) -> None:
        """Load policy from YAML file(s) and extract scope definitions.

        Loads the human-owned policy.yaml first, then merges machine-owned
        policy.auto.yaml on top (human policy takes precedence for conflicts).
        Extracts scope definitions into self.scopes for Redis sync.
        """
        if not self.policy_file.exists():
            logger.warning(f"Policy file not found: {self.policy_file}, using defaults")
            self.policy = self._get_default_policy()
            self._extract_scopes()
            return

        try:
            with open(self.policy_file) as f:
                self.policy = yaml.safe_load(f) or {}
                logger.info(f"Loaded policy from {self.policy_file}")
        except Exception as e:
            logger.error(f"Failed to load policy: {e}, using defaults")
            self.policy = self._get_default_policy()

        # Merge auto-generated policy (machine-owned) if it exists
        if self.auto_policy_file and self.auto_policy_file.exists():
            try:
                with open(self.auto_policy_file) as f:
                    auto_policy = yaml.safe_load(f) or {}
                self._merge_auto_policy(auto_policy)
                logger.info(f"Merged auto policy from {self.auto_policy_file}")
            except Exception as e:
                logger.error(f"Failed to load auto policy: {e}, skipping")

        self._extract_scopes()

    def _merge_auto_policy(self, auto_policy: dict[str, Any]) -> None:
        """Merge machine-owned auto policy into the main policy.

        Human-owned policy.yaml takes precedence: if the same key exists
        in both, the human-owned value wins.
        """
        for section_key, section_val in auto_policy.items():
            if section_key not in self.policy:
                self.policy[section_key] = section_val
            elif isinstance(section_val, dict) and isinstance(self.policy[section_key], dict):
                # Merge dicts: human keys win
                for k, v in section_val.items():
                    if k not in self.policy[section_key]:
                        self.policy[section_key][k] = v

    def _extract_scopes(self) -> None:
        """Extract scope definitions from policy into self.scopes.

        Scope format in policy.yaml:
            scopes:
              github-pr-review:
                description: "Code review agent"
                tools: [pulls/get, pulls/list, reviews/create]
              default:
                tools: "*"
        """
        raw_scopes = self.policy.get("scopes", {})
        self.scopes = {}

        for scope_name, scope_def in raw_scopes.items():
            tools = scope_def.get("tools", "*") if isinstance(scope_def, dict) else scope_def

            if tools == "*":
                self.scopes[scope_name] = ["*"]
            elif isinstance(tools, list):
                self.scopes[scope_name] = [str(t) for t in tools]
            else:
                logger.warning(f"Invalid scope tools for '{scope_name}': {tools}")
                self.scopes[scope_name] = ["*"]

        logger.info(f"Extracted {len(self.scopes)} scope definitions")

    async def sync_scopes_to_redis(self) -> int:
        """Push scope definitions to Redis for the Rust proxy to read.

        Redis keys: navil:scope:{scope_name} → JSON array of tool names
        Returns the number of scopes synced.
        """
        if self.redis is None:
            logger.debug("No Redis client, skipping scope sync")
            return 0

        synced = 0
        try:
            for scope_name, tools in self.scopes.items():
                key = f"{SCOPE_REDIS_PREFIX}:{scope_name}"
                tools_json = json.dumps(tools)
                await self.redis.set(key, tools_json)
                synced += 1
            logger.info(f"Synced {synced} scope definitions to Redis")
        except Exception as e:
            logger.error(f"Failed to sync scopes to Redis: {e}")

        return synced

    def get_scope_tools(self, scope_name: str) -> list[str] | None:
        """Get the list of tools allowed for a given scope.

        Returns None if the scope is not defined (caller should fall through
        to default scope). Returns ["*"] if all tools are allowed.
        """
        if scope_name in self.scopes:
            return self.scopes[scope_name]

        # Fall through to default scope
        default_tools = self.scopes.get("default")
        if default_tools is not None:
            return default_tools

        # No default scope defined → all tools allowed
        return None

    def check_tool_call(
        self,
        agent_name: str,
        tool_name: str,
        action: str,
        params: dict[str, Any] | None = None,
        data_sensitivity: str | None = None,
    ) -> tuple[bool, str]:
        """
        Check if a tool call is allowed by policy.

        Args:
            agent_name: Name of agent making the call
            tool_name: Name of tool being called
            action: Action being performed (e.g., "read", "write", "delete")
            params: Parameters passed to the tool
            data_sensitivity: Sensitivity level of data being accessed

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Check if tool is allowed
        if not self._is_tool_allowed(agent_name, tool_name):
            reason = f"Tool '{tool_name}' is not allowed for agent '{agent_name}'"
            self._log_decision(
                decision=PolicyDecision.DENY,
                rule="TOOL_DENIED",
                reason=reason,
                severity="HIGH",
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
            )
            return False, reason

        # Check if action is allowed
        if not self._is_action_allowed(agent_name, tool_name, action):
            reason = f"Action '{action}' not allowed for tool '{tool_name}'"
            self._log_decision(
                decision=PolicyDecision.DENY,
                rule="ACTION_DENIED",
                reason=reason,
                severity="HIGH",
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
            )
            return False, reason

        # Check rate limits
        if not self._check_rate_limit(agent_name, tool_name):
            reason = f"Rate limit exceeded for agent '{agent_name}' on tool '{tool_name}'"
            self._log_decision(
                decision=PolicyDecision.DENY,
                rule="RATE_LIMIT_EXCEEDED",
                reason=reason,
                severity="MEDIUM",
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
            )
            return False, reason

        # Check data sensitivity
        if data_sensitivity and not self._is_agent_allowed_sensitivity(
            agent_name, data_sensitivity
        ):
            reason = f"Agent not authorized for {data_sensitivity} data access"
            self._log_decision(
                decision=PolicyDecision.DENY,
                rule="INSUFFICIENT_CLEARANCE",
                reason=reason,
                severity="CRITICAL",
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
            )
            return False, reason

        # Check for suspicious patterns
        suspicious, pattern = self._detect_suspicious_patterns(tool_name, action, params or {})
        if suspicious:
            reason = f"Suspicious pattern detected: {pattern}"
            self._log_decision(
                decision=PolicyDecision.ALERT,
                rule="SUSPICIOUS_PATTERN",
                reason=reason,
                severity="MEDIUM",
                agent_name=agent_name,
                tool_name=tool_name,
                action=action,
            )
            logger.warning(f"ALERT: {reason} for agent {agent_name}")

        self._log_decision(
            decision=PolicyDecision.ALLOW,
            rule="POLICY_MATCH",
            reason="Tool call matches security policy",
            severity="INFO",
            agent_name=agent_name,
            tool_name=tool_name,
            action=action,
        )

        return True, "Policy check passed"

    def _is_tool_allowed(self, agent_name: str, tool_name: str) -> bool:
        """Check if tool is allowed for agent."""
        agents = self.policy.get("agents", {})
        agent_policy = agents.get(agent_name, {})

        # Check blacklist first
        if tool_name in agent_policy.get("tools_denied", []):
            return False

        # Check whitelist
        allowed_tools = agent_policy.get("tools_allowed", [])
        return not (allowed_tools and tool_name not in allowed_tools and "*" not in allowed_tools)

    def _is_action_allowed(self, agent_name: str, tool_name: str, action: str) -> bool:
        """Check if action is allowed on tool."""
        agents = self.policy.get("agents", {})
        agent_policy = agents.get(agent_name, {})

        # Get tool policy
        tools = self.policy.get("tools", {})
        tool_policy = tools.get(tool_name, {})

        # Check allowed actions (default includes standard MCP methods)
        allowed_actions = tool_policy.get("allowed_actions", ["read", "tools/call", "tools/list"])
        if action not in allowed_actions and "*" not in allowed_actions:
            return False

        # Check agent-specific action restrictions
        action_restrictions = agent_policy.get("action_restrictions", {}).get(tool_name, [])
        return action not in action_restrictions

    def _check_rate_limit(self, agent_name: str, tool_name: str) -> bool:
        """Check if rate limit is exceeded (thread-safe)."""
        agents = self.policy.get("agents", {})
        agent_policy = agents.get(agent_name, {})
        rate_limit = agent_policy.get("rate_limit_per_hour", 1000)

        key = (agent_name, tool_name)
        current_time = int(time.time())

        with self._rate_limit_lock:
            if key not in self.rate_limits:
                self.rate_limits[key] = {"count": 0, "reset_at": current_time}

            limit_data = self.rate_limits[key]

            # Reset if hour has passed
            if current_time - limit_data["reset_at"] > 3600:
                limit_data["count"] = 0
                limit_data["reset_at"] = current_time

            # rate_limit=0 means unlimited (no cap)
            if rate_limit == 0:
                return True

            # Atomic check-and-increment
            if limit_data["count"] >= rate_limit:
                return False

            limit_data["count"] += 1
            return True

    def _is_agent_allowed_sensitivity(self, agent_name: str, sensitivity: str) -> bool:
        """Check if agent has clearance for data sensitivity level."""
        agents = self.policy.get("agents", {})
        agent_policy = agents.get(agent_name, {})

        clearance_level = agent_policy.get("data_clearance", "PUBLIC")

        # Define clearance hierarchy
        hierarchy = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}

        agent_level = hierarchy.get(clearance_level, 0)
        data_level = hierarchy.get(sensitivity, 0)

        return agent_level >= data_level

    def _detect_suspicious_patterns(
        self, tool_name: str, action: str, params: dict[str, Any]
    ) -> tuple[bool, str]:
        """Detect suspicious patterns in tool calls."""
        suspicious_patterns = self.policy.get("suspicious_patterns", [])

        for pattern in suspicious_patterns:
            tool_match = pattern.get("tool") in (tool_name, "*")
            if (
                tool_match
                and action in pattern.get("actions", [])
                and self._matches_pattern_conditions(pattern, params)
            ):
                return True, pattern.get("name", "Unknown pattern")

        # Check for common attack patterns
        param_str = str(params).lower()

        attack_indicators = [
            ("file_exfiltration", "read" in action and "/etc/" in param_str),
            (
                "sql_injection",
                ";" in param_str and ("drop" in param_str or "delete" in param_str),
            ),
            ("command_injection", "$(" in param_str or "`" in param_str),
        ]

        for pattern_name, condition in attack_indicators:
            if condition:
                return True, pattern_name

        return False, ""

    def _matches_pattern_conditions(self, pattern: dict[str, Any], params: dict[str, Any]) -> bool:
        """Check if parameters match pattern conditions."""
        conditions = pattern.get("conditions", {})

        for param_name, expected_value in conditions.items():
            if param_name not in params:
                return False
            if params[param_name] != expected_value:
                return False

        return True

    def _log_decision(
        self,
        decision: PolicyDecision,
        rule: str,
        reason: str,
        severity: str,
        agent_name: str,
        tool_name: str,
        action: str,
    ) -> None:
        """Log a policy decision."""
        result = PolicyEvaluationResult(
            decision=decision.value,
            rule_matched=rule,
            reason=reason,
            severity=severity,
            agent_name=agent_name,
            tool_name=tool_name,
            action=action,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self.decisions_log.append(result)

        if decision == PolicyDecision.DENY:
            logger.warning(f"POLICY DENIED: {reason}")
        elif decision == PolicyDecision.ALERT:
            logger.warning(f"POLICY ALERT: {reason}")

    def get_decisions_log(self) -> list[dict[str, Any]]:
        """Get policy decisions log."""
        return [
            {
                "decision": d.decision,
                "rule": d.rule_matched,
                "reason": d.reason,
                "severity": d.severity,
                "agent": d.agent_name,
                "tool": d.tool_name,
                "action": d.action,
                "timestamp": d.timestamp,
            }
            for d in self.decisions_log
        ]

    def serialize_to_yaml(self, output_path: Path | None = None) -> bool:
        """Write current policy state to a YAML file.

        By default writes to policy.auto.yaml (machine-owned).
        Includes a versioned comment header.

        Returns True on success, False on failure.
        """
        target = output_path or self.auto_policy_file
        if target is None:
            logger.error("No output path for serialize_to_yaml")
            return False

        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            header = (
                f"# auto-generated by navil at {timestamp}\n"
                "# Do not edit manually — use 'navil policy suggest' to manage\n"
                "# Human-owned rules go in policy.yaml (takes precedence)\n\n"
            )
            yaml_content = yaml.dump(self.policy, default_flow_style=False, sort_keys=False)

            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w") as f:
                f.write(header)
                f.write(yaml_content)

            logger.info(f"Serialized policy to {target}")
            return True
        except Exception as e:
            logger.error(f"Failed to serialize policy to {target}: {e}")
            return False

    def _get_default_policy(self) -> dict[str, Any]:
        """Get default security policy."""
        return {
            "version": "1.0",
            "agents": {
                "default": {
                    "tools_allowed": ["*"],
                    "tools_denied": [],
                    "actions_allowed": ["read"],
                    "rate_limit_per_hour": 1000,
                    "data_clearance": "PUBLIC",
                }
            },
            "tools": {
                "file_system": {
                    "allowed_actions": ["read"],
                },
                "network": {
                    "allowed_actions": ["read"],
                },
                "database": {
                    "allowed_actions": ["read"],
                },
            },
            "scopes": {
                "default": {
                    "description": "Default scope — all tools visible",
                    "tools": "*",
                },
            },
            "suspicious_patterns": [],
        }
