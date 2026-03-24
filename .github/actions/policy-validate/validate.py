#!/usr/bin/env python3
"""Navil policy.yaml validation script with SARIF output.

Validates policy YAML files against the Navil schema and outputs
results in SARIF format for GitHub Security tab integration.

Usage:
    python validate.py --policy policy.yaml --sarif-output results.sarif
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Policy schema definition — required fields and types
POLICY_SCHEMA: dict[str, dict[str, Any]] = {
    "version": {"type": str, "required": True},
    "agents": {"type": dict, "required": False},
    "tools": {"type": dict, "required": False},
    "scopes": {"type": dict, "required": False},
    "cli_rules": {"type": dict, "required": False},
    "suspicious_patterns": {"type": list, "required": False},
}

AGENT_SCHEMA: dict[str, dict[str, Any]] = {
    "tools_allowed": {"type": list, "required": False},
    "tools_denied": {"type": list, "required": False},
    "actions_allowed": {"type": list, "required": False},
    "rate_limit_per_hour": {"type": (int, float), "required": False},
    "data_clearance": {"type": str, "required": False},
}

SCOPE_SCHEMA: dict[str, dict[str, Any]] = {
    "description": {"type": str, "required": False},
    "tools": {"type": (list, str), "required": True},
}


def validate_policy(policy_path: Path) -> list[dict[str, Any]]:
    """Validate a policy YAML file and return a list of findings.

    Each finding is a dict with keys:
      - level: "error" | "warning" | "note"
      - message: human-readable description
      - line: approximate line number (0 if unknown)
      - rule_id: identifier for the validation rule
    """
    findings: list[dict[str, Any]] = []

    if not policy_path.exists():
        findings.append(
            {
                "level": "note",
                "message": f"Policy file not found: {policy_path}",
                "line": 0,
                "rule_id": "navil/policy-not-found",
            }
        )
        return findings

    try:
        with open(policy_path) as f:
            raw_content = f.read()
    except OSError as e:
        findings.append(
            {
                "level": "error",
                "message": f"Cannot read policy file: {e}",
                "line": 0,
                "rule_id": "navil/policy-read-error",
            }
        )
        return findings

    try:
        policy = yaml.safe_load(raw_content)
    except yaml.YAMLError as e:
        line = 0
        if hasattr(e, "problem_mark") and e.problem_mark:
            line = e.problem_mark.line + 1
        findings.append(
            {
                "level": "error",
                "message": f"Invalid YAML syntax: {e}",
                "line": line,
                "rule_id": "navil/yaml-syntax-error",
            }
        )
        return findings

    if not isinstance(policy, dict):
        findings.append(
            {
                "level": "error",
                "message": "Policy must be a YAML mapping (dict), not a scalar or list",
                "line": 1,
                "rule_id": "navil/policy-not-mapping",
            }
        )
        return findings

    # Check required fields
    if "version" not in policy:
        findings.append(
            {
                "level": "error",
                "message": "Missing required field: version",
                "line": 1,
                "rule_id": "navil/missing-version",
            }
        )

    # Check top-level field types
    for field_name, schema in POLICY_SCHEMA.items():
        if field_name in policy:
            expected_type = schema["type"]
            if not isinstance(policy[field_name], expected_type):
                findings.append(
                    {
                        "level": "error",
                        "message": (
                            f"Field '{field_name}' has wrong type: "
                            f"expected {expected_type.__name__}, "
                            f"got {type(policy[field_name]).__name__}"
                        ),
                        "line": 1,
                        "rule_id": "navil/type-error",
                    }
                )

    # Check unknown top-level fields
    known_fields = set(POLICY_SCHEMA.keys())
    for field_name in policy:
        if field_name not in known_fields:
            findings.append(
                {
                    "level": "warning",
                    "message": f"Unknown top-level field: '{field_name}'",
                    "line": 1,
                    "rule_id": "navil/unknown-field",
                }
            )

    # Validate agents section
    agents = policy.get("agents", {})
    if isinstance(agents, dict):
        for agent_name, agent_config in agents.items():
            if not isinstance(agent_config, dict):
                findings.append(
                    {
                        "level": "error",
                        "message": f"Agent '{agent_name}' config must be a mapping",
                        "line": 1,
                        "rule_id": "navil/agent-not-mapping",
                    }
                )
                continue

            # Security: warn about wildcard tool access
            tools_allowed = agent_config.get("tools_allowed", [])
            if isinstance(tools_allowed, list) and "*" in tools_allowed and agent_name != "default":
                findings.append(
                    {
                        "level": "warning",
                        "message": (
                            f"Agent '{agent_name}' has wildcard tool access. "
                            "Consider restricting to specific tools."
                        ),
                        "line": 1,
                        "rule_id": "navil/wildcard-access",
                    }
                )

    # Validate scopes section
    scopes = policy.get("scopes", {})
    if isinstance(scopes, dict):
        for scope_name, scope_def in scopes.items():
            if not isinstance(scope_def, dict):
                findings.append(
                    {
                        "level": "error",
                        "message": f"Scope '{scope_name}' must be a mapping with 'tools' key",
                        "line": 1,
                        "rule_id": "navil/scope-not-mapping",
                    }
                )
                continue

            if "tools" not in scope_def:
                findings.append(
                    {
                        "level": "error",
                        "message": f"Scope '{scope_name}' missing required 'tools' field",
                        "line": 1,
                        "rule_id": "navil/scope-missing-tools",
                    }
                )

    return findings


def findings_to_sarif(
    findings: list[dict[str, Any]],
    policy_path: str,
) -> dict[str, Any]:
    """Convert validation findings to SARIF format."""
    level_map = {"error": "error", "warning": "warning", "note": "note"}

    rules = []
    results = []
    seen_rules: set[str] = set()

    for finding in findings:
        rule_id = finding["rule_id"]

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {
                        "text": rule_id.replace("navil/", "").replace("-", " ").title(),
                    },
                }
            )

        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(finding["level"], "note"),
                "message": {"text": finding["message"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": policy_path},
                            "region": {"startLine": max(1, finding["line"])},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "navil-policy-validate",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/navilai/navil",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Navil policy YAML files")
    parser.add_argument("--policy", default="policy.yaml", help="Path to policy.yaml")
    parser.add_argument(
        "--auto-policy",
        default="policy.auto.yaml",
        help="Path to policy.auto.yaml",
    )
    parser.add_argument(
        "--sarif-output",
        default="policy-validation.sarif",
        help="SARIF output file",
    )
    args = parser.parse_args()

    all_findings: list[dict[str, Any]] = []

    # Validate main policy
    policy_path = Path(args.policy)
    findings = validate_policy(policy_path)
    all_findings.extend(findings)

    # Validate auto policy if it exists
    auto_path = Path(args.auto_policy)
    if auto_path.exists():
        auto_findings = validate_policy(auto_path)
        all_findings.extend(auto_findings)

    # Generate SARIF
    sarif = findings_to_sarif(all_findings, args.policy)
    sarif_path = Path(args.sarif_output)
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)

    # Set GitHub Actions outputs
    error_count = sum(1 for f in all_findings if f["level"] == "error")
    is_valid = error_count == 0

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"valid={str(is_valid).lower()}\n")
            f.write(f"sarif-file={args.sarif_output}\n")
            f.write(f"error-count={error_count}\n")

    # Print summary
    warnings = sum(1 for f in all_findings if f["level"] == "warning")
    print(f"Policy validation: {error_count} errors, {warnings} warnings")
    for finding in all_findings:
        icon = {"error": "x", "warning": "!", "note": "i"}[finding["level"]]
        print(f"  [{icon}] {finding['message']}")

    return 1 if error_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
