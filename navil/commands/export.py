"""Export commands -- report generation, LLM analysis, and cloud dashboard."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from navil._compat import has_llm
from navil.credential_manager import CredentialStatus


def _report_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle report generation command."""
    print("\nGenerating Security Report")
    print("-" * 60)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_credentials": len(cli.credential_manager.credentials),
            "active_credentials": sum(
                1
                for c in cli.credential_manager.credentials.values()
                if c.status == CredentialStatus.ACTIVE
            ),
            "total_alerts": len(cli.anomaly_detector.alerts),
            "policy_decisions": len(cli.policy_engine.decisions_log),
        },
        "credentials": cli.credential_manager.list_credentials(),
        "anomalies": cli.anomaly_detector.get_alerts(),
        "policy_decisions": cli.policy_engine.get_decisions_log()[-10:],
    }

    print(json.dumps(report, indent=2))

    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {output_path}")

    return 0


# ── LLM helpers ─────────────────────────────────────────────

def _resolve_llm_api_key(args: argparse.Namespace) -> str | None:
    """Resolve API key from --api-key flag or environment variables."""
    if args.api_key:
        return str(args.api_key)
    env_map: dict[str, str] = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "openai_compatible": "OPENAI_API_KEY",
    }
    env_var = env_map.get(args.provider)
    if env_var:
        key = os.environ.get(env_var)
        if key:
            return key
    if args.provider == "ollama":
        return "ollama"
    return None


def _add_llm_args(p: argparse.ArgumentParser) -> None:
    """Add common LLM arguments to a parser."""
    p.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openai", "gemini", "ollama", "openai_compatible"],
        help="LLM provider (default: anthropic)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY env var)",
    )
    p.add_argument("--model", default=None, help="Model name override")
    p.add_argument(
        "--base-url", default=None, help="Custom API base URL (for ollama or openai_compatible)"
    )


def _llm_analyze_config_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Analyze MCP config using LLM."""
    if not has_llm():
        print(
            "Error: LLM dependencies not installed. Run: pip install navil[llm]",
            file=sys.stderr,
        )
        return 1

    from navil.llm.analyzer import LLMAnalyzer
    from navil.llm.client import LLMClient

    config_path = Path(args.config_path)
    if not config_path.exists():
        print(f"Error: File not found: {config_path}", file=sys.stderr)
        return 1

    config = json.loads(config_path.read_text())
    api_key = _resolve_llm_api_key(args)
    if not api_key:
        print(
            f"Error: No API key. Pass --api-key or set "
            f"{args.provider.upper()}_API_KEY env var.",
            file=sys.stderr,
        )
        return 1
    client = LLMClient(
        provider=args.provider,
        api_key=api_key,
        model=args.model or None,
        base_url=args.base_url,
    )
    analyzer = LLMAnalyzer(client=client)
    result = analyzer.analyze_config(config)
    print("\nLLM Config Analysis")
    print("-" * 60)
    print(json.dumps(result, indent=2))
    return 0


def _llm_explain_anomaly_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Explain an anomaly using LLM."""
    if not has_llm():
        print(
            "Error: LLM dependencies not installed. Run: pip install navil[llm]",
            file=sys.stderr,
        )
        return 1

    from navil.llm.analyzer import LLMAnalyzer
    from navil.llm.client import LLMClient

    anomaly_data = json.loads(args.anomaly_json)
    api_key = _resolve_llm_api_key(args)
    if not api_key:
        print(
            f"Error: No API key. Pass --api-key or set "
            f"{args.provider.upper()}_API_KEY env var.",
            file=sys.stderr,
        )
        return 1
    client = LLMClient(
        provider=args.provider,
        api_key=api_key,
        model=args.model or None,
        base_url=args.base_url,
    )
    analyzer = LLMAnalyzer(client=client)
    result = analyzer.explain_anomaly(anomaly_data)
    print("\nLLM Anomaly Explanation")
    print("-" * 60)
    print(json.dumps(result, indent=2))
    return 0


def _llm_generate_policy_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Generate policy YAML from natural language."""
    if not has_llm():
        print(
            "Error: LLM dependencies not installed. Run: pip install navil[llm]",
            file=sys.stderr,
        )
        return 1

    import yaml

    from navil.llm.client import LLMClient
    from navil.llm.policy_gen import PolicyGenerator

    api_key = _resolve_llm_api_key(args)
    if not api_key:
        print(
            f"Error: No API key. Pass --api-key or set "
            f"{args.provider.upper()}_API_KEY env var.",
            file=sys.stderr,
        )
        return 1
    client = LLMClient(
        provider=args.provider,
        api_key=api_key,
        model=args.model or None,
        base_url=args.base_url,
    )
    gen = PolicyGenerator(client=client)
    policy = gen.generate(args.description)
    output = yaml.dump(policy, default_flow_style=False)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Policy saved to {args.output}")
    else:
        print("\nGenerated Policy")
        print("-" * 60)
        print(output)
    return 0


def _llm_suggest_healing_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Suggest self-healing remediations using LLM."""
    if not has_llm():
        print(
            "Error: LLM dependencies not installed. Run: pip install navil[llm]",
            file=sys.stderr,
        )
        return 1

    from navil.llm.client import LLMClient
    from navil.llm.self_healing import SelfHealingEngine

    api_key = _resolve_llm_api_key(args)
    if not api_key:
        print(
            f"Error: No API key. Pass --api-key or set "
            f"{args.provider.upper()}_API_KEY env var.",
            file=sys.stderr,
        )
        return 1
    client = LLMClient(
        provider=args.provider,
        api_key=api_key,
        model=args.model or None,
        base_url=args.base_url,
    )
    engine = SelfHealingEngine(client=client)
    alerts = cli.anomaly_detector.get_alerts()
    policy = cli.policy_engine.policy
    result = engine.suggest_remediation(alerts, policy)
    print("\nSelf-Healing Suggestions")
    print("-" * 60)
    print(json.dumps(result, indent=2))
    return 0


def _cloud_serve(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    try:
        from navil.api.local.app import create_app
    except ImportError:
        print(
            "Error: Cloud dependencies not installed. Run: pip install navil[cloud]",
            file=sys.stderr,
        )
        return 1
    import uvicorn

    app = create_app(with_demo=not args.no_demo)
    print(f"\n  Navil Cloud starting at http://localhost:{args.port}\n")
    uvicorn.run(app, host=args.host, port=int(args.port), log_level="info")
    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register report, LLM, and cloud subcommands."""
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument("-o", "--output", help="Output file for JSON report", default=None)
    report_parser.set_defaults(func=lambda cli, args: _report_command(cli, args))

    # LLM commands
    llm_parser = subparsers.add_parser("llm", help="LLM-powered analysis (requires navil[llm])")
    llm_sub = llm_parser.add_subparsers(dest="llm_command")

    llm_analyze = llm_sub.add_parser("analyze-config", help="Analyze config with LLM")
    llm_analyze.add_argument("config_path", help="Path to MCP config (JSON)")
    _add_llm_args(llm_analyze)
    llm_analyze.set_defaults(func=lambda cli, args: _llm_analyze_config_command(cli, args))

    llm_explain = llm_sub.add_parser("explain-anomaly", help="Explain anomaly with LLM")
    llm_explain.add_argument("anomaly_json", help="Anomaly data as JSON string")
    _add_llm_args(llm_explain)
    llm_explain.set_defaults(func=lambda cli, args: _llm_explain_anomaly_command(cli, args))

    llm_genpol = llm_sub.add_parser("generate-policy", help="Generate policy from description")
    llm_genpol.add_argument("description", help="Natural language policy description")
    llm_genpol.add_argument("-o", "--output", help="Save policy YAML to file", default=None)
    _add_llm_args(llm_genpol)
    llm_genpol.set_defaults(func=lambda cli, args: _llm_generate_policy_command(cli, args))

    llm_heal = llm_sub.add_parser("suggest-healing", help="Suggest self-healing actions")
    _add_llm_args(llm_heal)
    llm_heal.set_defaults(func=lambda cli, args: _llm_suggest_healing_command(cli, args))

    # NOTE: cloud subcommands (login, logout, status, serve) are registered
    # in navil/commands/cloud.py to avoid argparse conflicts.
