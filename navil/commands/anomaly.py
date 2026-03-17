"""Anomaly commands -- monitoring, adaptive baselines, and ML anomaly detection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from navil._compat import has_ml


def _monitor_start_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle monitor start command."""
    print("\nStarting Monitoring Mode")
    print("-" * 60)
    print("Monitoring active. Press Ctrl+C to stop.")
    print("\nMonitoring features enabled:")
    print("  - Real-time policy evaluation")
    print("  - Behavioral anomaly detection")
    print("  - Credential usage tracking")
    print("  - Rate limit enforcement")

    print("\nNote: This is a demo. In production, this would start a monitoring service.")

    return 0


def _adaptive_status_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show adaptive baseline status for an agent."""
    agent = args.agent
    info = cli.anomaly_detector.get_adaptive_baseline(agent)
    print(f"\nAdaptive Baseline for: {agent}")
    print("-" * 60)
    print(json.dumps(info, indent=2))
    return 0


def _adaptive_reset_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Reset adaptive baseline for an agent."""
    agent = args.agent
    from navil.adaptive.baselines import AgentAdaptiveBaseline

    cli.anomaly_detector.adaptive_baselines[agent] = AgentAdaptiveBaseline(agent_name=agent)
    print(f"Adaptive baseline reset for agent: {agent}")
    return 0


def _adaptive_export_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Export all adaptive baselines to JSON."""
    data = {name: bl.to_dict() for name, bl in cli.anomaly_detector.adaptive_baselines.items()}
    output = json.dumps(data, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"Exported baselines to {args.output}")
    else:
        print(output)
    return 0


# ── ML commands ─────────────────────────────────────────────

def _ml_train_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Train the isolation forest model on recorded invocations."""
    import sys

    if not has_ml():
        print(
            "Error: ML dependencies not installed. Run: pip install navil[ml]",
            file=sys.stderr,
        )
        return 1

    from navil.ml.isolation_forest import IsolationForestDetector

    invocations = cli.anomaly_detector.invocations
    if len(invocations) < 10:
        print("Error: Need at least 10 recorded invocations to train.", file=sys.stderr)
        return 1

    detector = IsolationForestDetector()
    detector.train(invocations)
    if args.output:
        detector.save(args.output)
        print(f"Model saved to {args.output}")
    print(f"Trained isolation forest on {len(invocations)} invocations.")
    return 0


def _ml_status_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show ML model status."""
    import sys

    if not has_ml():
        print(
            "Error: ML dependencies not installed. Run: pip install navil[ml]",
            file=sys.stderr,
        )
        return 1

    print("\nML Model Status")
    print("-" * 60)
    print("  scikit-learn: installed")
    print(f"  Recorded invocations: {len(cli.anomaly_detector.invocations)}")
    print(f"  Adaptive baselines tracked: {len(cli.anomaly_detector.adaptive_baselines)}")
    return 0


def _ml_cluster_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Cluster agents by behavior."""
    import sys

    if not has_ml():
        print(
            "Error: ML dependencies not installed. Run: pip install navil[ml]",
            file=sys.stderr,
        )
        return 1

    from navil.ml.clustering import AgentClusterer

    invocations = cli.anomaly_detector.invocations
    if not invocations:
        print("Error: No recorded invocations to cluster.", file=sys.stderr)
        return 1

    # Group invocations by agent
    profiles: dict[str, list] = {}
    for inv in invocations:
        profiles.setdefault(inv.agent_name, []).append(inv)

    n_clusters = min(int(args.n_clusters), len(profiles))
    clusterer = AgentClusterer(n_clusters=n_clusters)
    result = clusterer.fit(profiles)
    print("\nAgent Clustering Results")
    print("-" * 60)
    print(json.dumps(result, indent=2, default=str))
    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register monitor, adaptive, and ML subcommands."""
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start monitoring")
    monitor_subparsers = monitor_parser.add_subparsers(dest="monitor_command")
    start_parser = monitor_subparsers.add_parser("start", help="Start monitoring")
    start_parser.set_defaults(func=lambda cli, args: _monitor_start_command(cli, args))

    # Adaptive commands
    adaptive_parser = subparsers.add_parser("adaptive", help="Manage adaptive baselines")
    adaptive_sub = adaptive_parser.add_subparsers(dest="adaptive_command")

    adaptive_status = adaptive_sub.add_parser("status", help="Show baseline status")
    adaptive_status.add_argument("--agent", required=True, help="Agent name")
    adaptive_status.set_defaults(func=lambda cli, args: _adaptive_status_command(cli, args))

    adaptive_reset = adaptive_sub.add_parser("reset", help="Reset baseline")
    adaptive_reset.add_argument("--agent", required=True, help="Agent name")
    adaptive_reset.set_defaults(func=lambda cli, args: _adaptive_reset_command(cli, args))

    adaptive_export = adaptive_sub.add_parser("export", help="Export baselines")
    adaptive_export.add_argument("-o", "--output", help="Output file", default=None)
    adaptive_export.set_defaults(func=lambda cli, args: _adaptive_export_command(cli, args))

    # ML commands
    ml_parser = subparsers.add_parser(
        "ml", help="ML-powered anomaly detection (requires navil[ml])"
    )
    ml_sub = ml_parser.add_subparsers(dest="ml_command")

    ml_train = ml_sub.add_parser("train", help="Train isolation forest model")
    ml_train.add_argument("-o", "--output", help="Save model to file", default=None)
    ml_train.set_defaults(func=lambda cli, args: _ml_train_command(cli, args))

    ml_status = ml_sub.add_parser("status", help="Show ML status")
    ml_status.set_defaults(func=lambda cli, args: _ml_status_command(cli, args))

    ml_cluster = ml_sub.add_parser("cluster", help="Cluster agents by behavior")
    ml_cluster.add_argument("--n-clusters", default="3", help="Number of clusters (default: 3)")
    ml_cluster.set_defaults(func=lambda cli, args: _ml_cluster_command(cli, args))
