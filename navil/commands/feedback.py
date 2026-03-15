"""Feedback commands -- submit operator feedback on anomaly alerts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def _feedback_submit_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Submit feedback on an anomaly alert."""
    from navil.adaptive.feedback import FeedbackLoop

    loop = cli.anomaly_detector.feedback_loop or FeedbackLoop()
    loop.submit_feedback(
        alert_timestamp=datetime.now(timezone.utc).isoformat(),
        anomaly_type="manual",
        agent_name=args.alert_id,
        verdict=args.verdict,
        operator_notes=args.notes or "",
    )
    print(f"Feedback recorded: {args.verdict} for alert {args.alert_id}")
    return 0


def _feedback_stats_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Show feedback statistics."""
    from navil.adaptive.feedback import FeedbackLoop

    loop = cli.anomaly_detector.feedback_loop or FeedbackLoop()
    stats = loop.get_stats()
    print("\nFeedback Statistics")
    print("-" * 60)
    print(json.dumps(stats, indent=2))
    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register feedback subcommands."""
    feedback_parser = subparsers.add_parser("feedback", help="Submit operator feedback on alerts")
    feedback_sub = feedback_parser.add_subparsers(dest="feedback_command")

    feedback_submit = feedback_sub.add_parser("submit", help="Submit feedback")
    feedback_submit.add_argument("--alert-id", required=True, help="Alert ID")
    feedback_submit.add_argument(
        "--verdict",
        required=True,
        choices=["confirmed", "dismissed", "escalated"],
        help="Feedback verdict",
    )
    feedback_submit.add_argument("--notes", default="", help="Operator notes")
    feedback_submit.set_defaults(func=lambda cli, args: _feedback_submit_command(cli, args))

    feedback_stats = feedback_sub.add_parser("stats", help="Show feedback stats")
    feedback_stats.set_defaults(func=lambda cli, args: _feedback_stats_command(cli, args))
