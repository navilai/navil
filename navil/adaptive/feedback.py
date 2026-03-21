"""Feedback loop for improving anomaly detection over time."""

from __future__ import annotations

import json
import logging
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """Record of operator feedback on an alert."""

    alert_timestamp: str
    anomaly_type: str
    agent_name: str
    verdict: str  # "confirmed", "dismissed", or "escalated"
    operator_notes: str = ""
    feedback_timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.feedback_timestamp:
            self.feedback_timestamp = datetime.now(timezone.utc).isoformat()


class FeedbackLoop:
    """Collects operator feedback and adjusts detection parameters.

    Tracks confirmed/dismissed/escalated verdicts for each anomaly type
    and computes threshold adjustments to reduce false positives while
    maintaining detection sensitivity.
    """

    def __init__(self, persistence_path: str | None = None, max_entries: int = 500) -> None:
        self.entries: deque[FeedbackEntry] = deque(maxlen=max_entries)
        self.persistence_path = Path(persistence_path) if persistence_path else None
        self._load()

    def submit_feedback(
        self,
        alert_timestamp: str,
        anomaly_type: str,
        agent_name: str,
        verdict: Literal["confirmed", "dismissed", "escalated"],
        operator_notes: str = "",
    ) -> FeedbackEntry:
        """Record operator feedback on an alert."""
        entry = FeedbackEntry(
            alert_timestamp=alert_timestamp,
            anomaly_type=anomaly_type,
            agent_name=agent_name,
            verdict=verdict,
            operator_notes=operator_notes,
        )
        self.entries.append(entry)
        self._persist()
        logger.info(f"Feedback recorded: {verdict} for {anomaly_type} alert on {agent_name}")
        return entry

    def compute_adjustments(self, anomaly_type: str) -> dict[str, float]:
        """Compute threshold adjustments based on feedback history.

        Returns dict with keys like 'threshold_multiplier_delta'.
        If many alerts are dismissed -> loosen threshold (reduce sensitivity).
        If many alerts are confirmed -> tighten threshold (increase sensitivity).
        """
        relevant = [e for e in self.entries if e.anomaly_type == anomaly_type]
        if len(relevant) < 5:
            return {}  # Not enough data to make adjustments

        recent = relevant[-20:]  # Last 20 feedback entries
        dismissed_count = sum(1 for e in recent if e.verdict == "dismissed")
        confirmed_count = sum(1 for e in recent if e.verdict == "confirmed")
        total = len(recent)

        false_positive_rate = dismissed_count / total

        adjustment: dict[str, float] = {}
        if false_positive_rate > 0.5:
            # Too many false positives -- loosen thresholds
            adjustment["threshold_multiplier_delta"] = 0.1 * false_positive_rate
            adjustment["confidence_threshold_delta"] = 0.05
        elif false_positive_rate < 0.2 and confirmed_count / total > 0.5:
            # Good detection rate, can tighten
            adjustment["threshold_multiplier_delta"] = -0.05
            adjustment["confidence_threshold_delta"] = -0.02

        return adjustment

    def apply_adjustments_to_baseline(self, baseline: Any, anomaly_type: str) -> None:
        """Apply computed adjustments to an AgentAdaptiveBaseline."""
        adjustments = self.compute_adjustments(anomaly_type)
        if not adjustments:
            return

        delta = adjustments.get("threshold_multiplier_delta", 0.0)
        if anomaly_type == "RATE_SPIKE":
            baseline.rate_threshold_multiplier = max(
                1.5, baseline.rate_threshold_multiplier + delta
            )
        elif anomaly_type == "DATA_EXFILTRATION":
            baseline.data_threshold_multiplier = max(
                2.0, baseline.data_threshold_multiplier + delta
            )

        if delta > 0:
            baseline.false_positive_count += 1
        elif delta < 0:
            baseline.true_positive_count += 1

    def apply_adjustments_to_policy(
        self,
        policy_generator: Any,
        current_policy: dict[str, Any],
        anomaly_type: str,
        agent_name: str,
    ) -> dict[str, Any] | None:
        """Apply feedback-driven policy refinement via PolicyGenerator.refine().

        This wires the CONFIRM → UPDATE step in the closed loop:
            OBSERVE → DETECT → SUGGEST → **CONFIRM** → **UPDATE** → LEARN

        When operator confirms an alert, we refine the policy to be stricter.
        When operator dismisses an alert, we refine to be more permissive.

        Returns the refined policy dict, or None if no refinement needed.
        """
        adjustments = self.compute_adjustments(anomaly_type)
        if not adjustments:
            return None

        # Build a natural language instruction from the feedback pattern
        recent = [e for e in self.entries if e.anomaly_type == anomaly_type][-20:]
        dismissed_count = sum(1 for e in recent if e.verdict == "dismissed")
        confirmed_count = sum(1 for e in recent if e.verdict == "confirmed")
        total = len(recent)

        if dismissed_count > confirmed_count:
            instruction = (
                f"The '{anomaly_type}' detector for agent '{agent_name}' has a "
                f"{dismissed_count}/{total} false positive rate. Make the policy more "
                f"permissive for this agent's {anomaly_type.lower().replace('_', ' ')} pattern — "
                f"increase rate limits or widen allowed tools as appropriate."
            )
        else:
            instruction = (
                f"The '{anomaly_type}' detector for agent '{agent_name}' has confirmed "
                f"{confirmed_count}/{total} alerts. Tighten the policy for this agent — "
                f"reduce rate limits, restrict tool access, or add suspicious patterns."
            )

        try:
            refined = policy_generator.refine(current_policy, instruction)
            logger.info(
                f"Policy refined for {agent_name}/{anomaly_type}: "
                f"{dismissed_count} dismissed, {confirmed_count} confirmed"
            )
            return refined
        except Exception as e:
            logger.error(f"Policy refinement failed: {e}")
            return None

    def get_stats(self) -> dict[str, Any]:
        """Return feedback statistics."""
        by_type: dict[str, dict[str, int]] = {}
        for entry in self.entries:
            if entry.anomaly_type not in by_type:
                by_type[entry.anomaly_type] = {
                    "confirmed": 0,
                    "dismissed": 0,
                    "escalated": 0,
                }
            by_type[entry.anomaly_type][entry.verdict] += 1
        return {"total_entries": len(self.entries), "by_anomaly_type": by_type}

    def _persist(self) -> None:
        """Save feedback entries to disk."""
        if self.persistence_path is None:
            return
        self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.persistence_path, "w") as f:
            json.dump([asdict(e) for e in self.entries], f, indent=2)

    def _load(self) -> None:
        """Load feedback entries from disk."""
        if self.persistence_path is None or not self.persistence_path.exists():
            return
        try:
            with open(self.persistence_path) as f:
                data = json.load(f)
            self.entries.clear()
            for d in data:
                self.entries.append(FeedbackEntry(**d))
        except (json.JSONDecodeError, TypeError):
            logger.warning(f"Could not load feedback from {self.persistence_path}")
            self.entries.clear()
