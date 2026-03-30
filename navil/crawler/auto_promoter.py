"""Auto-promoter — publishes high-risk scan findings to the threat intel channel.

When a registry scan discovers servers with risk scores above the threshold,
this module converts them into ThreatIntelEntry messages and publishes them
to the Redis ``navil:threat_intel:inbound`` pub/sub channel.

The existing ThreatIntelConsumer automatically picks up these entries and
merges them into the local PatternStore / blocklist.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from navil.crawler.risk_scorer import RiskAssessment

logger = logging.getLogger(__name__)

# Same channel used by ThreatIntelFetcher and ThreatIntelConsumer
THREAT_INTEL_CHANNEL = "navil:threat_intel:inbound"


def _assessment_to_threat_entry(assessment: RiskAssessment) -> dict[str, Any]:
    """Convert a high-risk assessment into a ThreatIntelEntry dict.

    Maps the scanner's vulnerability findings into the pattern format
    consumed by ThreatIntelConsumer.
    """
    return {
        "source": "registry-scanner",
        "entry_type": "pattern",
        "agent_name_hash": None,
        "tool_name": None,
        "pattern_data": {
            "pattern_id": f"registry:{assessment.source}:{assessment.server_name}",
            "anomaly_type": "suspicious_mcp_server",
            "description": (
                f"High-risk MCP server detected via registry scan: "
                f"{assessment.server_name} (source={assessment.source}, "
                f"risk_score={assessment.risk_score:.2f})"
            ),
            "features": {
                "server_name": assessment.server_name,
                "source": assessment.source,
                "url": assessment.url,
                "risk_score": assessment.risk_score,
                "high_risk_findings": assessment.high_risk_findings,
                "breakdown": assessment.breakdown.to_dict(),
            },
            "confidence_boost": min(assessment.risk_score * 0.5, 0.4),
            "source": "registry-scanner",
        },
    }


async def promote_high_risk_to_threat_intel(
    assessments: list[RiskAssessment],
    redis_client: Any,
) -> int:
    """Publish high-risk assessments to the threat intel Redis channel.

    Args:
        assessments: List of RiskAssessment objects (pre-filtered or not).
        redis_client: An async Redis client.

    Returns:
        Number of entries published.
    """
    high_risk = [a for a in assessments if a.is_high_risk]
    if not high_risk:
        logger.debug("No high-risk servers to promote")
        return 0

    published = 0
    for assessment in high_risk:
        entry = _assessment_to_threat_entry(assessment)
        try:
            await redis_client.publish(
                THREAT_INTEL_CHANNEL,
                json.dumps(entry),
            )
            published += 1
            logger.info(
                "Promoted high-risk server to threat intel: %s (score=%.2f)",
                assessment.server_name,
                assessment.risk_score,
            )
        except Exception:
            logger.exception("Failed to promote %s to threat intel", assessment.server_name)

    logger.info(
        "Registry scanner auto-promotion: %d/%d high-risk servers published",
        published,
        len(high_risk),
    )
    return published
