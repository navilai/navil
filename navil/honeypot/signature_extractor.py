"""Signature Extractor -- analyze honeypot data to generate blocklist entries.

Processes collected honeypot interaction records to extract:
  - Tool call patterns (suspicious tool names)
  - Tool sequence patterns (attack chains)
  - Argument patterns (sensitive path/credential access)
  - User-agent clustering

Generates candidate BlocklistEntry objects from observed attacks with
a minimum confidence threshold of 0.7.
"""

from __future__ import annotations

import logging
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Minimum confidence threshold for auto-generated entries
MIN_CONFIDENCE = 0.7

# Minimum observation count before we generate a signature
MIN_OBSERVATIONS = 3

# Known-sensitive argument patterns (used to boost confidence)
_SENSITIVE_PATTERNS = [
    r"\.ssh/",
    r"\.aws/",
    r"/etc/shadow",
    r"/etc/passwd",
    r"\.env",
    r"\.kube/config",
    r"credentials",
    r"secret",
    r"api[_-]?key",
    r"token",
]


class SignatureExtractor:
    """Extracts attack signatures from honeypot interaction data.

    Usage::

        extractor = SignatureExtractor()
        entries = extractor.analyze(collector.records)
        # entries is a list of BlocklistEntry objects
    """

    def __init__(self, min_confidence: float = MIN_CONFIDENCE) -> None:
        self.min_confidence = min_confidence
        self._id_counter = 0

    def _next_id(self) -> str:
        self._id_counter += 1
        return f"HP-AUTO-{self._id_counter:04d}"

    def analyze(self, records: list[dict[str, Any]]) -> list[Any]:
        """Analyze collected records and extract blocklist entries.

        Args:
            records: List of honeypot interaction dicts from the collector.

        Returns:
            List of BlocklistEntry objects with confidence >= min_confidence.
        """
        from navil.blocklist import BlocklistEntry

        entries: list[BlocklistEntry] = []

        if not records:
            return entries

        # 1. Extract tool name patterns
        entries.extend(self._extract_tool_patterns(records))

        # 2. Extract tool sequence patterns
        entries.extend(self._extract_sequence_patterns(records))

        # 3. Extract argument patterns
        entries.extend(self._extract_argument_patterns(records))

        # Filter by confidence threshold
        entries = [e for e in entries if e.confidence >= self.min_confidence]

        logger.info("Extracted %d signatures from %d records", len(entries), len(records))
        return entries

    def _extract_tool_patterns(self, records: list[dict[str, Any]]) -> list[Any]:
        """Extract suspicious tool name patterns."""
        from navil.blocklist import BlocklistEntry

        tool_counts = Counter(r["tool_name"] for r in records)
        entries: list[BlocklistEntry] = []

        # Known-bad tool names that appear frequently
        suspicious_keywords = {
            "inject",
            "backdoor",
            "exfil",
            "dump",
            "keylog",
            "rootkit",
            "exploit",
            "payload",
            "shell",
            "reverse",
            "shadow",
            "siphon",
            "c2",
            "beacon",
        }

        for tool_name, count in tool_counts.items():
            if count < MIN_OBSERVATIONS:
                continue
            if tool_name == "__tools_list__":
                continue

            # Check if tool name contains suspicious keywords
            name_lower = tool_name.lower()
            matched_keywords = [kw for kw in suspicious_keywords if kw in name_lower]

            if matched_keywords:
                confidence = min(0.95, 0.7 + 0.05 * len(matched_keywords) + 0.01 * count)
                entries.append(
                    BlocklistEntry(
                        pattern_id=self._next_id(),
                        pattern_type="tool_name",
                        value=tool_name,
                        severity="CRITICAL" if confidence > 0.85 else "HIGH",
                        description=(
                            f"Suspicious tool observed in honeypot "
                            f"({count} calls, keywords: {matched_keywords})"
                        ),
                        confidence=round(confidence, 2),
                    )
                )

        return entries

    def _extract_sequence_patterns(self, records: list[dict[str, Any]]) -> list[Any]:
        """Extract tool call sequence patterns grouped by source IP."""
        from navil.blocklist import BlocklistEntry

        # Group records by source IP
        by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in records:
            by_ip[r["source_ip"]].append(r)

        sequence_counts: Counter[str] = Counter()

        for _ip, ip_records in by_ip.items():
            # Sort by timestamp
            sorted_records = sorted(ip_records, key=lambda r: r["timestamp"])

            # Extract sequences of length 2-4
            tool_names = [
                r["tool_name"] for r in sorted_records if r["tool_name"] != "__tools_list__"
            ]

            for seq_len in range(2, min(5, len(tool_names) + 1)):
                for i in range(len(tool_names) - seq_len + 1):
                    seq = ",".join(tool_names[i : i + seq_len])
                    sequence_counts[seq] += 1

        entries: list[BlocklistEntry] = []
        for seq, count in sequence_counts.items():
            if count < MIN_OBSERVATIONS:
                continue

            tools_in_seq = seq.split(",")
            # Boost confidence if sequence involves sensitive operations
            has_read = any("read" in t.lower() or "get" in t.lower() for t in tools_in_seq)
            has_send = any(
                "send" in t.lower() or "fetch" in t.lower() or "exec" in t.lower()
                for t in tools_in_seq
            )

            confidence = 0.6 + 0.05 * count
            if has_read and has_send:
                confidence += 0.15  # Read-then-send is highly suspicious

            confidence = min(0.95, confidence)

            if confidence >= self.min_confidence:
                entries.append(
                    BlocklistEntry(
                        pattern_id=self._next_id(),
                        pattern_type="tool_sequence",
                        value=seq,
                        severity="HIGH" if confidence > 0.8 else "MEDIUM",
                        description=(
                            f"Suspicious tool sequence observed in honeypot ({count} occurrences)"
                        ),
                        confidence=round(confidence, 2),
                    )
                )

        return entries

    def _extract_argument_patterns(self, records: list[dict[str, Any]]) -> list[Any]:
        """Extract suspicious argument patterns."""
        from navil.blocklist import BlocklistEntry

        entries: list[BlocklistEntry] = []
        pattern_hits: Counter[str] = Counter()

        for r in records:
            args = r.get("arguments", {})
            if not args:
                continue

            args_str = str(args)

            for pattern in _SENSITIVE_PATTERNS:
                if re.search(pattern, args_str, re.IGNORECASE):
                    pattern_hits[pattern] += 1

        for pattern, count in pattern_hits.items():
            if count < MIN_OBSERVATIONS:
                continue

            confidence = min(0.95, 0.7 + 0.03 * count)

            entries.append(
                BlocklistEntry(
                    pattern_id=self._next_id(),
                    pattern_type="argument_pattern",
                    value=f".*{pattern}.*",
                    severity="HIGH",
                    description=(f"Sensitive argument pattern observed in honeypot ({count} hits)"),
                    confidence=round(confidence, 2),
                )
            )

        return entries

    def extract_timing_patterns(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze timing patterns in collected records.

        Returns timing statistics per source IP (not BlocklistEntry objects,
        since timing patterns are used by the ML detectors).
        """
        by_ip: dict[str, list[float]] = defaultdict(list)

        for r in records:
            try:
                ts = datetime.fromisoformat(r["timestamp"])
                by_ip[r["source_ip"]].append(ts.timestamp())
            except (ValueError, KeyError):
                continue

        results: dict[str, Any] = {}
        for ip, timestamps in by_ip.items():
            if len(timestamps) < 3:
                continue

            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            results[ip] = {
                "call_count": len(timestamps),
                "mean_interval_s": round(statistics.mean(intervals), 2),
                "std_interval_s": (
                    round(statistics.stdev(intervals), 2) if len(intervals) > 1 else 0.0
                ),
                "min_interval_s": round(min(intervals), 2),
                "max_interval_s": round(max(intervals), 2),
                "is_periodic": (
                    statistics.stdev(intervals) / statistics.mean(intervals) < 0.15
                    if len(intervals) > 1 and statistics.mean(intervals) > 0
                    else False
                ),
            }

        return results

    def extract_user_agent_patterns(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze user-agent patterns in collected records.

        Returns per-user-agent statistics including which tools they
        targeted and call frequency.
        """
        by_ua: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for r in records:
            ua = r.get("user_agent", "")
            if ua:
                by_ua[ua].append(r)

        results: dict[str, Any] = {}
        for ua, ua_records in by_ua.items():
            tool_counts = Counter(r["tool_name"] for r in ua_records)
            results[ua] = {
                "call_count": len(ua_records),
                "unique_tools": len(tool_counts),
                "top_tools": tool_counts.most_common(5),
                "source_ips": list({r["source_ip"] for r in ua_records}),
            }

        return results
