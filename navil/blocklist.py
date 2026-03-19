"""Blocklist Engine — pattern-based threat matching for MCP tool calls.

Loads signature patterns from blocklist_v1.json or Redis, matches incoming
tool calls against known-bad patterns, and manages version-controlled updates.

Redis keys:
    navil:blocklist:patterns  — JSON-encoded list of BlocklistEntry dicts
    navil:blocklist:version   — integer version counter (incremented on save)
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_BLOCKLIST = os.path.join(os.path.dirname(__file__), "data", "blocklist_v1.json")

REDIS_PATTERNS_KEY = "navil:blocklist:patterns"
REDIS_VERSION_KEY = "navil:blocklist:version"


@dataclass
class BlocklistEntry:
    """A single blocklist signature pattern."""

    pattern_id: str
    pattern_type: str  # "tool_name", "tool_sequence", "argument_pattern"
    value: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    confidence: float  # 0.0 - 1.0
    source: str = "local"  # "local", "community", "cloud", "manual"
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BlocklistEntry:
        return cls(
            pattern_id=d["pattern_id"],
            pattern_type=d["pattern_type"],
            value=d["value"],
            severity=d.get("severity", "MEDIUM"),
            description=d.get("description", ""),
            confidence=float(d.get("confidence", 0.5)),
            source=d.get("source", "local"),
            created_at=d.get("created_at", ""),
        )


class BlocklistManager:
    """Manages blocklist patterns with file/Redis persistence and matching.

    Usage::

        mgr = BlocklistManager()
        mgr.load_from_file()  # loads blocklist_v1.json
        matches = mgr.match("inject_backdoor", {"path": "/etc/shadow"})
    """

    def __init__(self, redis_client: Any | None = None) -> None:
        self._entries: dict[str, BlocklistEntry] = {}  # pattern_id -> entry
        self._version: int = 0
        self._last_update: str = ""
        self.redis = redis_client
        # Compiled regex cache for argument_pattern entries
        self._regex_cache: dict[str, re.Pattern[str]] = {}

    # ── Properties ───────────────────────────────────────────

    @property
    def entries(self) -> list[BlocklistEntry]:
        return list(self._entries.values())

    @property
    def version(self) -> int:
        return self._version

    @property
    def pattern_count(self) -> int:
        return len(self._entries)

    @property
    def last_update(self) -> str:
        return self._last_update

    # ── Load ─────────────────────────────────────────────────

    def load_from_file(self, path: str | None = None) -> int:
        """Load blocklist from a JSON file.

        Args:
            path: Path to blocklist JSON file. Defaults to blocklist_v1.json.

        Returns:
            Number of patterns loaded.
        """
        filepath = path or _DEFAULT_BLOCKLIST
        resolved = str(Path(filepath).resolve())

        with open(resolved) as fh:
            data = json.load(fh)

        patterns = data.get("patterns", [])
        version = data.get("version", 1)
        loaded = 0

        for p in patterns:
            try:
                entry = BlocklistEntry.from_dict(p)
                self._entries[entry.pattern_id] = entry
                loaded += 1
            except (KeyError, TypeError) as e:
                logger.warning("Skipping invalid blocklist entry: %s", e)

        self._version = max(self._version, version)
        self._last_update = datetime.now(timezone.utc).isoformat()
        self._rebuild_regex_cache()
        logger.info("Loaded %d blocklist patterns from %s (v%d)", loaded, resolved, self._version)
        return loaded

    def load_from_redis(self) -> int:
        """Load blocklist from Redis (synchronous).

        Returns:
            Number of patterns loaded.  Returns 0 if Redis unavailable or empty.
        """
        if self.redis is None:
            logger.debug("No Redis client configured, skipping blocklist load")
            return 0

        try:
            raw = self.redis.get(REDIS_PATTERNS_KEY)
            if not raw:
                return 0

            patterns = json.loads(raw)
            loaded = 0
            for p in patterns:
                try:
                    entry = BlocklistEntry.from_dict(p)
                    self._entries[entry.pattern_id] = entry
                    loaded += 1
                except (KeyError, TypeError):
                    continue

            version_raw = self.redis.get(REDIS_VERSION_KEY)
            if version_raw:
                self._version = max(self._version, int(version_raw))

            self._last_update = datetime.now(timezone.utc).isoformat()
            self._rebuild_regex_cache()
            logger.info("Loaded %d blocklist patterns from Redis (v%d)", loaded, self._version)
            return loaded

        except Exception:
            logger.debug("Failed to load blocklist from Redis", exc_info=True)
            return 0

    # ── Save ─────────────────────────────────────────────────

    def save_to_redis(self) -> bool:
        """Push current blocklist to Redis with version increment.

        Returns:
            True if saved successfully, False otherwise.
        """
        if self.redis is None:
            logger.warning("No Redis client configured, cannot save blocklist")
            return False

        try:
            serialized = json.dumps([e.to_dict() for e in self._entries.values()])
            pipe = self.redis.pipeline()
            pipe.set(REDIS_PATTERNS_KEY, serialized)
            pipe.incr(REDIS_VERSION_KEY)
            results = pipe.execute()

            self._version = int(results[1])  # INCR returns new value
            self._last_update = datetime.now(timezone.utc).isoformat()
            logger.info(
                "Saved %d blocklist patterns to Redis (v%d)", len(self._entries), self._version
            )
            return True

        except Exception:
            logger.error("Failed to save blocklist to Redis", exc_info=True)
            return False

    def save_to_file(self, path: str) -> None:
        """Export current blocklist to a JSON file."""
        data = {
            "version": self._version,
            "description": "Navil blocklist export",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "patterns": [e.to_dict() for e in self._entries.values()],
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Exported %d blocklist patterns to %s", len(self._entries), path)

    # ── Merge ────────────────────────────────────────────────

    def merge(self, other_entries: list[BlocklistEntry]) -> int:
        """Merge new entries into the blocklist.

        On conflicts (same pattern_id), keeps the entry with higher confidence.

        Args:
            other_entries: List of BlocklistEntry objects to merge.

        Returns:
            Number of entries added or updated.
        """
        changes = 0
        for entry in other_entries:
            existing = self._entries.get(entry.pattern_id)
            if existing is None or entry.confidence > existing.confidence:
                self._entries[entry.pattern_id] = entry
                changes += 1

        if changes > 0:
            self._rebuild_regex_cache()

        return changes

    # ── Match ────────────────────────────────────────────────

    def match(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> list[BlocklistEntry]:
        """Check a tool call against all blocklist patterns.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments (optional).

        Returns:
            List of matching BlocklistEntry objects, ordered by confidence desc.
        """
        matches: list[BlocklistEntry] = []
        args_str = json.dumps(arguments) if arguments else ""

        for entry in self._entries.values():
            if entry.pattern_type == "tool_name":
                if entry.value == tool_name:
                    matches.append(entry)

            elif entry.pattern_type == "tool_sequence":
                # Tool sequence matching: check if tool_name appears in sequence
                seq_parts = [s.strip() for s in entry.value.split(",")]
                if tool_name in seq_parts:
                    matches.append(entry)

            elif entry.pattern_type == "argument_pattern" and args_str:
                regex = self._regex_cache.get(entry.pattern_id)
                if regex and regex.search(args_str):
                    matches.append(entry)

        # Sort by confidence descending
        matches.sort(key=lambda e: e.confidence, reverse=True)
        return matches

    def search(self, pattern: str) -> list[BlocklistEntry]:
        """Search for blocklist entries by pattern string.

        Args:
            pattern: Search string (matched against pattern_id, value, description).

        Returns:
            List of matching BlocklistEntry objects.
        """
        pattern_lower = pattern.lower()
        results: list[BlocklistEntry] = []
        for entry in self._entries.values():
            if (
                pattern_lower in entry.pattern_id.lower()
                or pattern_lower in entry.value.lower()
                or pattern_lower in entry.description.lower()
            ):
                results.append(entry)
        return results

    # ── Add ──────────────────────────────────────────────────

    def add_entry(self, entry: BlocklistEntry) -> bool:
        """Add a single entry to the blocklist.

        Returns:
            True if added (new or replaced with higher confidence), False if skipped.
        """
        existing = self._entries.get(entry.pattern_id)
        if existing is not None and entry.confidence <= existing.confidence:
            return False
        self._entries[entry.pattern_id] = entry
        if entry.pattern_type == "argument_pattern":
            try:
                self._regex_cache[entry.pattern_id] = re.compile(entry.value, re.IGNORECASE)
            except re.error:
                logger.warning(
                    "Invalid regex in blocklist entry %s: %s", entry.pattern_id, entry.value
                )
        return True

    # ── Finding generation ───────────────────────────────────

    def match_to_findings(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> list[Any]:
        """Match a tool call and return Finding objects for each match.

        Returns:
            List of Finding objects (from navil.types).
        """
        from navil.types import Finding

        matches = self.match(tool_name, arguments)
        findings: list[Finding] = []
        for entry in matches:
            findings.append(
                Finding(
                    id=f"BLOCKLIST-{entry.pattern_id}",
                    title=f"Blocklist match: {entry.pattern_id}",
                    description=entry.description,
                    severity=entry.severity,
                    source="blocklist",
                    affected_field=tool_name,
                    remediation="Block the agent and investigate the tool call",
                    evidence=(
                        f"pattern_type={entry.pattern_type}, "
                        f"value={entry.value}, "
                        f"confidence={entry.confidence:.2f}"
                    ),
                    confidence=entry.confidence,
                )
            )
        return findings

    # ── Status ───────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Return status summary."""
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for entry in self._entries.values():
            by_type[entry.pattern_type] = by_type.get(entry.pattern_type, 0) + 1
            by_severity[entry.severity] = by_severity.get(entry.severity, 0) + 1

        return {
            "version": self._version,
            "pattern_count": len(self._entries),
            "last_update": self._last_update,
            "by_type": by_type,
            "by_severity": by_severity,
        }

    # ── Internal ─────────────────────────────────────────────

    def _rebuild_regex_cache(self) -> None:
        """Compile regex patterns for argument_pattern entries."""
        self._regex_cache.clear()
        for entry in self._entries.values():
            if entry.pattern_type == "argument_pattern":
                try:
                    self._regex_cache[entry.pattern_id] = re.compile(entry.value, re.IGNORECASE)
                except re.error:
                    logger.warning(
                        "Invalid regex in blocklist entry %s: %s", entry.pattern_id, entry.value
                    )
