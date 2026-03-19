"""Honeypot Collector -- aggregates all tool call attempts from honeypot servers.

Stores interactions with full request details for offline analysis and
real-time pattern extraction.  Supports JSONL export for persistent storage.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


class HoneypotCollector:
    """Collects and stores honeypot interaction records.

    Thread-safe collector that accumulates records from one or more
    honeypot server instances.  Records include timestamps, source IPs,
    user agents, and full tool call parameters.

    Usage::

        collector = HoneypotCollector(max_records=10000)
        server = HoneypotMCPServer(profile="dev_tools", collector=collector)
    """

    def __init__(
        self,
        max_records: int = 10000,
        log_path: str | None = None,
    ) -> None:
        self._records: deque[dict[str, Any]] = deque(maxlen=max_records)
        self._lock = threading.Lock()
        self._total_count: int = 0
        self._log_path: str | None = log_path
        self._log_file: Any = None

        if log_path:
            self._open_log(log_path)

    def _open_log(self, path: str) -> None:
        """Open (or create) the JSONL log file for append."""
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._log_file = open(path, "a", encoding="utf-8")  # noqa: SIM115
        self._log_path = path
        logger.info("Honeypot collector logging to %s", path)

    def record(self, honeypot_record: Any) -> None:
        """Record a honeypot interaction.

        Args:
            honeypot_record: A HoneypotRecord instance (from server.py).
        """
        entry = {
            "timestamp": honeypot_record.timestamp,
            "tool_name": honeypot_record.tool_name,
            "arguments": honeypot_record.arguments,
            "source_ip": honeypot_record.source_ip,
            "user_agent": getattr(honeypot_record, "user_agent", ""),
            "request_headers": honeypot_record.request_headers,
            "method": honeypot_record.method,
        }

        with self._lock:
            self._records.append(entry)
            self._total_count += 1

            # Append to JSONL log file if configured
            if self._log_file is not None:
                try:
                    self._log_file.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    self._log_file.flush()
                except OSError:
                    logger.warning("Failed to write to JSONL log file")

    @property
    def records(self) -> list[dict[str, Any]]:
        """Return a snapshot of all collected records."""
        with self._lock:
            return list(self._records)

    @property
    def count(self) -> int:
        """Total number of records collected (including evicted)."""
        return self._total_count

    @property
    def current_count(self) -> int:
        """Number of records currently in buffer."""
        with self._lock:
            return len(self._records)

    def get_records_since(self, since: str) -> list[dict[str, Any]]:
        """Get records collected after the given ISO timestamp.

        Args:
            since: ISO-format timestamp string.

        Returns:
            List of records with timestamp > since.
        """
        with self._lock:
            return [r for r in self._records if r["timestamp"] > since]

    def get_tool_call_counts(self) -> dict[str, int]:
        """Get per-tool call count summary."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records:
                tool = r["tool_name"]
                counts[tool] = counts.get(tool, 0) + 1
        return counts

    def get_source_ip_counts(self) -> dict[str, int]:
        """Get per-source-IP call count summary."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records:
                ip = r["source_ip"]
                counts[ip] = counts.get(ip, 0) + 1
        return counts

    def get_user_agent_counts(self) -> dict[str, int]:
        """Get per-user-agent call count summary."""
        counts: dict[str, int] = {}
        with self._lock:
            for r in self._records:
                ua = r.get("user_agent", "")
                if ua:
                    counts[ua] = counts.get(ua, 0) + 1
        return counts

    def export_json(self) -> str:
        """Export all records as a JSON string."""
        return json.dumps(self.records, indent=2)

    def export_jsonl(self, path: str | None = None) -> str:
        """Export all records as JSONL (one JSON object per line).

        Args:
            path: Optional file path to write to.  If None, returns the
                  JSONL string without writing to disk.

        Returns:
            The JSONL content as a string.
        """
        records = self.records
        lines = [json.dumps(r, separators=(",", ":")) for r in records]
        content = "\n".join(lines)
        if content:
            content += "\n"

        if path is not None:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Exported %d records to %s (JSONL)", len(records), path)

        return content

    def load_jsonl(self, path: str) -> int:
        """Load records from a JSONL file into the collector.

        Args:
            path: Path to JSONL file.

        Returns:
            Number of records loaded.
        """
        loaded = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    with self._lock:
                        self._records.append(record)
                        self._total_count += 1
                    loaded += 1
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid JSONL line")
        logger.info("Loaded %d records from %s", loaded, path)
        return loaded

    def clear(self) -> int:
        """Clear all records. Returns the number of records cleared."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
            return count

    def close(self) -> None:
        """Close the JSONL log file if open."""
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    def __del__(self) -> None:
        self.close()
