"""Batch scanner — scans crawled MCP server entries in bulk.

Reads crawl results from a directory, constructs a minimal MCP config for
each, runs ``navil scan`` on it, and streams results to a JSONL file as each
scan completes.

Key safety properties:
  - 30-second timeout per individual scan (prevents hanging on bad configs)
  - Results streamed to disk immediately (not held in memory)
  - Tracks total / successful / failed / timed-out counts
"""

from __future__ import annotations

import dataclasses
import json
import logging
import signal
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import orjson

from navil.scanner import MCPSecurityScanner

logger = logging.getLogger(__name__)


@dataclass
class BatchStats:
    """Aggregate statistics for a batch scan run."""

    total: int = 0
    successful: int = 0
    failed: int = 0
    timed_out: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class _ScanTimeoutError(Exception):
    """Raised when a single scan exceeds the timeout."""


@contextmanager
def _timeout_context(seconds: int) -> Iterator[None]:
    """Context manager that raises _ScanTimeoutError after *seconds*.

    Uses SIGALRM on Unix; on Windows this is a no-op (no timeout enforcement).
    """
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(signum: int, frame: Any) -> None:
        raise _ScanTimeoutError(f"Scan timed out after {seconds}s")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _load_crawl_results(input_dir: Path) -> list[dict[str, Any]]:
    """Load all JSON crawl result files from *input_dir*."""
    results: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.json")):
        try:
            data = orjson.loads(path.read_bytes())
            results.append(data)
        except (orjson.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping %s: %s", path, exc)
    return results


def _build_config(entry: dict[str, Any]) -> dict[str, Any]:
    """Build a minimal MCP config dict from a crawl result entry."""
    config_example = entry.get("config_example")
    if config_example and isinstance(config_example, dict):
        config = dict(config_example)
    else:
        # Fallback: construct a generic config from the server URL
        name = entry.get("server_name", "unknown")
        url = entry.get("url", "")
        config = {
            "server": {
                "name": name,
                "source": url,
            }
        }

    # Always include the description so the scanner can analyze it
    description = entry.get("description", "")
    if description:
        config.setdefault("metadata", {})["description"] = description

    return config


def scan_batch(
    input_dir: str | Path,
    output_path: str | Path,
    *,
    timeout_per_scan: int = 30,
) -> BatchStats:
    """Scan all crawl results in *input_dir*, streaming to JSONL at *output_path*.

    Args:
        input_dir: Directory containing JSON crawl result files.
        output_path: Path to write JSONL scan results.
        timeout_per_scan: Maximum seconds per individual scan.

    Returns:
        BatchStats with aggregate counts.
    """
    input_dir = Path(input_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    entries = _load_crawl_results(input_dir)
    stats = BatchStats(total=len(entries))
    scanner = MCPSecurityScanner()

    with open(output_path, "wb") as out:
        for entry in entries:
            server_name = entry.get("server_name", "unknown")
            source = entry.get("source", "unknown")
            config = _build_config(entry)

            # Write the config to a temp file so the scanner can read it
            result_record: dict[str, Any] = {
                "server_name": server_name,
                "source": source,
                "url": entry.get("url", ""),
            }

            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=True) as tmp:
                    json.dump(config, tmp)
                    tmp.flush()

                    with _timeout_context(timeout_per_scan):
                        scan_result = scanner.scan(tmp.name)

                # Serialize findings for JSONL (dataclass -> dict)
                if "findings" in scan_result:
                    scan_result["findings"] = [
                        dataclasses.asdict(f)
                        if dataclasses.is_dataclass(f) and not isinstance(f, type)
                        else f
                        for f in scan_result["findings"]
                    ]

                result_record["scan"] = scan_result
                result_record["status"] = "success"
                stats.successful += 1

            except _ScanTimeoutError:
                result_record["status"] = "timeout"
                result_record["error"] = f"Scan timed out after {timeout_per_scan}s"
                stats.timed_out += 1
                logger.warning("Timeout scanning %s", server_name)

            except Exception as exc:
                result_record["status"] = "error"
                result_record["error"] = str(exc)
                stats.failed += 1
                logger.warning("Error scanning %s: %s", server_name, exc)

            # Stream each result immediately
            out.write(orjson.dumps(result_record))
            out.write(b"\n")
            out.flush()

    return stats
