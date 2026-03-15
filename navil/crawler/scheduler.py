"""Scheduler — lightweight periodic re-scan scheduling.

Supports two modes:
  1. **Daemon mode**: long-running process using the ``schedule`` library
  2. **Crontab mode**: generates a crontab entry for system-level scheduling

After each scan, automatically stores results in the scan history database
and runs trend analysis.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from navil.crawler.batch_scanner import scan_batch
from navil.crawler.registry_crawler import RegistryCrawler
from navil.crawler.scan_history import ScanHistoryStore

logger = logging.getLogger(__name__)

# ── Interval mapping ──────────────────────────────────────────

INTERVAL_CRON: dict[str, str] = {
    "hourly": "0 * * * *",
    "daily": "0 2 * * *",          # 2 AM
    "weekly": "0 2 * * 0",         # Sunday 2 AM
    "monthly": "0 2 1 * *",        # 1st of month, 2 AM
}

INTERVAL_SECONDS: dict[str, int] = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,  # ~30 days
}


# ── Core scan pipeline ───────────────────────────────────────


def run_full_scan(
    *,
    limit: int = 0,
    timeout_per_scan: int = 30,
    store: ScanHistoryStore | None = None,
    webhook_url: str | None = None,
) -> dict[str, Any]:
    """Run a full crawl + batch scan + store pipeline.

    1. Crawl registries to discover MCP servers
    2. Batch-scan all discovered servers
    3. Store results in scan history database
    4. Optionally notify via webhook

    Returns:
        Dict with scan_id, stats, and timing info.
    """
    import orjson

    start_time = time.monotonic()

    if store is None:
        store = ScanHistoryStore()

    # Step 1: Crawl
    logger.info("Starting registry crawl...")
    crawler = RegistryCrawler(limit=limit)
    crawl_results = asyncio.run(crawler.crawl())
    logger.info("Discovered %d servers", len(crawl_results))

    if not crawl_results:
        return {
            "status": "no_servers",
            "message": "No servers discovered from registries.",
            "elapsed_seconds": time.monotonic() - start_time,
        }

    # Step 2: Write crawl results to temp dir, then batch scan
    with tempfile.TemporaryDirectory(prefix="navil_scan_") as tmpdir:
        crawl_dir = Path(tmpdir) / "crawl"
        crawl_dir.mkdir()

        for i, result in enumerate(crawl_results):
            path = crawl_dir / f"{result.source}_{i:04d}.json"
            path.write_bytes(orjson.dumps(result.to_dict(), option=orjson.OPT_INDENT_2))

        output_path = Path(tmpdir) / "scan_results.jsonl"

        logger.info("Starting batch scan of %d servers...", len(crawl_results))
        stats = scan_batch(crawl_dir, output_path, timeout_per_scan=timeout_per_scan)

        # Step 3: Store results
        scan_records: list[dict[str, Any]] = []
        if output_path.exists():
            for line in output_path.read_text().splitlines():
                line = line.strip()
                if line:
                    scan_records.append(orjson.loads(line))

    scan_id = store.store_scan_results(scan_records, source_file="scheduled_scan")

    elapsed = time.monotonic() - start_time

    result_info: dict[str, Any] = {
        "status": "complete",
        "scan_id": scan_id,
        "servers_discovered": len(crawl_results),
        "stats": stats.to_dict(),
        "elapsed_seconds": round(elapsed, 1),
    }

    # Step 4: Optional webhook notification
    if webhook_url:
        _send_webhook(webhook_url, result_info)

    logger.info(
        "Scan %d complete: %d total, %d successful, %d failed, %d timed out (%.1fs)",
        scan_id,
        stats.total,
        stats.successful,
        stats.failed,
        stats.timed_out,
        elapsed,
    )

    return result_info


# ── Daemon mode ───────────────────────────────────────────────


def run_daemon(
    interval: str = "weekly",
    *,
    limit: int = 0,
    timeout_per_scan: int = 30,
    webhook_url: str | None = None,
) -> None:
    """Run the scheduler as a long-running daemon.

    Uses a simple sleep loop for the specified interval.

    Args:
        interval: One of "hourly", "daily", "weekly", "monthly".
        limit: Max servers to crawl per run (0 = unlimited).
        timeout_per_scan: Seconds to allow per individual scan.
        webhook_url: URL to POST results to after each scan.
    """
    seconds = INTERVAL_SECONDS.get(interval)
    if seconds is None:
        raise ValueError(f"Unknown interval: {interval!r}. Choose from: {list(INTERVAL_SECONDS)}")

    store = ScanHistoryStore()
    logger.info("Starting Navil scan daemon (interval=%s, every %ds)", interval, seconds)

    # Run immediately on start, then sleep
    while True:
        try:
            result = run_full_scan(
                limit=limit,
                timeout_per_scan=timeout_per_scan,
                store=store,
                webhook_url=webhook_url,
            )
            logger.info("Scan result: %s", result.get("status"))
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
            break
        except Exception:
            logger.exception("Scan failed — will retry at next interval")

        try:
            logger.info("Sleeping %ds until next scan...", seconds)
            time.sleep(seconds)
        except KeyboardInterrupt:
            logger.info("Daemon stopped by user")
            break


# ── Crontab generation ────────────────────────────────────────


def generate_crontab_entry(
    interval: str = "weekly",
    *,
    limit: int = 0,
    timeout_per_scan: int = 30,
    log_path: str = "~/.navil/scan.log",
) -> str:
    """Generate a crontab entry for scheduled scanning.

    Args:
        interval: One of "hourly", "daily", "weekly", "monthly".
        limit: Max servers to crawl per run (0 = unlimited).
        timeout_per_scan: Seconds per scan.
        log_path: Path for log output.

    Returns:
        A crontab line string.
    """
    cron = INTERVAL_CRON.get(interval)
    if cron is None:
        raise ValueError(f"Unknown interval: {interval!r}. Choose from: {list(INTERVAL_CRON)}")

    # Find the navil executable
    navil_bin = shutil.which("navil")
    if navil_bin is None:
        navil_bin = f"{sys.executable} -m navil"

    cmd_parts = [navil_bin, "crawl", "run-scan"]
    if limit > 0:
        cmd_parts.extend(["--limit", str(limit)])
    if timeout_per_scan != 30:
        cmd_parts.extend(["--timeout", str(timeout_per_scan)])

    cmd = " ".join(cmd_parts)
    expanded_log = Path(log_path).expanduser()

    return f"{cron} {cmd} >> {expanded_log} 2>&1"


def generate_systemd_timer(
    interval: str = "weekly",
    *,
    limit: int = 0,
    timeout_per_scan: int = 30,
) -> dict[str, str]:
    """Generate systemd service and timer unit file contents.

    Returns:
        Dict with keys 'service' and 'timer' containing file contents.
    """
    navil_bin = shutil.which("navil")
    if navil_bin is None:
        navil_bin = f"{sys.executable} -m navil"

    cmd_parts = [navil_bin, "crawl", "run-scan"]
    if limit > 0:
        cmd_parts.extend(["--limit", str(limit)])
    if timeout_per_scan != 30:
        cmd_parts.extend(["--timeout", str(timeout_per_scan)])

    exec_cmd = " ".join(cmd_parts)

    # Map interval to systemd calendar spec
    calendar_map = {
        "hourly": "hourly",
        "daily": "daily",
        "weekly": "weekly",
        "monthly": "monthly",
    }
    on_calendar = calendar_map.get(interval, "weekly")

    service = f"""[Unit]
Description=Navil MCP Security Re-scan
After=network-online.target

[Service]
Type=oneshot
ExecStart={exec_cmd}
Environment=HOME={Path.home()}

[Install]
WantedBy=multi-user.target
"""

    timer = f"""[Unit]
Description=Navil MCP Security Re-scan Timer

[Timer]
OnCalendar={on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""

    return {"service": service, "timer": timer}


# ── Webhook ───────────────────────────────────────────────────


def _send_webhook(url: str, data: dict[str, Any]) -> None:
    """POST scan results to a webhook URL (best-effort, no retry)."""
    try:
        import httpx

        resp = httpx.post(url, json=data, timeout=10.0)
        if resp.status_code >= 400:
            logger.warning("Webhook returned HTTP %d: %s", resp.status_code, url)
        else:
            logger.info("Webhook notification sent to %s", url)
    except Exception:
        logger.warning("Failed to send webhook notification to %s", url, exc_info=True)
