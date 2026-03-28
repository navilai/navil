#!/usr/bin/env python3
"""Honeypot Log Collector — reads Docker logs and syncs to Navil Cloud.

Runs as a sidecar container alongside the honeypots. Periodically reads
Docker container logs, parses honeypot interaction lines, converts them
to SyncEvent format, and POSTs batches to /v1/telemetry/sync.

Environment variables:
  NAVIL_CLOUD_API  — Backend URL (default: https://navil-cloud-api.onrender.com)
  NAVIL_API_KEY    — API key for authenticated sync (optional, higher rate limit)
  SYNC_INTERVAL    — Seconds between sync cycles (default: 60)
  CONTAINER_PREFIX — Docker container name prefix (default: navil-honeypot-)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("honeypot-collector")

API_URL = os.environ.get("NAVIL_CLOUD_API", "https://navil-cloud-api.onrender.com")
API_KEY = os.environ.get("NAVIL_API_KEY", "")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "60"))
CONTAINER_PREFIX = os.environ.get("CONTAINER_PREFIX", "navil-honeypot-")
STATE_FILE = Path("/data/collector-state.json")

# Map honeypot tool names → recognized anomaly types
TOOL_TO_ANOMALY: dict[str, str] = {
    # Recon & enumeration
    "__tools_list__": "RECONNAISSANCE",
    "__initialize__": "RECONNAISSANCE",
    "tools": "RECONNAISSANCE",
    "list_tables": "RECONNAISSANCE",
    "dump_schema": "RECONNAISSANCE",
    "memory": "RECONNAISSANCE",
    # Data exfiltration
    "read_file": "DATA_EXFILTRATION",
    "read_env": "DATA_EXFILTRATION",
    "export_data": "DATA_EXFILTRATION",
    "query_db": "DATA_EXFILTRATION",
    # Code execution / command & control
    "exec_command": "COMMAND_AND_CONTROL",
    "http_request": "COMMAND_AND_CONTROL",
    # Persistence
    "write_file": "PERSISTENCE",
    "create_resource": "PERSISTENCE",
    # Privilege escalation
    "create_user": "PRIVILEGE_ESCALATION",
    "grant_permissions": "PRIVILEGE_ESCALATION",
}

# Severity heuristics based on tool
TOOL_SEVERITY: dict[str, str] = {
    "exec_command": "high",
    "write_file": "high",
    "create_user": "critical",
    "grant_permissions": "critical",
    "export_data": "high",
    "read_env": "high",
    "read_file": "medium",
    "query_db": "medium",
    "http_request": "high",
    "dump_schema": "medium",
    "list_tables": "low",
    "__tools_list__": "low",
    "__initialize__": "low",
    "tools": "low",
    "memory": "low",
    "create_resource": "medium",
}

# Regex to parse the structured log line from honeypot entrypoint
# Format: Honeypot interaction: tool=X source=Y user_agent=Z
INTERACTION_RE = re.compile(r"Honeypot interaction: tool=(\S+) source=([\d.]+) user_agent=(.+)")
# Also parse the INFO format: INTERACTION tool=X source=Y agent=Z
INTERACTION_RE2 = re.compile(r"INTERACTION tool=(\S+) source=([\d.]+) agent=(.+)")


def load_state() -> dict[str, str]:
    """Load last-seen timestamps per container."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_state(state: dict[str, str]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def get_honeypot_containers() -> list[dict[str, str]]:
    """List running honeypot containers."""
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{.Names}}\t{{.Labels}}",
                "--filter",
                f"name={CONTAINER_PREFIX}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        containers = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            name = parts[0]
            # Extract machine_id from env or derive from name
            machine_id = f"honeypot-{name.replace(CONTAINER_PREFIX, '').rstrip('-1')}-oci"
            containers.append({"name": name, "machine_id": machine_id})
        return containers
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.error("Failed to list Docker containers")
        return []


def get_container_logs(container_name: str, since: str | None) -> list[str]:
    """Get log lines from a Docker container."""
    cmd = ["docker", "logs", container_name]
    if since:
        cmd.extend(["--since", since])
    cmd.append("--timestamps")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Docker logs go to both stdout and stderr
        lines = (result.stdout + result.stderr).splitlines()
        return lines
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.error("Failed to get logs for %s", container_name)
        return []


def parse_interactions(
    lines: list[str],
    machine_id: str,
) -> list[dict[str, object]]:
    """Parse Docker log lines into SyncEvent dicts."""
    events: list[dict[str, object]] = []
    for line in lines:
        # Try both log formats
        match = INTERACTION_RE.search(line) or INTERACTION_RE2.search(line)
        if not match:
            continue

        tool_name = match.group(1)
        source_ip = match.group(2)
        # match.group(3) is user_agent — captured for future enrichment

        anomaly_type = TOOL_TO_ANOMALY.get(tool_name, "RECONNAISSANCE")
        severity = TOOL_SEVERITY.get(tool_name, "medium")

        # Extract timestamp from Docker log prefix (format: 2026-03-28T12:34:56.123456789Z)
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
        if ts_match:
            timestamp = ts_match.group(1) + "Z"
        else:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Deterministic UUID based on timestamp + source + tool + machine
        # This prevents duplicates on re-sync
        raw = f"{timestamp}:{source_ip}:{tool_name}:{machine_id}"
        event_uuid = hashlib.sha256(raw.encode()).hexdigest()[:64]

        events.append(
            {
                "event_uuid": event_uuid,
                "agent_id": f"attacker:{source_ip}",
                "tool_name": tool_name,
                "anomaly_type": anomaly_type,
                "severity": severity,
                "confidence": 0.95,  # honeypot interactions are high-confidence
                "timestamp": timestamp,
                "action": "logged",
                "machine_id": machine_id,
                "mcp_server_name": machine_id,
            }
        )

    return events


def sync_events(events: list[dict[str, object]]) -> tuple[int, int]:
    """POST events to /v1/telemetry/sync in batches."""
    if not events:
        return 0, 0

    total_accepted = 0
    total_rejected = 0
    batch_size = 500  # API limit is 1000, use 500 for safety

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        payload = json.dumps({"events": batch}).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "navil-honeypot-collector/1.0",
            "X-Machine-ID": "honeypot-collector-oci",
        }
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"

        try:
            req = Request(
                f"{API_URL}/v1/telemetry/sync",
                data=payload,
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
                total_accepted += body.get("accepted", 0)
                total_rejected += body.get("rejected", 0)
        except Exception as exc:
            logger.error("Sync failed for batch %d-%d: %s", i, i + len(batch), exc)
            total_rejected += len(batch)

    return total_accepted, total_rejected


def collect_and_sync() -> None:
    """One collection cycle: read logs, parse, sync."""
    state = load_state()
    containers = get_honeypot_containers()

    if not containers:
        logger.warning("No honeypot containers found")
        return

    all_events: list[dict[str, object]] = []

    for container in containers:
        name = container["name"]
        machine_id = container["machine_id"]
        since = state.get(name)

        lines = get_container_logs(name, since)
        events = parse_interactions(lines, machine_id)

        if events:
            logger.info(
                "Container %s: %d interactions since %s",
                name,
                len(events),
                since or "start",
            )
            all_events.extend(events)

        # Update state to current time
        state[name] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if all_events:
        accepted, rejected = sync_events(all_events)
        logger.info(
            "Synced %d events: %d accepted, %d rejected",
            len(all_events),
            accepted,
            rejected,
        )
    else:
        logger.debug("No new interactions to sync")

    save_state(state)


def main() -> None:
    logger.info(
        "Honeypot collector starting: api=%s interval=%ds",
        API_URL,
        SYNC_INTERVAL,
    )

    # Persist logs to file as well
    log_dir = Path("/data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            collect_and_sync()
        except Exception:
            logger.exception("Collection cycle failed")
        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()
