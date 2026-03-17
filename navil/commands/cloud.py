"""Cloud commands -- login, logout, and status for Navil Cloud."""

from __future__ import annotations

import argparse
import os
import sys
import time
import webbrowser
from typing import Any

import httpx
import yaml

from navil.commands.init import (
    CONFIG_FILE,
    DEFAULT_BACKEND_URL,
    ensure_machine_id,
    load_config,
)


def _cloud_login_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil cloud login` — OAuth device flow enrollment."""
    api_url = os.environ.get("NAVIL_API_URL", DEFAULT_BACKEND_URL).rstrip("/")
    machine_id = ensure_machine_id()

    print("Starting cloud enrollment...")

    # 1. Create enrollment session
    try:
        resp = httpx.post(
            f"{api_url}/v1/enroll/session",
            json={"machine_id": machine_id},
            timeout=10.0,
        )
        resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        print("Cannot reach Navil Cloud. Check your connection.", file=sys.stderr)
        return 1
    except httpx.HTTPStatusError as e:
        print(f"Enrollment failed: {e.response.status_code}", file=sys.stderr)
        return 1

    data = resp.json()
    session_token = data["session_token"]
    enroll_url = data["enroll_url"]

    # 2. Open browser
    print("Opening browser to link your machine...")
    webbrowser.open(enroll_url)
    print(f"If the browser didn't open, visit: {enroll_url}")
    print()

    # 3. Poll for completion (timeout 5 minutes = 150 polls at 2s)
    poll_url = f"{api_url}/v1/enroll/poll"
    max_polls = 150

    for i in range(max_polls):
        time.sleep(2)
        try:
            poll_resp = httpx.get(
                poll_url,
                params={"session_token": session_token},
                timeout=10.0,
            )
            poll_resp.raise_for_status()
        except Exception:
            # Transient error, keep polling
            continue

        poll_data = poll_resp.json()
        status = poll_data.get("status")

        if status == "complete":
            api_key = poll_data["api_key"]
            org_name = poll_data.get("org_name", "your organization")

            # Write api_key to config
            config = load_config(CONFIG_FILE)
            config.setdefault("cloud", {})["api_key"] = api_key
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(yaml.dump(config, default_flow_style=False))

            print(f"\u2713 Linked to org '{org_name}'. Machine visible in dashboard.")
            return 0

        if status == "error":
            print("Enrollment failed. Please try again.", file=sys.stderr)
            return 1

        # status == "pending" — keep polling
        if i % 15 == 14:
            print("Still waiting for browser authentication...")

    print("Session expired (5 minute timeout). Run `navil cloud login` again.", file=sys.stderr)
    return 1


def _cloud_logout_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil cloud logout` — remove API key, keep machine_id."""
    config = load_config(CONFIG_FILE)

    cloud_section = config.get("cloud", {})
    if "api_key" in cloud_section:
        del cloud_section["api_key"]
        config["cloud"] = cloud_section
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(yaml.dump(config, default_flow_style=False))

    print("\u2713 Logged out. Anonymous sharing continues.")
    return 0


def _cloud_status_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil cloud status` — show connection status."""
    config = load_config(CONFIG_FILE)

    api_key = config.get("cloud", {}).get("api_key", "")
    machine_id = config.get("machine", {}).get("id", "not set")

    if api_key:
        masked = api_key[:10] + "****" if len(api_key) > 10 else "****"
        print(f"Connected to Navil Cloud. API key: {masked}")
    else:
        print("Sharing anonymously. Run `navil cloud login` for dashboard access.")

    sync_disabled = os.environ.get("NAVIL_DISABLE_CLOUD_SYNC", "").lower() in (
        "true",
        "1",
        "yes",
    )
    if sync_disabled:
        print("Cloud sync: DISABLED")
    else:
        print("Cloud sync: enabled")

    print(f"Machine ID: {machine_id}")
    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the cloud subcommands."""
    cloud_parser = subparsers.add_parser("cloud", help="Manage cloud connection")
    cloud_subparsers = cloud_parser.add_subparsers(dest="cloud_command")

    # login
    login_parser = cloud_subparsers.add_parser(
        "login", help="Link this machine to your Navil Cloud account"
    )
    login_parser.set_defaults(func=lambda cli, args: _cloud_login_command(cli, args))

    # logout
    logout_parser = cloud_subparsers.add_parser(
        "logout", help="Disconnect from cloud (anonymous sharing continues)"
    )
    logout_parser.set_defaults(func=lambda cli, args: _cloud_logout_command(cli, args))

    # status
    status_parser = cloud_subparsers.add_parser(
        "status", help="Show current cloud connection status"
    )
    status_parser.set_defaults(func=lambda cli, args: _cloud_status_command(cli, args))
