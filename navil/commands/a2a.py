"""A2A Agent Card commands -- manage agent discovery cards."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx

from navil.a2a.agent_card import build_navil_agent_card
from navil.commands.init import (
    CONFIG_FILE,
    DEFAULT_BACKEND_URL,
    load_config,
)


def _get_api_url() -> str:
    """Get the cloud API URL from env or config."""
    return os.environ.get("NAVIL_API_URL", DEFAULT_BACKEND_URL).rstrip("/")


def _get_api_key() -> str | None:
    """Get the API key from env or config."""
    key = os.environ.get("NAVIL_API_KEY", "")
    if key:
        return key
    config = load_config(CONFIG_FILE)
    return config.get("cloud", {}).get("api_key", "") or None


def _a2a_card_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil a2a card` -- build and print the local agent card JSON."""
    config = load_config(CONFIG_FILE)

    agent_card = build_navil_agent_card(
        agent_name=config.get("agent", {}).get("name", ""),
        agent_description=config.get("agent", {}).get("description", ""),
        base_url=config.get("agent", {}).get("base_url", ""),
        provider_org=config.get("agent", {}).get("provider_org", ""),
        provider_url=config.get("agent", {}).get("provider_url", ""),
    )
    print(json.dumps(agent_card.to_dict(), indent=2))
    return 0


def _a2a_publish_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil a2a publish` -- publish agent card to Navil Cloud registry."""
    api_key = _get_api_key()
    if not api_key:
        print(
            "No API key configured. Run `navil cloud login` or set NAVIL_API_KEY.",
            file=sys.stderr,
        )
        return 1

    config = load_config(CONFIG_FILE)
    agent_card = build_navil_agent_card(
        agent_name=config.get("agent", {}).get("name", ""),
        agent_description=config.get("agent", {}).get("description", ""),
        base_url=config.get("agent", {}).get("base_url", ""),
        provider_org=config.get("agent", {}).get("provider_org", ""),
        provider_url=config.get("agent", {}).get("provider_url", ""),
    )
    card_dict = agent_card.to_dict()

    api_url = _get_api_url()
    print(f"Publishing agent card to {api_url}/v1/a2a/register ...")

    try:
        resp = httpx.post(
            f"{api_url}/v1/a2a/register",
            json={"card": card_dict},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15.0,
        )
        resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        print("Cannot reach Navil Cloud. Check your connection.", file=sys.stderr)
        return 1
    except httpx.HTTPStatusError as e:
        print(f"Publish failed: {e.response.status_code} — {e.response.text}", file=sys.stderr)
        return 1

    data = resp.json()
    print(f"Published! Agent ID: {data.get('agent_id', 'unknown')}")
    print(f"Trust score: {data.get('trust_score', 'N/A')}")
    return 0


def _a2a_discover_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil a2a discover` -- discover registered agents from cloud."""
    api_url = _get_api_url()

    try:
        resp = httpx.get(f"{api_url}/v1/a2a/discover", timeout=15.0)
        resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        print("Cannot reach Navil Cloud. Check your connection.", file=sys.stderr)
        return 1
    except httpx.HTTPStatusError as e:
        print(f"Discovery failed: {e.response.status_code}", file=sys.stderr)
        return 1

    data = resp.json()
    agents = data.get("agents", [])
    total = data.get("total", 0)

    if total == 0:
        print("No agents registered in the cloud registry.")
        return 0

    print(f"Found {total} registered agent(s):\n")

    # Print table header
    print(f"{'Agent ID':<30} {'Trust':<8} {'Last Heartbeat':<22} {'Description'}")
    print(f"{'-' * 30} {'-' * 8} {'-' * 22} {'-' * 40}")

    for agent in agents:
        agent_id = agent.get("agent_id", "?")[:30]
        trust = f"{agent.get('trust_score', 0):.2f}"
        heartbeat = agent.get("last_heartbeat", "never") or "never"
        if heartbeat != "never":
            heartbeat = heartbeat[:19]  # trim to datetime without microseconds
        card = agent.get("card", {})
        description = card.get("description", "")[:40]
        print(f"{agent_id:<30} {trust:<8} {heartbeat:<22} {description}")

    return 0


def _a2a_status_command(cli: Any, args: argparse.Namespace) -> int:
    """Handle `navil a2a status` -- show local card and cloud registration status."""
    config = load_config(CONFIG_FILE)

    # Build local card
    agent_card = build_navil_agent_card(
        agent_name=config.get("agent", {}).get("name", ""),
        agent_description=config.get("agent", {}).get("description", ""),
        base_url=config.get("agent", {}).get("base_url", ""),
        provider_org=config.get("agent", {}).get("provider_org", ""),
        provider_url=config.get("agent", {}).get("provider_url", ""),
    )
    card_dict = agent_card.to_dict()

    print("Local Agent Card:")
    print(f"  Name:        {card_dict.get('name', 'not set')}")
    print(f"  Description: {card_dict.get('description', 'not set')}")
    print(f"  Version:     {card_dict.get('version', 'not set')}")
    provider = card_dict.get("provider", {})
    print(f"  Provider:    {provider.get('organization', 'not set')}")
    print()

    # Check cloud status
    api_key = _get_api_key()
    if not api_key:
        print("Cloud: Not connected (run `navil cloud login`)")
        return 0

    api_url = _get_api_url()
    agent_id = card_dict.get("name", "")

    if agent_id:
        try:
            resp = httpx.get(f"{api_url}/v1/a2a/discover/{agent_id}", timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                print(f"Cloud: Registered (trust score: {data.get('trust_score', 'N/A')})")
                print(f"  Last heartbeat: {data.get('last_heartbeat', 'never')}")
            elif resp.status_code == 404:
                print("Cloud: Not registered (run `navil a2a publish`)")
            else:
                print(f"Cloud: Unable to check status (HTTP {resp.status_code})")
        except (httpx.ConnectError, httpx.TimeoutException, OSError):
            print("Cloud: Cannot reach Navil Cloud")
    else:
        print("Cloud: No agent name configured")

    return 0


def _handle_a2a(args: argparse.Namespace, cli: Any) -> int:
    """Route a2a subcommands."""
    cmd = getattr(args, "a2a_command", None)
    if cmd == "card":
        return _a2a_card_command(cli, args)
    elif cmd == "publish":
        return _a2a_publish_command(cli, args)
    elif cmd == "discover":
        return _a2a_discover_command(cli, args)
    elif cmd == "status":
        return _a2a_status_command(cli, args)
    else:
        print("Usage: navil a2a {card,publish,discover,status}", file=sys.stderr)
        return 1


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the a2a subcommands."""
    a2a_parser = subparsers.add_parser("a2a", help="Manage A2A Agent Cards")
    a2a_sub = a2a_parser.add_subparsers(dest="a2a_command")
    a2a_sub.add_parser("card", help="Print current agent card JSON")
    a2a_sub.add_parser("publish", help="Publish agent card to Navil Cloud registry")
    a2a_sub.add_parser("discover", help="Discover registered agents")
    a2a_sub.add_parser("status", help="Show A2A registration status")
    a2a_parser.set_defaults(func=lambda cli, args: _handle_a2a(args, cli))
