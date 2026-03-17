"""Credential commands -- issue, revoke, delegate, exchange, and list MCP agent credentials."""

from __future__ import annotations

import argparse
import sys


def _credential_issue_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential issue command."""
    agent_name = args.agent
    scope = args.scope
    ttl = int(args.ttl)

    print(f"\nIssuing credential for agent: {agent_name}")
    print(f"Scope: {scope}")
    print(f"TTL: {ttl} seconds")
    print("-" * 60)

    try:
        result = cli.credential_manager.issue_credential(
            agent_name=agent_name, scope=scope, ttl_seconds=ttl
        )

        print("\nCredential Issued Successfully")
        print(f"Token ID: {result['token_id']}")
        print(f"Agent: {result['agent_name']}")
        print(f"Scope: {result['scope']}")
        print(f"Issued At: {result['issued_at']}")
        print(f"Expires At: {result['expires_at']}")
        print("\nToken (save this securely):")
        print(result["token"])

        return 0
    except Exception as e:
        print(f"Error: {e!s}", file=sys.stderr)
        return 1


def _credential_revoke_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential revoke command."""
    token_id = args.token_id
    cascade = getattr(args, "cascade", False)

    if cascade:
        print(f"\nCascade revoking credential and all descendants: {token_id}")
    else:
        print(f"\nRevoking credential: {token_id}")
    print("-" * 60)

    try:
        if cascade:
            count = cli.credential_manager.cascade_revoke(token_id)
            print(f"Cascade revocation complete: {count} credential(s) revoked")
        else:
            cli.credential_manager.revoke_credential(token_id, reason="CLI revocation")
            print("Credential revoked successfully")
        return 0
    except ValueError as e:
        print(f"Error: {e!s}", file=sys.stderr)
        return 1


def _credential_list_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential list command."""
    agent_name = args.agent
    status = args.status

    print("\nListing Credentials")
    print("-" * 60)

    credentials = cli.credential_manager.list_credentials(agent_name=agent_name, status=status)

    if not credentials:
        print("No credentials found")
        return 0

    print(f"{'Token ID':<20} {'Agent':<15} {'Status':<10} {'Expires At':<20}")
    print("-" * 65)

    for cred in credentials:
        print(
            f"{cred['token_id']:<20} {cred['agent_name']:<15} "
            f"{cred['status']:<10} {cred['expires_at']:<20}"
        )

    return 0


def _credential_exchange_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential exchange command (OIDC token exchange)."""
    from navil.oidc import exchange_oidc_token

    oidc_token = args.oidc_token
    agent_name = args.agent
    scope = args.scope

    print(f"\nExchanging OIDC token for agent: {agent_name}")
    print(f"Scope: {scope}")
    print("-" * 60)

    try:
        result = exchange_oidc_token(
            oidc_token=oidc_token,
            agent_name=agent_name,
            scope=scope,
            credential_manager=cli.credential_manager,
            audience=getattr(args, "audience", None),
        )

        print("\nCredential Issued Successfully (OIDC Exchange)")
        print(f"Token ID: {result['token_id']}")
        print(f"Agent: {result['agent_name']}")
        print(f"Scope: {result['scope']}")
        print(f"Issued At: {result['issued_at']}")
        print(f"Expires At: {result['expires_at']}")

        hc = result.get("human_context")
        if hc:
            print(f"\nHuman Identity:")
            print(f"  Subject: {hc.get('sub', 'N/A')}")
            print(f"  Email: {hc.get('email', 'N/A')}")
            print(f"  Roles: {', '.join(hc.get('roles', []))}")

        print("\nToken (save this securely):")
        print(result["token"])

        return 0
    except Exception as e:
        print(f"Error: {e!s}", file=sys.stderr)
        return 1


def _credential_delegate_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential delegate command."""
    parent_id = args.parent
    agent_name = args.agent
    scope = args.scope
    ttl = int(args.ttl)

    print(f"\nDelegating credential from: {parent_id}")
    print(f"To agent: {agent_name}")
    print(f"Scope: {scope}")
    print(f"TTL: {ttl} seconds")
    print("-" * 60)

    try:
        result = cli.credential_manager.delegate_credential(
            parent_credential_id=parent_id,
            agent_name=agent_name,
            narrowed_scope=scope,
            ttl_seconds=ttl,
        )

        print("\nDelegated Credential Issued Successfully")
        print(f"Token ID: {result['token_id']}")
        print(f"Agent: {result['agent_name']}")
        print(f"Scope: {result['scope']}")
        print(f"Parent: {result.get('parent_credential_id', 'N/A')}")
        chain = result.get("delegation_chain", [])
        print(f"Chain depth: {len(chain)}")
        print(f"Issued At: {result['issued_at']}")
        print(f"Expires At: {result['expires_at']}")

        print("\nToken (save this securely):")
        print(result["token"])

        return 0
    except ValueError as e:
        print(f"Error: {e!s}", file=sys.stderr)
        return 1


def _credential_chain_command(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    """Handle credential chain command -- display full delegation chain."""
    token_id = args.token_id

    print(f"\nDelegation Chain for: {token_id}")
    print("-" * 60)

    try:
        cred_info = cli.credential_manager.get_credential_info(token_id)
        if not cred_info:
            print(f"Error: Credential not found: {token_id}", file=sys.stderr)
            return 1

        chain = cred_info.get("delegation_chain", [])
        human_context = cred_info.get("human_context")

        # Display human identity at root if present
        if human_context:
            email = human_context.get("email", "unknown")
            sub = human_context.get("sub", "unknown")
            print(f"  Human ({email}, sub={sub})")

        # Display each ancestor
        for i, ancestor_id in enumerate(chain):
            ancestor = cli.credential_manager.get_credential_info(ancestor_id)
            if ancestor:
                status_marker = " [REVOKED]" if ancestor.get("status") == "REVOKED" else ""
                scope = ancestor.get("scope", "?")
                agent = ancestor.get("agent_name", "?")
                prefix = "  |" + "  " * i
                print(f"{prefix}-> {agent} (scope: {scope}){status_marker}")
                print(f"{prefix}   ID: {ancestor_id[:20]}...")
            else:
                prefix = "  |" + "  " * i
                print(f"{prefix}-> [missing] ID: {ancestor_id[:20]}...")

        # Display current credential
        status_marker = " [REVOKED]" if cred_info.get("status") == "REVOKED" else ""
        prefix = "  |" + "  " * len(chain)
        print(
            f"{prefix}-> {cred_info.get('agent_name', '?')} "
            f"(scope: {cred_info.get('scope', '?')}){status_marker}"
        )
        print(f"{prefix}   ID: {token_id[:20]}... [CURRENT]")

        print(f"\nChain depth: {len(chain)}")
        print(f"Max further delegation: {cred_info.get('max_delegation_depth', '?')}")

        return 0
    except Exception as e:
        print(f"Error: {e!s}", file=sys.stderr)
        return 1


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the credential subcommands."""
    credential_parser = subparsers.add_parser("credential", help="Manage credentials")
    credential_subparsers = credential_parser.add_subparsers(dest="credential_command")

    # Issue credential
    issue_parser = credential_subparsers.add_parser("issue", help="Issue new credential")
    issue_parser.add_argument("--agent", required=True, help="Agent name")
    issue_parser.add_argument("--scope", required=True, help="Permission scope")
    issue_parser.add_argument(
        "--ttl", default="3600", help="Time to live in seconds (default: 3600)"
    )
    issue_parser.set_defaults(func=lambda cli, args: _credential_issue_command(cli, args))

    # Revoke credential
    revoke_parser = credential_subparsers.add_parser("revoke", help="Revoke credential")
    revoke_parser.add_argument("--token-id", required=True, help="Token ID to revoke")
    revoke_parser.add_argument(
        "--cascade",
        action="store_true",
        default=False,
        help="Cascade revocation to all descendants",
    )
    revoke_parser.set_defaults(func=lambda cli, args: _credential_revoke_command(cli, args))

    # List credentials
    list_parser = credential_subparsers.add_parser("list", help="List credentials")
    list_parser.add_argument("--agent", help="Filter by agent name", default=None)
    list_parser.add_argument("--status", help="Filter by status", default=None)
    list_parser.set_defaults(func=lambda cli, args: _credential_list_command(cli, args))

    # Exchange OIDC token
    exchange_parser = credential_subparsers.add_parser(
        "exchange", help="Exchange OIDC token for credential"
    )
    exchange_parser.add_argument("--oidc-token", required=True, help="OIDC JWT token")
    exchange_parser.add_argument("--agent", required=True, help="Agent name")
    exchange_parser.add_argument("--scope", required=True, help="Permission scope")
    exchange_parser.add_argument(
        "--audience",
        default=None,
        help="Expected OIDC audience (client ID) for token verification",
    )
    exchange_parser.set_defaults(func=lambda cli, args: _credential_exchange_command(cli, args))

    # Delegate credential
    delegate_parser = credential_subparsers.add_parser(
        "delegate", help="Delegate credential to child agent"
    )
    delegate_parser.add_argument("--parent", required=True, help="Parent credential ID")
    delegate_parser.add_argument("--agent", required=True, help="Child agent name")
    delegate_parser.add_argument("--scope", required=True, help="Narrowed scope for child")
    delegate_parser.add_argument(
        "--ttl", default="3600", help="Time to live in seconds (default: 3600)"
    )
    delegate_parser.set_defaults(func=lambda cli, args: _credential_delegate_command(cli, args))

    # Show delegation chain
    chain_parser = credential_subparsers.add_parser(
        "chain", help="Display delegation chain for a credential"
    )
    chain_parser.add_argument("token_id", help="Credential token ID")
    chain_parser.set_defaults(func=lambda cli, args: _credential_chain_command(cli, args))
