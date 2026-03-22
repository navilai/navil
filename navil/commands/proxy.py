"""Proxy command -- start the MCP security proxy."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _proxy_start(cli, args: argparse.Namespace) -> int:  # type: ignore[no-untyped-def]
    try:
        from navil.proxy import MCPSecurityProxy, create_proxy_app
    except ImportError:
        print(
            "Error: Cloud dependencies not installed. Run: pip install navil[cloud]",
            file=sys.stderr,
        )
        return 1
    import uvicorn

    # Load policy if provided
    if args.policy:
        cli.policy_engine.policy_file = Path(args.policy)
        cli.policy_engine._load_policy()

    # Set up cloud telemetry if API key provided
    cloud_client = None
    if args.cloud_key:
        try:
            from navil.telemetry import NavilCloudClient

            cloud_client = NavilCloudClient(
                api_key=args.cloud_key,
                cloud_url=args.cloud_url,
            )
        except ImportError:
            print(
                "Warning: httpx not installed for cloud telemetry. "
                "Install with: pip install navil[cloud]",
                file=sys.stderr,
            )

    proxy = MCPSecurityProxy(
        target_url=args.target,
        policy_engine=cli.policy_engine,
        anomaly_detector=cli.anomaly_detector,
        credential_manager=cli.credential_manager,
        require_auth=not args.no_auth,
        cloud_client=cloud_client,
    )
    app = create_proxy_app(proxy)
    port = int(args.port)
    print("\n  Navil MCP Security Proxy")
    print(f"  Target: {args.target}")
    print(f"  Listening: http://{args.host}:{port}")
    print(f"  Auth: {'required' if not args.no_auth else 'disabled'}")
    if cloud_client:
        print(f"  Cloud: {args.cloud_url} (telemetry enabled)")
    print(f"  Health: http://{args.host}:{port}/health\n")

    # Start CloudSyncWorker for threat intel sharing
    from navil.cloud.telemetry_sync import CloudSyncWorker
    from navil.commands.init import load_config

    config = load_config()
    api_key = args.cloud_key or config.get("cloud", {}).get("api_key", "")
    machine_id = config.get("machine", {}).get("id", "")
    cloud_url = args.cloud_url or "https://navil-cloud-api.onrender.com"

    sync_worker = CloudSyncWorker(
        detector=cli.anomaly_detector,
        api_url=f"{cloud_url}/v1/telemetry/sync",
        api_key=api_key,
        machine_id=machine_id,
        sync_interval=60,
        enabled=bool(api_key or machine_id),
    )

    if sync_worker.enabled:
        import asyncio
        import threading

        def _run_sync() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(sync_worker.run())

        sync_thread = threading.Thread(target=_run_sync, daemon=True)
        sync_thread.start()
        print(f"  Cloud sync: enabled (→ {cloud_url})")

    uvicorn.run(app, host=args.host, port=port, log_level="info")
    return 0


def register(subparsers: argparse._SubParsersAction, cli_class: type) -> None:
    """Register the proxy subcommands."""
    proxy_parser = subparsers.add_parser("proxy", help="MCP security proxy (requires navil[cloud])")
    proxy_sub = proxy_parser.add_subparsers(dest="proxy_command")

    proxy_start = proxy_sub.add_parser("start", help="Start the MCP security proxy")
    proxy_start.add_argument(
        "--target", required=True, help="Upstream MCP server URL (e.g., http://localhost:3000)"
    )
    proxy_start.add_argument("--port", default="9090", help="Port to listen on (default: 9090)")
    proxy_start.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    proxy_start.add_argument("--policy", default=None, help="Path to policy YAML file")
    proxy_start.add_argument(
        "--no-auth", action="store_true", help="Disable JWT authentication requirement"
    )
    proxy_start.add_argument(
        "--cloud-key",
        default=None,
        help="API key for navil.ai cloud telemetry (nvl_...)",
    )
    proxy_start.add_argument(
        "--cloud-url",
        default="https://navil.ai",
        help="Cloud API URL (default: https://navil.ai)",
    )
    proxy_start.set_defaults(func=_proxy_start)
