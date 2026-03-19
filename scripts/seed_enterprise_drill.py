#!/usr/bin/env python3
"""Seed Enterprise Drill — The World Builder.

Resets the cloud-backend Postgres database, provisions an Enterprise-tier
organization with a CISO user, configures webhooks, and generates a fresh
API key for the live-fire E2E test.

Usage:
    export DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/navil"
    python scripts/seed_enterprise_drill.py

    # Optional: set a real Slack webhook for alert testing
    export TEST_SLACK_WEBHOOK="https://hooks.slack.com/services/..."

Environment:
    DATABASE_URL           — Postgres connection string (asyncpg dialect)
    TEST_SLACK_WEBHOOK     — (optional) Slack webhook URL for alert delivery
    TEST_DISCORD_WEBHOOK   — (optional) Discord webhook URL
    WEBHOOK_SECRET_ENCRYPTION_KEY — Fernet key for webhook secret encryption

Outputs:
    Prints the generated NAVIL_API_KEY to stdout for use by enterprise_live_fire.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
import uuid
from datetime import datetime

# ---------------------------------------------------------------------------
# Database URL — required
# ---------------------------------------------------------------------------
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/navil",
)

# Optional webhook URLs
TEST_SLACK_WEBHOOK = os.environ.get("TEST_SLACK_WEBHOOK", "https://httpbin.org/post")
TEST_DISCORD_WEBHOOK = os.environ.get("TEST_DISCORD_WEBHOOK", "")

# ---------------------------------------------------------------------------
# Enterprise test user constants
# ---------------------------------------------------------------------------
CISO_EMAIL = "ciso@enterprise-test.com"
CISO_CLERK_ID = f"e2e_drill_{uuid.uuid4().hex[:12]}"
ORG_NAME = "Enterprise Drill Corp"
ORG_SLUG = f"enterprise-drill-{secrets.token_hex(4)}"


def _banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


async def main() -> None:
    """Run the full seed sequence."""

    # Late imports — keep startup fast and allow the script to print help
    # even if sqlalchemy is not installed.
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import (
            async_sessionmaker,
            create_async_engine,
        )
    except ImportError:
        print("ERROR: sqlalchemy[asyncpg] is required.")
        print("  pip install 'sqlalchemy[asyncpg]' asyncpg")
        sys.exit(1)

    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        pool_size=5,
        pool_pre_ping=True,
        connect_args={"statement_cache_size": 0, "prepared_statement_cache_size": 0},
    )
    Session = async_sessionmaker(engine, expire_on_commit=False)  # noqa: N806

    async with Session() as db:  # type: AsyncSession
        # ------------------------------------------------------------------
        # Step 1: Wipe dummy data
        # ------------------------------------------------------------------
        _banner("Step 1/5 — Wiping test telemetry and drill data")

        # Tables in dependency order (children first to avoid FK violations).
        # We delete ALL rows from telemetry/event tables but only drill-
        # specific rows from users/orgs so we don't nuke real data.
        telemetry_tables = [
            "sync_events",
            "telemetry_events",
            "webhook_deliveries",
            "threat_patterns",
            "pattern_contributions",
            "global_threats",
        ]
        for table in telemetry_tables:
            try:
                result = await db.execute(text(f"DELETE FROM {table}"))
                print(f"  Purged {table}: {result.rowcount} rows")
            except Exception as exc:
                # Table might not exist yet if migrations haven't run
                await db.rollback()
                print(f"  Skipped {table}: {exc.__class__.__name__}")

        # Clean up any previous drill users/orgs (matched by email pattern)
        try:
            await db.execute(
                text(
                    "DELETE FROM api_keys WHERE org_id IN "
                    "(SELECT id FROM organizations WHERE slug LIKE 'enterprise-drill-%')"
                )
            )
            await db.execute(
                text(
                    "DELETE FROM webhook_endpoints WHERE org_id IN "
                    "(SELECT id FROM organizations WHERE slug LIKE 'enterprise-drill-%')"
                )
            )
            await db.execute(
                text("DELETE FROM users WHERE email = :email"),
                {"email": CISO_EMAIL},
            )
            await db.execute(
                text("DELETE FROM organizations WHERE slug LIKE 'enterprise-drill-%'"),
            )
            print("  Purged previous drill users/orgs")
        except Exception:
            await db.rollback()
            print("  No previous drill data to purge")

        await db.commit()
        print("  Done.")

        # ------------------------------------------------------------------
        # Step 2: Create the Organization (enterprise tier)
        # ------------------------------------------------------------------
        _banner("Step 2/5 — Creating Enterprise organization")

        org_id = uuid.uuid4()
        await db.execute(
            text(
                """
                INSERT INTO organizations (id, name, slug, tier,
                    slack_webhook_url, discord_webhook_url, created_at, updated_at)
                VALUES (:id, :name, :slug, :tier,
                    :slack, :discord, :now, :now)
                """
            ),
            {
                "id": str(org_id),
                "name": ORG_NAME,
                "slug": ORG_SLUG,
                "tier": "enterprise",
                "slack": TEST_SLACK_WEBHOOK,
                "discord": TEST_DISCORD_WEBHOOK or None,
                "now": datetime.utcnow(),
            },
        )
        await db.commit()
        print(f"  Org ID:   {org_id}")
        print(f"  Slug:     {ORG_SLUG}")
        print("  Tier:     enterprise")
        print(f"  Slack WH: {TEST_SLACK_WEBHOOK[:50]}...")

        # ------------------------------------------------------------------
        # Step 3: Create the VIP user
        # ------------------------------------------------------------------
        _banner("Step 3/5 — Creating CISO user")

        user_id = uuid.uuid4()
        await db.execute(
            text(
                """
                INSERT INTO users (id, clerk_id, email, role, org_id,
                    is_active, created_at, updated_at)
                VALUES (:id, :clerk_id, :email, :role, :org_id,
                    true, :now, :now)
                """
            ),
            {
                "id": str(user_id),
                "clerk_id": CISO_CLERK_ID,
                "email": CISO_EMAIL,
                "role": "admin",
                "org_id": str(org_id),
                "now": datetime.utcnow(),
            },
        )
        await db.commit()
        print(f"  User ID:  {user_id}")
        print(f"  Email:    {CISO_EMAIL}")
        print(f"  Clerk ID: {CISO_CLERK_ID}")

        # ------------------------------------------------------------------
        # Step 4: Set up webhook endpoint
        # ------------------------------------------------------------------
        _banner("Step 4/5 — Configuring webhook endpoint")

        webhook_secret = secrets.token_hex(32)

        # Store webhook secret. If encryption key is configured, encrypt it;
        # otherwise store plaintext (test-only).
        fernet_key = os.environ.get("WEBHOOK_SECRET_ENCRYPTION_KEY", "")
        if fernet_key:
            try:
                from cryptography.fernet import Fernet

                encrypted = Fernet(fernet_key.encode()).encrypt(webhook_secret.encode()).decode()
            except Exception:
                encrypted = webhook_secret
        else:
            encrypted = webhook_secret

        webhook_id = uuid.uuid4()
        await db.execute(
            text(
                """
                INSERT INTO webhook_endpoints
                    (id, org_id, url, events, encrypted_secret,
                     is_active, status, created_at, updated_at)
                VALUES
                    (:id, :org_id, :url, :events, :secret,
                     true, 'active', :now, :now)
                """
            ),
            {
                "id": str(webhook_id),
                "org_id": str(org_id),
                "url": TEST_SLACK_WEBHOOK,
                "events": '["anomaly.critical","anomaly.high","blocked","alert"]',
                "secret": encrypted,
                "now": datetime.utcnow(),
            },
        )
        await db.commit()
        print(f"  Webhook ID:  {webhook_id}")
        print(f"  URL:         {TEST_SLACK_WEBHOOK[:60]}")
        print("  Events:      anomaly.critical, anomaly.high, blocked, alert")

        # ------------------------------------------------------------------
        # Step 5: Generate API key
        # ------------------------------------------------------------------
        _banner("Step 5/5 — Generating API key")

        # Replicate the key generation from app/core/security.py
        B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"  # noqa: N806

        def base62_encode(data: bytes) -> str:
            num = int.from_bytes(data, "big")
            if num == 0:
                return B62[0]
            chars: list[str] = []
            while num:
                num, rem = divmod(num, 62)
                chars.append(B62[rem])
            return "".join(reversed(chars))

        random_part = base62_encode(secrets.token_bytes(24))
        plain_key = f"navil_live_{random_part}"
        key_prefix = plain_key[:20]
        hashed_key = hashlib.sha256(plain_key.encode()).hexdigest()

        api_key_id = uuid.uuid4()
        await db.execute(
            text(
                """
                INSERT INTO api_keys
                    (id, org_id, key_prefix, hashed_key, label,
                     is_active, created_at, updated_at)
                VALUES
                    (:id, :org_id, :prefix, :hash, :label,
                     true, :now, :now)
                """
            ),
            {
                "id": str(api_key_id),
                "org_id": str(org_id),
                "prefix": key_prefix,
                "hash": hashed_key,
                "label": "E2E Live Fire Drill",
                "now": datetime.utcnow(),
            },
        )
        await db.commit()
        print(f"  Key ID:     {api_key_id}")
        print(f"  Key Prefix: {key_prefix}")

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        _banner("SEED COMPLETE")
        print(f"""
  Organization: {ORG_NAME} ({ORG_SLUG})
  Tier:         enterprise
  User:         {CISO_EMAIL}
  Webhook:      {TEST_SLACK_WEBHOOK[:60]}

  ┌─────────────────────────────────────────────────────────┐
  │  NAVIL_API_KEY={plain_key}
  └─────────────────────────────────────────────────────────┘

  Export this key and run the live-fire script:

    export NAVIL_API_KEY="{plain_key}"
    export NAVIL_BACKEND_URL="https://api.navil.ai"
    python scripts/enterprise_live_fire.py
""")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
