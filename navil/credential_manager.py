"""
Agent Credential Lifecycle Manager

Manages generation, rotation, revocation, and lifecycle of credentials
for agent-to-service communication.
Implements Just-In-Time (JIT) credential provisioning and comprehensive audit logging.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt

logger = logging.getLogger(__name__)

# Redis key prefix for credential hashes
_CRED_KEY_PREFIX = "navil:cred:"


class CredentialStatus:
    """Credential lifecycle status constants."""

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INACTIVE = "INACTIVE"


@dataclass
class CredentialAuditLog:
    """Record of credential operation for audit trail."""

    timestamp: str
    token_id: str
    agent_name: str
    operation: str  # issued, rotated, revoked, accessed, expired
    details: str
    ip_address: str | None = None


@dataclass
class Credential:
    """Represents an issued credential."""

    token_id: str
    agent_name: str
    scope: str  # e.g., "read:tools write:logs"
    token: str  # JWT token
    issued_at: str
    expires_at: str
    status: str
    rotation_count: int = 0
    last_used: str | None = None
    used_count: int = 0
    secret_hash: str = ""  # Hash of token for verification without storing plaintext
    human_context: dict | None = None  # Contains sub, email, roles from OIDC
    parent_credential_id: str | None = None
    delegation_chain: list[str] | None = None  # Ordered list of ancestor credential IDs
    delegated_by: str = ""  # Who delegated this credential
    max_delegation_depth: int = 10  # Hard cap on further delegation
    scope_narrowing_only: bool = True  # If True, children can only narrow scope, never widen


def _credential_to_hash(cred: Credential) -> dict[str, str]:
    """Serialize a Credential dataclass into a flat dict suitable for Redis HSET."""
    return {
        "token_id": cred.token_id,
        "agent_name": cred.agent_name,
        "scope": cred.scope,
        "token": cred.token,
        "issued_at": cred.issued_at,
        "expires_at": cred.expires_at,
        "status": cred.status,
        "rotation_count": str(cred.rotation_count),
        "last_used": cred.last_used if cred.last_used is not None else "",
        "used_count": str(cred.used_count),
        "secret_hash": cred.secret_hash,
        "human_context": json.dumps(cred.human_context) if cred.human_context else "",
        "parent_credential_id": cred.parent_credential_id or "",
        "delegation_chain": json.dumps(cred.delegation_chain) if cred.delegation_chain else "[]",
        "delegated_by": cred.delegated_by or "",
        "max_delegation_depth": str(cred.max_delegation_depth),
        "scope_narrowing_only": "1" if cred.scope_narrowing_only else "0",
    }


def _hash_to_credential(data: dict[str, str]) -> Credential:
    """Deserialize a Redis hash (dict of strings) back into a Credential."""
    # Parse human_context from JSON string
    human_context_raw = data.get("human_context", "")
    human_context = None
    if human_context_raw:
        try:
            human_context = json.loads(human_context_raw)
        except (json.JSONDecodeError, TypeError):
            human_context = None

    # Parse delegation_chain from JSON string
    delegation_chain_raw = data.get("delegation_chain", "[]")
    try:
        delegation_chain = json.loads(delegation_chain_raw) if delegation_chain_raw else []
    except (json.JSONDecodeError, TypeError):
        delegation_chain = []

    return Credential(
        token_id=data["token_id"],
        agent_name=data["agent_name"],
        scope=data["scope"],
        token=data["token"],
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        status=data["status"],
        rotation_count=int(data.get("rotation_count", "0")),
        last_used=data.get("last_used") or None,
        used_count=int(data.get("used_count", "0")),
        secret_hash=data.get("secret_hash", ""),
        human_context=human_context,
        parent_credential_id=data.get("parent_credential_id") or None,
        delegation_chain=delegation_chain,
        delegated_by=data.get("delegated_by", ""),
        max_delegation_depth=int(data.get("max_delegation_depth", "10")),
        scope_narrowing_only=data.get("scope_narrowing_only", "1") != "0",
    )


class _InMemoryStore:
    """Dict-backed store that mirrors the Redis interface used by CredentialManager."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, str] | set[str]] = {}

    def hset(self, name: str, mapping: dict[str, str] | None = None, **kwargs: str) -> int:  # noqa: ARG002
        if name not in self._data or isinstance(self._data[name], set):
            self._data[name] = {}
        d = self._data[name]
        assert isinstance(d, dict)
        if mapping:
            d.update(mapping)
        d.update(kwargs)
        return len(mapping) if mapping else len(kwargs)

    def hgetall(self, name: str) -> dict[str, str]:
        val = self._data.get(name, {})
        if isinstance(val, set):
            return {}
        return dict(val)

    def hget(self, name: str, key: str) -> str | None:
        val = self._data.get(name, {})
        if isinstance(val, set):
            return None
        return val.get(key)

    def hincrby(self, name: str, key: str, amount: int = 1) -> int:
        if name not in self._data:
            self._data[name] = {}
        d = self._data[name]
        if isinstance(d, set):
            self._data[name] = {}
            d = self._data[name]
        assert isinstance(d, dict)
        cur = int(d.get(key, "0"))
        cur += amount
        d[key] = str(cur)
        return cur

    def delete(self, *names: str) -> int:
        count = 0
        for n in names:
            if n in self._data:
                del self._data[n]
                count += 1
        return count

    def scan_iter(self, match: str | None = None) -> list[str]:
        if match is None:
            return list(self._data.keys())
        import fnmatch

        return [k for k in self._data if fnmatch.fnmatch(k, match)]

    def exists(self, *names: str) -> int:
        return sum(1 for n in names if n in self._data)

    def sadd(self, name: str, *values: str) -> int:
        if name not in self._data:
            self._data[name] = set()
        s = self._data[name]
        if not isinstance(s, set):
            s = set()
            self._data[name] = s
        added = 0
        for v in values:
            if v not in s:
                s.add(v)
                added += 1
        return added

    def smembers(self, name: str) -> set[str]:
        s = self._data.get(name)
        if isinstance(s, set):
            return set(s)
        return set()

    def mget(self, *names: str) -> list[str | None]:
        """Get values for multiple keys. For hash keys ending in a specific field,
        we retrieve the simple string value stored at that key."""
        result: list[str | None] = []
        for n in names:
            val = self._data.get(n)
            if isinstance(val, str):
                result.append(val)
            elif isinstance(val, dict):
                # If the key itself is a hash, return None (use hget for hashes)
                result.append(None)
            else:
                result.append(None)
        return result

    def set(self, name: str, value: str) -> bool:
        """Set a simple string value (not a hash)."""
        self._data[name] = value  # type: ignore[assignment]
        return True

    def get(self, name: str) -> str | None:
        """Get a simple string value."""
        val = self._data.get(name)
        if isinstance(val, str):
            return val
        return None

    def watch(self, *names: str) -> None:
        """No-op for in-memory store (no concurrency issues)."""
        pass

    def multi(self) -> _InMemoryStore:
        """No-op transaction start for in-memory store."""
        return self

    def execute(self) -> list:
        """No-op transaction execute for in-memory store."""
        return []

    def pipeline(self) -> _InMemoryPipeline:
        return _InMemoryPipeline(self)

    def register_script(self, script: str) -> _InMemoryScript:
        """Register a Lua script (simulated for in-memory store)."""
        return _InMemoryScript(self, script)


class _InMemoryPipeline:
    """Simple pipeline for in-memory store that executes commands immediately."""

    def __init__(self, store: _InMemoryStore) -> None:
        self._store = store
        self._results: list[Any] = []

    def watch(self, *names: str) -> _InMemoryPipeline:
        return self

    def multi(self) -> _InMemoryPipeline:
        return self

    def hgetall(self, name: str) -> _InMemoryPipeline:
        self._results.append(self._store.hgetall(name))
        return self

    def hset(
        self, name: str, mapping: dict[str, str] | None = None, **kwargs: str
    ) -> _InMemoryPipeline:
        self._store.hset(name, mapping=mapping, **kwargs)
        self._results.append(True)
        return self

    def set(self, name: str, value: str) -> _InMemoryPipeline:
        self._store.set(name, value)
        self._results.append(True)
        return self

    def sadd(self, name: str, *values: str) -> _InMemoryPipeline:
        self._results.append(self._store.sadd(name, *values))
        return self

    def execute(self) -> list:
        results = list(self._results)
        self._results.clear()
        return results

    def reset(self) -> None:
        self._results.clear()


class _InMemoryScript:
    """Simulated registered Lua script for in-memory store.

    Implements cascade revocation logic in Python for the in-memory backend.
    """

    def __init__(self, store: _InMemoryStore, script: str) -> None:
        self._store = store
        self._script = script

    def __call__(self, keys: list[str] | None = None, args: list[str] | None = None) -> int:
        """Execute cascade revocation for in-memory store."""
        if not args:
            return 0
        credential_id = args[0]
        max_depth = int(args[1]) if len(args) > 1 else 10
        return self._cascade_revoke(credential_id, max_depth, 0)

    def _cascade_revoke(self, credential_id: str, max_depth: int, current_depth: int) -> int:
        if current_depth >= max_depth:
            return 0

        key = _CRED_KEY_PREFIX + credential_id
        data = self._store.hgetall(key)
        if not data:
            return 0

        count = 0
        if data.get("status") != CredentialStatus.REVOKED:
            self._store.hset(key, mapping={"status": CredentialStatus.REVOKED})
            self._store.set(f"{key}:status", CredentialStatus.REVOKED)
            count = 1

        # Get children
        children_key = f"{_CRED_KEY_PREFIX}{credential_id}:children"
        children = self._store.smembers(children_key)
        for child_id in children:
            count += self._cascade_revoke(child_id, max_depth, current_depth + 1)

        return count


class CredentialManager:
    """
    Manages credential lifecycle for MCP agent-to-service communication.

    Features:
    - JWT token generation with custom claims
    - Credential rotation policies
    - Just-In-Time (JIT) credential provisioning
    - Usage tracking and monitoring
    - Comprehensive audit logging
    - Revocation support
    """

    def __init__(
        self,
        secret_key: str = "",
        audit_log_path: str | None = None,
        redis_url: str = "redis://127.0.0.1:6379",
    ) -> None:
        """
        Initialize credential manager.

        Args:
            secret_key: Secret key for JWT signing (if empty, generates secure key)
            audit_log_path: Path to write audit logs (None disables file logging)
            redis_url: Redis connection URL (falls back to in-memory if connection fails)
        """
        self.secret_key = secret_key or secrets.token_urlsafe(64)
        self.audit_log_path: Path | None = Path(audit_log_path) if audit_log_path else None
        self.rotation_policies: dict[str, dict[str, Any]] = {}
        self._rotation_lock = threading.Lock()

        # Try Redis; fall back to in-memory dict for local dev / tests without Redis
        self._cascade_script: _InMemoryScript | None = None
        self._redis: Any  # redis.Redis | _InMemoryStore
        try:
            import redis as _redis_mod

            client = _redis_mod.Redis.from_url(redis_url, decode_responses=True)
            client.ping()
            self._redis = client
            logger.info("Connected to Redis at %s", redis_url)
        except Exception:
            logger.info("Redis unavailable — falling back to in-memory credential store")
            self._redis = _InMemoryStore()

    # ---- internal store helpers ------------------------------------------------

    def _store_credential(self, cred: Credential) -> None:
        """Persist a Credential into the backing store."""
        key = _CRED_KEY_PREFIX + cred.token_id
        self._redis.hset(key, mapping=_credential_to_hash(cred))
        # Also write standalone status key for proxy MGET chain verification
        # (proxies read navil:cred:{id}:status via MGET for single-round-trip checks)
        self._redis.set(f"{key}:status", cred.status)

    def _load_credential(self, token_id: str) -> Credential | None:
        """Load a single Credential from the backing store, or None."""
        data = self._redis.hgetall(_CRED_KEY_PREFIX + token_id)
        if not data:
            return None
        return _hash_to_credential(data)

    def _credential_exists(self, token_id: str) -> bool:
        """Check whether a credential key exists in the backing store."""
        return bool(self._redis.exists(_CRED_KEY_PREFIX + token_id))

    def _delete_credential(self, token_id: str) -> None:
        """Remove a credential key from the backing store."""
        self._redis.delete(_CRED_KEY_PREFIX + token_id)

    def _iter_all_credentials(self) -> list[Credential]:
        """Return all stored credentials."""
        keys = self._redis.scan_iter(match=_CRED_KEY_PREFIX + "*")
        creds: list[Credential] = []
        for key in keys:
            # Skip sub-keys like navil:cred:{id}:children
            # Credential keys are exactly navil:cred:{token_id}
            # with no further colons after the prefix
            suffix = key[len(_CRED_KEY_PREFIX) :]
            if ":" in suffix:
                continue
            data = self._redis.hgetall(key)
            if data and "token_id" in data:
                creds.append(_hash_to_credential(data))
        return creds

    # ---- Backwards-compatible property so tests that touch .credentials still work
    @property
    def credentials(self) -> dict[str, Credential]:
        """Return a dict view of all stored credentials (for backwards compat)."""
        return {c.token_id: c for c in self._iter_all_credentials()}

    @credentials.setter
    def credentials(self, value: dict[str, Credential]) -> None:
        """Allow bulk-setting credentials (for backwards compat in tests)."""
        # Clear existing
        for key in self._redis.scan_iter(match=_CRED_KEY_PREFIX + "*"):
            self._redis.delete(key)
        for cred in value.values():
            self._store_credential(cred)

    # Maximum number of active credentials allowed globally
    MAX_CREDENTIALS: int = 500

    def issue_credential(
        self,
        agent_name: str,
        scope: str,
        ttl_seconds: int = 3600,
        metadata: dict[str, Any] | None = None,
        human_context: dict | None = None,
        parent_credential_id: str | None = None,
        delegation_chain: list[str] | None = None,
        delegated_by: str = "",
        max_delegation_depth: int = 10,
        scope_narrowing_only: bool = True,
    ) -> dict[str, Any]:
        """
        Issue a new credential for an agent.

        Args:
            agent_name: Name of the agent
            scope: Permission scope (e.g., "read:tools write:logs")
            ttl_seconds: Time to live in seconds (default 1 hour)
            metadata: Additional metadata to include in token
            human_context: Human identity context from OIDC (sub, email, roles)
            parent_credential_id: Immediate parent credential ID (for delegation)
            delegation_chain: List of ancestor credential IDs
            delegated_by: Name of the agent/entity that delegated this credential
            max_delegation_depth: Maximum further delegation depth allowed
            scope_narrowing_only: If True, children can only narrow scope (default True)

        Returns:
            Dictionary containing token and credential information

        Raises:
            ValueError: If TTL is not positive or credential cap is reached
        """
        if ttl_seconds <= 0:
            raise ValueError(f"TTL must be positive, got {ttl_seconds}")

        # Purge expired credentials so they don't count toward the cap
        self._purge_expired()

        active_count = sum(
            1 for c in self._iter_all_credentials() if c.status == CredentialStatus.ACTIVE
        )
        if active_count >= self.MAX_CREDENTIALS:
            raise ValueError(
                f"Credential cap reached ({self.MAX_CREDENTIALS} active). "
                "Revoke unused credentials before issuing new ones."
            )

        token_id = self._generate_token_id()
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=ttl_seconds)

        chain = delegation_chain or []

        # Create JWT payload
        payload = {
            "token_id": token_id,
            "agent_name": agent_name,
            "scope": scope,
            "iat": issued_at.isoformat(),
            "exp": expires_at.isoformat(),
            "human_context": human_context,
            "delegation_chain": chain,
            "parent_credential_id": parent_credential_id,
            **(metadata or {}),
        }

        # Sign JWT
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")

        # Store credential
        credential = Credential(
            token_id=token_id,
            agent_name=agent_name,
            scope=scope,
            token=token,
            issued_at=issued_at.isoformat(),
            expires_at=expires_at.isoformat(),
            status=CredentialStatus.ACTIVE,
            secret_hash=self._hash_token(token),
            human_context=human_context,
            parent_credential_id=parent_credential_id,
            delegation_chain=chain,
            delegated_by=delegated_by,
            max_delegation_depth=max_delegation_depth,
            scope_narrowing_only=scope_narrowing_only,
        )

        self._store_credential(credential)

        # Log operation
        self._log_audit(
            token_id=token_id,
            agent_name=agent_name,
            operation="issued",
            details=f"Credential issued with scope: {scope}, TTL: {ttl_seconds}s",
        )

        logger.info(f"Issued credential {token_id} for agent {agent_name}")

        return {
            "token_id": token_id,
            "token": token,
            "agent_name": agent_name,
            "scope": scope,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ttl_seconds": ttl_seconds,
            "human_context": human_context,
            "delegation_chain": chain,
            "parent_credential_id": parent_credential_id,
        }

    def rotate_credential(self, token_id: str) -> dict[str, Any]:
        """
        Rotate an existing credential (issue new token, revoke old).

        Thread-safe: acquires ``_rotation_lock`` so concurrent rotations
        of the same credential are serialized (second caller sees EXPIRED
        and raises ValueError instead of creating a duplicate).

        Args:
            token_id: ID of credential to rotate

        Returns:
            Dictionary containing new token information
        """
        with self._rotation_lock:
            old_credential = self._load_credential(token_id)
            if old_credential is None:
                raise ValueError(f"Credential not found: {token_id}")

            if old_credential.status == CredentialStatus.REVOKED:
                raise ValueError(f"Cannot rotate revoked credential: {token_id}")

            if old_credential.status != CredentialStatus.ACTIVE:
                raise ValueError(
                    f"Cannot rotate credential with status {old_credential.status}: {token_id}"
                )

            # Mark old credential as expired BEFORE issuing new one
            old_credential.status = CredentialStatus.EXPIRED
            self._store_credential(old_credential)

            # Compute remaining TTL; if credential is expired, use a fresh 1-hour TTL
            remaining = int(
                (
                    datetime.fromisoformat(old_credential.expires_at) - datetime.now(timezone.utc)
                ).total_seconds()
            )
            ttl = remaining if remaining > 0 else 3600

            # Issue new credential with same scope
            new_cred_info = self.issue_credential(
                agent_name=old_credential.agent_name,
                scope=old_credential.scope,
                ttl_seconds=ttl,
            )

        # Log rotation (outside lock — no mutation)
        self._log_audit(
            token_id=token_id,
            agent_name=old_credential.agent_name,
            operation="rotated",
            details=f"Rotated to new credential: {new_cred_info['token_id']}",
        )

        logger.info(f"Rotated credential {token_id}")

        return new_cred_info

    def revoke_credential(self, token_id: str, reason: str = "Manual revocation") -> bool:
        """
        Revoke a credential immediately.

        Args:
            token_id: ID of credential to revoke
            reason: Reason for revocation

        Returns:
            True if revocation successful
        """
        credential = self._load_credential(token_id)
        if credential is None:
            raise ValueError(f"Credential not found: {token_id}")

        credential.status = CredentialStatus.REVOKED
        self._store_credential(credential)

        self._log_audit(
            token_id=token_id,
            agent_name=credential.agent_name,
            operation="revoked",
            details=f"Revoked: {reason}",
        )

        logger.info(f"Revoked credential {token_id}: {reason}")
        return True

    def _purge_expired(self) -> int:
        """Remove credentials whose expires_at is in the past.

        Returns the number of credentials purged.
        """
        now = datetime.now(timezone.utc)
        expired_ids: list[str] = []
        for cred in self._iter_all_credentials():
            if (
                cred.status == CredentialStatus.ACTIVE
                and datetime.fromisoformat(cred.expires_at) < now
            ):
                expired_ids.append(cred.token_id)

        for tid in expired_ids:
            self._redis.hset(_CRED_KEY_PREFIX + tid, mapping={"status": CredentialStatus.EXPIRED})
            self._redis.set(f"{_CRED_KEY_PREFIX}{tid}:status", CredentialStatus.EXPIRED)
        if expired_ids:
            logger.debug("Purged %d expired credentials", len(expired_ids))
        return len(expired_ids)

    def verify_credential(self, token: str) -> dict[str, Any]:
        """
        Verify and decode a token.

        Args:
            token: JWT token to verify

        Returns:
            Dictionary containing decoded payload

        Raises:
            jwt.InvalidTokenError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])

            token_id = payload.get("token_id")
            if token_id and self._credential_exists(token_id):
                credential = self._load_credential(token_id)
                if credential and credential.status == CredentialStatus.REVOKED:
                    raise jwt.InvalidTokenError("Credential has been revoked")

            return payload
        except jwt.ExpiredSignatureError:
            raise jwt.InvalidTokenError("Token has expired")  # noqa: B904
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {e!s}")  # noqa: B904

    def record_usage(self, token_id: str, ip_address: str | None = None) -> None:
        """
        Record usage of a credential.

        Args:
            token_id: ID of credential being used
            ip_address: IP address of usage (optional)
        """
        if not self._credential_exists(token_id):
            logger.warning(f"Usage recorded for unknown credential: {token_id}")
            return

        key = _CRED_KEY_PREFIX + token_id
        now = datetime.now(timezone.utc).isoformat()
        self._redis.hset(key, mapping={"last_used": now})
        new_count = self._redis.hincrby(key, "used_count", 1)

        # Read agent_name for audit log
        agent_name = self._redis.hget(key, "agent_name") or ""

        self._log_audit(
            token_id=token_id,
            agent_name=agent_name,
            operation="accessed",
            details=f"Credential used (total uses: {new_count})",
            ip_address=ip_address,
        )

    def set_rotation_policy(
        self, agent_name: str, rotate_after_days: int, max_age_days: int
    ) -> None:
        """
        Set rotation policy for an agent.

        Args:
            agent_name: Name of agent
            rotate_after_days: Days before automatic rotation
            max_age_days: Maximum age before revocation
        """
        self.rotation_policies[agent_name] = {
            "rotate_after_days": rotate_after_days,
            "max_age_days": max_age_days,
        }

        logger.info(
            f"Set rotation policy for {agent_name}: "
            f"rotate after {rotate_after_days}d, max age {max_age_days}d"
        )

    def check_rotation_needed(self) -> list[str]:
        """
        Check which credentials need rotation.

        Returns:
            List of token IDs that need rotation
        """
        needs_rotation = []
        now = datetime.now(timezone.utc)

        for credential in self._iter_all_credentials():
            agent_name = credential.agent_name

            if agent_name not in self.rotation_policies:
                continue

            policy = self.rotation_policies[agent_name]
            issued_at = datetime.fromisoformat(credential.issued_at)
            days_old = (now - issued_at).days

            if days_old >= policy["rotate_after_days"]:
                needs_rotation.append(credential.token_id)

        return needs_rotation

    def cleanup_expired(self) -> int:
        """
        Clean up expired and revoked credentials older than 90 days.

        Returns:
            Number of credentials removed
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=90)
        removed = 0

        token_ids_to_remove = []
        for credential in self._iter_all_credentials():
            if credential.status in [
                CredentialStatus.EXPIRED,
                CredentialStatus.REVOKED,
            ]:
                issued_at = datetime.fromisoformat(credential.issued_at)
                if issued_at < cutoff:
                    token_ids_to_remove.append(credential.token_id)

        for token_id in token_ids_to_remove:
            self._delete_credential(token_id)
            removed += 1

        logger.info(f"Cleaned up {removed} expired credentials")
        return removed

    def get_credential_info(self, token_id: str) -> dict[str, Any]:
        """
        Get information about a credential.

        Args:
            token_id: ID of credential

        Returns:
            Dictionary with credential information (token excluded)
        """
        cred = self._load_credential(token_id)
        if cred is None:
            return {}

        return {
            "token_id": cred.token_id,
            "agent_name": cred.agent_name,
            "scope": cred.scope,
            "issued_at": cred.issued_at,
            "expires_at": cred.expires_at,
            "status": cred.status,
            "rotation_count": cred.rotation_count,
            "last_used": cred.last_used,
            "used_count": cred.used_count,
            "human_context": cred.human_context,
            "parent_credential_id": cred.parent_credential_id,
            "delegation_chain": cred.delegation_chain or [],
            "delegated_by": cred.delegated_by,
            "max_delegation_depth": cred.max_delegation_depth,
            "scope_narrowing_only": cred.scope_narrowing_only,
        }

    def list_credentials(
        self, agent_name: str | None = None, status: str | None = None
    ) -> list[dict[str, Any]]:
        """
        List credentials with optional filtering.

        Args:
            agent_name: Filter by agent name
            status: Filter by status

        Returns:
            List of credential information dictionaries
        """
        result = []

        for cred in self._iter_all_credentials():
            if agent_name and cred.agent_name != agent_name:
                continue
            if status and cred.status != status:
                continue

            result.append(self.get_credential_info(cred.token_id))

        return result

    def export_audit_log(self, start_time: str | None = None) -> list[dict[str, Any]]:
        """
        Export audit log entries.

        Args:
            start_time: ISO format timestamp to filter from

        Returns:
            List of audit log entries
        """
        logs: list[dict[str, Any]] = []
        if self.audit_log_path is None or not self.audit_log_path.exists():
            return logs

        start_dt = None
        if start_time:
            start_dt = datetime.fromisoformat(start_time)

        with open(self.audit_log_path) as f:
            for line in f:
                try:
                    log_entry = json.loads(line)
                    if start_dt:
                        log_time = datetime.fromisoformat(log_entry["timestamp"])
                        if log_time < start_dt:
                            continue
                    logs.append(log_entry)
                except json.JSONDecodeError:
                    continue

        return logs

    # ---- Delegation --------------------------------------------------------

    # Global hard cap on delegation chain depth
    MAX_DELEGATION_DEPTH: int = 10

    def delegate_credential(
        self,
        parent_credential_id: str,
        agent_name: str,
        narrowed_scope: str,
        ttl_seconds: int,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        """Delegate a credential to a child agent with narrowed scope.

        Args:
            parent_credential_id: ID of the parent credential
            agent_name: Name of the child agent receiving the delegated credential
            narrowed_scope: Scope for the child (must be subset of parent's scope)
            ttl_seconds: TTL for the child credential
            max_depth: Max further delegation depth (optional, capped by parent's remaining)

        Returns:
            Dictionary containing the new delegated credential info

        Raises:
            ValueError: If delegation constraints are violated
        """
        max_retries = 3
        for attempt in range(max_retries):
            try:
                return self._delegate_credential_inner(
                    parent_credential_id, agent_name, narrowed_scope, ttl_seconds, max_depth
                )
            except RuntimeError as e:
                if "WATCH" in str(e) and attempt < max_retries - 1:
                    logger.warning(
                        "Delegation race condition on attempt %d, retrying...", attempt + 1
                    )
                    continue
                raise
        # Should not reach here, but satisfy type checker
        raise RuntimeError("Delegation failed after max retries")  # pragma: no cover

    def _delegate_credential_inner(
        self,
        parent_credential_id: str,
        agent_name: str,
        narrowed_scope: str,
        ttl_seconds: int,
        max_depth: int | None,
    ) -> dict[str, Any]:
        """Inner delegation logic, wrapped in WATCH/retry by delegate_credential."""
        parent = self._load_credential(parent_credential_id)
        if parent is None:
            raise ValueError(f"Parent credential not found: {parent_credential_id}")

        # Check parent status
        if parent.status != CredentialStatus.ACTIVE:
            raise ValueError(
                f"Parent credential is not active (status={parent.status}): {parent_credential_id}"
            )

        # Check parent not expired
        now = datetime.now(timezone.utc)
        parent_expires = datetime.fromisoformat(parent.expires_at)
        if parent_expires <= now:
            raise ValueError(f"Parent credential has expired: {parent_credential_id}")

        # Check remaining delegation depth
        remaining_depth = parent.max_delegation_depth
        if remaining_depth <= 0:
            raise ValueError(f"Delegation depth exhausted for credential: {parent_credential_id}")

        # Global depth cap check
        parent_chain = parent.delegation_chain or []
        if len(parent_chain) + 1 >= self.MAX_DELEGATION_DEPTH:
            raise ValueError(
                f"Delegation chain would exceed global cap of {self.MAX_DELEGATION_DEPTH}"
            )

        # Scope subset check
        parent_scope_set = set(parent.scope.split()) if parent.scope else set()
        child_scope_set = set(narrowed_scope.split()) if narrowed_scope else set()
        if not child_scope_set <= parent_scope_set:
            extra = child_scope_set - parent_scope_set
            raise ValueError(f"Scope is not a subset of parent's scope. Extra scopes: {extra}")

        # TTL check: child cannot outlive parent
        parent_remaining_ttl = int((parent_expires - now).total_seconds())
        if ttl_seconds > parent_remaining_ttl:
            raise ValueError(
                f"TTL ({ttl_seconds}s) exceeds parent's remaining TTL ({parent_remaining_ttl}s)"
            )

        # Calculate child's max delegation depth
        child_max_depth = remaining_depth - 1
        if max_depth is not None:
            child_max_depth = min(child_max_depth, max_depth)

        # Build child delegation chain
        child_chain = list(parent_chain) + [parent_credential_id]

        # Use WATCH for race condition guard on real Redis
        if hasattr(self._redis, "watch") and not isinstance(self._redis, _InMemoryStore):
            parent_key = _CRED_KEY_PREFIX + parent_credential_id
            try:
                pipe = self._redis.pipeline()
                pipe.watch(parent_key)

                # Re-read under WATCH to detect concurrent changes
                status = self._redis.hget(parent_key, "status")
                if status != CredentialStatus.ACTIVE:
                    pipe.reset()
                    raise ValueError(
                        f"Parent credential status changed during delegation: {status}"
                    )

                pipe.multi()
            except Exception as e:
                if "WatchError" in type(e).__name__:
                    raise RuntimeError("WATCH conflict during delegation") from e
                raise

        # Issue child credential
        result = self.issue_credential(
            agent_name=agent_name,
            scope=narrowed_scope,
            ttl_seconds=ttl_seconds,
            human_context=parent.human_context,
            parent_credential_id=parent_credential_id,
            delegation_chain=child_chain,
            delegated_by=parent.agent_name,
            max_delegation_depth=child_max_depth,
            scope_narrowing_only=parent.scope_narrowing_only,
        )

        # Store parent→children index
        children_key = f"{_CRED_KEY_PREFIX}{parent_credential_id}:children"
        self._redis.sadd(children_key, result["token_id"])

        self._log_audit(
            token_id=result["token_id"],
            agent_name=agent_name,
            operation="delegated",
            details=(
                f"Delegated from {parent_credential_id} by {parent.agent_name}, "
                f"scope: {narrowed_scope}, depth: {len(child_chain)}"
            ),
        )

        return result

    # ---- Cascade Revocation -----------------------------------------------

    # Lua script for atomic cascade revocation in Redis
    _CASCADE_REVOKE_LUA = """
local function cascade(cred_id, max_depth, depth)
    if depth >= max_depth then
        return 0
    end

    local key = "navil:cred:" .. cred_id
    local status = redis.call("HGET", key, "status")
    if not status then
        return 0
    end

    local count = 0
    if status ~= "REVOKED" then
        redis.call("HSET", key, "status", "REVOKED")
        redis.call("SET", key .. ":status", "REVOKED")
        count = 1
    end

    local children_key = key .. ":children"
    local children = redis.call("SMEMBERS", children_key)
    for _, child_id in ipairs(children) do
        count = count + cascade(child_id, max_depth, depth + 1)
    end

    return count
end

return cascade(ARGV[1], tonumber(ARGV[2]), 0)
"""

    def _register_cascade_script(self) -> None:
        """Register the cascade revocation Lua script with Redis."""
        if isinstance(self._redis, _InMemoryStore):
            self._cascade_script = self._redis.register_script(self._CASCADE_REVOKE_LUA)
        else:
            try:
                self._cascade_script = self._redis.register_script(self._CASCADE_REVOKE_LUA)
            except Exception:
                logger.warning("Failed to register cascade Lua script")
                self._cascade_script = None

    def cascade_revoke(self, credential_id: str) -> int:
        """Revoke a credential and all its descendants atomically.

        Args:
            credential_id: Root credential ID to revoke

        Returns:
            Total number of credentials revoked

        Raises:
            ValueError: If credential not found
        """
        cred = self._load_credential(credential_id)
        if cred is None:
            raise ValueError(f"Credential not found: {credential_id}")

        # Initialize script if not already done
        if not hasattr(self, "_cascade_script") or self._cascade_script is None:
            self._register_cascade_script()

        if self._cascade_script is not None:
            try:
                count = self._cascade_script(
                    keys=[],
                    args=[credential_id, str(self.MAX_DELEGATION_DEPTH)],
                )
                count = int(count)
            except Exception:
                logger.warning("Lua cascade failed, falling back to Python cascade")
                count = self._cascade_revoke_python(credential_id, 0)
        else:
            count = self._cascade_revoke_python(credential_id, 0)

        self._log_audit(
            token_id=credential_id,
            agent_name=cred.agent_name,
            operation="cascade_revoked",
            details=f"Cascade revocation: {count} credentials revoked",
        )

        logger.info(f"Cascade revoked {count} credentials starting from {credential_id}")
        return count

    def _cascade_revoke_python(self, credential_id: str, depth: int) -> int:
        """Fallback Python-based cascade revocation (non-atomic)."""
        if depth >= self.MAX_DELEGATION_DEPTH:
            return 0

        key = _CRED_KEY_PREFIX + credential_id
        data = self._redis.hgetall(key)
        if not data:
            return 0

        count = 0
        if data.get("status") != CredentialStatus.REVOKED:
            self._redis.hset(key, mapping={"status": CredentialStatus.REVOKED})
            self._redis.set(f"{key}:status", CredentialStatus.REVOKED)
            count = 1

        children_key = f"{_CRED_KEY_PREFIX}{credential_id}:children"
        children = self._redis.smembers(children_key)
        for child_id in children:
            count += self._cascade_revoke_python(child_id, depth + 1)

        return count

    def _generate_token_id(self) -> str:
        """Generate a unique token ID."""
        return f"cred_{secrets.token_hex(32)}"

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage without plaintext."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _log_audit(
        self,
        token_id: str,
        agent_name: str,
        operation: str,
        details: str,
        ip_address: str | None = None,
    ) -> None:
        """Write entry to audit log."""
        log_entry = CredentialAuditLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            token_id=token_id,
            agent_name=agent_name,
            operation=operation,
            details=details,
            ip_address=ip_address,
        )

        if self.audit_log_path is not None:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(asdict(log_entry)) + "\n")
