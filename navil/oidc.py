"""OIDC Token Exchange for Navil Identity System.

Verifies OIDC tokens from identity providers, extracts human identity claims,
and issues Navil credentials with human_context populated.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import jwt
import requests

logger = logging.getLogger(__name__)

# JWKS cache: { issuer_url: (jwks_data, fetch_timestamp) }
_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
_JWKS_CACHE_TTL = 3600  # 1 hour

# Allowed OIDC issuers — prevents SSRF via attacker-controlled iss claims.
# Set NAVIL_OIDC_ALLOWED_ISSUERS as comma-separated URLs, or leave empty to
# allow any HTTPS issuer (open federation mode).
_ALLOWED_ISSUERS: list[str] | None = None
_raw = os.environ.get("NAVIL_OIDC_ALLOWED_ISSUERS", "")
if _raw.strip():
    _ALLOWED_ISSUERS = [i.strip().rstrip("/") for i in _raw.split(",") if i.strip()]


def _fetch_jwks(issuer: str) -> dict[str, Any]:
    """Fetch JWKS from an OIDC issuer's well-known endpoint.

    Caches the JWKS for 1 hour to avoid repeated network calls.

    Args:
        issuer: The OIDC issuer URL (e.g., "https://accounts.google.com")

    Returns:
        The JWKS dict containing 'keys' array

    Raises:
        ValueError: If JWKS cannot be fetched or parsed
    """
    now = time.time()
    cached = _jwks_cache.get(issuer)
    if cached is not None:
        jwks_data, fetch_time = cached
        if now - fetch_time < _JWKS_CACHE_TTL:
            return jwks_data

    # Normalize issuer URL
    issuer_url = issuer.rstrip("/")

    # SSRF guard: only allow HTTPS issuers and validate against allowlist
    parsed = urlparse(issuer_url)
    if parsed.scheme != "https":
        raise ValueError(f"OIDC issuer must use HTTPS: {issuer_url}")
    if _ALLOWED_ISSUERS is not None and issuer_url not in _ALLOWED_ISSUERS:
        raise ValueError(
            f"OIDC issuer {issuer_url} not in allowed list. "
            f"Set NAVIL_OIDC_ALLOWED_ISSUERS to add it."
        )

    jwks_url = f"{issuer_url}/.well-known/jwks.json"

    # Some providers use OpenID Connect discovery first
    try:
        discovery_url = f"{issuer_url}/.well-known/openid-configuration"
        disc_resp = requests.get(discovery_url, timeout=10)
        if disc_resp.status_code == 200:
            disc_data = disc_resp.json()
            if "jwks_uri" in disc_data:
                jwks_url = disc_data["jwks_uri"]
    except Exception:
        # Fall back to direct JWKS URL
        pass

    try:
        resp = requests.get(jwks_url, timeout=10)
        resp.raise_for_status()
        jwks_data = resp.json()
    except Exception as e:
        raise ValueError(f"Failed to fetch JWKS from {jwks_url}: {e}") from e

    if "keys" not in jwks_data:
        raise ValueError(f"Invalid JWKS response from {jwks_url}: missing 'keys'")

    _jwks_cache[issuer] = (jwks_data, now)
    logger.info("Fetched and cached JWKS from %s", jwks_url)
    return jwks_data


def _get_signing_key(jwks_data: dict[str, Any], token_header: dict[str, Any]) -> Any:
    """Find the signing key from JWKS that matches the token's kid header.

    Args:
        jwks_data: The JWKS data containing 'keys' array
        token_header: The decoded JWT header

    Returns:
        The matching public key

    Raises:
        ValueError: If no matching key found
    """
    kid = token_header.get("kid")
    alg = token_header.get("alg", "RS256")

    from jwt.algorithms import RSAAlgorithm

    for key_data in jwks_data.get("keys", []):
        if kid and key_data.get("kid") != kid:
            continue
        if key_data.get("kty") == "RSA":
            return RSAAlgorithm.from_jwk(json.dumps(key_data))

    raise ValueError(f"No matching key found in JWKS for kid={kid}, alg={alg}")


def verify_oidc_token(
    oidc_token: str,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verify an OIDC token and extract claims.

    Args:
        oidc_token: The raw OIDC JWT token
        issuer: Expected issuer URL. If None, extracted from token.
        audience: Expected audience (client ID). If provided, the token's ``aud``
            claim is verified against this value.  Strongly recommended to prevent
            token confusion attacks.

    Returns:
        Dict with verified claims including sub, email, roles

    Raises:
        ValueError: If token verification fails
    """
    try:
        # Decode header without verification to find kid and issuer
        unverified_header = jwt.get_unverified_header(oidc_token)
        unverified_payload = jwt.decode(oidc_token, options={"verify_signature": False})
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid OIDC token format: {e}") from e

    # Determine issuer
    token_issuer = issuer or unverified_payload.get("iss")
    if not token_issuer:
        raise ValueError("No issuer found in OIDC token and none provided")

    # Fetch JWKS
    jwks_data = _fetch_jwks(token_issuer)

    # Get signing key
    signing_key = _get_signing_key(jwks_data, unverified_header)

    # Build decode kwargs -- verify issuer + audience claims
    decode_options: dict[str, Any] = {
        "verify_aud": audience is not None,
        "verify_iss": True,
    }
    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256", "RS384", "RS512"],
        "issuer": token_issuer,
        "options": decode_options,
    }
    if audience is not None:
        decode_kwargs["audience"] = audience

    # Verify token
    try:
        claims = jwt.decode(
            oidc_token,
            signing_key,
            **decode_kwargs,
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("OIDC token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"OIDC token verification failed: {e}") from e

    return claims


def exchange_oidc_token(
    oidc_token: str,
    agent_name: str,
    scope: str,
    credential_manager: Any,
    ttl_seconds: int = 3600,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    """Exchange an OIDC token for a Navil credential with human_context.

    This is the main entry point for OIDC-based credential issuance.

    Args:
        oidc_token: The raw OIDC JWT token from an identity provider
        agent_name: Name of the agent requesting the credential
        scope: Permission scope for the new credential
        credential_manager: CredentialManager instance to issue the credential
        ttl_seconds: TTL for the new credential (default 1 hour)
        issuer: Expected OIDC issuer URL (optional, extracted from token if not provided)
        audience: Expected OIDC audience / client ID (optional but strongly recommended
            to prevent token confusion attacks)

    Returns:
        Dictionary containing the new Navil credential info with human_context

    Raises:
        ValueError: If OIDC token is invalid or exchange fails
    """
    # Verify the OIDC token and extract claims
    claims = verify_oidc_token(oidc_token, issuer=issuer, audience=audience)

    # Extract human identity claims
    sub = claims.get("sub", "")
    email = claims.get("email", "")
    roles = claims.get("roles", [])
    # Some providers use different claim names for roles
    if not roles:
        roles = claims.get("groups", [])
    if not roles:
        realm_access = claims.get("realm_access", {})
        if isinstance(realm_access, dict):
            roles = realm_access.get("roles", [])

    human_context = {
        "sub": sub,
        "email": email,
        "roles": roles if isinstance(roles, list) else [roles],
    }

    # Issue a new Navil credential with human_context
    result = credential_manager.issue_credential(
        agent_name=agent_name,
        scope=scope,
        ttl_seconds=ttl_seconds,
        human_context=human_context,
    )

    logger.info(
        "Exchanged OIDC token for credential %s (agent=%s, sub=%s, email=%s)",
        result["token_id"],
        agent_name,
        sub,
        email,
    )

    return result


def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing."""
    _jwks_cache.clear()
