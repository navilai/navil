"""V1 API endpoints for Navil identity system (credential exchange, delegation, chain)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from navil.api.local.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")


# ── Request / Response Models ───────────────────────────────


class CredentialExchangeRequest(BaseModel):
    oidc_token: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1, max_length=256)
    scope: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)
    issuer: str | None = None
    audience: str | None = None


class CredentialDelegateRequest(BaseModel):
    parent_credential_id: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1, max_length=256)
    scope: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 365)
    max_depth: int | None = None


# ── Credential Exchange ─────────────────────────────────────


@router.post("/credentials/exchange")
def exchange_credential(req: CredentialExchangeRequest) -> dict[str, Any]:
    """Exchange an OIDC token + Agent ID for a Navil credential with human_context.

    Accepts an OIDC JWT from any supported identity provider, verifies it
    against the provider's JWKS (with 1-hour caching), extracts human identity
    claims (sub, email, roles), and issues a Navil credential with
    human_context populated.
    """
    from navil.oidc import exchange_oidc_token

    s = AppState.get()
    try:
        return exchange_oidc_token(
            oidc_token=req.oidc_token,
            agent_name=req.agent_name,
            scope=req.scope,
            credential_manager=s.credential_manager,
            ttl_seconds=req.ttl_seconds,
            issuer=req.issuer,
            audience=req.audience,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ── Credential Delegation ───────────────────────────────────


@router.post("/credentials/delegate")
def delegate_credential(req: CredentialDelegateRequest) -> dict[str, Any]:
    """Delegate a credential to a child agent with narrowed scope."""
    s = AppState.get()
    try:
        return s.credential_manager.delegate_credential(
            parent_credential_id=req.parent_credential_id,
            agent_name=req.agent_name,
            narrowed_scope=req.scope,
            ttl_seconds=req.ttl_seconds,
            max_depth=req.max_depth,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ── Credential Chain ─────────────────────────────────────────


@router.get("/credentials/{token_id}/chain")
def get_credential_chain(token_id: str) -> dict[str, Any]:
    """Get the full delegation chain for a credential."""
    s = AppState.get()
    cred_info = s.credential_manager.get_credential_info(token_id)
    if not cred_info:
        raise HTTPException(status_code=404, detail=f"Credential not found: {token_id}")

    chain = cred_info.get("delegation_chain", [])
    chain_details = []
    for ancestor_id in chain:
        ancestor_info = s.credential_manager.get_credential_info(ancestor_id)
        if ancestor_info:
            chain_details.append(ancestor_info)

    chain_details.append(cred_info)

    return {
        "credential_id": token_id,
        "chain_length": len(chain),
        "human_context": cred_info.get("human_context"),
        "chain": chain_details,
    }


# ── Cascade Revocation ───────────────────────────────────────


@router.delete("/credentials/{token_id}")
def revoke_credential(token_id: str, cascade: bool = False) -> dict[str, str]:
    """Revoke a credential, optionally cascading to all descendants."""
    s = AppState.get()
    try:
        if cascade:
            count = s.credential_manager.cascade_revoke(token_id)
            return {"status": "cascade_revoked", "count": str(count)}
        s.credential_manager.revoke_credential(token_id, reason="API v1 revocation")
        return {"status": "revoked"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
