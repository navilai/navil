# Copyright (c) 2026 Pantheon Lab Pte Ltd
# Licensed under the Business Source License 1.1 (see LICENSE.cloud)
"""Credential management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from navil.api.local.state import AppState

from ._helpers import (
    CredentialDelegateRequest,
    CredentialExchangeRequest,
    CredentialIssueRequest,
    _require_dashboard_auth,
)

router = APIRouter()


@router.get("/credentials", dependencies=[Depends(_require_dashboard_auth)])
def list_credentials(agent: str | None = None) -> list[dict[str, Any]]:
    s = AppState.get()
    return s.credential_manager.list_credentials(agent_name=agent)


@router.post("/credentials", dependencies=[Depends(_require_dashboard_auth)])
def issue_credential(req: CredentialIssueRequest) -> dict[str, Any]:
    s = AppState.get()
    return s.credential_manager.issue_credential(
        agent_name=req.agent_name,
        scope=req.scope,
        ttl_seconds=req.ttl_seconds,
    )


@router.delete("/credentials/{token_id}", dependencies=[Depends(_require_dashboard_auth)])
def revoke_credential(token_id: str, cascade: bool = False) -> dict[str, str]:
    s = AppState.get()
    try:
        if cascade:
            count = s.credential_manager.cascade_revoke(token_id)
            return {"status": "cascade_revoked", "count": str(count)}
        s.credential_manager.revoke_credential(token_id, reason="Dashboard revocation")
        return {"status": "revoked"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/credentials/exchange", dependencies=[Depends(_require_dashboard_auth)])
def exchange_credential(req: CredentialExchangeRequest) -> dict[str, Any]:
    """Exchange an OIDC token for a Navil credential with human identity context."""
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


@router.post("/credentials/delegate", dependencies=[Depends(_require_dashboard_auth)])
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


@router.get("/credentials/{token_id}/chain", dependencies=[Depends(_require_dashboard_auth)])
def get_credential_chain(token_id: str) -> dict[str, Any]:
    """Get the full delegation chain for a credential."""
    s = AppState.get()
    cred_info = s.credential_manager.get_credential_info(token_id)
    if not cred_info:
        raise HTTPException(status_code=404, detail=f"Credential not found: {token_id}")

    chain = cred_info.get("delegation_chain", [])
    chain_details = []

    # Build chain from root to current
    for ancestor_id in chain:
        ancestor_info = s.credential_manager.get_credential_info(ancestor_id)
        if ancestor_info:
            chain_details.append(ancestor_info)

    # Add current credential
    chain_details.append(cred_info)

    return {
        "credential_id": token_id,
        "chain_length": len(chain),
        "human_context": cred_info.get("human_context"),
        "chain": chain_details,
    }
