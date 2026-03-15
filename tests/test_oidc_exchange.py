"""Tests for OIDC token exchange with mock OIDC tokens and JWKS."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from navil.credential_manager import CredentialManager
from navil.oidc import (
    _fetch_jwks,
    _jwks_cache,
    clear_jwks_cache,
    exchange_oidc_token,
    verify_oidc_token,
)


@pytest.fixture
def rsa_keypair():
    """Generate an RSA keypair for testing OIDC token signing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def jwks_data(rsa_keypair):
    """Build JWKS data from the test RSA keypair."""
    _, public_key = rsa_keypair
    from jwt.algorithms import RSAAlgorithm

    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = "test-key-id"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


@pytest.fixture
def oidc_token(rsa_keypair):
    """Create a signed OIDC token using the test RSA private key."""
    private_key, _ = rsa_keypair
    payload = {
        "iss": "https://test-issuer.example.com",
        "sub": "google-oauth2|108234567890",
        "email": "alice@example.com",
        "roles": ["engineer", "on-call"],
        "aud": "test-audience",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-id"},
    )
    return token


@pytest.fixture
def expired_oidc_token(rsa_keypair):
    """Create an expired OIDC token."""
    private_key, _ = rsa_keypair
    payload = {
        "iss": "https://test-issuer.example.com",
        "sub": "google-oauth2|108234567890",
        "email": "alice@example.com",
        "roles": ["engineer"],
        "aud": "test-audience",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,  # expired 1 hour ago
    }
    return pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-id"},
    )


@pytest.fixture
def cm() -> CredentialManager:
    """Create a CredentialManager with in-memory store."""
    return CredentialManager(
        secret_key="test-secret-for-oidc",
        redis_url="redis://127.0.0.1:1",  # bogus port → forces in-memory fallback
    )


@pytest.fixture(autouse=True)
def _clear_cache():
    """Clear JWKS cache before each test."""
    clear_jwks_cache()
    yield
    clear_jwks_cache()


class TestVerifyOIDCToken:
    """Tests for OIDC token verification."""

    def test_valid_token(self, oidc_token, jwks_data) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            claims = verify_oidc_token(oidc_token, issuer="https://test-issuer.example.com")
            assert claims["sub"] == "google-oauth2|108234567890"
            assert claims["email"] == "alice@example.com"
            assert claims["roles"] == ["engineer", "on-call"]

    def test_expired_token_raises(self, expired_oidc_token, jwks_data) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            with pytest.raises(ValueError, match="expired"):
                verify_oidc_token(expired_oidc_token, issuer="https://test-issuer.example.com")

    def test_invalid_token_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid OIDC token format"):
            verify_oidc_token("not-a-jwt-token")

    def test_no_issuer_raises(self, rsa_keypair) -> None:
        private_key, _ = rsa_keypair
        payload = {
            "sub": "user1",
            "email": "user@test.com",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-id"})
        with pytest.raises(ValueError, match="No issuer"):
            verify_oidc_token(token)

    def test_valid_token_with_audience(self, oidc_token, jwks_data) -> None:
        """Token verification succeeds when the correct audience is supplied."""
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            claims = verify_oidc_token(
                oidc_token,
                issuer="https://test-issuer.example.com",
                audience="test-audience",
            )
            assert claims["sub"] == "google-oauth2|108234567890"
            assert claims["aud"] == "test-audience"

    def test_wrong_audience_raises(self, oidc_token, jwks_data) -> None:
        """Token verification fails when the audience does not match."""
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            with pytest.raises(ValueError, match="verification failed"):
                verify_oidc_token(
                    oidc_token,
                    issuer="https://test-issuer.example.com",
                    audience="wrong-audience",
                )

    def test_wrong_signing_key_raises(self, oidc_token) -> None:
        """Token signed with key A, JWKS contains key B."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pub = other_key.public_key()
        from jwt.algorithms import RSAAlgorithm
        jwk = json.loads(RSAAlgorithm.to_jwk(other_pub))
        jwk["kid"] = "test-key-id"
        jwk["use"] = "sig"
        wrong_jwks = {"keys": [jwk]}

        with patch("navil.oidc._fetch_jwks", return_value=wrong_jwks):
            with pytest.raises(ValueError, match="verification failed"):
                verify_oidc_token(oidc_token, issuer="https://test-issuer.example.com")


class TestExchangeOIDCToken:
    """Tests for the full OIDC token exchange flow."""

    def test_exchange_creates_credential_with_human_context(
        self, oidc_token, jwks_data, cm
    ) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=oidc_token,
                agent_name="deploy-bot",
                scope="read:tools write:logs",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            assert result["agent_name"] == "deploy-bot"
            assert result["scope"] == "read:tools write:logs"
            assert result["human_context"]["sub"] == "google-oauth2|108234567890"
            assert result["human_context"]["email"] == "alice@example.com"
            assert result["human_context"]["roles"] == ["engineer", "on-call"]

    def test_exchange_credential_is_stored(
        self, oidc_token, jwks_data, cm
    ) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=oidc_token,
                agent_name="deploy-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            # Verify the credential is stored and retrievable
            info = cm.get_credential_info(result["token_id"])
            assert info["agent_name"] == "deploy-bot"
            assert info["human_context"]["email"] == "alice@example.com"

    def test_exchange_jwt_contains_human_context(
        self, oidc_token, jwks_data, cm
    ) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=oidc_token,
                agent_name="deploy-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            # Decode the issued Navil JWT and check human_context
            # iat/exp are ISO strings (not numeric), so disable those checks
            payload = pyjwt.decode(
                result["token"], cm.secret_key, algorithms=["HS256"],
                options={"verify_exp": False, "verify_iat": False},
            )
            assert payload["human_context"]["sub"] == "google-oauth2|108234567890"
            assert payload["human_context"]["email"] == "alice@example.com"

    def test_exchange_with_expired_oidc_raises(
        self, expired_oidc_token, jwks_data, cm
    ) -> None:
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            with pytest.raises(ValueError, match="expired"):
                exchange_oidc_token(
                    oidc_token=expired_oidc_token,
                    agent_name="deploy-bot",
                    scope="read:tools",
                    credential_manager=cm,
                    issuer="https://test-issuer.example.com",
                )

    def test_exchange_with_audience(self, oidc_token, jwks_data, cm) -> None:
        """Exchange succeeds when the correct audience is supplied."""
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=oidc_token,
                agent_name="deploy-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
                audience="test-audience",
            )
            assert result["human_context"]["email"] == "alice@example.com"

    def test_exchange_wrong_audience_raises(self, oidc_token, jwks_data, cm) -> None:
        """Exchange fails when the audience does not match the token."""
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            with pytest.raises(ValueError, match="verification failed"):
                exchange_oidc_token(
                    oidc_token=oidc_token,
                    agent_name="deploy-bot",
                    scope="read:tools",
                    credential_manager=cm,
                    issuer="https://test-issuer.example.com",
                    audience="wrong-audience",
                )

    def test_exchange_roles_from_groups_claim(self, rsa_keypair, jwks_data, cm) -> None:
        """Some providers use 'groups' instead of 'roles'."""
        private_key, _ = rsa_keypair
        payload = {
            "iss": "https://test-issuer.example.com",
            "sub": "azure-ad|user456",
            "email": "bob@example.com",
            "groups": ["developers", "admins"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-id"})

        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=token,
                agent_name="dev-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            assert result["human_context"]["roles"] == ["developers", "admins"]


class TestJWKSCache:
    """Tests for JWKS caching behavior."""

    def test_cache_hit(self, jwks_data) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = jwks_data

        with patch("navil.oidc.requests.get", return_value=mock_resp):
            result1 = _fetch_jwks("https://test-issuer.example.com")
            result2 = _fetch_jwks("https://test-issuer.example.com")
            assert result1 == result2

    def test_cache_miss_after_clear(self, jwks_data) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = jwks_data

        with patch("navil.oidc.requests.get", return_value=mock_resp) as mock_get:
            _fetch_jwks("https://issuer1.example.com")
            clear_jwks_cache()
            _fetch_jwks("https://issuer1.example.com")
            # Should have been called twice (cache was cleared)
            assert mock_get.call_count == 4  # 2 calls x 2 (discovery + jwks)

    def test_fetch_jwks_failure_raises(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.raise_for_status.side_effect = Exception("Not found")

        # First call to discovery endpoint returns 404
        with patch("navil.oidc.requests.get", side_effect=Exception("Network error")):
            with pytest.raises(ValueError, match="Failed to fetch JWKS"):
                _fetch_jwks("https://bad-issuer.example.com")

    def test_cache_expires_after_ttl(self, jwks_data) -> None:
        """JWKS cache entries expire after the 1-hour TTL."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = jwks_data

        with patch("navil.oidc.requests.get", return_value=mock_resp) as mock_get:
            _fetch_jwks("https://ttl-test.example.com")
            initial_count = mock_get.call_count

            # Manually expire the cache by setting a past timestamp
            issuer = "https://ttl-test.example.com"
            if issuer in _jwks_cache:
                data, _ = _jwks_cache[issuer]
                _jwks_cache[issuer] = (data, time.time() - 3601)

            _fetch_jwks("https://ttl-test.example.com")
            # Should have fetched again after TTL expiry
            assert mock_get.call_count > initial_count

    def test_http_issuer_rejected(self) -> None:
        """Non-HTTPS issuers should be rejected for SSRF protection."""
        with pytest.raises(ValueError, match="HTTPS"):
            _fetch_jwks("http://insecure-issuer.example.com")


class TestExchangeRolesExtraction:
    """Tests for role extraction from different OIDC providers."""

    def test_keycloak_realm_access_roles(self, rsa_keypair, jwks_data, cm) -> None:
        """Keycloak uses realm_access.roles for role claims."""
        private_key, _ = rsa_keypair
        payload = {
            "iss": "https://test-issuer.example.com",
            "sub": "keycloak|user789",
            "email": "carol@example.com",
            "realm_access": {"roles": ["admin", "user"]},
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-id"})

        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=token,
                agent_name="kc-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            assert result["human_context"]["roles"] == ["admin", "user"]

    def test_no_roles_defaults_empty(self, rsa_keypair, jwks_data, cm) -> None:
        """Tokens without any role claims produce an empty roles list."""
        private_key, _ = rsa_keypair
        payload = {
            "iss": "https://test-issuer.example.com",
            "sub": "noroles|user000",
            "email": "noroles@example.com",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-id"})

        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            result = exchange_oidc_token(
                oidc_token=token,
                agent_name="no-role-bot",
                scope="read:tools",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            assert result["human_context"]["roles"] == []

    def test_exchanged_credential_can_be_delegated(
        self, oidc_token, jwks_data, cm
    ) -> None:
        """Credential obtained via OIDC exchange can be delegated to a sub-agent."""
        with patch("navil.oidc._fetch_jwks", return_value=jwks_data):
            parent = exchange_oidc_token(
                oidc_token=oidc_token,
                agent_name="parent-bot",
                scope="read:tools write:logs",
                credential_manager=cm,
                issuer="https://test-issuer.example.com",
            )
            child = cm.delegate_credential(
                parent_credential_id=parent["token_id"],
                agent_name="child-bot",
                narrowed_scope="read:tools",
                ttl_seconds=1800,
            )
            child_info = cm.get_credential_info(child["token_id"])
            # Human context should flow down to delegated credential
            assert child_info["human_context"]["email"] == "alice@example.com"
            assert child_info["parent_credential_id"] == parent["token_id"]
