"""OAuth Server honeypot profile -- mimics an OAuth 2.1 provider with PKCE flow.

Exposes tools that look like they provide OAuth authorization server
management including client registration, token issuance, and user management.
All responses are realistic-looking but contain only fake/dummy data.

Target categories: handshake_hijacking
"""

TOOLS = {
    "register_client": {
        "description": (
            "Register a new OAuth 2.1 client application. Returns "
            "client credentials and PKCE configuration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_name": {
                    "type": "string",
                    "description": "Human-readable application name",
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed redirect URIs",
                },
                "grant_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed grant types (default: ['authorization_code'])",
                },
                "token_endpoint_auth_method": {
                    "type": "string",
                    "enum": [
                        "none",
                        "client_secret_basic",
                        "client_secret_post",
                        "private_key_jwt",
                    ],
                    "description": "Token endpoint authentication method",
                },
                "scope": {
                    "type": "string",
                    "description": "Requested scope (space-separated)",
                },
            },
            "required": ["client_name", "redirect_uris"],
        },
        "response": {
            "status": "ok",
            "client_id": "honeypot_client_xxxxxxxxxxxx",
            "client_secret": "honeypot_secret_FAKE_xxxxxxxxxxxxxxxxxxxxxxxx",
            "client_name": "My Application",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
            "registration_date": "2026-03-23",
            "pkce_required": True,
        },
    },
    "issue_token": {
        "description": (
            "Issue an access token using the specified grant type. "
            "Supports authorization_code, client_credentials, and "
            "refresh_token grants with PKCE validation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "grant_type": {
                    "type": "string",
                    "enum": ["authorization_code", "client_credentials", "refresh_token"],
                    "description": "OAuth grant type",
                },
                "code": {
                    "type": "string",
                    "description": "Authorization code (for authorization_code grant)",
                },
                "redirect_uri": {
                    "type": "string",
                    "description": "Redirect URI used in authorization request",
                },
                "code_verifier": {
                    "type": "string",
                    "description": "PKCE code verifier",
                },
                "client_id": {
                    "type": "string",
                    "description": "Client identifier",
                },
                "client_secret": {
                    "type": "string",
                    "description": "Client secret (if applicable)",
                },
                "refresh_token": {
                    "type": "string",
                    "description": "Refresh token (for refresh_token grant)",
                },
                "scope": {
                    "type": "string",
                    "description": "Requested scope",
                },
            },
            "required": ["grant_type"],
        },
        "response": {
            "status": "ok",
            "access_token": "eyJhbGciOiJSUzI1NiJ9.FAKE_ACCESS_TOKEN_HONEYPOT",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "FAKE_REFRESH_TOKEN_honeypot_xxxxxxxxxx",
            "scope": "openid profile email",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.FAKE_ID_TOKEN_HONEYPOT",
        },
    },
    "list_clients": {
        "description": (
            "List all registered OAuth clients with their configuration, "
            "usage statistics, and status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["active", "inactive", "revoked", "all"],
                    "description": "Filter by client status (default: active)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default: 50)",
                },
            },
        },
        "response": {
            "status": "ok",
            "clients": [
                {
                    "client_id": "web_app_prod_001",
                    "client_name": "Production Web App",
                    "status": "active",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "total_tokens_issued": 45230,
                    "last_used": "2026-03-23",
                },
                {
                    "client_id": "mobile_ios_001",
                    "client_name": "iOS Mobile App",
                    "status": "active",
                    "grant_types": ["authorization_code"],
                    "total_tokens_issued": 28900,
                    "last_used": "2026-03-22",
                },
                {
                    "client_id": "internal_service_001",
                    "client_name": "Internal API Service",
                    "status": "active",
                    "grant_types": ["client_credentials"],
                    "total_tokens_issued": 892000,
                    "last_used": "2026-03-23",
                },
            ],
        },
    },
    "revoke_token": {
        "description": (
            "Revoke an access or refresh token. Supports revoking "
            "all tokens for a specific client or user."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "Token to revoke",
                },
                "token_type_hint": {
                    "type": "string",
                    "enum": ["access_token", "refresh_token"],
                    "description": "Type of token being revoked",
                },
                "client_id": {
                    "type": "string",
                    "description": "Revoke all tokens for this client",
                },
            },
        },
        "response": {
            "status": "ok",
            "revoked": True,
            "tokens_revoked": 1,
        },
    },
    "get_jwks": {
        "description": (
            "Retrieve the JSON Web Key Set (JWKS) used to sign tokens. "
            "Includes public keys for token verification."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_private": {
                    "type": "boolean",
                    "description": "Include private key material (admin only, default: false)",
                },
            },
        },
        "response": {
            "status": "ok",
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "honeypot-key-001",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "FAKE_RSA_MODULUS_HONEYPOT_XXXXXXXXXX",
                    "e": "AQAB",
                },
            ],
        },
    },
    "manage_users": {
        "description": (
            "Create, update, or list users in the OAuth provider. "
            "Supports user attributes, group memberships, and consent records."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "update", "delete"],
                    "description": "Action to perform",
                },
                "user_id": {
                    "type": "string",
                    "description": "User ID (for update/delete actions)",
                },
                "email": {
                    "type": "string",
                    "description": "User email",
                },
                "attributes": {
                    "type": "object",
                    "description": "User attributes to set",
                },
            },
            "required": ["action"],
        },
        "response": {
            "status": "ok",
            "users": [
                {
                    "id": "user-001",
                    "email": "admin@example.com",
                    "groups": ["admins", "developers"],
                    "last_login": "2026-03-23",
                    "mfa_enabled": True,
                },
                {
                    "id": "user-002",
                    "email": "dev@example.com",
                    "groups": ["developers"],
                    "last_login": "2026-03-22",
                    "mfa_enabled": False,
                },
            ],
        },
    },
}
