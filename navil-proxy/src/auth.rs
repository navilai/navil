// Copyright (c) 2026 Pantheon Lab Pte Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Authentication module — JWT validation + HMAC fallback.
//!
//! Implements the proxy-interface-spec.md Section 2-3 authentication flow:
//! 1. If Authorization: Bearer <JWT> is present → JWT validation path
//! 2. If x-navil-signature is present → HMAC validation path
//! 3. If neither → anonymous (if HMAC secret not configured)

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
// tracing used in verify_delegation_chain

type HmacSha256 = Hmac<Sha256>;

/// JWT claims from a Navil credential token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavilClaims {
    pub token_id: String,
    pub agent_name: String,
    pub scope: String,
    pub human_context: Option<HumanContext>,
    pub delegation_chain: Option<Vec<String>>,
    pub parent_credential_id: Option<String>,
    pub iat: serde_json::Value, // ISO 8601 string (not numeric)
    pub exp: serde_json::Value, // ISO 8601 string (not numeric)
}

/// Human identity context from OIDC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanContext {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
}

/// Result of authentication attempt.
#[derive(Debug)]
pub enum AuthResult {
    /// JWT authentication succeeded.
    Jwt(NavilClaims),
    /// HMAC authentication succeeded.
    Hmac { agent_name: String },
    /// No authentication attempted, anonymous access.
    Anonymous,
    /// Authentication failed with error message.
    Failed(String),
}

/// Authenticate a request using the proxy-interface-spec.md Section 2 flow.
///
/// Critical rule: If a Bearer token is present but fails validation,
/// the proxy MUST reject — never fall back to HMAC.
pub fn authenticate(
    headers: &HeaderMap,
    body: &[u8],
    hmac_secret: Option<&[u8]>,
    jwt_secret: &[u8],
) -> AuthResult {
    // Check for Authorization: Bearer header
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return AuthResult::Failed("Invalid Authorization header encoding".into()),
        };

        if auth_str.starts_with("Bearer ") {
            let token = &auth_str[7..];
            return match validate_jwt(token, jwt_secret) {
                Ok(claims) => AuthResult::Jwt(claims),
                Err(msg) => AuthResult::Failed(msg),
            };
        }
    }

    // Check for HMAC signature
    if let Some(sig_header) = headers.get("x-navil-signature") {
        if let Some(secret) = hmac_secret {
            let sig_str = sig_header.to_str().unwrap_or("");
            if verify_hmac(secret, body, sig_str) {
                let agent_name = headers
                    .get("x-agent-name")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("anonymous")
                    .to_string();
                return AuthResult::Hmac { agent_name };
            } else {
                return AuthResult::Failed("Invalid HMAC signature".into());
            }
        } else {
            // HMAC signature present but no secret configured — reject
            // Cannot verify signature without a secret; do not trust x-agent-name
            return AuthResult::Failed("HMAC signature present but no secret configured".into());
        }
    }

    // No Bearer token and no HMAC signature
    if hmac_secret.is_some() {
        return AuthResult::Failed("Missing HMAC signature".into());
    }

    // Anonymous access
    AuthResult::Anonymous
}

/// Validate a JWT token and extract Navil claims.
fn validate_jwt(token: &str, secret: &[u8]) -> Result<NavilClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    // Disable default exp/iat validation since we use ISO 8601 strings, not numeric timestamps
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let key = DecodingKey::from_secret(secret);

    let token_data = jsonwebtoken::decode::<NavilClaims>(token, &key, &validation)
        .map_err(|e| format!("JWT validation failed: {e}"))?;

    let claims = token_data.claims;

    // Manual expiry check using ISO 8601 string
    if let serde_json::Value::String(ref exp_str) = claims.exp {
        if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
            if exp_dt < chrono::Utc::now() {
                return Err("Token has expired".into());
            }
        } else {
            // Try ISO 8601 without timezone
            if let Ok(exp_dt) = exp_str.parse::<chrono::DateTime<chrono::Utc>>() {
                if exp_dt < chrono::Utc::now() {
                    return Err("Token has expired".into());
                }
            }
        }
    }

    Ok(claims)
}

/// Verify HMAC-SHA256 signature.
pub fn verify_hmac(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);

    let expected = match hex_decode(signature) {
        Some(bytes) => bytes,
        None => return false,
    };

    mac.verify_slice(&expected).is_ok()
}

/// Hex-decode a signature string, stripping optional "sha256=" prefix.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("sha256=").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Verify delegation chain by checking all ancestor credentials are ACTIVE in Redis.
///
/// Uses a single MGET round trip for efficiency.
/// Returns Ok(()) if all ancestors are active, Err(message) otherwise.
pub async fn verify_delegation_chain(
    redis_client: &redis::Client,
    chain: &[String],
) -> Result<(), String> {
    // Chain depth limit (hard cap from spec Section 6.1)
    if chain.len() > 10 {
        return Err("Delegation chain too deep".into());
    }

    if chain.is_empty() {
        return Ok(());
    }

    // Build MGET keys: navil:cred:{id}:status for each ancestor (per spec Section 6.2)
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| format!("Redis connection failed for chain verification: {e}"))?;

    // Single MGET round trip for all ancestor status keys
    let keys: Vec<String> = chain
        .iter()
        .map(|id| format!("navil:cred:{}:status", id))
        .collect();

    let mut cmd = redis::cmd("MGET");
    for key in &keys {
        cmd.arg(key);
    }

    let results: Vec<Option<String>> = cmd
        .query_async(&mut conn)
        .await
        .map_err(|e| format!("Redis chain verification failed: {e}"))?;

    for (i, status) in results.iter().enumerate() {
        match status {
            Some(s) if s == "ACTIVE" => continue,
            Some(s) => {
                return Err(format!(
                    "Ancestor credential {} is not active (status: {})",
                    chain[i], s
                ));
            }
            None => {
                return Err(format!(
                    "Ancestor credential {} is not active",
                    chain[i]
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode_plain() {
        let result = hex_decode("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_hex_decode_with_prefix() {
        let result = hex_decode("sha256=48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn test_hmac_verification() {
        use hmac::Mac;

        let secret = b"test-secret";
        let body = b"test body";

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        assert!(verify_hmac(secret, body, &sig));
        assert!(!verify_hmac(secret, body, "invalid_signature"));
    }

    #[test]
    fn test_jwt_validation() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(1);

        let claims = NavilClaims {
            token_id: "cred_test123".to_string(),
            agent_name: "test-agent".to_string(),
            scope: "read:tools".to_string(),
            human_context: Some(HumanContext {
                sub: "user123".to_string(),
                email: "test@example.com".to_string(),
                roles: vec!["engineer".to_string()],
            }),
            delegation_chain: Some(vec![]),
            parent_credential_id: None,
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.agent_name, "test-agent");
        assert_eq!(decoded.scope, "read:tools");
        assert!(decoded.human_context.is_some());
        assert_eq!(decoded.human_context.unwrap().email, "test@example.com");
    }

    #[test]
    fn test_jwt_expired() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let now = chrono::Utc::now();
        let exp = now - chrono::Duration::hours(1); // expired

        let claims = NavilClaims {
            token_id: "cred_test123".to_string(),
            agent_name: "test-agent".to_string(),
            scope: "read:tools".to_string(),
            human_context: None,
            delegation_chain: None,
            parent_credential_id: None,
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_jwt_wrong_secret() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let wrong_secret = b"wrong-secret-that-is-also-long-enough-for-hs256-ok";
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(1);

        let claims = NavilClaims {
            token_id: "cred_test123".to_string(),
            agent_name: "test-agent".to_string(),
            scope: "read:tools".to_string(),
            human_context: None,
            delegation_chain: None,
            parent_credential_id: None,
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let result = validate_jwt(&token, wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_bearer_jwt() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(1);

        let claims = NavilClaims {
            token_id: "cred_test123".to_string(),
            agent_name: "jwt-agent".to_string(),
            scope: "read:tools".to_string(),
            human_context: None,
            delegation_chain: Some(vec![]),
            parent_credential_id: None,
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", token).parse().unwrap());

        match authenticate(&headers, b"body", None, secret) {
            AuthResult::Jwt(c) => assert_eq!(c.agent_name, "jwt-agent"),
            other => panic!("Expected Jwt, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_failed_jwt_no_fallback() {
        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer invalid.jwt.token".parse().unwrap());
        headers.insert("x-agent-name", "hmac-agent".parse().unwrap());

        // Even with x-agent-name, if Bearer fails, must NOT fall back
        match authenticate(&headers, b"body", None, secret) {
            AuthResult::Failed(_) => {} // expected
            other => panic!("Expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_anonymous() {
        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let headers = HeaderMap::new();

        match authenticate(&headers, b"body", None, secret) {
            AuthResult::Anonymous => {} // expected
            other => panic!("Expected Anonymous, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_hmac_required_missing() {
        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let hmac_secret = b"hmac-secret";
        let headers = HeaderMap::new();

        match authenticate(&headers, b"body", Some(hmac_secret), secret) {
            AuthResult::Failed(msg) => assert!(msg.contains("Missing HMAC")),
            other => panic!("Expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn test_jwt_with_human_context_extraction() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(1);

        let claims = NavilClaims {
            token_id: "cred_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            agent_name: "deploy-bot".to_string(),
            scope: "read:tools write:logs".to_string(),
            human_context: Some(HumanContext {
                sub: "google-oauth2|108234567890".to_string(),
                email: "alice@example.com".to_string(),
                roles: vec!["engineer".to_string(), "on-call".to_string()],
            }),
            delegation_chain: Some(vec![
                "cred_0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ]),
            parent_credential_id: Some("cred_0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", token).parse().unwrap());

        match authenticate(&headers, b"body", None, secret) {
            AuthResult::Jwt(c) => {
                assert_eq!(c.agent_name, "deploy-bot");
                assert_eq!(c.scope, "read:tools write:logs");
                let hc = c.human_context.unwrap();
                assert_eq!(hc.sub, "google-oauth2|108234567890");
                assert_eq!(hc.email, "alice@example.com");
                assert_eq!(hc.roles, vec!["engineer", "on-call"]);
                let chain = c.delegation_chain.unwrap();
                assert_eq!(chain.len(), 1);
            }
            other => panic!("Expected Jwt, got {:?}", other),
        }
    }

    #[test]
    fn test_jwt_no_human_context() {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::hours(1);

        let claims = NavilClaims {
            token_id: "cred_test456".to_string(),
            agent_name: "ci-bot".to_string(),
            scope: "read:tools".to_string(),
            human_context: None,
            delegation_chain: None,
            parent_credential_id: None,
            iat: serde_json::Value::String(now.to_rfc3339()),
            exp: serde_json::Value::String(exp.to_rfc3339()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {}", token).parse().unwrap());

        match authenticate(&headers, b"body", None, secret) {
            AuthResult::Jwt(c) => {
                assert_eq!(c.agent_name, "ci-bot");
                assert!(c.human_context.is_none());
                assert!(c.delegation_chain.is_none());
            }
            other => panic!("Expected Jwt, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_hmac_valid_signature() {
        use hmac::Mac;

        let jwt_secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let hmac_secret = b"hmac-shared-secret";
        let body = b"compact-json-body";

        let mut mac = HmacSha256::new_from_slice(hmac_secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-navil-signature", sig.parse().unwrap());
        headers.insert("x-agent-name", "hmac-agent".parse().unwrap());

        match authenticate(&headers, body, Some(hmac_secret), jwt_secret) {
            AuthResult::Hmac { agent_name } => assert_eq!(agent_name, "hmac-agent"),
            other => panic!("Expected Hmac, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_hmac_with_sha256_prefix() {
        use hmac::Mac;

        let jwt_secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let hmac_secret = b"hmac-shared-secret";
        let body = b"compact-json-body";

        let mut mac = HmacSha256::new_from_slice(hmac_secret).unwrap();
        mac.update(body);
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        let mut headers = HeaderMap::new();
        headers.insert("x-navil-signature", sig.parse().unwrap());
        headers.insert("x-agent-name", "hmac-agent".parse().unwrap());

        match authenticate(&headers, body, Some(hmac_secret), jwt_secret) {
            AuthResult::Hmac { agent_name } => assert_eq!(agent_name, "hmac-agent"),
            other => panic!("Expected Hmac, got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_hmac_wrong_signature_rejected() {
        let jwt_secret = b"test-jwt-secret-that-is-long-enough-for-hs256-validation";
        let hmac_secret = b"hmac-shared-secret";
        let body = b"compact-json-body";

        let mut headers = HeaderMap::new();
        headers.insert("x-navil-signature", "deadbeef00001111".parse().unwrap());
        headers.insert("x-agent-name", "attacker".parse().unwrap());

        match authenticate(&headers, body, Some(hmac_secret), jwt_secret) {
            AuthResult::Failed(msg) => assert!(msg.contains("Invalid HMAC")),
            other => panic!("Expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn test_chain_depth_limit() {
        // verify_delegation_chain is async, so we test the depth check directly
        let chain: Vec<String> = (0..11)
            .map(|i| format!("cred_{:064x}", i))
            .collect();
        assert!(chain.len() > 10);

        // We can't easily test async in a sync test, but we can verify
        // the chain length check logic by using tokio::test
    }

    #[tokio::test]
    async fn test_chain_depth_exceeds_limit() {
        // This test verifies that chains > 10 are rejected without Redis
        let chain: Vec<String> = (0..11)
            .map(|i| format!("cred_{:064x}", i))
            .collect();

        // We need a Redis client but the chain depth check happens before Redis
        // So we can use a dummy URL (it won't be called)
        let redis_client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let result = verify_delegation_chain(&redis_client, &chain).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too deep"));
    }

    #[tokio::test]
    async fn test_empty_chain_passes() {
        let redis_client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let chain: Vec<String> = vec![];
        let result = verify_delegation_chain(&redis_client, &chain).await;
        assert!(result.is_ok());
    }

    // Helper for hex encoding in tests
    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            bytes
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect()
        }
    }
}
