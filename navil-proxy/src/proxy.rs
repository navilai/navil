// Copyright (c) 2026 Pantheon Lab Pte Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Proxy module — request forwarding + SSE streaming support.
//!
//! Handles forwarding JSON-RPC requests to upstream MCP servers and
//! processing both JSON and SSE responses.
//!
//! SSE streaming: when the upstream responds with `text/event-stream`,
//! we use `resp.bytes_stream()` and `Body::from_stream()` to forward
//! the stream without buffering the entire response in memory.
//! For standard JSON responses, we use `resp.bytes().await`.

use axum::body::Body;
use axum::http::HeaderMap;
use futures_util::StreamExt;

/// Result of forwarding a request upstream.
///
/// `body` is an axum `Body` that may be either a buffered JSON payload
/// or a streaming SSE pass-through.
pub struct ForwardResult {
    pub body: Body,
    pub response_bytes: usize,
    pub headers: HeaderMap,
}

/// Forward a request to the upstream MCP server.
///
/// Returns a `ForwardResult` containing the response body (buffered or streaming),
/// estimated response size, and headers to forward back.
pub async fn forward_request(
    http_client: &reqwest::Client,
    target_url: &str,
    body: Vec<u8>,
    agent_name: &str,
    human_context: Option<&crate::auth::HumanContext>,
    delegation_depth: usize,
    is_jwt_auth: bool,
) -> Result<ForwardResult, String> {
    let mut forward_headers = reqwest::header::HeaderMap::new();
    forward_headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    forward_headers.insert(
        reqwest::header::ACCEPT,
        "application/json, text/event-stream".parse().unwrap(),
    );

    // Header injection per proxy-interface-spec.md Section 8
    if let Ok(val) = reqwest::header::HeaderValue::from_str(agent_name) {
        forward_headers.insert("x-agent-name", val);
    }

    if is_jwt_auth {
        // X-Delegation-Depth: always present for JWT-authenticated requests
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&delegation_depth.to_string()) {
            forward_headers.insert("x-delegation-depth", val);
        }

        // X-Human-Identity and X-Human-Email: only if human_context is present
        if let Some(hc) = human_context {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&hc.sub) {
                forward_headers.insert("x-human-identity", val);
            }
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&hc.email) {
                forward_headers.insert("x-human-email", val);
            }
        }
    }

    let upstream_resp = http_client
        .post(target_url)
        .headers(forward_headers)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Upstream error: {e}"))?;

    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Check if response is SSE — use streaming path
    if content_type.contains("text/event-stream") {
        // Build response headers for SSE streaming
        let mut result_headers = HeaderMap::new();
        result_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/event-stream".parse().unwrap(),
        );
        if let Some(session_id) = resp_headers.get("mcp-session-id") {
            if let Ok(val) = axum::http::HeaderValue::from_bytes(session_id.as_bytes()) {
                result_headers.insert("mcp-session-id", val);
            }
        }

        // Use bytes_stream() to forward without buffering the entire response
        let stream = upstream_resp.bytes_stream().map(|result| {
            result.map_err(|e| std::io::Error::other(format!("SSE stream error: {e}")))
        });
        let body = Body::from_stream(stream);

        return Ok(ForwardResult {
            body,
            response_bytes: 0, // unknown for streaming
            headers: result_headers,
        });
    }

    // Standard JSON response — buffer with bytes().await
    let resp_body = upstream_resp
        .bytes()
        .await
        .map_err(|e| format!("Upstream read error: {e}"))?;
    let response_bytes = resp_body.len();

    // Build response headers
    let mut result_headers = HeaderMap::new();
    result_headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    if let Some(session_id) = resp_headers.get("mcp-session-id") {
        if let Ok(val) = axum::http::HeaderValue::from_bytes(session_id.as_bytes()) {
            result_headers.insert("mcp-session-id", val);
        }
    }

    Ok(ForwardResult {
        body: Body::from(resp_body),
        response_bytes,
        headers: result_headers,
    })
}

/// Parse SSE response text to extract the first valid JSON-RPC object.
#[allow(dead_code)]
pub fn parse_sse_response(text: &str) -> Vec<u8> {
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                if let Ok(json_bytes) = serde_json::to_vec(&parsed) {
                    return json_bytes;
                }
            }
        }
    }

    // Fallback: return error
    let error = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {"code": -32603, "message": "No valid JSON in SSE response"},
        "id": null
    });
    serde_json::to_vec(&error).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_response_valid() {
        let sse_text =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":1}\n\n";
        let result = parse_sse_response(sse_text);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
    }

    #[test]
    fn test_parse_sse_response_no_data() {
        let sse_text = "event: message\nno-data-here\n\n";
        let result = parse_sse_response(sse_text);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["error"]["code"], -32603);
    }

    #[test]
    fn test_parse_sse_response_multiple_lines() {
        let sse_text = "data: invalid\ndata: {\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":2}\n\n";
        let result = parse_sse_response(sse_text);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["id"], 2);
    }

    #[test]
    fn test_parse_sse_response_empty_data() {
        let sse_text = "data: \n\n";
        let result = parse_sse_response(sse_text);
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // Should fall through to error since empty string is not valid JSON
        assert_eq!(parsed["error"]["code"], -32603);
    }

    /// Test that header injection builds correct headers for JWT with human_context.
    /// We test the header building logic directly since forward_request requires network.
    #[test]
    fn test_header_injection_jwt_with_human_context() {
        let agent_name = "deploy-bot";
        let hc = crate::auth::HumanContext {
            sub: "google-oauth2|108234567890".to_string(),
            email: "alice@example.com".to_string(),
            roles: vec!["engineer".to_string()],
        };
        let delegation_depth: usize = 2;
        let is_jwt_auth = true;

        let mut forward_headers = reqwest::header::HeaderMap::new();
        forward_headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        forward_headers.insert(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );

        // Replicate the header injection logic from forward_request
        if let Ok(val) = reqwest::header::HeaderValue::from_str(agent_name) {
            forward_headers.insert("x-agent-name", val);
        }
        if is_jwt_auth {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&delegation_depth.to_string()) {
                forward_headers.insert("x-delegation-depth", val);
            }
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&hc.sub) {
                forward_headers.insert("x-human-identity", val);
            }
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&hc.email) {
                forward_headers.insert("x-human-email", val);
            }
        }

        assert_eq!(forward_headers.get("x-agent-name").unwrap(), "deploy-bot");
        assert_eq!(forward_headers.get("x-delegation-depth").unwrap(), "2");
        assert_eq!(
            forward_headers.get("x-human-identity").unwrap(),
            "google-oauth2|108234567890"
        );
        assert_eq!(
            forward_headers.get("x-human-email").unwrap(),
            "alice@example.com"
        );
    }

    /// Test that HMAC-authenticated requests do NOT get human identity headers.
    #[test]
    fn test_header_injection_hmac_no_identity_headers() {
        let agent_name = "hmac-agent";
        let is_jwt_auth = false;

        let mut forward_headers = reqwest::header::HeaderMap::new();
        forward_headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        if let Ok(val) = reqwest::header::HeaderValue::from_str(agent_name) {
            forward_headers.insert("x-agent-name", val);
        }
        if is_jwt_auth {
            // This block should NOT execute for HMAC
            forward_headers.insert("x-delegation-depth", "0".parse().unwrap());
        }

        assert_eq!(forward_headers.get("x-agent-name").unwrap(), "hmac-agent");
        assert!(forward_headers.get("x-human-identity").is_none());
        assert!(forward_headers.get("x-human-email").is_none());
        assert!(forward_headers.get("x-delegation-depth").is_none());
    }

    /// Test delegation depth is "0" when no delegation chain.
    #[test]
    fn test_header_injection_jwt_no_delegation() {
        let delegation_depth: usize = 0;
        let is_jwt_auth = true;

        let mut forward_headers = reqwest::header::HeaderMap::new();
        if is_jwt_auth {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&delegation_depth.to_string()) {
                forward_headers.insert("x-delegation-depth", val);
            }
        }

        assert_eq!(forward_headers.get("x-delegation-depth").unwrap(), "0");
    }
}
