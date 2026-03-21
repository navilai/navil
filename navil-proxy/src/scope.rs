// Copyright (c) 2026 Pantheon Lab Pte Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Scope module — context-aware tool scoping for MCP tools/list responses.
//!
//! Scope = VISIBILITY: controls which tools an agent SEES in tools/list.
//! (Distinct from policy = PERMISSION: controls which tools an agent can CALL.)
//!
//! The Python control plane pushes scope definitions to Redis:
//!     navil:scope:{scope_name} → JSON array of tool names (or ["*"] for all)
//!
//! The Rust proxy reads the X-Navil-Scope header, looks up the scope
//! in Redis (O(1)), and filters the tools/list response accordingly.
//!
//! Caching: filtered responses are cached in Redis with 60s TTL to avoid
//! re-filtering on repeat requests.
//!
//! Flow:
//!     Agent → X-Navil-Scope: github-pr-review → Proxy
//!         → Redis GET navil:scope:github-pr-review → ["pulls/get", "pulls/list", ...]
//!         → Forward to upstream MCP server → tools/list response
//!         → Filter tools array to only include scoped tools
//!         → Cache filtered response → Return to agent

use serde_json::Value;
use tracing::warn;

/// Redis key prefix for scope definitions (written by Python PolicyEngine).
const SCOPE_KEY_PREFIX: &str = "navil:scope";

/// Redis key prefix for cached filtered responses.
const CACHE_KEY_PREFIX: &str = "navil:scope_cache";

/// Cache TTL in seconds for filtered tools/list responses.
const CACHE_TTL_SECS: u64 = 60;

/// Look up scope tools from Redis.
///
/// Returns `Some(vec![...])` if a scope is defined, `None` if not found.
/// Returns `Some(vec!["*"])` if the scope allows all tools.
pub async fn get_scope_tools(
    conn: &mut redis::aio::MultiplexedConnection,
    scope_name: &str,
) -> Option<Vec<String>> {
    let key = format!("{SCOPE_KEY_PREFIX}:{scope_name}");
    let result: Result<Option<String>, _> = redis::cmd("GET").arg(&key).query_async(conn).await;

    match result {
        Ok(Some(json_str)) => match serde_json::from_str::<Vec<String>>(&json_str) {
            Ok(tools) => Some(tools),
            Err(e) => {
                warn!("Failed to parse scope '{}' from Redis: {}", scope_name, e);
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            warn!("Redis GET failed for scope '{}': {}", scope_name, e);
            None
        }
    }
}

/// Check for a cached filtered response.
///
/// Cache key: navil:scope_cache:{hash(target_url + scope_name)}
pub async fn get_cached_response(
    conn: &mut redis::aio::MultiplexedConnection,
    target_url: &str,
    scope_name: &str,
) -> Option<Vec<u8>> {
    let cache_key = make_cache_key(target_url, scope_name);
    let result: Result<Option<Vec<u8>>, _> =
        redis::cmd("GET").arg(&cache_key).query_async(conn).await;

    match result {
        Ok(Some(data)) => Some(data),
        Ok(None) => None,
        Err(e) => {
            warn!("Redis cache GET failed: {}", e);
            None
        }
    }
}

/// Store a filtered response in the cache with TTL.
pub async fn set_cached_response(
    conn: &mut redis::aio::MultiplexedConnection,
    target_url: &str,
    scope_name: &str,
    response: &[u8],
) {
    let cache_key = make_cache_key(target_url, scope_name);
    let result: Result<(), _> = redis::cmd("SET")
        .arg(&cache_key)
        .arg(response)
        .arg("EX")
        .arg(CACHE_TTL_SECS)
        .query_async(conn)
        .await;

    if let Err(e) = result {
        warn!("Redis cache SET failed: {}", e);
    }
}

/// Filter a tools/list JSON-RPC response to only include tools in the scope.
///
/// The tools/list response has structure:
/// ```json
/// {
///   "jsonrpc": "2.0",
///   "result": {
///     "tools": [
///       {"name": "pulls/get", "description": "...", "inputSchema": {...}},
///       ...
///     ]
///   },
///   "id": 1
/// }
/// ```
///
/// If scope_tools contains "*", the response is returned unmodified.
/// Otherwise, only tools whose "name" field matches a scope tool are kept.
pub fn filter_tools_list(response_bytes: &[u8], scope_tools: &[String]) -> Result<Vec<u8>, String> {
    // Wildcard scope — return unmodified
    if scope_tools.iter().any(|t| t == "*") {
        return Ok(response_bytes.to_vec());
    }

    let mut parsed: Value =
        serde_json::from_slice(response_bytes).map_err(|e| format!("JSON parse error: {e}"))?;

    // Navigate to result.tools array
    if let Some(tools_array) = parsed
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    {
        tools_array.retain(|tool| {
            tool.get("name")
                .and_then(|n| n.as_str())
                .map(|name| scope_tools.iter().any(|s| s == name))
                .unwrap_or(false)
        });
    }

    serde_json::to_vec(&parsed).map_err(|e| format!("JSON serialize error: {e}"))
}

/// Generate a scope violation JSON-RPC error response.
///
/// Used when a scoped agent tries to call a tool not in its scope.
pub fn scope_violation_error(scope_name: &str, tool_name: &str, req_id: &Value) -> Vec<u8> {
    let error = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32600,
            "message": format!("Tool '{}' not available in scope '{}'", tool_name, scope_name)
        },
        "id": req_id
    });
    serde_json::to_vec(&error).unwrap_or_default()
}

/// Check if a tool call is allowed by the current scope.
///
/// Returns true if the tool is in scope (or scope is wildcard).
pub fn is_tool_in_scope(scope_tools: &[String], tool_name: &str) -> bool {
    scope_tools.iter().any(|t| t == "*" || t == tool_name)
}

/// Create a deterministic cache key from target URL and scope name.
fn make_cache_key(target_url: &str, scope_name: &str) -> String {
    // Simple hash using the strings directly (fast, deterministic)
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    target_url.hash(&mut hasher);
    scope_name.hash(&mut hasher);
    format!("{CACHE_KEY_PREFIX}:{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_tools_list_scoped() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "pulls/get", "description": "Get a PR"},
                    {"name": "pulls/list", "description": "List PRs"},
                    {"name": "issues/create", "description": "Create an issue"},
                    {"name": "repos/delete", "description": "Delete a repo"},
                ]
            },
            "id": 1
        });
        let bytes = serde_json::to_vec(&response).unwrap();
        let scope = vec!["pulls/get".to_string(), "pulls/list".to_string()];

        let filtered = filter_tools_list(&bytes, &scope).unwrap();
        let parsed: Value = serde_json::from_slice(&filtered).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "pulls/get");
        assert_eq!(tools[1]["name"], "pulls/list");
    }

    #[test]
    fn test_filter_tools_list_wildcard() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "pulls/get", "description": "Get a PR"},
                    {"name": "issues/create", "description": "Create an issue"},
                ]
            },
            "id": 1
        });
        let bytes = serde_json::to_vec(&response).unwrap();
        let scope = vec!["*".to_string()];

        let filtered = filter_tools_list(&bytes, &scope).unwrap();
        // Wildcard scope returns unmodified (byte-equal)
        assert_eq!(filtered, bytes);
    }

    #[test]
    fn test_filter_tools_list_empty_scope() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "pulls/get", "description": "Get a PR"},
                ]
            },
            "id": 1
        });
        let bytes = serde_json::to_vec(&response).unwrap();
        let scope: Vec<String> = vec![];

        let filtered = filter_tools_list(&bytes, &scope).unwrap();
        let parsed: Value = serde_json::from_slice(&filtered).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 0);
    }

    #[test]
    fn test_is_tool_in_scope_match() {
        let scope = vec!["pulls/get".to_string(), "pulls/list".to_string()];
        assert!(is_tool_in_scope(&scope, "pulls/get"));
        assert!(is_tool_in_scope(&scope, "pulls/list"));
        assert!(!is_tool_in_scope(&scope, "repos/delete"));
    }

    #[test]
    fn test_is_tool_in_scope_wildcard() {
        let scope = vec!["*".to_string()];
        assert!(is_tool_in_scope(&scope, "anything"));
        assert!(is_tool_in_scope(&scope, "repos/delete"));
    }

    #[test]
    fn test_scope_violation_error() {
        let error = scope_violation_error(
            "github-pr-review",
            "repos/delete",
            &serde_json::json!(42),
        );
        let parsed: Value = serde_json::from_slice(&error).unwrap();
        assert_eq!(parsed["error"]["code"], -32600);
        assert_eq!(parsed["id"], 42);
        let msg = parsed["error"]["message"].as_str().unwrap();
        assert!(msg.contains("repos/delete"));
        assert!(msg.contains("github-pr-review"));
    }

    #[test]
    fn test_cache_key_deterministic() {
        let key1 = make_cache_key("http://localhost:3000", "github-pr-review");
        let key2 = make_cache_key("http://localhost:3000", "github-pr-review");
        assert_eq!(key1, key2);

        let key3 = make_cache_key("http://localhost:3000", "deploy");
        assert_ne!(key1, key3);
    }
}
