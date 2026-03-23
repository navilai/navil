// Copyright (c) 2026 Pantheon Lab Pte Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Navil MCP Security Proxy — Rust Data Plane
//!
//! Hot-path reverse proxy for MCP JSON-RPC 2.0.
//! Reads pre-computed thresholds from Redis (written by the Python control plane)
//! and enforces payload limits, rate limits, JWT/HMAC authentication,
//! delegation chain verification, and identity header injection
//! before forwarding to the upstream MCP server.
//!
//! Architecture:
//!     Agent → POST /mcp → navil-proxy (Rust) → reqwest → MCP Server
//!                              ↓
//!                     Pre-execution:  JWT/HMAC verify, payload limit,
//!                                     delegation chain check,
//!                                     Redis threshold + rate check
//!                     Post-execution: header injection, telemetry

mod auth;
mod proxy;
mod scope;
mod telemetry;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use auth::{AuthResult, HumanContext};
use telemetry::{iso8601_now, publish_telemetry, TelemetryEvent};

// ── Constants (match Python proxy) ───────────────────────────────

const MAX_PAYLOAD_BYTES: usize = 5 * 1024 * 1024; // 5 MB
const MAX_JSON_DEPTH: usize = 10;

// ── App State ────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    target_url: String,
    http_client: reqwest::Client,
    redis_client: redis::Client,
    hmac_secret: Option<Vec<u8>>,
    jwt_secret: Vec<u8>, // Same as HMAC secret for HS256 signing
}

// ── Redis Threshold Schema ───────────────────────────────────────

#[derive(Debug, Clone)]
struct AgentThresholds {
    max_payload_bytes: usize,
    rate_limit_per_min: u64,
    blocked: bool,
}

impl Default for AgentThresholds {
    fn default() -> Self {
        Self {
            max_payload_bytes: 10_000_000,
            rate_limit_per_min: 120,
            blocked: false,
        }
    }
}

// ── JSON-RPC types ───────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    method: Option<String>,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcError {
    jsonrpc: &'static str,
    error: JsonRpcErrorBody,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcErrorBody {
    code: i32,
    message: String,
}

fn jsonrpc_error(
    code: i32,
    message: impl Into<String>,
    id: Option<serde_json::Value>,
) -> Json<JsonRpcError> {
    Json(JsonRpcError {
        jsonrpc: "2.0",
        error: JsonRpcErrorBody {
            code,
            message: message.into(),
        },
        id: id.unwrap_or(serde_json::Value::Null),
    })
}

// ── Sanitization ─────────────────────────────────────────────────

fn check_json_depth(value: &serde_json::Value, current: usize, limit: usize) -> Result<(), String> {
    if current > limit {
        return Err(format!(
            "JSON nesting depth {} exceeds limit {}",
            current, limit
        ));
    }
    match value {
        serde_json::Value::Object(map) => {
            for v in map.values() {
                check_json_depth(v, current + 1, limit)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                check_json_depth(v, current + 1, limit)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn sanitize_request(body: &[u8]) -> Result<(serde_json::Value, Vec<u8>), (i32, String)> {
    if body.len() > MAX_PAYLOAD_BYTES {
        return Err((
            -32700,
            format!(
                "Payload too large: {} bytes (limit {} bytes)",
                body.len(),
                MAX_PAYLOAD_BYTES
            ),
        ));
    }

    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| (-32700, format!("Invalid JSON: {e}")))?;

    check_json_depth(&value, 1, MAX_JSON_DEPTH).map_err(|msg| (-32700, msg))?;

    let compact = serde_json::to_vec(&value)
        .map_err(|e| (-32700, format!("JSON re-serialize failed: {e}")))?;

    Ok((value, compact))
}

// ── Redis Threshold Lookup ───────────────────────────────────────

async fn get_thresholds(
    conn: &mut redis::aio::MultiplexedConnection,
    agent: &str,
) -> AgentThresholds {
    let key = format!("navil:agent:{}:thresholds", agent);
    let result: Result<Vec<Option<String>>, _> = redis::cmd("HMGET")
        .arg(&key)
        .arg("max_payload_bytes")
        .arg("rate_limit_per_min")
        .arg("blocked")
        .query_async(conn)
        .await;

    match result {
        Ok(fields) => {
            let max_payload = fields
                .first()
                .and_then(|v| v.as_ref())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(10_000_000);
            let rate_limit = fields
                .get(1)
                .and_then(|v| v.as_ref())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(120);
            let blocked = fields
                .get(2)
                .and_then(|v| v.as_ref())
                .map(|s| s == "1" || s == "true" || s == "True")
                .unwrap_or(false);

            AgentThresholds {
                max_payload_bytes: max_payload,
                rate_limit_per_min: rate_limit,
                blocked,
            }
        }
        Err(e) => {
            warn!("Redis HMGET failed for {}: {}", agent, e);
            AgentThresholds::default()
        }
    }
}

async fn check_rate_limit(
    conn: &mut redis::aio::MultiplexedConnection,
    agent: &str,
    limit: u64,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let bucket = now / 60;
    let key = format!("navil:agent:{}:rate:{}", agent, bucket);

    let result: Result<(u64,), _> = redis::pipe()
        .atomic()
        .cmd("INCR")
        .arg(&key)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(120_u64)
        .ignore()
        .query_async(conn)
        .await;

    match result {
        Ok((count,)) => {
            if count > limit {
                Err(format!(
                    "Rate limit exceeded: {} requests/min (limit {})",
                    count, limit
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => {
            warn!("Redis rate limit check failed for {}: {}", agent, e);
            Ok(())
        }
    }
}

// ── Handler ──────────────────────────────────────────────────────

async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let start = Instant::now();

    // 1. Sanitize: size limit, JSON parse, depth check
    let (parsed, compact_body) = match sanitize_request(&body) {
        Ok(v) => v,
        Err((code, msg)) => {
            return (StatusCode::BAD_REQUEST, jsonrpc_error(code, msg, None)).into_response();
        }
    };

    // 2. Parse JSON-RPC envelope
    let rpc: JsonRpcRequest = match serde_json::from_value(parsed) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                jsonrpc_error(-32700, format!("Invalid JSON-RPC: {e}"), None),
            )
                .into_response();
        }
    };

    let method = rpc.method.as_deref().unwrap_or("").to_string();
    let req_id = rpc.id.clone();

    let tool_name = rpc
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    // Parse X-Navil-Scope header for context-aware tool scoping
    let scope_name = headers
        .get("x-navil-scope")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 3. Authenticate: JWT → HMAC → Anonymous
    let auth_result = auth::authenticate(
        &headers,
        &compact_body,
        state.hmac_secret.as_deref(),
        &state.jwt_secret,
    );

    let (agent_name, human_context, delegation_chain, is_jwt_auth): (
        String,
        Option<HumanContext>,
        Vec<String>,
        bool,
    ) = match auth_result {
        AuthResult::Jwt(claims) => {
            let chain = claims.delegation_chain.clone().unwrap_or_default();
            let hc = claims.human_context.clone();
            (claims.agent_name.clone(), hc, chain, true)
        }
        AuthResult::Hmac { agent_name } => (agent_name, None, vec![], false),
        AuthResult::Anonymous => ("anonymous".to_string(), None, vec![], false),
        AuthResult::Failed(msg) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let payload_bytes = compact_body.len();

            // Emit BLOCKED_AUTH telemetry
            let tele_state = state.clone();
            let tele_target = state.target_url.clone();
            let tele_tool = tool_name.clone();
            let tele_method = method.clone();
            tokio::spawn(async move {
                publish_telemetry(
                    &tele_state.redis_client,
                    TelemetryEvent {
                        agent_name: "unknown".to_string(),
                        tool_name: tele_tool,
                        method: tele_method,
                        action: "BLOCKED_AUTH".to_string(),
                        payload_bytes,
                        response_bytes: 0,
                        duration_ms,
                        timestamp: iso8601_now(),
                        target_server: tele_target,
                        human_email: None,
                        delegation_depth: None,
                    },
                )
                .await;
            });

            return (StatusCode::UNAUTHORIZED, jsonrpc_error(-32003, msg, req_id)).into_response();
        }
    };

    let payload_bytes = compact_body.len();

    // 4. Delegation chain verification (JWT path only)
    if is_jwt_auth && !delegation_chain.is_empty() {
        match auth::verify_delegation_chain(&state.redis_client, &delegation_chain).await {
            Ok(()) => {}
            Err(msg) => {
                return (StatusCode::UNAUTHORIZED, jsonrpc_error(-32003, msg, req_id))
                    .into_response();
            }
        }
    }

    // 5a. Scope enforcement: check if tool is visible in the active scope
    //     Scope = VISIBILITY (what tools agent sees), enforced before forwarding.
    let mut scope_tools: Option<Vec<String>> = None;
    if let Some(ref sn) = scope_name {
        let scope_check = async {
            let mut conn = state
                .redis_client
                .get_multiplexed_async_connection()
                .await
                .ok();
            if let Some(ref mut conn) = conn {
                scope::get_scope_tools(conn, sn).await
            } else {
                None
            }
        }
        .await;

        match scope_check {
            Some(tools) => {
                // For tools/call: deny if tool is not in scope
                if method == "tools/call"
                    && !tool_name.is_empty()
                    && !scope::is_tool_in_scope(&tools, &tool_name)
                {
                    let req_id_val = req_id.clone().unwrap_or(serde_json::Value::Null);
                    let error_body = scope::scope_violation_error(sn, &tool_name, &req_id_val);

                    // Emit telemetry for scope violation
                    let duration_ms = start.elapsed().as_millis() as u64;
                    let tele_state = state.clone();
                    let tele_agent = agent_name.clone();
                    let tele_tool = tool_name.clone();
                    let tele_method = method.clone();
                    let tele_target = state.target_url.clone();
                    tokio::spawn(async move {
                        publish_telemetry(
                            &tele_state.redis_client,
                            TelemetryEvent {
                                agent_name: tele_agent,
                                tool_name: tele_tool,
                                method: tele_method,
                                action: "BLOCKED_SCOPE".to_string(),
                                payload_bytes,
                                response_bytes: 0,
                                duration_ms,
                                timestamp: iso8601_now(),
                                target_server: tele_target,
                                human_email: None,
                                delegation_depth: None,
                            },
                        )
                        .await;
                    });

                    return (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        Body::from(error_body),
                    )
                        .into_response();
                }
                scope_tools = Some(tools);
            }
            None => {
                // Unknown scope: fall through to default (all tools visible)
                warn!("Unknown scope '{}', falling through to default", sn);
            }
        }
    }

    // 5b. For tools/list with scope: check cache first
    if method == "tools/list" {
        if let Some(ref sn) = scope_name {
            let cache_check = async {
                let mut conn = state
                    .redis_client
                    .get_multiplexed_async_connection()
                    .await
                    .ok();
                if let Some(ref mut conn) = conn {
                    scope::get_cached_response(conn, &state.target_url, sn).await
                } else {
                    None
                }
            }
            .await;

            if let Some(cached) = cache_check {
                let duration_ms = start.elapsed().as_millis() as u64;
                let cached_len = cached.len();

                // Emit telemetry for cache hit
                let tele_state = state.clone();
                let tele_agent = agent_name.clone();
                let tele_method = method.clone();
                let tele_target = state.target_url.clone();
                tokio::spawn(async move {
                    publish_telemetry(
                        &tele_state.redis_client,
                        TelemetryEvent {
                            agent_name: tele_agent,
                            tool_name: String::new(),
                            method: tele_method,
                            action: "SCOPE_CACHE_HIT".to_string(),
                            payload_bytes,
                            response_bytes: cached_len,
                            duration_ms,
                            timestamp: iso8601_now(),
                            target_server: tele_target,
                            human_email: None,
                            delegation_depth: None,
                        },
                    )
                    .await;
                });

                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    Body::from(cached),
                )
                    .into_response();
            }
        }
    }

    // 5c. For tools/call: Redis threshold + rate check
    if method == "tools/call" {
        let redis_check = async {
            let mut conn = state
                .redis_client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| {
                    warn!("Redis connection failed: {}", e);
                    e
                })
                .ok();

            if let Some(ref mut conn) = conn {
                let thresholds = get_thresholds(conn, &agent_name).await;

                if thresholds.blocked {
                    return Err((-32002, "BLOCKED_AGENT".to_string()));
                }

                if compact_body.len() > thresholds.max_payload_bytes {
                    return Err((-32002, "BLOCKED_THRESHOLD".to_string()));
                }

                if let Err(_msg) =
                    check_rate_limit(conn, &agent_name, thresholds.rate_limit_per_min).await
                {
                    return Err((-32002, "BLOCKED_RATE".to_string()));
                }
            }
            Ok(())
        }
        .await;

        if let Err((_code, action)) = redis_check {
            let duration_ms = start.elapsed().as_millis() as u64;

            let tele_state = state.clone();
            let tele_agent = agent_name.clone();
            let tele_tool = tool_name.clone();
            let tele_method = method.clone();
            let tele_action = action.clone();
            let tele_target = state.target_url.clone();
            let tele_email = human_context.as_ref().map(|hc| hc.email.clone());
            let tele_depth = if is_jwt_auth {
                Some(delegation_chain.len())
            } else {
                None
            };
            tokio::spawn(async move {
                publish_telemetry(
                    &tele_state.redis_client,
                    TelemetryEvent {
                        agent_name: tele_agent,
                        tool_name: tele_tool,
                        method: tele_method,
                        action: tele_action,
                        payload_bytes,
                        response_bytes: 0,
                        duration_ms,
                        timestamp: iso8601_now(),
                        target_server: tele_target,
                        human_email: tele_email,
                        delegation_depth: tele_depth,
                    },
                )
                .await;
            });

            let msg = match action.as_str() {
                "BLOCKED_AGENT" => "Agent is blocked",
                "BLOCKED_RATE" => "Rate limit exceeded",
                _ => "Blocked by threshold",
            };
            return (
                StatusCode::TOO_MANY_REQUESTS,
                jsonrpc_error(-32002, msg, req_id),
            )
                .into_response();
        }
    }

    // 6. Forward to upstream MCP server with identity headers
    let delegation_depth = delegation_chain.len();
    let forward_result = match proxy::forward_request(
        &state.http_client,
        &state.target_url,
        compact_body,
        &agent_name,
        human_context.as_ref(),
        delegation_depth,
        is_jwt_auth,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Upstream request failed: {}", e);
            return (StatusCode::BAD_GATEWAY, jsonrpc_error(-32603, e, req_id)).into_response();
        }
    };

    let response_bytes = forward_result.response_bytes;
    let upstream_headers = forward_result.headers;
    let mut resp_body = forward_result.body;

    // 6b. Post-forward: filter tools/list response if scope is active
    //     Only for non-streaming (JSON) responses with a defined scope.
    if method == "tools/list" && scope_tools.is_some() {
        if let Some(ref tools) = scope_tools {
            // We need to read the body bytes to filter, then reconstruct
            // This only applies to buffered JSON responses (not SSE streams)
            let body_bytes = match axum::body::to_bytes(resp_body, 10 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to read tools/list response body: {}", e);
                    return (
                        StatusCode::BAD_GATEWAY,
                        jsonrpc_error(-32603, format!("Body read error: {e}"), req_id),
                    )
                        .into_response();
                }
            };

            match scope::filter_tools_list(&body_bytes, tools) {
                Ok(filtered) => {
                    // Cache the filtered response
                    if let Some(ref sn) = scope_name {
                        let cache_state = state.clone();
                        let cache_scope = sn.clone();
                        let cache_data = filtered.clone();
                        tokio::spawn(async move {
                            if let Ok(mut conn) = cache_state
                                .redis_client
                                .get_multiplexed_async_connection()
                                .await
                            {
                                scope::set_cached_response(
                                    &mut conn,
                                    &cache_state.target_url,
                                    &cache_scope,
                                    &cache_data,
                                )
                                .await;
                            }
                        });
                    }

                    resp_body = Body::from(filtered);
                }
                Err(e) => {
                    warn!("Scope filtering failed, returning unfiltered: {}", e);
                    resp_body = Body::from(body_bytes);
                }
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    // 7. Emit telemetry for forwarded request (background)
    {
        let tele_state = state.clone();
        let tele_agent = agent_name.clone();
        let tele_tool = tool_name.clone();
        let tele_method = method.clone();
        let tele_target = state.target_url.clone();
        let tele_email = human_context.as_ref().map(|hc| hc.email.clone());
        let tele_depth = if is_jwt_auth {
            Some(delegation_depth)
        } else {
            None
        };
        tokio::spawn(async move {
            publish_telemetry(
                &tele_state.redis_client,
                TelemetryEvent {
                    agent_name: tele_agent,
                    tool_name: tele_tool,
                    method: tele_method,
                    action: "FORWARDED".to_string(),
                    payload_bytes,
                    response_bytes,
                    duration_ms,
                    timestamp: iso8601_now(),
                    target_server: tele_target,
                    human_email: tele_email,
                    delegation_depth: tele_depth,
                },
            )
            .await;
        });
    }

    // Build response
    (StatusCode::OK, upstream_headers, resp_body).into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "navil-proxy-rust",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Serve A2A Agent Card at /.well-known/agent.json
///
/// Per Google A2A spec v0.2: agents publish a JSON metadata document
/// at this well-known URI for discovery by other agents.
async fn agent_card(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let base_url = format!(
        "http://{}",
        std::env::var("NAVIL_BASE_URL").unwrap_or_else(|_| format!(
            "localhost:{}",
            std::env::var("NAVIL_PORT").unwrap_or_else(|_| "8080".to_string())
        ))
    );
    let agent_name =
        std::env::var("NAVIL_AGENT_NAME").unwrap_or_else(|_| "navil-agent".to_string());
    let agent_desc = std::env::var("NAVIL_AGENT_DESCRIPTION")
        .unwrap_or_else(|_| "An agent protected by Navil agent governance middleware".to_string());
    let provider_org = std::env::var("NAVIL_PROVIDER_ORG").unwrap_or_default();

    Json(serde_json::json!({
        "name": agent_name,
        "description": agent_desc,
        "provider": {
            "organization": provider_org,
            "url": std::env::var("NAVIL_PROVIDER_URL").unwrap_or_default(),
        },
        "version": "1.0.0",
        "capabilities": {
            "streaming": true,
            "pushNotifications": false,
            "extendedAgentCard": true,
        },
        "skills": [{
            "id": "mcp-tool-execution",
            "name": "MCP Tool Execution",
            "description": "Execute MCP server tools with governance and policy enforcement",
            "tags": ["mcp", "tools", "governance"],
        }],
        "securitySchemes": {
            "navil_jwt": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Navil-issued JWT with agent identity and delegation chain",
            },
        },
        "security": [{"navil_jwt": []}],
        "interfaces": [{
            "protocol": "jsonrpc",
            "url": format!("{}/a2a", base_url),
            "contentTypes": ["application/json"],
        }],
        "documentationUrl": "https://github.com/nicholasgriffintn/navil",
        "extensions": [{
            "name": "navil-governance",
            "version": "1.0.0",
            "description": "Navil agent governance — policy enforcement, tool scoping, anomaly detection",
            "fields": {
                "governance_endpoint": format!("{}/mcp", base_url),
                "policy_version": "1.0",
                "supports_scoping": true,
                "supports_threat_detection": true,
            },
        }],
    }))
}

// ── Main ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "navil_proxy=info".into()),
        )
        .init();

    let target_url =
        std::env::var("NAVIL_TARGET_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let redis_url =
        std::env::var("NAVIL_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let hmac_secret = std::env::var("NAVIL_HMAC_SECRET")
        .ok()
        .map(|s| s.into_bytes());
    let port: u16 = std::env::var("NAVIL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    // JWT secret = HMAC secret (both use HS256)
    let jwt_secret = hmac_secret.clone().unwrap_or_else(|| {
        std::env::var("NAVIL_JWT_SECRET")
            .unwrap_or_default()
            .into_bytes()
    });

    let redis_client = redis::Client::open(redis_url.as_str()).expect("Invalid Redis URL");
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(AppState {
        target_url: target_url.clone(),
        http_client,
        redis_client,
        hmac_secret,
        jwt_secret,
    });

    // Reject non-POST on MCP endpoints — closes the GET query-string bypass (NTS-ADV-008)
    async fn reject_non_post() -> impl IntoResponse {
        warn!("Rejected non-POST request on MCP endpoint");
        (
            StatusCode::METHOD_NOT_ALLOWED,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            Body::from(
                r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Only POST is allowed on MCP endpoints"},"id":null}"#,
            ),
        )
    }

    let app = Router::new()
        .route(
            "/mcp",
            post(handle_mcp)
                .get(reject_non_post)
                .put(reject_non_post)
                .delete(reject_non_post),
        )
        .route(
            "/a2a",
            post(handle_mcp)
                .get(reject_non_post)
                .put(reject_non_post)
                .delete(reject_non_post),
        )
        .route("/.well-known/agent.json", get(agent_card))
        .route("/health", get(health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind");

    info!("navil-proxy listening on 0.0.0.0:{} → {}", port, target_url);

    axum::serve(listener, app).await.expect("Server error");
}
