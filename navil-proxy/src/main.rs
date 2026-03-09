// Copyright (c) 2026 Pantheon Lab Limited
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Navil MCP Security Proxy — Rust Data Plane
//!
//! Hot-path reverse proxy for MCP JSON-RPC 2.0.
//! Reads pre-computed thresholds from Redis (written by the Python control plane)
//! and enforces payload limits, rate limits, and HMAC signature verification
//! before forwarding to the upstream MCP server.
//!
//! Architecture:
//!     Agent → POST /mcp → navil-proxy (Rust) → reqwest → MCP Server
//!                              ↓
//!                     Pre-execution:  HMAC verify, payload limit,
//!                                     Redis threshold + rate check
//!                     Post-execution: forward response as-is

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{error, info, warn};

// ── Constants (match Python proxy) ───────────────────────────────

const MAX_PAYLOAD_BYTES: usize = 5 * 1024 * 1024; // 5 MB
const MAX_JSON_DEPTH: usize = 10;

type HmacSha256 = Hmac<Sha256>;

// ── App State ────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    target_url: String,
    http_client: reqwest::Client,
    redis_client: redis::Client,
    hmac_secret: Option<Vec<u8>>,
}

// ── Redis Threshold Schema ───────────────────────────────────────
// Keys match the Python control plane:
//   navil:agent:{agent}:thresholds  → hash { max_payload_bytes, rate_limit_per_min, blocked }
//   navil:agent:{agent}:rate:{bucket} → integer counter (INCR, 120s TTL)

#[derive(Debug, Clone)]
struct AgentThresholds {
    max_payload_bytes: usize,
    rate_limit_per_min: u64,
    blocked: bool,
}

impl Default for AgentThresholds {
    fn default() -> Self {
        Self {
            max_payload_bytes: 10_000_000, // 10 MB
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

/// Check JSON nesting depth. Returns Err if depth exceeds limit.
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

/// Sanitize request bytes: size limit, JSON parse+compact, depth limit.
/// Returns the parsed JSON value and compacted bytes on success.
fn sanitize_request(body: &[u8]) -> Result<(serde_json::Value, Vec<u8>), (i32, String)> {
    // Byte limit
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

    // Parse
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| (-32700, format!("Invalid JSON: {e}")))?;

    // Depth check
    check_json_depth(&value, 1, MAX_JSON_DEPTH).map_err(|msg| (-32700, msg))?;

    // Re-serialize compact (strips whitespace padding)
    let compact = serde_json::to_vec(&value)
        .map_err(|e| (-32700, format!("JSON re-serialize failed: {e}")))?;

    Ok((value, compact))
}

// ── HMAC Verification ────────────────────────────────────────────

fn verify_hmac(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);

    // Signature is hex-encoded
    let expected = match hex_decode(signature) {
        Some(bytes) => bytes,
        None => return false,
    };

    mac.verify_slice(&expected).is_ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("sha256=").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
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
            // Fail-open: use defaults on Redis error
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
    let bucket = now / 60; // minute bucket
    let key = format!("navil:agent:{}:rate:{}", agent, bucket);

    // INCR + EXPIRE via pipeline
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
            // Fail-open: allow on Redis error
            warn!("Redis rate limit check failed for {}: {}", agent, e);
            Ok(())
        }
    }
}

// ── Telemetry Event ──────────────────────────────────────────────

const TELEMETRY_QUEUE: &str = "navil:telemetry:queue";

#[derive(Serialize)]
struct TelemetryEvent {
    agent_name: String,
    tool_name: String,
    method: String,
    action: String, // "FORWARDED", "BLOCKED_THRESHOLD", "BLOCKED_RATE", etc.
    payload_bytes: usize,
    response_bytes: usize,
    duration_ms: u64,
    timestamp: String, // ISO 8601
    target_server: String,
}

/// Fire-and-forget: serialize event and LPUSH to Redis telemetry queue.
async fn publish_telemetry(redis_client: &redis::Client, event: TelemetryEvent) {
    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize telemetry event: {}", e);
            return;
        }
    };
    match redis_client.get_multiplexed_async_connection().await {
        Ok(mut conn) => {
            let result: Result<(), _> = redis::cmd("LPUSH")
                .arg(TELEMETRY_QUEUE)
                .arg(&json)
                .query_async(&mut conn)
                .await;
            if let Err(e) = result {
                warn!("Failed to LPUSH telemetry: {}", e);
            }
        }
        Err(e) => {
            warn!("Redis connection failed for telemetry: {}", e);
        }
    }
}

// ── Extract agent identity ───────────────────────────────────────

fn extract_agent_name(headers: &HeaderMap) -> Option<String> {
    // Check X-Agent-Name header first
    if let Some(name) = headers.get("x-agent-name") {
        return name.to_str().ok().map(String::from);
    }
    None
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

    // Extract tool_name from params if available
    let tool_name = rpc
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();

    // 3. Extract agent identity
    let agent_name = extract_agent_name(&headers).unwrap_or_else(|| "anonymous".to_string());
    let payload_bytes = compact_body.len();

    // 4. HMAC signature verification (if configured)
    if let Some(ref secret) = state.hmac_secret {
        if let Some(sig) = headers.get("x-navil-signature") {
            let sig_str = sig.to_str().unwrap_or("");
            if !verify_hmac(secret, &compact_body, sig_str) {
                return (
                    StatusCode::UNAUTHORIZED,
                    jsonrpc_error(-32003, "Invalid HMAC signature", req_id),
                )
                    .into_response();
            }
        } else {
            return (
                StatusCode::UNAUTHORIZED,
                jsonrpc_error(-32003, "Missing HMAC signature", req_id),
            )
                .into_response();
        }
    }

    // 5. For tools/call: Redis threshold + rate check
    if method == "tools/call" {
        // Get Redis connection (fail-open on error)
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
                // Threshold check
                let thresholds = get_thresholds(conn, &agent_name).await;

                if thresholds.blocked {
                    return Err((-32002, "BLOCKED_AGENT".to_string()));
                }

                if compact_body.len() > thresholds.max_payload_bytes {
                    return Err((-32002, "BLOCKED_THRESHOLD".to_string()));
                }

                // Rate limit check
                if let Err(_msg) =
                    check_rate_limit(conn, &agent_name, thresholds.rate_limit_per_min).await
                {
                    return Err((-32002, "BLOCKED_RATE".to_string()));
                }
            }
            // Fail-open: if no Redis connection, allow through
            Ok(())
        }
        .await;

        if let Err((_code, action)) = redis_check {
            let duration_ms = start.elapsed().as_millis() as u64;

            // Emit telemetry for blocked request
            let tele_state = state.clone();
            let tele_agent = agent_name.clone();
            let tele_tool = tool_name.clone();
            let tele_method = method.clone();
            let tele_action = action.clone();
            let tele_target = state.target_url.clone();
            tokio::spawn(async move {
                let ts = chrono_iso8601_now();
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
                        timestamp: ts,
                        target_server: tele_target,
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

    // 6. Forward to upstream MCP server
    let mut forward_headers = reqwest::header::HeaderMap::new();
    forward_headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    forward_headers.insert(
        reqwest::header::ACCEPT,
        "application/json, text/event-stream".parse().unwrap(),
    );
    // Forward x-agent-name
    if let Some(name) = headers.get("x-agent-name") {
        if let Ok(val) = reqwest::header::HeaderValue::from_bytes(name.as_bytes()) {
            forward_headers.insert("x-agent-name", val);
        }
    }

    let upstream_resp = match state
        .http_client
        .post(&state.target_url)
        .headers(forward_headers)
        .body(compact_body)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Upstream request failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                jsonrpc_error(-32603, format!("Upstream error: {e}"), req_id),
            )
                .into_response();
        }
    };

    // 7. Return upstream response
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read upstream response: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                jsonrpc_error(-32603, format!("Upstream read error: {e}"), req_id),
            )
                .into_response();
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let response_bytes = resp_body.len();

    // 8. Emit telemetry for forwarded request (background)
    {
        let tele_state = state.clone();
        let tele_agent = agent_name.clone();
        let tele_tool = tool_name.clone();
        let tele_method = method.clone();
        let tele_target = state.target_url.clone();
        tokio::spawn(async move {
            let ts = chrono_iso8601_now();
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
                    timestamp: ts,
                    target_server: tele_target,
                },
            )
            .await;
        });
    }

    // Build response with selected upstream headers (e.g. mcp-session-id)
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    if let Some(session_id) = resp_headers.get("mcp-session-id") {
        if let Ok(val) = axum::http::HeaderValue::from_bytes(session_id.as_bytes()) {
            response_headers.insert("mcp-session-id", val);
        }
    }

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        response_headers,
        resp_body,
    )
        .into_response()
}

/// Generate an ISO 8601 timestamp (no chrono crate needed).
fn chrono_iso8601_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    // Calculate from epoch seconds
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to date (simplified Gregorian)
    let mut y = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let year_days = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        y += 1;
    }
    let leap = is_leap_year(y);
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }
    let d = remaining_days + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        d,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "navil-proxy-rust",
        "version": env!("CARGO_PKG_VERSION"),
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
    });

    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .route("/health", get(health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("Failed to bind");

    info!("navil-proxy listening on 0.0.0.0:{} → {}", port, target_url);

    axum::serve(listener, app).await.expect("Server error");
}
