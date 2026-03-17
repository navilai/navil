// Copyright (c) 2026 Pantheon Lab Pte Ltd
// Licensed under the Apache License, Version 2.0 (see LICENSE)

//! Telemetry module — Redis event emission.
//!
//! Emits telemetry events to the Redis queue for consumption by the
//! TelemetryWorker in the Python control plane.

use serde::Serialize;
use tracing::warn;

/// Redis key for the telemetry event queue.
pub const TELEMETRY_QUEUE: &str = "navil:telemetry:queue";

/// A telemetry event emitted for every tool call.
#[derive(Serialize)]
pub struct TelemetryEvent {
    pub agent_name: String,
    pub tool_name: String,
    pub method: String,
    pub action: String, // "FORWARDED", "BLOCKED_AUTH", "BLOCKED_RATE", etc.
    pub payload_bytes: usize,
    pub response_bytes: usize,
    pub duration_ms: u64,
    pub timestamp: String, // ISO 8601 via chrono
    pub target_server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_depth: Option<usize>,
}

/// Fire-and-forget: serialize event and LPUSH to Redis telemetry queue.
pub async fn publish_telemetry(redis_client: &redis::Client, event: TelemetryEvent) {
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

/// Generate an ISO 8601 UTC timestamp using chrono.
pub fn iso8601_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso8601_format() {
        let ts = iso8601_now();
        assert!(ts.contains('T'));
        assert!(ts.contains('+') || ts.contains('Z'));
    }

    #[test]
    fn test_telemetry_event_serialization() {
        let event = TelemetryEvent {
            agent_name: "test-agent".to_string(),
            tool_name: "run_command".to_string(),
            method: "tools/call".to_string(),
            action: "FORWARDED".to_string(),
            payload_bytes: 100,
            response_bytes: 200,
            duration_ms: 42,
            timestamp: iso8601_now(),
            target_server: "http://localhost:3000".to_string(),
            human_email: Some("alice@example.com".to_string()),
            delegation_depth: Some(2),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("test-agent"));
        assert!(json.contains("alice@example.com"));
        assert!(json.contains("\"delegation_depth\":2"));
    }

    #[test]
    fn test_telemetry_event_no_identity() {
        let event = TelemetryEvent {
            agent_name: "anonymous".to_string(),
            tool_name: "".to_string(),
            method: "tools/list".to_string(),
            action: "FORWARDED".to_string(),
            payload_bytes: 50,
            response_bytes: 1000,
            duration_ms: 10,
            timestamp: iso8601_now(),
            target_server: "http://localhost:3000".to_string(),
            human_email: None,
            delegation_depth: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        // human_email and delegation_depth should be absent (skip_serializing_if)
        assert!(!json.contains("human_email"));
        assert!(!json.contains("delegation_depth"));
    }
}
