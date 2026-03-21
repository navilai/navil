//! Telemetry logging for shim invocations.
//!
//! Writes JSONL to `~/.navil/logs/YYYY-MM-DD.jsonl`.
//! Non-blocking, fire-and-forget. Failures are silently ignored
//! to never impact the wrapped tool's execution.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Serialize)]
pub struct InvocationLog {
    pub tool: String,
    pub args: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub real_path: String,
}

#[derive(Serialize)]
struct CompletionLog {
    tool: String,
    exit_code: i32,
    duration_ms: u64,
    timestamp: String,
}

/// Write an invocation log entry.
pub async fn write_invocation_log(logs_dir: &Path, entry: &InvocationLog) -> Result<(), String> {
    fs::create_dir_all(logs_dir)
        .await
        .map_err(|e| format!("create logs dir: {}", e))?;

    let date = entry.timestamp.format("%Y-%m-%d").to_string();
    let log_path = logs_dir.join(format!("{}.jsonl", date));

    let mut line = serde_json::to_string(&serde_json::json!({
        "type": "invocation",
        "tool": entry.tool,
        "args": entry.args,
        "real_path": entry.real_path,
        "timestamp": entry.timestamp.to_rfc3339(),
    }))
    .map_err(|e| format!("serialize: {}", e))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
        .map_err(|e| format!("open log file: {}", e))?;

    file.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write log: {}", e))?;

    Ok(())
}

/// Write a completion log entry.
pub async fn write_completion_log(
    logs_dir: &Path,
    tool: &str,
    exit_code: i32,
    duration: Duration,
) -> Result<(), String> {
    let now = Utc::now();
    let date = now.format("%Y-%m-%d").to_string();
    let log_path = logs_dir.join(format!("{}.jsonl", date));

    let entry = CompletionLog {
        tool: tool.to_string(),
        exit_code,
        duration_ms: duration.as_millis() as u64,
        timestamp: now.to_rfc3339(),
    };

    let mut line = serde_json::to_string(&serde_json::json!({
        "type": "completion",
        "tool": entry.tool,
        "exit_code": entry.exit_code,
        "duration_ms": entry.duration_ms,
        "timestamp": entry.timestamp,
    }))
    .map_err(|e| format!("serialize: {}", e))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
        .map_err(|e| format!("open log file: {}", e))?;

    file.write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write log: {}", e))?;

    Ok(())
}
