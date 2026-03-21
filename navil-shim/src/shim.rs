//! Shim execution: log -> policy check -> forward -> telemetry.
//!
//! Hot path target: < 10ms overhead per invocation.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use tokio::fs;
use tokio::process::Command;

use crate::policy;
use crate::telemetry;

/// Run as a shim for the given tool name.
/// Called when the binary is invoked via a wrapper symlink/script.
pub async fn run_as_shim(tool_name: &str, args: &[String], navil_home: &Path) -> ExitCode {
    let start = Instant::now();

    // 1. Resolve real binary path from metadata
    let meta_path = navil_home.join("meta").join(format!("{}.json", tool_name));
    let real_path = match read_real_path(&meta_path).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[navil] error resolving {}: {}", tool_name, e);
            // Fail-open: try to find it in PATH directly
            match which_fallback(tool_name, navil_home).await {
                Some(p) => p,
                None => {
                    eprintln!("[navil] '{}' not found", tool_name);
                    return ExitCode::from(127);
                }
            }
        }
    };

    // 2. Log invocation (non-blocking, fire-and-forget)
    let log_entry = telemetry::InvocationLog {
        tool: tool_name.to_string(),
        args: args.to_vec(),
        timestamp: chrono::Utc::now(),
        real_path: real_path.clone(),
    };
    let logs_dir = navil_home.join("logs");
    // Spawn log write as background task -- don't block execution
    let logs_dir_clone = logs_dir.clone();
    let log_entry_clone = log_entry.clone();
    tokio::spawn(async move {
        let _ = telemetry::write_invocation_log(&logs_dir_clone, &log_entry_clone).await;
    });

    // 3. Policy check (observability MVP: always allow)
    let decision = policy::check_policy(tool_name, args);
    if !decision.allowed {
        eprintln!(
            "[navil] BLOCKED: {} (reason: {})",
            tool_name,
            decision.reason.as_deref().unwrap_or("policy violation")
        );
        return ExitCode::from(77);
    }

    // 4. Forward to real binary
    let status = Command::new(&real_path)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await;

    let elapsed = start.elapsed();

    // 5. Telemetry (fire-and-forget)
    let exit_code = match &status {
        Ok(s) => s.code().unwrap_or(-1),
        Err(_) => -1,
    };

    tokio::spawn(async move {
        let _ = telemetry::write_completion_log(
            &logs_dir,
            tool_name,
            exit_code,
            elapsed,
        )
        .await;
    });

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("[navil] failed to execute {}: {}", real_path, e);
            ExitCode::from(126)
        }
    }
}

/// Read the real binary path from the metadata JSON file.
async fn read_real_path(meta_path: &Path) -> Result<String, String> {
    let content = fs::read_to_string(meta_path)
        .await
        .map_err(|e| format!("cannot read metadata: {}", e))?;

    let meta: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("invalid metadata JSON: {}", e))?;

    meta.get("real_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing 'real_path' in metadata".to_string())
}

/// Fallback: try to find the tool in PATH, skipping our bin dir.
async fn which_fallback(tool: &str, navil_home: &Path) -> Option<String> {
    let output = Command::new("which")
        .arg("-a")
        .arg(tool)
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let navil_bin = navil_home.join("bin");
    let navil_bin_str = navil_bin.to_string_lossy();

    for line in stdout.lines() {
        let path = line.trim();
        if !path.is_empty() && !path.starts_with(navil_bin_str.as_ref()) {
            return Some(path.to_string());
        }
    }
    None
}
