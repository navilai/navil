//! Wrapper creation and management.
//!
//! Creates shell scripts in `~/.navil/bin/` that invoke `navil-shim` as the
//! wrapped tool. The real binary path is resolved via `which` and stored in
//! a metadata file so the shim knows where to forward.

use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

/// Resolve the real binary path for a tool, skipping ~/.navil/bin/ entries.
async fn resolve_real_binary(tool: &str, navil_bin: &Path) -> Result<PathBuf, String> {
    // Use `which -a` to find all matches, skip any in our bin dir
    let output = Command::new("which")
        .arg("-a")
        .arg(tool)
        .output()
        .await
        .map_err(|e| format!("failed to run `which`: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let navil_bin_str = navil_bin.to_string_lossy();

    for line in stdout.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        // Skip our own wrapper
        if path.starts_with(navil_bin_str.as_ref()) {
            continue;
        }
        return Ok(PathBuf::from(path));
    }

    Err(format!("'{}' not found in PATH (outside ~/.navil/bin/)", tool))
}

/// Create a wrapper script for the given tool.
pub async fn create_wrapper(tool: &str, navil_home: &Path) -> Result<PathBuf, String> {
    let bin_dir = navil_home.join("bin");
    let meta_dir = navil_home.join("meta");
    let logs_dir = navil_home.join("logs");

    // Ensure directories exist
    for dir in [&bin_dir, &meta_dir, &logs_dir] {
        fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("failed to create {}: {}", dir.display(), e))?;
    }

    // Resolve real binary
    let real_path = resolve_real_binary(tool, &bin_dir).await?;

    // Write metadata (real binary path)
    let meta_file = meta_dir.join(format!("{}.json", tool));
    let meta = serde_json::json!({
        "tool": tool,
        "real_path": real_path.to_string_lossy(),
        "wrapped_at": chrono::Utc::now().to_rfc3339(),
    });
    fs::write(&meta_file, serde_json::to_string_pretty(&meta).unwrap())
        .await
        .map_err(|e| format!("failed to write metadata: {}", e))?;

    // Find the navil-shim binary path (ourselves)
    let shim_binary = std::env::current_exe()
        .map_err(|e| format!("cannot resolve own binary path: {}", e))?;

    // Create wrapper shell script
    let wrapper_path = bin_dir.join(tool);
    let script = format!(
        "#!/bin/sh\nexec \"{}\" \"$@\"\n",
        shim_binary.display()
    );
    fs::write(&wrapper_path, &script)
        .await
        .map_err(|e| format!("failed to write wrapper: {}", e))?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&wrapper_path, perms)
            .map_err(|e| format!("failed to chmod: {}", e))?;
    }

    Ok(wrapper_path)
}

/// List all currently wrapped tools.
pub async fn list_wrappers(navil_home: &Path) -> Result<Vec<String>, String> {
    let meta_dir = navil_home.join("meta");
    if !meta_dir.exists() {
        return Ok(Vec::new());
    }

    let mut tools = Vec::new();
    let mut entries = fs::read_dir(&meta_dir)
        .await
        .map_err(|e| format!("failed to read meta dir: {}", e))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| format!("failed to read entry: {}", e))?
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Some(tool) = name_str.strip_suffix(".json") {
            tools.push(tool.to_string());
        }
    }

    tools.sort();
    Ok(tools)
}

/// Remove a wrapper for the given tool.
pub async fn remove_wrapper(tool: &str, navil_home: &Path) -> Result<(), String> {
    let wrapper_path = navil_home.join("bin").join(tool);
    let meta_path = navil_home.join("meta").join(format!("{}.json", tool));

    if wrapper_path.exists() {
        fs::remove_file(&wrapper_path)
            .await
            .map_err(|e| format!("failed to remove wrapper: {}", e))?;
    }

    if meta_path.exists() {
        fs::remove_file(&meta_path)
            .await
            .map_err(|e| format!("failed to remove metadata: {}", e))?;
    }

    Ok(())
}
