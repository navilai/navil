//! navil-shim: CLI PATH-prefix shim for tool wrapping.
//!
//! `navil wrap` creates thin wrapper scripts at `~/.navil/bin/` for specified tools.
//! Each wrapper:
//!   1. Logs the invocation (tool, args, timestamp) to `~/.navil/logs/`
//!   2. Checks policy (placeholder for future graduated enforcement)
//!   3. Forwards to the real binary
//!   4. Logs telemetry (exit code, duration)
//!
//! Graduated approach: observability MVP first, enforcement later.

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod policy;
mod shim;
mod telemetry;
mod wrap;

fn navil_home() -> PathBuf {
    dirs::home_dir()
        .expect("HOME directory not found")
        .join(".navil")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    // If invoked as a shim wrapper (symlink name != "navil-shim")
    let binary_name = Path::new(&args[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if binary_name != "navil-shim" && binary_name != "navil" {
        // We're running as a shim for a wrapped tool
        return shim::run_as_shim(binary_name, &args[1..], &navil_home()).await;
    }

    // CLI mode: `navil-shim wrap <tool1> <tool2> ...`
    if args.len() < 2 {
        eprintln!("Usage: navil-shim wrap <tool1> [tool2 ...]");
        eprintln!("       navil-shim list");
        eprintln!("       navil-shim unwrap <tool1> [tool2 ...]");
        return ExitCode::from(1);
    }

    match args[1].as_str() {
        "wrap" => {
            if args.len() < 3 {
                eprintln!("Usage: navil-shim wrap <tool1> [tool2 ...]");
                return ExitCode::from(1);
            }
            let home = navil_home();
            for tool in &args[2..] {
                match wrap::create_wrapper(tool, &home).await {
                    Ok(path) => eprintln!("  \u{2713} wrapped: {} -> {}", tool, path.display()),
                    Err(e) => eprintln!("  \u{2717} failed to wrap {}: {}", tool, e),
                }
            }
            eprintln!("\nAdd ~/.navil/bin to the front of your PATH:");
            eprintln!("  export PATH=\"$HOME/.navil/bin:$PATH\"");
            ExitCode::SUCCESS
        }
        "list" => {
            let home = navil_home();
            match wrap::list_wrappers(&home).await {
                Ok(tools) => {
                    if tools.is_empty() {
                        eprintln!("No wrapped tools found.");
                    } else {
                        for tool in &tools {
                            eprintln!("  {}", tool);
                        }
                    }
                }
                Err(e) => eprintln!("Error listing wrappers: {}", e),
            }
            ExitCode::SUCCESS
        }
        "unwrap" => {
            if args.len() < 3 {
                eprintln!("Usage: navil-shim unwrap <tool1> [tool2 ...]");
                return ExitCode::from(1);
            }
            let home = navil_home();
            for tool in &args[2..] {
                match wrap::remove_wrapper(tool, &home).await {
                    Ok(()) => eprintln!("  \u{2713} unwrapped: {}", tool),
                    Err(e) => eprintln!("  \u{2717} failed to unwrap {}: {}", tool, e),
                }
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Usage: navil-shim wrap|list|unwrap");
            ExitCode::from(1)
        }
    }
}
