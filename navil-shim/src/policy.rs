//! Policy engine for CLI wrapping.
//!
//! Graduated approach: observability MVP always allows execution.
//! Future phases will add configurable rules.

/// Result of a policy check.
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// Check policy for a tool invocation.
///
/// MVP phase: always allow. This function exists as the extension point
/// for future graduated enforcement (warn -> audit -> block).
pub fn check_policy(_tool: &str, _args: &[String]) -> PolicyDecision {
    // Phase 1: Observability only -- always allow
    PolicyDecision {
        allowed: true,
        reason: None,
    }
}
