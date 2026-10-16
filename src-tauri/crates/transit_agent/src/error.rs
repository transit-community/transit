//! Errors raised by the agent's tool dispatcher.
//!
//! These cross the LLM boundary (the model sees them as tool-call
//! errors), so messages MUST NOT include credential bytes, scrollback
//! content, or anything else from a device. Variants reference WHAT
//! went wrong, not WHAT the device contained.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    /// The session id from the model doesn't match an open session.
    /// Returned to the model so it can `list_open_sessions` and retry.
    #[error("session not found: {session_id}")]
    SessionNotFound { session_id: String },

    /// The proposed command failed the per-vendor policy gate
    /// (`transit_policy`). Includes the gate's deny reason — the
    /// reason is human-readable and intentionally credential-free
    /// (see `transit_policy::Decision`).
    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },

    /// Catch-all for dispatcher implementation failures. Real impls
    /// should map their own errors to a more specific variant where
    /// possible; this exists so trait users have a path for anything
    /// not modeled above.
    #[error("dispatcher error: {0}")]
    Dispatcher(String),

    /// The tool was correctly typed but its inputs were unacceptable
    /// to the dispatcher (e.g. `max_bytes` over the per-call cap). Distinct from
    /// serde-level validation, which fails at deserialization.
    #[error("invalid tool arguments: {0}")]
    InvalidArgument(String),

    /// Reserved for tools that aren't implemented in the current
    /// phase (e.g. Phase 5a returns this for ProposeCommand and
    /// AskUser when called against the production dispatcher —
    /// those land in Phase 6).
    #[error("tool not implemented in this build: {tool}")]
    NotImplemented { tool: &'static str },
}
