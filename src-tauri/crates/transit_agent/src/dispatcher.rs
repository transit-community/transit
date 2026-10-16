//! The agent's entry point: a single async trait that takes a
//! `ToolCall` and returns a `ToolResult`. Production implementations
//! live OUTSIDE this crate (`transit_app::commands::agent_dispatch`
//! per CLAUDE.md §8); test implementations live in
//! [`crate::testing::MockDispatcher`].
//!
//! Why a trait, not a concrete struct: the dispatcher has to call
//! into `transit_ssh` (for scrollback), `transit_policy` (for the
//! command gate), and Tauri (for the UI approval modal). All of those
//! live downstream of `transit_agent`. Pulling them in as deps would
//! either invert the dependency graph or make the agent crate
//! dependent on Tauri's runtime, both of which break the
//! architectural firewall (`transit_agent ↛ transit_auth` works
//! transitively only because the dep graph stays unidirectional).
//!
//! The trait keeps `transit_agent` framework-agnostic and lets the
//! integration crate compose it however it needs.

use async_trait::async_trait;

use crate::error::AgentError;
use crate::tools::{ToolCall, ToolResult};

#[async_trait]
pub trait ToolDispatcher: Send + Sync {
    /// Adjudicate a single tool call. Returning an `AgentError`
    /// surfaces back to the model as a tool-call failure; the
    /// model can retry, switch tools, or `ask_user`.
    ///
    /// Implementations MUST run scrollback through `RedactionFilter`
    /// before returning it from a `ReadScrollback` call. Failure to
    /// do so is a security regression — the redaction-boundary
    /// memory.
    async fn dispatch(&self, call: ToolCall) -> Result<ToolResult, AgentError>;
}
