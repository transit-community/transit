//! Per-vendor command policy gate.
//!
//! Loads `policies/<vendor>.yaml`. Default-deny: if a command does not
//! match an `allowed` regex (and any pipe stages don't match the
//! per-stage allowlist), it is rejected. The agent's
//! `propose_command` tool routes through this gate AND the UI
//! approval modal — both, never either (CLAUDE.md §3, Rule 3).
//!
//! Public API:
//! - [`PolicyEngine::load_from_dir`] — construct from `policies/`.
//! - [`PolicyEngine::evaluate`] — adjudicate a command for a vendor.
//! - [`Decision`] — `Allow`, `AllowUnrestricted { warning }`, or
//!   `Deny { reason }`. Phase 8b added the unrestricted variant for
//!   generic Linux/Unix vendors; every match-on-Decision site must
//!   handle it.
//! - [`PolicyError`] — load-time errors only; evaluation is total.

mod canonicalize;
mod engine;
mod error;
mod loader;
mod pipe;

pub use engine::{
    Decision, DenyKind, LayeredLoad, PolicyEngine, PolicyMode, PolicySummary, Precedence,
    VendorPolicy,
};
pub use error::PolicyError;

#[cfg(test)]
pub use canonicalize::canonicalize as canonicalize_for_tests;
#[cfg(test)]
pub use pipe::split_pipe as split_pipe_for_tests;
