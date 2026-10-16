//! Analysis: conversations, TCP health, deterministic findings, and the
//! capture digest.
//!
//! This layer is what makes the assistant side of PCaps possible. The
//! model never receives packets — it receives what is computed here: a
//! digest that is O(1) in packet count, a conversation table that
//! collapses a million packets into a few thousand rows, and a findings
//! list produced by explicit rules rather than by inference.
//!
//! Computing rather than inferring matters twice over. It is exact and
//! reproducible, so two people asking the same question of the same
//! capture get the same answer; and it is free, so the expensive thing
//! (the model) spends its budget on judgement rather than on arithmetic
//! a `for` loop already did.

pub mod digest;
pub mod findings;
pub mod flow;

pub use digest::{render as render_digest, DigestOptions};
pub use findings::{evaluate as evaluate_findings, Finding, Severity};
pub use flow::{
    Flow, FlowKey, FlowTable, ANALYSIS_DUP_ACK, ANALYSIS_OUT_OF_ORDER, ANALYSIS_RESET,
    ANALYSIS_RETRANSMIT, ANALYSIS_ZERO_WINDOW, NO_FLOW,
};
