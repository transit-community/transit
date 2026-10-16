//! Local OS shell (PTY) transport for the Terminal surface (v4.4.0).
//!
//! Companion to `transit_ssh` (remote shells) and `transit_console`
//! (serial cables): this crate spawns a **local** shell — zsh / bash /
//! pwsh / cmd — attached to a pseudo-terminal, and presents it through
//! the same [`transit_core::session::TerminalSession`] surface so the
//! Tauri layer treats it like any other terminal tab.
//!
//! # Human-only — the agent is structurally blind
//!
//! A local shell is a HUMAN productivity surface, classified exactly
//! like the button bar / broadcast bar: human input, never
//! policy-gated, never an agent tool. The agent CANNOT see or drive a
//! local shell — enforced structurally by NOT composing this transport
//! into the agent's `UnifiedScrollbackSource` / `UnifiedSessionExecutor`
//! (see the local terminal surface design notes (not included in this repository) and threat
//! model T42). Defense in depth: [`SessionMeta::vendor`] is always
//! [`transit_core::inventory::Vendor::LocalShell`], which ships with no
//! policy and default-denies if it were ever routed to the gate.
//!
//! # Concurrency (the divergence from `transit_console`)
//!
//! `portable-pty`'s reader/writer are BLOCKING `std::io`, so — unlike
//! the async `tokio_serial` split — the two background loops run on
//! dedicated OS threads:
//!
//! - **Reader thread** — blocking `read` from the PTY master into the
//!   shared [`transit_core::scrollback::ScrollbackRing`] + broadcast; on
//!   EOF it reaps the child for its exit code, then flips the
//!   level-triggered `closed` signal.
//! - **Control thread** — drains the command channel ([`Session`]'s
//!   internal `Data` / `Resize`) FIFO; a real PTY `resize`
//!   (`master.resize`) is the one operation `transit_console` has no
//!   analog for.
//!
//! Teardown kills the child (its blocking read then returns EOF) and
//! drops the command sender (ending the control loop).

mod error;
mod session;
mod types;

pub use error::LocalPtyError;
pub use session::{Session, SessionMeta, INPUT_CHANNEL_SIZE, OUTPUT_CHANNEL_SIZE};
pub use types::{OpenParams, DEFAULT_COLS, DEFAULT_ROWS};
