//! `ScrollbackRing` — re-exported from `transit_core::scrollback`.
//!
//! Lifted in Phase 7b C15 so `transit_console` can share the same
//! buffer type without depending on `transit_ssh`. This module exists
//! only for source compatibility — existing imports of
//! `transit_ssh::scrollback::ScrollbackRing` keep working unchanged.

pub use transit_core::scrollback::{ScrollbackRing, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES};
