//! Transit core: shared types, parsing, and utilities.
//!
//! No Tauri, no async runtime. Other crates depend on this; it depends on
//! nothing in the workspace.

pub mod diff;
pub mod export;
pub mod import;
pub mod inventory;
pub mod log;
pub mod scrollback;
pub mod session;
