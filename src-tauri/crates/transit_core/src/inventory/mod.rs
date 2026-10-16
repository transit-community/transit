//! Inventory file (`transit.toml`) types, errors, and loader.
//!
//! The inventory file holds device metadata + **references** to where
//! credentials live. It NEVER contains a password, key, passphrase, or
//! token. The loader rejects any inline secret-shaped value with a
//! parse error pointing at `file:line`.
//!
//! The secret-pattern catalog here is best-effort and focused on the
//! obvious top-of-file inline values. The comprehensive catalog used to
//! filter scrollback before it reaches the LLM lives in
//! `transit_agent::redaction` (Phase 5a).

mod errors;
pub mod loader;
pub mod mutator;
mod types;

pub use errors::InventoryError;
pub use loader::{load, MAX_JUMP_CHAIN};
pub use types::{
    ApiEndpointKind, ApiSession, AuthProfile, AuthScheme, Device, InventoryFile, SecretRef, Vendor,
};
