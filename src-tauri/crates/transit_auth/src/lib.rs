//! The sole crate that reads or holds device credentials.
//!
//! Other crates consume an already-authenticated `Connection`; they
//! never receive a password, key, or token. The `transit_agent` crate
//! is explicitly forbidden from depending on this one (see workspace
//! `deny.toml` and the `transit-agent-firewall-test` skill).
//!
//! Public surface:
//! - [`SecretBackend`] trait — the contract every backend implements.
//! - [`SshAgentSession`] — connected agent client + selected
//!   identity, handed to transit_ssh for russh's
//!   `authenticate_publickey_with`.
//! - [`SecretRegistry`] — orchestrates backends, owns the 60s
//!   zeroizing in-memory cache, exposes per-backend availability.
//! - [`BackendError`] — typed errors with classifications the UI uses
//!   to surface actionable messages.
//!
//! Backends (priority order, declared in [`SecretRegistry::standard`]):
//!   1. `ssh_agent` (covers 1Password SSH Agent transparently)
//!   2. `op` (1Password CLI for non-key secrets)
//!   3. `keyring` (OS keystore)
//!   4. `env` (headless / CI fallback)
//!
//! `encrypted_file` (age-based) is deferred to Phase 2a.1.

mod agent;
mod availability;
mod backend;
mod backends;
mod cache;
mod error;
mod registry;

pub use agent::{open_agent_byte_stream, AgentByteStream, DynAgentClient, SshAgentSession};
pub use availability::BackendAvailability;
pub use backend::SecretBackend;
pub use backends::ssh_key::KeyProbeVerdict;
pub use error::BackendError;
pub use registry::SecretRegistry;
