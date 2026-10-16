//! russh-based PTY transport. Owns `Connection`, `Session`,
//! `ScrollbackRing`, and `HostKeyStore` types.
//!
//! The workspace lints set `unsafe_code = "deny"` (deny, not forbid
//! — deny is overridable at item level with a documented rationale).
//! This crate's single opt-out is `connection::AssumeSendFuture`:
//! two item-scoped `#[allow(unsafe_code)]`s working around a rustc
//! higher-ranked-lifetime inference limitation, with the soundness
//! premise (`russh::client::Handle` et al are `Send + Sync`)
//! machine-checked by a `const` assertion beside the `unsafe impl`.
//! There is no crate-level allow.
//!
//! Authenticates via [`transit_auth::SecretRegistry`]; the rest of the
//! workspace consumes an already-authenticated `Connection`. Cipher /
//! KEX / MAC algorithms are restricted to a strict modern allowlist
//! (no CBC, no SHA1, no MD5, no `none` auth) — connection refused
//! when the server only offers weak crypto.
//!
//! Host-key handling is TOFU: first connect surfaces the SHA256
//! fingerprint to the user via a Tauri event + dialog; subsequent
//! connects compare against `~/.config/TransitCommunity/known_hosts.toml`.
//! Mismatch is a hard error with no in-app override (defense against
//! social-engineering "just trust it" pressure).

mod agent_forward;
mod ciphers;
mod connection;
mod error;
mod host_key;
mod scrollback;
mod session;

pub use ciphers::{client_config, host_key_algos, CIPHERS, KEX, MACS};
pub use connection::{
    ConnectParams, Connection, HostKeyConfirmRequest, KbiPrompt, KbiPromptRequest, CONNECT_TIMEOUT,
};
pub use error::SshError;
pub use host_key::{Fingerprint, FingerprintParseError, HostKeyStore, PinMatch, PinTier};
/// Re-exported because [`HostKeyStore::insert`] and
/// [`HostKeyStore::replace`] take one: without this a caller outside this
/// crate cannot name the type its own public API demands.
pub use russh::keys::ssh_key::Algorithm as HostKeyAlgorithm;
pub use scrollback::{ScrollbackRing, DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES};
pub use session::{
    Session, SessionMeta, INPUT_CHANNEL_SIZE, OUTPUT_CHANNEL_SIZE, SESSION_OPEN_TIMEOUT,
};
