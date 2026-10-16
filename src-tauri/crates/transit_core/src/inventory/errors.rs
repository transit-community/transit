use std::path::PathBuf;

use thiserror::Error;

/// All ways `transit.toml` loading can fail. Every variant carries
/// enough context to surface a useful message to the user via the
/// frontend's parse-error banner.
#[derive(Error, Debug)]
pub enum InventoryError {
    #[error("inventory file too large: {size} bytes (max {max})")]
    TooLarge { size: u64, max: u64 },

    #[error("inventory file not found: {path}")]
    NotFound { path: PathBuf },

    #[error("symlink not allowed: {path} -> {target}")]
    SymlinkRejected { path: PathBuf, target: PathBuf },

    #[error(
        "inline secret-shaped value at {path}:{line}: matched pattern '{pattern}'. Move secrets to a backend; see transit.toml.example."
    )]
    InlineSecret {
        path: PathBuf,
        line: usize,
        pattern: String,
    },

    #[error("TOML parse error at {path}:{line}: {message}")]
    ParseFailed {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("device '{id}' references unknown auth profile '{auth}'")]
    UnknownAuth { id: String, auth: String },

    #[error("invalid device definition: {reason}")]
    InvalidDevice { reason: String },

    #[error("duplicate device id '{id}' (first at line {first}, again at line {second})")]
    DuplicateDevice {
        id: String,
        first: usize,
        second: usize,
    },

    #[error("invalid api session definition: {reason}")]
    InvalidApiSession { reason: String },

    #[error("duplicate api session id '{id}'")]
    DuplicateApiSession { id: String },

    #[error("api session id '{id}' is already in use")]
    ApiSessionIdConflict { id: String },

    #[error("api session '{id}' not found")]
    ApiSessionNotFound { id: String },

    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("device id '{id}' is already in use")]
    DeviceIdConflict { id: String },

    #[error("device '{id}' not found")]
    DeviceNotFound { id: String },

    #[error("auth profile '{name}' is already defined")]
    AuthProfileConflict { name: String },

    #[error("auth profile '{name}' not found")]
    AuthProfileNotFound { name: String },

    #[error(
        "auth profile '{name}' is still referenced by device(s): {}",
        devices.join(", ")
    )]
    AuthProfileInUse { name: String, devices: Vec<String> },

    #[error("device '{id}' references unknown jump host '{jump_via}'")]
    UnknownJumpHost { id: String, jump_via: String },

    #[error("jump-host cycle: {}", chain.join(" -> "))]
    JumpCycle { chain: Vec<String> },

    #[error(
        "jump-host chain starting at device '{}' exceeds the maximum depth of {max}: {}",
        chain.first().map(String::as_str).unwrap_or("?"),
        chain.join(" -> ")
    )]
    JumpChainTooDeep { chain: Vec<String>, max: usize },

    #[error(
        "device '{id}' is still used as a jump host by device(s): {}",
        devices.join(", ")
    )]
    JumpHostInUse { id: String, devices: Vec<String> },

    #[error("invalid group path '{path}': must be non-empty")]
    InvalidGroupPath { path: String },

    #[error(
        "top-level '{key}' uses an inline TOML form the in-app editor cannot modify. Rewrite it using the standard [[device]] / [auth.<name>] table syntax to enable in-app edits."
    )]
    UnsupportedTomlShape { key: String },
}
