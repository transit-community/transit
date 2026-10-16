//! Error taxonomy for the Files surface.
//!
//! Every variant is written to be stringified straight into a UI toast —
//! the IPC layer (`transit_app::files`) does `map_err(|e| e.to_string())`
//! and nothing else. Never interpolate file *contents* here; paths are
//! the most detail an error carries (§6 logging policy).

use thiserror::Error;

/// Why a remote-supplied (or local) name was refused. The T43 boundary
/// (`crate::sanitize`) returns this; it is deliberately a small, `Copy`
/// enum so the corpus tests can compare exact reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    #[error("the name is empty")]
    Empty,
    #[error("`.` and `..` are not transferable entries")]
    DotSegment,
    #[error("the name contains a path separator")]
    Separator,
    #[error("the name contains a NUL or control character")]
    ControlChar,
    #[error("the name is reserved or unusable on Windows")]
    WindowsReserved,
}

#[derive(Debug, Error)]
pub enum FilesError {
    /// The SFTP handshake over an otherwise-open stream failed. Usually
    /// means the peer isn't speaking SFTP (a subsystem that started but
    /// isn't an SFTP server) or the stream died mid-INIT.
    #[error("could not start an SFTP session on this connection: {detail}")]
    Init { detail: String },

    /// A remote (SFTP) operation failed. `op` is the verb for the log
    /// line; `path` is the target; `detail` is the server's status text.
    #[error("remote {op} failed for {path}: {detail}")]
    Remote {
        op: &'static str,
        path: String,
        detail: String,
    },

    /// A local-filesystem operation failed.
    #[error("local {op} failed for {path}: {detail}")]
    Local {
        op: &'static str,
        path: String,
        detail: String,
    },

    /// The stream is gone (EOF / fatal transport error) — the pane shows
    /// its reconnect banner rather than a live browser over a dead
    /// socket (plan §4 "synthesize the closed signal").
    #[error("the file-transfer session is closed — reconnect to continue")]
    SessionClosed,

    /// A name failed the T43 validation boundary. The name is quoted
    /// (`{name:?}`) so control characters render escaped, never raw.
    #[error("refusing the name {name:?}: {source}")]
    UnsafeName {
        name: String,
        #[source]
        source: NameError,
    },

    /// A hard safety bound was hit (recursive delete / walk caps). Not a
    /// server error — Transit refuses to keep going.
    #[error("{what} exceeded Transit's safety limit of {limit}")]
    LimitExceeded { what: &'static str, limit: usize },

    /// The user cancelled the transfer.
    #[error("transfer cancelled")]
    Cancelled,

    /// A local path had no usable final component (e.g. `/`), so there
    /// is nothing to name the transferred item.
    #[error("{path} has no file name to transfer")]
    NoFileName { path: String },
}

impl FilesError {
    pub(crate) fn unsafe_name(name: impl Into<String>, source: NameError) -> Self {
        Self::UnsafeName {
            name: name.into(),
            source,
        }
    }
}
