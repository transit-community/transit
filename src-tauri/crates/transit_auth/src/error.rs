use thiserror::Error;

/// Errors a [`SecretBackend`] (or the registry orchestrating it) can
/// surface. Variants are designed to be stringified into actionable
/// messages by the UI — pick a variant for each failure shape the user
/// can reasonably do something about.
///
/// [`SecretBackend`]: crate::SecretBackend
#[derive(Error, Debug)]
pub enum BackendError {
    /// The operation isn't applicable to this backend (e.g. enrolling
    /// into `ssh_agent`, or fetching a value from a sign-only backend).
    #[error("backend '{backend}' does not support {operation}")]
    Unsupported {
        backend: &'static str,
        operation: &'static str,
    },

    /// The backend exists but is unavailable on this system right now —
    /// e.g. Linux Secret Service not running, `op` CLI not in PATH.
    /// `hint` is the install / setup instruction the UI surfaces.
    #[error("backend '{backend}' unavailable: {hint}")]
    Unavailable { backend: &'static str, hint: String },

    /// The reference resolved against a backend, but the backend has no
    /// entry under that key (keyring lookup miss; missing env var).
    #[error("no entry for {kind} reference")]
    NotFound { kind: &'static str },

    /// `op` CLI is present and signed in but lacks access to the
    /// referenced vault, or the user is signed out and the CLI returned
    /// an auth error. UI shows a "Run `op signin` and try again"
    /// message.
    #[error("op CLI error: {detail}")]
    OpAuth { detail: String },

    /// Generic backend-side resolve failure (network, IPC, decoding).
    /// Distinct from `NotFound` so the UI can render "transient — try
    /// again" vs "the entry doesn't exist".
    #[error("resolve failed: {detail}")]
    ResolveFailed { detail: String },

    /// Generic backend-side enroll failure. Same separation rationale.
    #[error("enroll failed: {detail}")]
    EnrollFailed { detail: String },

    /// The SSH key file couldn't be read (missing, unreadable, or not
    /// UTF-8 text). `detail` carries the path + OS error — NEVER the
    /// file contents.
    #[error("ssh key file error: {detail}")]
    KeyFile { detail: String },

    /// The SSH key is passphrase-protected but the auth profile carries
    /// no passphrase reference. The user adds one (enrolled to the
    /// keychain) to connect.
    #[error("this SSH key is passphrase-protected — add its passphrase to the auth profile")]
    KeyNeedsPassphrase,

    /// A passphrase was supplied but the key did not decrypt — almost
    /// always a wrong passphrase.
    #[error("wrong passphrase for the SSH key")]
    KeyWrongPassphrase,

    /// The file isn't a private key we can parse. `detail` carries an
    /// actionable hint (e.g. the `puttygen` conversion command for an
    /// unparseable PuTTY `.ppk`) — NEVER the file contents.
    #[error("could not parse the SSH key: {detail}")]
    KeyUnparseable { detail: String },
}

impl BackendError {
    /// Convenience for `Unsupported` with the calling backend's name.
    /// Wired up by the per-backend impls landing in Tasks #48-#50.
    #[allow(dead_code)]
    pub(crate) fn unsupported(backend: &'static str, operation: &'static str) -> Self {
        Self::Unsupported { backend, operation }
    }
}
