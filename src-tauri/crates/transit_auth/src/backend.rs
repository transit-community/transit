use async_trait::async_trait;
use secrecy::SecretString;
use transit_core::inventory::SecretRef;

use crate::BackendError;

/// Contract every secret backend implements.
///
/// Two operations: **value resolution** (passwords, API keys) and
/// **enrollment** (writing a new value, when the backend supports
/// in-app writes). Agent-style backends (`ssh_agent`) live outside
/// this trait — their session/sign flow uses the concrete
/// [`crate::SshAgentSession`] type, since russh's auth flow needs a
/// live wire-protocol client, not a value-returning method.
///
/// Backends are expected to be cheap to construct; expensive setup
/// (probing the keyring, looking up `op`) is the registry's job at
/// startup, exposed via [`crate::BackendAvailability`].
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Stable identifier used in errors and as the
    /// `BackendAvailability` map key. `"keyring"`, `"ssh_agent"`,
    /// `"op"`, `"env"`.
    fn kind(&self) -> &'static str;

    /// Whether this backend handles the given reference. A
    /// [`SecretRegistry`] uses this to route — the first backend whose
    /// `supports` returns true wins.
    ///
    /// [`SecretRegistry`]: crate::SecretRegistry
    fn supports(&self, refp: &SecretRef) -> bool;

    /// Fetch the credential as bytes, wrapped so the caller can't
    /// accidentally log it. Used by password-style auth and (later)
    /// provider-key fetches. Sign-only backends (`ssh_agent`) return
    /// [`BackendError::Unsupported`].
    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError>;

    /// Persist a new value. Used by the `enroll_secret` Tauri command.
    /// Backends that can't enroll (the user supplies the value out of
    /// band — `ssh_agent` via the agent, `op` via 1Password, `env` via
    /// the shell) return [`BackendError::Unsupported`].
    async fn enroll(&self, refp: &SecretRef, value: SecretString) -> Result<(), BackendError>;
}
