use serde::Serialize;

/// Per-backend startup-probe result. The frontend reads a snapshot of
/// these via the `secret_backend_availability` IPC and renders an
/// install-instruction banner under the backend select when the user
/// picks a backend that's [`BackendAvailability::NeedsInstall`].
///
/// We snapshot at startup rather than re-probing on every dialog open
/// because:
///   - Probes shell out (`op`) or hit DBus (`keyring` on Linux), and
///     we don't want flicker / races on every render.
///   - The stuff we're checking (CLI installed, daemon running)
///     doesn't change mid-session in any realistic flow. If the user
///     installs `op` mid-session, they restart Transit — that's fine.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum BackendAvailability {
    /// Probe succeeded. UI renders nothing extra.
    Ready,
    /// Backend is theoretically supported on this platform but the
    /// dependency it needs is missing or mis-configured. `hint` is
    /// the actionable message the UI surfaces verbatim.
    NeedsInstall { hint: String },
    /// Backend isn't applicable on this platform at all (no analog of
    /// `keyring` here, etc.). Rare today; reserved for future fallback
    /// backends.
    Unsupported,
}
