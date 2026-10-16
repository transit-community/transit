//! `keyring` backend — OS keystore (macOS Keychain / Windows Credential
//! Manager / Linux Secret Service via libsecret).
//!
//! Uses the `keyring` crate v3 to abstract per-platform APIs. We
//! commit to a single service name (`SERVICE`) so all Transit
//! credentials live under one Keychain "kind" and are easy to find /
//! audit. The account name is the user-supplied lookup key from
//! `SecretRef::Keyring { key }`.
//!
//! Linux Secret Service is the fragile platform: requires
//! `gnome-keyring-daemon` or KWallet's compatibility shim. We probe
//! at construct time with a sentinel write+delete so the registry
//! reports `BackendAvailability::NeedsInstall` with an actionable
//! hint instead of failing later at resolve time.

use async_trait::async_trait;
use keyring::Entry;
use secrecy::SecretString;
use transit_core::inventory::SecretRef;

use crate::{BackendAvailability, BackendError, SecretBackend};

/// All Transit keyring entries live under this service name. Visible
/// in macOS Keychain Access.app as the "Where" / "Service" column.
const SERVICE: &str = "transit";
const KIND: &str = "keyring";

/// Probe key written + deleted at construct time to verify the
/// underlying keystore is reachable. Namespaced with PID + nanosecond
/// timestamp so concurrent registry constructions (e.g. parallel
/// integration tests in the same binary) don't collide on the same
/// sentinel account name.
fn probe_account() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("__transit_keyring_probe_{}_{}", std::process::id(), nanos)
}

pub(crate) struct KeyringBackend {
    availability: BackendAvailability,
}

impl KeyringBackend {
    pub(crate) fn new() -> Self {
        Self {
            availability: probe_keyring(),
        }
    }

    pub(crate) fn availability(&self) -> BackendAvailability {
        self.availability.clone()
    }
}

/// Run a write+read+delete probe to detect whether the OS keystore
/// is reachable. On Linux without a running Secret Service daemon
/// this fails; we map the error to a Linux-specific install hint.
fn probe_keyring() -> BackendAvailability {
    let account = probe_account();
    let entry = match Entry::new(SERVICE, &account) {
        Ok(e) => e,
        Err(e) => return needs_install_hint(&e),
    };
    // Defensive: if a previous probe (or a stale entry from a crashed
    // run with the same nanosecond — astronomically unlikely but let's
    // be tidy) is around, clean it up before our write. Ignored here;
    // a real "can't talk to keystore" failure surfaces below.
    let _ = entry.delete_credential();

    if let Err(e) = entry.set_password("transit-keyring-probe") {
        return needs_install_hint(&e);
    }
    // Read it back as a sanity check.
    if let Err(e) = entry.get_password() {
        return needs_install_hint(&e);
    }
    // Best-effort cleanup — failure to delete the probe is harmless.
    let _ = entry.delete_credential();
    BackendAvailability::Ready
}

fn needs_install_hint(err: &keyring::Error) -> BackendAvailability {
    let hint = if cfg!(target_os = "linux") {
        format!(
            "OS keychain unavailable — install gnome-keyring \
             (Debian/Ubuntu: `sudo apt install gnome-keyring`) and ensure \
             the daemon is running. Underlying error: {err}"
        )
    } else if cfg!(target_os = "windows") {
        format!("Windows Credential Manager unavailable: {err}")
    } else if cfg!(target_os = "macos") {
        format!("macOS Keychain unavailable: {err}")
    } else {
        format!("OS keychain unavailable: {err}")
    };
    BackendAvailability::NeedsInstall { hint }
}

#[async_trait]
impl SecretBackend for KeyringBackend {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn supports(&self, refp: &SecretRef) -> bool {
        matches!(refp, SecretRef::Keyring { .. })
    }

    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        let SecretRef::Keyring { key } = refp else {
            return Err(BackendError::unsupported(
                KIND,
                "resolve_value (wrong kind)",
            ));
        };
        if let BackendAvailability::NeedsInstall { hint } = &self.availability {
            return Err(BackendError::Unavailable {
                backend: KIND,
                hint: hint.clone(),
            });
        }
        // The `keyring` crate is sync; the lookup is fast on every
        // platform we ship to. Spawn-blocking would be defensible but
        // adds latency. Keep it inline for now; revisit if profiling
        // shows hot-path stalls.
        let entry = Entry::new(SERVICE, key).map_err(|e| BackendError::ResolveFailed {
            detail: e.to_string(),
        })?;
        match entry.get_password() {
            Ok(pw) => Ok(SecretString::from(pw)),
            Err(keyring::Error::NoEntry) => Err(BackendError::NotFound { kind: KIND }),
            Err(e) => Err(BackendError::ResolveFailed {
                detail: e.to_string(),
            }),
        }
    }

    async fn enroll(&self, refp: &SecretRef, value: SecretString) -> Result<(), BackendError> {
        let SecretRef::Keyring { key } = refp else {
            return Err(BackendError::unsupported(KIND, "enroll (wrong kind)"));
        };
        if let BackendAvailability::NeedsInstall { hint } = &self.availability {
            return Err(BackendError::Unavailable {
                backend: KIND,
                hint: hint.clone(),
            });
        }
        let entry = Entry::new(SERVICE, key).map_err(|e| BackendError::EnrollFailed {
            detail: e.to_string(),
        })?;
        // `set_password` is upsert on every supported OS — clean for
        // both initial enrollment and rotation.
        use secrecy::ExposeSecret;
        entry
            .set_password(value.expose_secret())
            .map_err(|e| BackendError::EnrollFailed {
                detail: e.to_string(),
            })?;
        Ok(())
    }
}
