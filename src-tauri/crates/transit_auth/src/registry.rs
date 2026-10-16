use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use secrecy::{ExposeSecret, SecretString};
use tokio::time::interval;
use transit_core::inventory::SecretRef;

use crate::agent::SshAgentSession;
use crate::backends::env::EnvBackend;
use crate::backends::keyring::KeyringBackend;
use crate::backends::op::OpBackend;
use crate::backends::ssh_agent::SshAgentBackend;
use crate::backends::ssh_key::{KeyProbeVerdict, SshKeyBackend};
use crate::cache::{ZeroizingCache, DEFAULT_TTL};
use crate::{BackendAvailability, BackendError, SecretBackend};

/// How often the background sweep task evicts expired cache entries.
/// Lazy eviction on `get` is the primary mechanism; the sweep is
/// belt-and-suspenders for long-idle sessions where nothing reads from
/// the cache.
const CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// Orchestrates the four backends. Built once at startup via
/// [`SecretRegistry::standard`]; held in `AppState` and shared across
/// every Tauri command via `Arc`.
///
/// Routes `SecretRef` → first matching backend. Caches resolved values
/// for 60s to mitigate biometric-prompt fatigue.
///
/// Agent-style references (`SshAgent`) bypass the value cache entirely;
/// the agent itself owns key lifetime, and the [`SshAgentSession`]
/// returned by [`Self::open_ssh_agent_session`] is a transient
/// wire-protocol handle that closes when dropped.
pub struct SecretRegistry {
    /// Routed by `SecretRef` variant. First-supports wins.
    backends: Vec<Box<dyn SecretBackend>>,
    /// Concrete handle to the agent backend so we can call its
    /// [`SshAgentBackend::open_session`] method (not on the trait).
    ssh_agent: Arc<SshAgentBackend>,
    /// Concrete handle to the on-disk key backend so we can call its
    /// `load` method (not on the trait) from [`Self::load_ssh_key`].
    ssh_key: Arc<SshKeyBackend>,
    /// Per-backend startup-probe snapshot. Read by `availability()`
    /// without re-probing.
    snapshots: HashMap<String, BackendAvailability>,
    /// 60s zeroizing cache shared with the background sweep task.
    cache: Arc<ZeroizingCache<SecretRef>>,
}

impl SecretRegistry {
    /// Construct the production registry with all four backends.
    /// Each backend runs its own preflight inside `new()`; we capture
    /// the snapshot here for the `availability()` query.
    pub fn standard() -> Self {
        let keyring = KeyringBackend::new();
        let env = EnvBackend::new();
        let op = OpBackend::new();
        let ssh_agent = Arc::new(SshAgentBackend::new());
        let ssh_key = Arc::new(SshKeyBackend::new());

        let mut snapshots = HashMap::new();
        snapshots.insert("keyring".to_string(), keyring.availability());
        snapshots.insert("env".to_string(), env.availability());
        snapshots.insert("op".to_string(), op.availability());
        snapshots.insert("ssh_agent".to_string(), ssh_agent.availability());
        snapshots.insert("ssh_key".to_string(), ssh_key.availability());

        // Order matters for routing: first `supports(refp) == true`
        // wins. SshAgent / Op / Keyring / Env are all variant-disjoint
        // so the order is defensive rather than load-bearing.
        let backends: Vec<Box<dyn SecretBackend>> = vec![
            Box::new(SshAgentBackendShim(Arc::clone(&ssh_agent))),
            Box::new(SshKeyBackendShim(Arc::clone(&ssh_key))),
            Box::new(op),
            Box::new(keyring),
            Box::new(env),
        ];

        let cache = Arc::new(ZeroizingCache::new(DEFAULT_TTL));

        Self {
            backends,
            ssh_agent,
            ssh_key,
            snapshots,
            cache,
        }
    }

    /// Background sweep that evicts expired cache entries every
    /// [`CACHE_SWEEP_INTERVAL`]. Returns a future the caller spawns —
    /// transit_auth stays runtime-agnostic (no `tokio::spawn` here, no
    /// dep on tauri's async runtime), and `transit_app::lib::run` does
    /// the actual `tauri::async_runtime::spawn` from inside its setup
    /// callback where the runtime context is available.
    ///
    /// The future runs forever; cancellation happens when the caller
    /// drops the spawned task handle (typically at process exit).
    pub async fn run_cache_sweep_loop(&self) {
        let mut tick = interval(CACHE_SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            self.cache.evict_expired().await;
        }
    }

    /// Snapshot of per-backend startup-probe results. Frontend reads
    /// this via the `secret_backend_availability` IPC.
    pub fn availability(&self) -> HashMap<String, BackendAvailability> {
        self.snapshots.clone()
    }

    /// Resolve a value-style reference (keyring / op / env). Cache
    /// hits return immediately; misses route to the first backend
    /// that supports the variant and persist the result.
    pub async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        if let Some(hit) = self.cache.get(refp).await {
            return Ok(hit);
        }
        let backend = self.find_backend(refp)?;
        let value = backend.resolve_value(refp).await?;
        // Cache a clone — `SecretString::clone` is cheap (Arc inside).
        self.cache.put(refp.clone(), value.clone()).await;
        Ok(value)
    }

    /// Force a fresh round-trip through the backend, bypassing the
    /// cache. Used by the `test_secret_resolve` IPC: the user's intent
    /// is "tell me the live backend works *right now*", not "tell me
    /// what was cached 30s ago." We invalidate the cache entry first
    /// so the post-success cache reflects the just-resolved value.
    pub async fn resolve_value_uncached(
        &self,
        refp: &SecretRef,
    ) -> Result<SecretString, BackendError> {
        self.cache.invalidate(refp).await;
        let backend = self.find_backend(refp)?;
        let value = backend.resolve_value(refp).await?;
        self.cache.put(refp.clone(), value.clone()).await;
        Ok(value)
    }

    /// Open a live SSH agent session and select the identity matching
    /// the reference's `public_key_fingerprint` pin. Returns a
    /// [`SshAgentSession`] that transit_ssh hands to russh's
    /// `authenticate_publickey_with`.
    ///
    /// Errors are pre-classified — `Unavailable` if the agent isn't
    /// running, `ResolveFailed` if the pinned identity isn't loaded,
    /// `Unsupported` if the reference isn't a `SecretRef::SshAgent`.
    pub async fn open_ssh_agent_session(
        &self,
        refp: &SecretRef,
    ) -> Result<SshAgentSession, BackendError> {
        self.ssh_agent.open_session(refp).await
    }

    /// Load + decode the on-disk SSH private key referenced by `refp`,
    /// resolving its optional passphrase from a value backend
    /// (keyring/op/env) first. Returns a sign-ready russh [`PrivateKey`]
    /// that transit_ssh wraps for `authenticate_publickey` — the key
    /// never surfaces as a `SecretString` and never enters the value
    /// cache. Mirrors [`Self::open_ssh_agent_session`].
    pub async fn load_ssh_key(&self, refp: &SecretRef) -> Result<PrivateKey, BackendError> {
        let SecretRef::SshKey { path, passphrase } = refp else {
            return Err(BackendError::unsupported(
                "ssh_key",
                "load_ssh_key (wrong kind)",
            ));
        };
        // The optional passphrase MUST ride a value backend
        // (keyring/op/env) — never another key/agent (which can't
        // produce a passphrase string, and would invite nesting loops).
        let pass = match passphrase {
            Some(p) => {
                validate_passphrase_ref(p)?;
                Some(self.resolve_value(p).await?)
            }
            None => None,
        };
        // `expose_secret` only here, scope-bounded — the &str view does
        // not outlive this call. `load` reads + decodes in-process.
        self.ssh_key
            .load(path, pass.as_ref().map(|s| s.expose_secret()))
    }

    /// Read-only probe of an on-disk SSH key file for the import wizard:
    /// classify it as unencrypted / encrypted / unparseable / unreadable
    /// **without** returning any key bytes or file contents. Decodes with
    /// no passphrase (so it needs no passphrase round-trip) and delegates
    /// to the same `SshKeyBackend::load` path used at connect time.
    pub fn probe_ssh_key(&self, path: &Path) -> KeyProbeVerdict {
        self.ssh_key.probe(path)
    }

    /// Persist a new value via the appropriate backend. Used by the
    /// `enroll_secret` Tauri command.
    pub async fn enroll(&self, refp: &SecretRef, value: SecretString) -> Result<(), BackendError> {
        let backend = self.find_backend(refp)?;
        backend.enroll(refp, value).await?;
        // Don't cache the just-enrolled value — let the next resolve
        // round-trip through the backend so we know the persisted
        // value matches what we read back. Defensive against bugs in
        // backend.enroll that succeed but write the wrong bytes.
        self.cache.invalidate(refp).await;
        Ok(())
    }

    /// First backend whose `supports(refp)` returns true.
    fn find_backend(&self, refp: &SecretRef) -> Result<&dyn SecretBackend, BackendError> {
        self.backends
            .iter()
            .find(|b| b.supports(refp))
            .map(|b| b.as_ref())
            .ok_or_else(|| BackendError::ResolveFailed {
                detail: format!("no backend supports {refp:?}"),
            })
    }
}

impl Default for SecretRegistry {
    fn default() -> Self {
        Self::standard()
    }
}

/// Adapter that lets the routing list hold a shared `Arc<SshAgentBackend>`
/// alongside the boxed `dyn SecretBackend` trait. Forwarding-only.
struct SshAgentBackendShim(Arc<SshAgentBackend>);

#[async_trait::async_trait]
impl SecretBackend for SshAgentBackendShim {
    fn kind(&self) -> &'static str {
        SecretBackend::kind(&*self.0)
    }
    fn supports(&self, refp: &SecretRef) -> bool {
        SecretBackend::supports(&*self.0, refp)
    }
    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        SecretBackend::resolve_value(&*self.0, refp).await
    }
    async fn enroll(&self, refp: &SecretRef, value: SecretString) -> Result<(), BackendError> {
        SecretBackend::enroll(&*self.0, refp, value).await
    }
}

/// Adapter that lets the routing list hold a shared `Arc<SshKeyBackend>`
/// alongside the boxed `dyn SecretBackend`. Forwarding-only.
struct SshKeyBackendShim(Arc<SshKeyBackend>);

#[async_trait::async_trait]
impl SecretBackend for SshKeyBackendShim {
    fn kind(&self) -> &'static str {
        SecretBackend::kind(&*self.0)
    }
    fn supports(&self, refp: &SecretRef) -> bool {
        SecretBackend::supports(&*self.0, refp)
    }
    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        SecretBackend::resolve_value(&*self.0, refp).await
    }
    async fn enroll(&self, refp: &SecretRef, value: SecretString) -> Result<(), BackendError> {
        SecretBackend::enroll(&*self.0, refp, value).await
    }
}

/// An SSH key passphrase must come from a *value* backend. Reject a
/// passphrase whose backend is itself key/agent-shaped — it can't
/// produce a passphrase string, and it would invite nesting loops.
fn validate_passphrase_ref(p: &SecretRef) -> Result<(), BackendError> {
    match p {
        SecretRef::Keyring { .. } | SecretRef::Op { .. } | SecretRef::Env { .. } => Ok(()),
        SecretRef::SshKey { .. } | SecretRef::SshAgent { .. } | SecretRef::EncryptedFile { .. } => {
            Err(BackendError::ResolveFailed {
                detail: "an SSH key passphrase must come from a keyring, op, or env backend".into(),
            })
        }
        // `prompt` is an SSH-auth-level flow (RFC 4256 keyboard-interactive,
        // driven from the connect path); it cannot supply a key-decryption
        // passphrase, which `load_ssh_key` needs in-process before auth
        // begins. Refused explicitly rather than folded into the arm above
        // so the reason names the actual mismatch. Prompting for a key
        // passphrase would be a separate feature with its own UI seam.
        SecretRef::Prompt => Err(BackendError::ResolveFailed {
            detail: "an SSH key passphrase cannot use the interactive `prompt` backend; \
                     use keyring, op, or env"
                .into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A test backend that records every call and returns a canned
    /// value. Lets us assert routing + caching behaviors without
    /// touching real OS services.
    struct CountingBackend {
        kind: &'static str,
        match_variant: fn(&SecretRef) -> bool,
        resolve_calls: AtomicUsize,
        canned_value: String,
    }

    impl CountingBackend {
        fn new(
            kind: &'static str,
            match_variant: fn(&SecretRef) -> bool,
            canned_value: &str,
        ) -> Self {
            Self {
                kind,
                match_variant,
                resolve_calls: AtomicUsize::new(0),
                canned_value: canned_value.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl SecretBackend for CountingBackend {
        fn kind(&self) -> &'static str {
            self.kind
        }
        fn supports(&self, refp: &SecretRef) -> bool {
            (self.match_variant)(refp)
        }
        async fn resolve_value(&self, _refp: &SecretRef) -> Result<SecretString, BackendError> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from(self.canned_value.clone()))
        }
        async fn enroll(
            &self,
            _refp: &SecretRef,
            _value: SecretString,
        ) -> Result<(), BackendError> {
            Err(BackendError::unsupported(self.kind, "enroll"))
        }
    }

    /// Build a registry with a single test backend. The `ssh_agent`
    /// field is still populated (real backend) but irrelevant for
    /// these tests since the test backend matches `Env` refs.
    fn registry_with_backend(b: Box<dyn SecretBackend>) -> SecretRegistry {
        let cache = Arc::new(ZeroizingCache::new(Duration::from_secs(60)));
        SecretRegistry {
            backends: vec![b],
            ssh_agent: Arc::new(SshAgentBackend::new()),
            ssh_key: Arc::new(SshKeyBackend::new()),
            snapshots: HashMap::new(),
            cache,
        }
    }

    #[tokio::test]
    async fn cache_short_circuits_repeat_resolve() {
        let counter = Arc::new(CountingBackend::new(
            "test",
            |r| matches!(r, SecretRef::Env { .. }),
            "v1",
        ));
        // We need to share the counter for assertions; wrap behind
        // Box that just defers to the Arc.
        struct Wrapper(Arc<CountingBackend>);
        #[async_trait::async_trait]
        impl SecretBackend for Wrapper {
            fn kind(&self) -> &'static str {
                self.0.kind()
            }
            fn supports(&self, r: &SecretRef) -> bool {
                self.0.supports(r)
            }
            async fn resolve_value(&self, r: &SecretRef) -> Result<SecretString, BackendError> {
                self.0.resolve_value(r).await
            }
            async fn enroll(&self, r: &SecretRef, v: SecretString) -> Result<(), BackendError> {
                self.0.enroll(r, v).await
            }
        }

        let reg = registry_with_backend(Box::new(Wrapper(Arc::clone(&counter))));
        let refp = SecretRef::Env {
            var: "TRANSIT_TEST".into(),
        };

        let _ = reg.resolve_value(&refp).await.unwrap();
        let _ = reg.resolve_value(&refp).await.unwrap();
        let _ = reg.resolve_value(&refp).await.unwrap();

        assert_eq!(
            counter.resolve_calls.load(Ordering::SeqCst),
            1,
            "second + third resolves should hit the cache"
        );
    }

    #[tokio::test]
    async fn no_backend_for_variant_errors_resolve_failed() {
        // Empty backend list — no backend supports anything.
        let reg = SecretRegistry {
            backends: vec![],
            ssh_agent: Arc::new(SshAgentBackend::new()),
            ssh_key: Arc::new(SshKeyBackend::new()),
            snapshots: HashMap::new(),
            cache: Arc::new(ZeroizingCache::new(Duration::from_secs(60))),
        };
        let refp = SecretRef::Env { var: "X".into() };
        match reg.resolve_value(&refp).await {
            Err(BackendError::ResolveFailed { .. }) => {}
            other => panic!("expected ResolveFailed, got {other:?}"),
        }
    }
}
