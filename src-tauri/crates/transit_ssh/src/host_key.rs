//! `HostKeyStore` — TOFU persistence at
//! `~/.config/TransitCommunity/known_hosts.toml`. `Fingerprint` —
//! constant-time comparable SHA256 wrapper around 32 raw bytes.
//!
//! TOFU contract:
//!
//! 1. Caller computes the server's fingerprint, calls [`HostKeyStore::lookup`].
//! 2. `Some(known)` → caller compares with what the server presented;
//!    match means proceed. Mismatch surfaces the changed-key WARNING
//!    dialog (both fingerprints, explicit verify-and-replace); on
//!    Replace the caller calls [`HostKeyStore::replace`] AFTER auth
//!    succeeds, on decline the connect fails with
//!    [`SshError::HostKeyMismatch`].
//! 3. `None` → caller surfaces the user TOFU dialog. On Trust, caller
//!    calls [`HostKeyStore::insert`] (also post-auth).
//!
//! `insert` errors when an entry already exists for `(host, port)`;
//! `replace` is the explicit rotation path and is only reachable with
//! a user verdict from the changed-key warning dialog in hand. (The
//! original design had no in-app rotation at all — users hand-deleted
//! the entry — but that pushed them into a blind file edit with no
//! fingerprint comparison in view; the warning dialog keeps both
//! fingerprints in front of the user. Threat model T11.)

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::{Algorithm, Fingerprint as SshKeyFingerprint, HashAlg};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::error::SshError;

// ---------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------

/// SHA256 fingerprint of an SSH host key. Wraps the raw 32-byte
/// digest. Equality is constant-time.
#[derive(Clone)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute a SHA256 fingerprint from a public-key blob.
    pub fn sha256(key: &KeyData) -> Self {
        let upstream = SshKeyFingerprint::new(HashAlg::Sha256, key);
        let bytes = upstream
            .sha256()
            .expect("SshKeyFingerprint::new(Sha256, _) always returns Sha256 variant");
        Self(bytes)
    }

    /// Construct from raw bytes. Test-only — production callers
    /// derive via [`Self::sha256`] or parse from a string.
    #[cfg(test)]
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Fingerprint {}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reuse upstream's `SHA256:<base64-no-pad>` rendering.
        SshKeyFingerprint::Sha256(self.0).fmt(f)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FingerprintParseError {
    #[error("invalid SSH fingerprint: expected 'SHA256:<base64>'")]
    Invalid,
    #[error("only SHA256 fingerprints are supported (got {0})")]
    WrongAlgorithm(&'static str),
}

impl FromStr for Fingerprint {
    type Err = FingerprintParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upstream: SshKeyFingerprint = s.parse().map_err(|_| FingerprintParseError::Invalid)?;
        match upstream {
            SshKeyFingerprint::Sha256(bytes) => Ok(Self(bytes)),
            // ssh_key::Fingerprint is `#[non_exhaustive]`; the only
            // currently-defined non-Sha256 variant is Sha512. Future
            // hash variants land under the wildcard arm.
            SshKeyFingerprint::Sha512(_) => Err(FingerprintParseError::WrongAlgorithm("SHA512")),
            _ => Err(FingerprintParseError::WrongAlgorithm("unknown")),
        }
    }
}

// ---------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------

const KNOWN_HOSTS_HEADER: &str = "\
# Transit known_hosts pinned fingerprints.
#
# Each entry was confirmed via the in-app host-key dialog. When a
# device is legitimately re-keyed (re-image, RMA, firmware upgrade),
# just reconnect — Transit shows a changed-key warning with the
# pinned and new fingerprints and replaces the pin only after you
# explicitly confirm the change.
#
# DO NOT edit the fingerprint field in place. The integrity guarantee
# of TOFU rests on this file being a record of explicit user
# confirmation, not free-form configuration.

";

/// On-disk schema. `version` lets us evolve later without breaking
/// existing users; for now everyone is on v1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KnownHostsFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default, rename = "host")]
    hosts: Vec<HostEntry>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostEntry {
    /// The device this pin belongs to (its inventory id). `None` is a
    /// **legacy** entry written before pins were device-scoped, when the
    /// key was `(host, port)` alone.
    ///
    /// `#[serde(default)]` is load-bearing, not tidiness: the other five
    /// fields have no defaults, so a required sixth would make every
    /// pre-existing `known_hosts.toml` fail to parse — and a parse failure
    /// here is a fatal startup error, not a recoverable state.
    /// `skip_serializing_if` keeps a legacy entry byte-identical on rewrite
    /// until it is adopted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    host: String,
    port: u16,
    fingerprint: String,
    algorithm: String,
    first_seen: String,
}

/// Which tier of [`HostKeyStore::lookup`] produced a hit.
///
/// The distinction exists so the caller can **adopt** a legacy entry —
/// rewrite it as this device's pin — but only after auth succeeds, the
/// same rule that governs every other write to this file (T11 mitigation 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinTier {
    /// Matched this device's own pin. Steady state.
    Scoped,
    /// Matched an unscoped pre-upgrade entry for the same `(host, port)`.
    /// Behaves exactly like a scoped hit for the trust decision; the
    /// difference is that a successful connect takes ownership of it.
    Legacy,
}

/// A [`HostKeyStore::lookup`] hit.
#[derive(Debug, Clone)]
pub struct PinMatch {
    pub fingerprint: Fingerprint,
    pub tier: PinTier,
}

/// Reader / writer for `known_hosts.toml`. Cheap to clone via `Arc`
/// at the call site (`Arc::new(HostKeyStore::open(...).await?)`).
pub struct HostKeyStore {
    path: PathBuf,
    file: RwLock<KnownHostsFile>,
}

// Prove the auto-Sync derivation works. If this stops compiling
// because some inner field grew a non-Sync member, the
// "Send is not general enough" errors at command sites trip first
// — this assertion catches it earlier with a clearer message.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HostKeyStore>();
    assert_send_sync::<Fingerprint>();
    assert_send_sync::<russh::keys::ssh_key::Algorithm>();
};

impl HostKeyStore {
    /// Resolve the canonical path:
    ///
    /// 1. `$TRANSIT_KNOWN_HOSTS` env override (test / power user).
    /// 2. `dirs::config_dir()/TransitCommunity/known_hosts.toml`.
    pub fn default_path() -> Result<PathBuf, SshError> {
        let env = std::env::var("TRANSIT_KNOWN_HOSTS").ok();
        let cfg = dirs::config_dir();
        resolve_default_path(env.as_deref(), cfg.as_deref())
    }

    /// Open the store at `path`. A missing file yields an empty
    /// store; the file is materialized on the first `insert`.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, SshError> {
        let path = path.into();
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str::<KnownHostsFile>(&text).map_err(|e| SshError::KnownHostsIo {
                    path: path.clone(),
                    detail: format!("parse: {e}"),
                })?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => KnownHostsFile::default(),
            Err(e) => {
                return Err(SshError::KnownHostsIo {
                    path: path.clone(),
                    detail: format!("io: {e}"),
                })
            }
        };
        Ok(Self {
            path,
            file: RwLock::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look up the pin for `scope` (a device's inventory id), falling back
    /// to a legacy `(host, port)` entry.
    ///
    /// Two tiers, scoped first:
    ///
    /// 1. **Scoped** — an entry whose `scope` is this device. Note this
    ///    ignores `host`/`port` entirely: the pin follows the DEVICE, so a
    ///    renumbered box keeps its pin and a device entry repointed at a
    ///    different box correctly raises the changed-key warning.
    /// 2. **Legacy** — an unscoped entry for the same `(host, port)`,
    ///    written before pins were device-scoped. Trust-wise identical; the
    ///    caller should adopt it via [`Self::adopt_legacy`] once auth succeeds.
    ///
    /// `host`/`port` are therefore only consulted for tier 2.
    pub async fn lookup(
        &self,
        scope: &str,
        host: &str,
        port: u16,
    ) -> Result<Option<PinMatch>, SshError> {
        let guard = self.file.read().await;
        let hit = guard
            .hosts
            .iter()
            .find(|h| h.scope.as_deref() == Some(scope))
            .map(|e| (e, PinTier::Scoped))
            .or_else(|| {
                guard
                    .hosts
                    .iter()
                    .find(|h| h.scope.is_none() && h.host == host && h.port == port)
                    .map(|e| (e, PinTier::Legacy))
            });
        match hit {
            None => Ok(None),
            Some((e, tier)) => Fingerprint::from_str(&e.fingerprint)
                .map(|fingerprint| Some(PinMatch { fingerprint, tier }))
                .map_err(|_| SshError::KnownHostsIo {
                    path: self.path.clone(),
                    detail: format!("entry for {}:{} has unparseable fingerprint", host, port),
                }),
        }
    }

    /// Pin a new fingerprint for `scope`. Errors with
    /// [`SshError::KnownHostsConflict`] if that device already has an
    /// entry — the caller must `lookup` first, and a rotation goes through
    /// [`Self::replace`].
    ///
    /// The conflict check is on the SCOPE, not `(host, port)`: two devices
    /// legitimately sharing an address is the whole point of this design,
    /// so it must not be an error.
    pub async fn insert(
        &self,
        scope: &str,
        host: &str,
        port: u16,
        fingerprint: &Fingerprint,
        algorithm: &Algorithm,
    ) -> Result<(), SshError> {
        let mut guard = self.file.write().await;
        if guard
            .hosts
            .iter()
            .any(|h| h.scope.as_deref() == Some(scope))
        {
            return Err(SshError::KnownHostsConflict {
                device_id: scope.into(),
                host: host.into(),
                port,
            });
        }
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        guard.hosts.push(HostEntry {
            scope: Some(scope.into()),
            host: host.into(),
            port,
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.as_str().to_string(),
            first_seen: now,
        });
        guard.version = 1;
        self.persist(&guard)
    }

    /// Replace the pinned fingerprint for `(host, port)` after the
    /// user explicitly confirmed a key change in the warning dialog.
    /// The entry's `algorithm` and `first_seen` are rewritten too —
    /// they describe the NEW key (a rotation often changes the
    /// algorithm, e.g. ssh-rsa → ssh-ed25519 after a firmware
    /// upgrade).
    ///
    /// Unlike [`Self::insert`] this is deliberately upsert-shaped: if
    /// the old entry vanished between the dialog and the post-auth
    /// persist (a hand-edit race), the user's verdict — "pin THIS
    /// fingerprint" — still holds, so the pin is written rather than
    /// failing an already-authenticated connect.
    pub async fn replace(
        &self,
        scope: &str,
        host: &str,
        port: u16,
        fingerprint: &Fingerprint,
        algorithm: &Algorithm,
    ) -> Result<(), SshError> {
        let mut guard = self.file.write().await;
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let entry = HostEntry {
            scope: Some(scope.into()),
            host: host.into(),
            port,
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.as_str().to_string(),
            first_seen: now,
        };
        // Same two-tier search as `lookup`, and for the same reason: the
        // user may have been shown a mismatch against a LEGACY entry, and
        // approving the change must rewrite that entry (now scoped to this
        // device) rather than leaving it behind for another device to hit.
        let existing = guard
            .hosts
            .iter_mut()
            .position(|h| h.scope.as_deref() == Some(scope))
            .or_else(|| {
                guard
                    .hosts
                    .iter()
                    .position(|h| h.scope.is_none() && h.host == host && h.port == port)
            });
        match existing {
            Some(idx) => guard.hosts[idx] = entry,
            None => {
                tracing::warn!(
                    device = scope,
                    host,
                    port,
                    "replace: no existing known_hosts entry (removed mid-connect?); inserting"
                );
                guard.hosts.push(entry);
            }
        }
        guard.version = 1;
        self.persist(&guard)
    }

    /// Take ownership of a legacy (unscoped) entry for `scope`.
    ///
    /// Called ONLY after auth succeeds, on a [`PinTier::Legacy`] hit whose
    /// fingerprint already matched. It writes no new trust — the pin is
    /// unchanged — it just records which device the existing trust belongs
    /// to, so a second device at the same address gets a clean first-contact
    /// prompt instead of inheriting this one's pin.
    ///
    /// Idempotent and forgiving: if the entry vanished or was already
    /// adopted (a concurrent connect to the same address), this is a no-op
    /// rather than an error — an already-authenticated connect must not fail
    /// over bookkeeping.
    pub async fn adopt_legacy(&self, scope: &str, host: &str, port: u16) -> Result<(), SshError> {
        let mut guard = self.file.write().await;
        let Some(entry) = guard
            .hosts
            .iter_mut()
            .find(|h| h.scope.is_none() && h.host == host && h.port == port)
        else {
            return Ok(());
        };
        entry.scope = Some(scope.into());
        guard.version = 1;
        self.persist(&guard)
    }

    /// Move a pin to a new device id, for an in-app device rename.
    /// No-op when the device had no pin.
    pub async fn rescope(&self, old_scope: &str, new_scope: &str) -> Result<(), SshError> {
        let mut guard = self.file.write().await;
        let Some(entry) = guard
            .hosts
            .iter_mut()
            .find(|h| h.scope.as_deref() == Some(old_scope))
        else {
            return Ok(());
        };
        entry.scope = Some(new_scope.into());
        guard.version = 1;
        self.persist(&guard)
    }

    /// Drop a device's pin, for an in-app device delete. No-op when the
    /// device had no pin. Deleting and re-adding a device therefore
    /// re-establishes trust from scratch, which is the honest reading of
    /// "this inventory entry is gone".
    pub async fn forget(&self, scope: &str) -> Result<(), SshError> {
        let mut guard = self.file.write().await;
        let before = guard.hosts.len();
        guard.hosts.retain(|h| h.scope.as_deref() != Some(scope));
        if guard.hosts.len() == before {
            return Ok(());
        }
        guard.version = 1;
        self.persist(&guard)
    }

    /// Serialize + atomically write the store. Shared tail of
    /// [`Self::insert`] / [`Self::replace`]; the caller holds the
    /// write guard.
    fn persist(&self, file: &KnownHostsFile) -> Result<(), SshError> {
        let serialized = format!(
            "{}{}",
            KNOWN_HOSTS_HEADER,
            toml::to_string_pretty(file).map_err(|e| SshError::KnownHostsIo {
                path: self.path.clone(),
                detail: format!("serialize: {e}"),
            })?
        );
        write_atomic(&self.path, &serialized)
    }

    /// Number of pinned hosts. Useful for tests and a future
    /// "manage trusted hosts" UI.
    pub async fn len(&self) -> usize {
        self.file.read().await.hosts.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.file.read().await.hosts.is_empty()
    }
}

/// Pure helper for resolving the canonical path. Split from
/// [`HostKeyStore::default_path`] so tests can drive both branches
/// without touching process-global env state.
fn resolve_default_path(
    env_override: Option<&str>,
    config_dir: Option<&Path>,
) -> Result<PathBuf, SshError> {
    if let Some(p) = env_override {
        return Ok(PathBuf::from(p));
    }
    let dir = config_dir.ok_or_else(|| SshError::KnownHostsIo {
        path: PathBuf::from("known_hosts.toml"),
        detail: "platform has no config_dir; set $TRANSIT_KNOWN_HOSTS".into(),
    })?;
    Ok(dir.join("TransitCommunity").join("known_hosts.toml"))
}

/// Atomic write: `tempfile::NamedTempFile::new_in(parent) +
/// persist`. Same shape as
/// `transit_core::inventory::mutator::write_atomic`. Creates the
/// parent directory if missing.
fn write_atomic(path: &Path, contents: &str) -> Result<(), SshError> {
    let parent = path.parent().ok_or_else(|| SshError::KnownHostsIo {
        path: path.to_path_buf(),
        detail: "path has no parent directory".into(),
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent).map_err(|e| SshError::KnownHostsIo {
            path: parent.to_path_buf(),
            detail: format!("mkdir: {e}"),
        })?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| SshError::KnownHostsIo {
        path: path.to_path_buf(),
        detail: format!("tempfile: {e}"),
    })?;
    tmp.write_all(contents.as_bytes())
        .map_err(|e| SshError::KnownHostsIo {
            path: path.to_path_buf(),
            detail: format!("write: {e}"),
        })?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| SshError::KnownHostsIo {
            path: path.to_path_buf(),
            detail: format!("fsync: {e}"),
        })?;
    tmp.persist(path).map_err(|e| SshError::KnownHostsIo {
        path: path.to_path_buf(),
        detail: format!("rename: {}", e.error),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::PublicKey;

    /// Test fixture — Ed25519 public key generated via
    /// `ssh-keygen -t ed25519 -C transit-host-key-test`. Throwaway,
    /// never used outside these tests. Its SHA256 fingerprint is
    /// asserted in [`KNOWN_FINGERPRINT`] so we can validate the
    /// SHA256 derivation against an external source of truth
    /// (`ssh-keygen -lf <pub>`).
    const TEST_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeWGarXFCkY8zX2GTR2H7M311S6iLXWv7AyA9AN5Tgu \
         transit-host-key-test";

    /// `ssh-keygen -lf transit-host-key-test.pub` output. Confirms
    /// our SHA256 derivation matches OpenSSH's.
    const KNOWN_FINGERPRINT: &str = "SHA256:TB9yfs7U9suPXvdMryrKA/UG1ZJrp3DXaZWulMipLoM";

    fn test_key_data() -> KeyData {
        let key = PublicKey::from_openssh(TEST_PUBKEY).expect("test pubkey parses");
        key.key_data().clone()
    }

    #[test]
    fn fingerprint_sha256_matches_ssh_keygen() {
        let kd = test_key_data();
        let fp = Fingerprint::sha256(&kd);
        let s = fp.to_string();
        assert_eq!(
            s, KNOWN_FINGERPRINT,
            "SHA256 derivation drifted from OpenSSH"
        );
    }

    #[test]
    fn fingerprint_round_trip_string() {
        let kd = test_key_data();
        let fp1 = Fingerprint::sha256(&kd);
        let s = fp1.to_string();
        let fp2: Fingerprint = s.parse().expect("parse own output");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_eq_is_value_equality() {
        let kd = test_key_data();
        let a = Fingerprint::sha256(&kd);
        let b = Fingerprint::sha256(&kd);
        assert_eq!(a, b);

        let mut c_bytes = *a.as_bytes();
        c_bytes[0] ^= 0x01;
        let c = Fingerprint::from_bytes(c_bytes);
        assert_ne!(a, c);
    }

    #[test]
    fn fingerprint_rejects_sha512_and_garbage() {
        let res: Result<Fingerprint, _> = "SHA512:abc".parse();
        assert!(matches!(
            res,
            Err(FingerprintParseError::Invalid | FingerprintParseError::WrongAlgorithm(_))
        ));
        let res: Result<Fingerprint, _> = "not a fingerprint".parse();
        assert!(matches!(res, Err(FingerprintParseError::Invalid)));
    }

    #[tokio::test]
    async fn store_open_missing_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("known_hosts.toml");
        // Parent doesn't exist either — open should still succeed.
        let store = HostKeyStore::open(&path).await.expect("open empty");
        assert_eq!(store.len().await, 0);
        assert!(store
            .lookup("dev-any", "any", 22)
            .await
            .expect("lookup empty")
            .is_none());
    }

    #[tokio::test]
    async fn store_insert_then_lookup_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let store = HostKeyStore::open(&path).await.unwrap();

        let kd = test_key_data();
        let fp = Fingerprint::sha256(&kd);
        store
            .insert("dev-a", "192.0.2.35", 22, &fp, &Algorithm::Ed25519)
            .await
            .expect("insert ok");

        let got = store.lookup("dev-a", "192.0.2.35", 22).await.unwrap();
        let got = got.expect("pinned");
        assert_eq!(got.fingerprint, fp);
        assert_eq!(got.tier, PinTier::Scoped);

        // A DIFFERENT device is not pinned, even at the same address —
        // this is the whole point of scoping.
        assert!(store
            .lookup("dev-b", "192.0.2.35", 22)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn two_devices_at_one_address_keep_independent_pins() {
        // The user case: two MSP sites whose gateways are both
        // 192.168.1.1. Before device scoping these shared a pin slot and
        // every switch between them raised a changed-key MITM warning.
        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();

        let fp_a = Fingerprint::sha256(&test_key_data());
        let fp_b: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();

        store
            .insert(
                "customerA-gw",
                "192.168.1.1",
                22,
                &fp_a,
                &Algorithm::Ed25519,
            )
            .await
            .expect("first device pins");
        store
            .insert(
                "customerB-gw",
                "192.168.1.1",
                22,
                &fp_b,
                &Algorithm::Ed25519,
            )
            .await
            .expect("second device at the SAME address must also pin, not conflict");

        assert_eq!(
            store
                .lookup("customerA-gw", "192.168.1.1", 22)
                .await
                .unwrap()
                .unwrap()
                .fingerprint,
            fp_a
        );
        assert_eq!(
            store
                .lookup("customerB-gw", "192.168.1.1", 22)
                .await
                .unwrap()
                .unwrap()
                .fingerprint,
            fp_b
        );
    }

    #[tokio::test]
    async fn scoped_pin_follows_the_device_across_an_address_change() {
        // Scoped matching ignores host/port on purpose: a renumbered box
        // (NetBox sync accepting a new primary IP, say) keeps its pin
        // instead of silently re-TOFU-ing.
        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();
        let fp = Fingerprint::sha256(&test_key_data());
        store
            .insert("dev-a", "10.0.0.1", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();

        let got = store
            .lookup("dev-a", "10.9.9.9", 2222)
            .await
            .unwrap()
            .expect("pin follows the device, not the address");
        assert_eq!(got.fingerprint, fp);
        assert_eq!(got.tier, PinTier::Scoped);
    }

    /// A `known_hosts.toml` written before pins were device-scoped: the
    /// `[[host]]` block has no `scope` key at all.
    const LEGACY_FILE: &str = r#"
version = 1

[[host]]
host = "192.168.1.1"
port = 22
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
algorithm = "ssh-ed25519"
first_seen = "2026-05-08T00:00:00Z"
"#;

    #[tokio::test]
    async fn legacy_unscoped_file_still_loads_and_matches() {
        // Backward compatibility: an upgrade must not re-prompt a fleet.
        // The five original fields have no serde defaults, so `scope`
        // MUST stay optional or every existing file fails to parse — and
        // a parse failure here is a fatal startup error.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        std::fs::write(&path, LEGACY_FILE).unwrap();
        let store = HostKeyStore::open(&path).await.expect("legacy file parses");

        let got = store
            .lookup("any-device", "192.168.1.1", 22)
            .await
            .unwrap()
            .expect("legacy entry matches any device at that address");
        assert_eq!(got.tier, PinTier::Legacy);
    }

    #[tokio::test]
    async fn adopting_a_legacy_pin_hands_it_to_one_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        std::fs::write(&path, LEGACY_FILE).unwrap();
        let store = HostKeyStore::open(&path).await.unwrap();

        store
            .adopt_legacy("customerA-gw", "192.168.1.1", 22)
            .await
            .expect("adopt ok");

        // A: now a scoped hit.
        let a = store
            .lookup("customerA-gw", "192.168.1.1", 22)
            .await
            .unwrap()
            .expect("A owns it");
        assert_eq!(a.tier, PinTier::Scoped);

        // B: the legacy tier is gone, so B gets a clean first contact —
        // a TOFU prompt, NOT an inherited pin and NOT a MITM warning.
        assert!(
            store
                .lookup("customerB-gw", "192.168.1.1", 22)
                .await
                .unwrap()
                .is_none(),
            "an adopted pin must not still be inheritable"
        );

        // And it survives a reopen with the scope written to disk.
        let reopened = HostKeyStore::open(&path).await.unwrap();
        assert_eq!(
            reopened
                .lookup("customerA-gw", "192.168.1.1", 22)
                .await
                .unwrap()
                .unwrap()
                .tier,
            PinTier::Scoped
        );
    }

    #[tokio::test]
    async fn one_device_cannot_clobber_anothers_pin() {
        // The security property that makes scoping safe rather than merely
        // convenient: every write path is confined to the caller's own
        // scope (or the unscoped legacy tier). A key change approved for
        // device B must never rewrite device A's pin, even though both
        // sit at the same address.
        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();
        let fp_a = Fingerprint::sha256(&test_key_data());
        let fp_b: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();

        store
            .insert("dev-a", "192.168.1.1", 22, &fp_a, &Algorithm::Ed25519)
            .await
            .unwrap();

        // B approves a key change at the SAME address.
        store
            .replace("dev-b", "192.168.1.1", 22, &fp_b, &Algorithm::Ed25519)
            .await
            .unwrap();

        assert_eq!(
            store
                .lookup("dev-a", "192.168.1.1", 22)
                .await
                .unwrap()
                .unwrap()
                .fingerprint,
            fp_a,
            "A's pin must survive B's approved replacement"
        );

        // And B cannot adopt A's entry either — adoption only ever
        // matches the UNSCOPED tier.
        store
            .adopt_legacy("dev-b", "192.168.1.1", 22)
            .await
            .unwrap();
        assert_eq!(
            store
                .lookup("dev-a", "192.168.1.1", 22)
                .await
                .unwrap()
                .unwrap()
                .fingerprint,
            fp_a,
            "adoption must not reach a scoped entry"
        );
    }

    #[tokio::test]
    async fn adopt_legacy_is_idempotent_and_never_errors() {
        // Called post-auth on an already-authenticated connect, so a
        // concurrent adoption (or a hand-edit that removed the entry)
        // must be a no-op rather than a failure.
        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();
        store.adopt_legacy("dev-a", "10.0.0.1", 22).await.unwrap();
        store.adopt_legacy("dev-a", "10.0.0.1", 22).await.unwrap();
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn rescope_moves_a_pin_and_forget_drops_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();
        let fp = Fingerprint::sha256(&test_key_data());
        store
            .insert("old-name", "10.0.0.1", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();

        store.rescope("old-name", "new-name").await.unwrap();
        assert!(store
            .lookup("old-name", "10.0.0.1", 22)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .lookup("new-name", "10.0.0.1", 22)
                .await
                .unwrap()
                .unwrap()
                .fingerprint,
            fp
        );

        store.forget("new-name").await.unwrap();
        assert!(store.is_empty().await);

        // Both are no-ops on an unknown device.
        store.rescope("ghost", "ghost2").await.unwrap();
        store.forget("ghost").await.unwrap();
    }

    #[tokio::test]
    async fn store_insert_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("a").join("known_hosts.toml");
        let store = HostKeyStore::open(&path).await.unwrap();
        let fp = Fingerprint::sha256(&test_key_data());
        store
            .insert("dev-a", "host", 22, &fp, &Algorithm::Ed25519)
            .await
            .expect("insert creates dirs");
        assert!(path.exists(), "expected file written at {path:?}");
    }

    #[tokio::test]
    async fn store_insert_rejects_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let store = HostKeyStore::open(&path).await.unwrap();

        let fp = Fingerprint::sha256(&test_key_data());
        store
            .insert("dev-a", "host", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();
        let res = store
            .insert("dev-a", "host", 22, &fp, &Algorithm::Ed25519)
            .await;
        assert!(matches!(res, Err(SshError::KnownHostsConflict { .. })));
    }

    #[tokio::test]
    async fn store_persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let fp = Fingerprint::sha256(&test_key_data());

        {
            let store = HostKeyStore::open(&path).await.unwrap();
            store
                .insert("dev-a", "host", 22, &fp, &Algorithm::Ed25519)
                .await
                .unwrap();
        }

        let store2 = HostKeyStore::open(&path).await.unwrap();
        assert_eq!(
            store2
                .lookup("dev-a", "host", 22)
                .await
                .unwrap()
                .map(|m| m.fingerprint),
            Some(fp)
        );
    }

    #[tokio::test]
    async fn store_load_rejects_unparseable_fingerprint_on_lookup() {
        // Hand-write a file with a bogus fingerprint and confirm
        // lookup classifies it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let bad = r#"
version = 1

[[host]]
host = "h"
port = 22
fingerprint = "garbage"
algorithm = "ssh-ed25519"
first_seen = "2026-05-08T00:00:00Z"
"#;
        std::fs::write(&path, bad).unwrap();
        let store = HostKeyStore::open(&path).await.unwrap();
        let res = store.lookup("dev-h", "h", 22).await;
        assert!(matches!(res, Err(SshError::KnownHostsIo { .. })));
    }

    #[tokio::test]
    async fn store_replace_rewrites_existing_entry_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let store = HostKeyStore::open(&path).await.unwrap();

        // Pin a bogus fingerprint under a different algorithm, then
        // replace with the real key — fingerprint AND algorithm must
        // both be rewritten, without growing the entry list.
        let old: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();
        store
            .insert("dev-a", "host", 22, &old, &Algorithm::Rsa { hash: None })
            .await
            .unwrap();

        let new = Fingerprint::sha256(&test_key_data());
        store
            .replace("dev-a", "host", 22, &new, &Algorithm::Ed25519)
            .await
            .expect("replace ok");

        assert_eq!(store.len().await, 1, "replace must not add an entry");
        assert_eq!(
            store
                .lookup("dev-a", "host", 22)
                .await
                .unwrap()
                .map(|m| m.fingerprint),
            Some(new)
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("ssh-ed25519"), "algorithm rewritten");
        assert!(!on_disk.contains("ssh-rsa"), "old algorithm gone");
    }

    #[tokio::test]
    async fn store_replace_persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let old: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();
        let new = Fingerprint::sha256(&test_key_data());

        {
            let store = HostKeyStore::open(&path).await.unwrap();
            store
                .insert("dev-a", "host", 22, &old, &Algorithm::Ed25519)
                .await
                .unwrap();
            store
                .replace("dev-a", "host", 22, &new, &Algorithm::Ed25519)
                .await
                .unwrap();
        }

        let store2 = HostKeyStore::open(&path).await.unwrap();
        assert_eq!(
            store2
                .lookup("dev-a", "host", 22)
                .await
                .unwrap()
                .map(|m| m.fingerprint),
            Some(new)
        );
        assert_eq!(store2.len().await, 1);
    }

    #[tokio::test]
    async fn store_replace_missing_entry_inserts() {
        // Upsert shape: the entry vanished between the changed-key
        // dialog and the post-auth persist (hand-edit race). The
        // user's verdict still holds — pin it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        let store = HostKeyStore::open(&path).await.unwrap();

        let fp = Fingerprint::sha256(&test_key_data());
        store
            .replace("dev-a", "host", 22, &fp, &Algorithm::Ed25519)
            .await
            .expect("replace-on-missing inserts");
        assert_eq!(
            store
                .lookup("dev-a", "host", 22)
                .await
                .unwrap()
                .map(|m| m.fingerprint),
            Some(fp)
        );
        assert_eq!(store.len().await, 1);
    }

    #[test]
    fn default_path_env_override_wins_over_config_dir() {
        let cfg = PathBuf::from("/home/u/.config");
        let p = resolve_default_path(Some("/explicit/path.toml"), Some(&cfg)).unwrap();
        assert_eq!(p, PathBuf::from("/explicit/path.toml"));
    }

    #[test]
    fn default_path_falls_back_to_config_dir() {
        let cfg = PathBuf::from("/home/u/.config");
        let p = resolve_default_path(None, Some(&cfg)).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/home/u/.config/TransitCommunity/known_hosts.toml")
        );
    }

    #[test]
    fn default_path_errors_when_neither_available() {
        let res = resolve_default_path(None, None);
        assert!(matches!(res, Err(SshError::KnownHostsIo { .. })));
    }
}
