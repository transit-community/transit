//! `ssh_key` backend — loads an SSH private key from a file on disk
//! ("pick the key file"), decrypting it with an
//! optional passphrase that rides a *value* backend (keyring/op/env).
//!
//! Like [`SshAgentBackend`](super::ssh_agent::SshAgentBackend), the
//! credential never surfaces as a [`SecretString`] through
//! [`SecretBackend::resolve_value`] — the key is sign-capable, not a
//! value. The registry's `load_ssh_key` reads + decodes the file
//! in-process and hands transit_ssh a russh [`PrivateKey`], which it
//! wraps in a `PrivateKeyWithHashAlg` for `authenticate_publickey`. Raw
//! key bytes and the passphrase never cross Tauri IPC (Rule 1) and are
//! never logged (§10) — in particular, no error variant produced here
//! embeds the file contents.
//!
//! Supported formats: OpenSSH and PEM (RSA / ECDSA / Ed25519) **and**
//! PuTTY `.ppk` — all handled transparently by
//! `russh::keys::decode_secret_key` (the `ssh-key` `ppk` feature is on
//! in russh's default set). A `.ppk` that russh can't parse falls back
//! to a `puttygen` conversion hint rather than a blanket rejection.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use russh::keys::{decode_secret_key, PrivateKey};
use secrecy::SecretString;
use transit_core::inventory::SecretRef;

use crate::{BackendAvailability, BackendError, SecretBackend};

const KIND: &str = "ssh_key";

pub(crate) struct SshKeyBackend;

impl SshKeyBackend {
    pub(crate) fn new() -> Self {
        Self
    }

    /// File-based backend: always "available". Whether a *specific* key
    /// file exists is a connect-time concern surfaced as a
    /// [`BackendError::KeyFile`], not a startup probe.
    pub(crate) fn availability(&self) -> BackendAvailability {
        BackendAvailability::Ready
    }

    /// Read the key file at `path` (expanding a leading `~`) and decode
    /// it with the optional `passphrase`. Synchronous: the file is tiny
    /// and parsing is CPU-bound. Returns a sign-ready russh
    /// [`PrivateKey`]; the caller (transit_ssh) wraps it for
    /// `authenticate_publickey`.
    pub(crate) fn load(
        &self,
        path: &Path,
        passphrase: Option<&str>,
    ) -> Result<PrivateKey, BackendError> {
        let expanded = expand_tilde(path);
        // `read_to_string` (not `read`): OpenSSH / PEM / PPK are all
        // text. A non-UTF-8 file isn't a key we support — surface a
        // file error, not a parse error. The contents are NEVER placed
        // into the returned error.
        // Wrap in `Zeroizing` so the plaintext key file (raw private key
        // bytes for an unencrypted key) is scrubbed from the heap on drop
        // rather than freed intact — matching the zeroize discipline the
        // rest of the crate follows (see `op.rs`). `decode_secret_key`
        // and `map_decode_error` take `&str`; `&Zeroizing<String>` deref-
        // coerces cleanly.
        let contents =
            zeroize::Zeroizing::new(std::fs::read_to_string(&expanded).map_err(|e| {
                BackendError::KeyFile {
                    detail: format!("{}: {e}", expanded.display()),
                }
            })?);
        decode_secret_key(&contents, passphrase)
            .map_err(|e| map_decode_error(e, &contents, passphrase.is_some()))
    }

    /// Read-only classification of the key file at `path`, for the
    /// import wizard's credential step. Decodes with **no** passphrase
    /// and maps the outcome to a [`KeyProbeVerdict`] — reusing
    /// [`Self::load`] so the verdict matches the real connect path
    /// exactly. The decoded key (the `Unencrypted` case) is dropped
    /// immediately and never returned; no file contents reach the verdict.
    pub(crate) fn probe(&self, path: &Path) -> KeyProbeVerdict {
        match self.load(path, None) {
            // Parsed with no passphrase ⇒ the key is unencrypted.
            Ok(_key) => KeyProbeVerdict::Unencrypted,
            // Decoding an encrypted key with no passphrase yields this.
            Err(BackendError::KeyNeedsPassphrase) => KeyProbeVerdict::Encrypted,
            // Bad / unsupported / unconvertible `.ppk`. `detail` already
            // carries the puttygen hint and is contents-free.
            Err(BackendError::KeyUnparseable { detail }) => {
                KeyProbeVerdict::Unparseable { hint: detail }
            }
            // Missing / unreadable / non-UTF-8. `detail` is path + io error.
            Err(BackendError::KeyFile { detail }) => KeyProbeVerdict::Unreadable { detail },
            // `load(_, None)` can't return KeyWrongPassphrase (no
            // passphrase supplied); anything else is unexpected — treat as
            // unreadable rather than claim a usable key.
            Err(other) => KeyProbeVerdict::Unreadable {
                detail: other.to_string(),
            },
        }
    }
}

/// Verdict from a read-only probe of an on-disk key file
/// ([`SshKeyBackend::probe`]). The import wizard uses it to decide, per
/// referenced `IdentityFile`, whether a profile can be created silently
/// (`Unencrypted`), needs a passphrase prompt (`Encrypted`), or can't be
/// used (`Unparseable` / `Unreadable`). Carries **no key bytes and no
/// file contents** — only a classification plus a contents-free
/// hint/detail (it mirrors [`map_decode_error`], which never embeds the
/// file).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum KeyProbeVerdict {
    /// Parsed with no passphrase — usable as-is (`passphrase = None`).
    Unencrypted,
    /// A valid private key, but passphrase-protected — the import must
    /// collect a passphrase and enroll it to the keychain.
    Encrypted,
    /// Not a key we can parse (corrupt, unsupported, or an unconvertible
    /// `.ppk`). `hint` is the actionable, contents-free message.
    Unparseable { hint: String },
    /// The file couldn't be read at all (missing on this machine, no
    /// permission, or non-UTF-8). `detail` is the path + io error.
    Unreadable { detail: String },
}

/// Map russh's key-decode error to an actionable [`BackendError`]
/// WITHOUT ever embedding the file contents. `had_passphrase`
/// disambiguates "needs a passphrase" from "wrong passphrase".
fn map_decode_error(err: russh::keys::Error, contents: &str, had_passphrase: bool) -> BackendError {
    // `KeyIsEncrypted` is returned only when we decoded with no
    // passphrase against an encrypted key.
    if matches!(err, russh::keys::Error::KeyIsEncrypted) {
        return BackendError::KeyNeedsPassphrase;
    }
    if had_passphrase {
        // We supplied a passphrase and decryption still failed:
        // overwhelmingly a wrong passphrase (vs. a corrupt key).
        return BackendError::KeyWrongPassphrase;
    }
    // Unencrypted but unparseable: bad file, unsupported type, or a
    // PuTTY key russh couldn't read. Give the `puttygen` hint for `.ppk`.
    let is_ppk = contents.trim_start().starts_with("PuTTY-User-Key-File-");
    let detail = if is_ppk {
        "this PuTTY .ppk couldn't be read — convert it with \
         `puttygen key.ppk -O private-openssh -o key` and pick the converted file"
            .to_string()
    } else {
        "unrecognized or corrupt key file (expected an OpenSSH, PEM, or PuTTY .ppk private key)"
            .to_string()
    };
    BackendError::KeyUnparseable { detail }
}

/// Expand a leading `~` / `~/` (or `~\` on Windows) to the user's home
/// directory. The file picker yields absolute paths; this is for
/// hand-edited `transit.toml`. `~user` is not expanded (rare). No new
/// dependency — reads `$HOME` / `%USERPROFILE%` directly.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let rest = if s == "~" {
        Some("")
    } else {
        s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\"))
    };
    if let Some(rest) = rest {
        if let Some(home) = home_dir() {
            return if rest.is_empty() {
                home
            } else {
                home.join(rest)
            };
        }
    }
    path.to_path_buf()
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[async_trait]
impl SecretBackend for SshKeyBackend {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn supports(&self, refp: &SecretRef) -> bool {
        matches!(refp, SecretRef::SshKey { .. })
    }

    async fn resolve_value(&self, _refp: &SecretRef) -> Result<SecretString, BackendError> {
        // The key is sign-capable, not a value. Loading happens via the
        // registry's `load_ssh_key`, mirroring the agent backend.
        Err(BackendError::unsupported(KIND, "resolve_value"))
    }

    async fn enroll(&self, _refp: &SecretRef, _value: SecretString) -> Result<(), BackendError> {
        // The key file is supplied out of band (it already exists on
        // disk). Only the optional passphrase is enrolled — and that
        // rides its own keyring `SecretRef`, not this backend.
        Err(BackendError::unsupported(KIND, "enroll"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::LineEnding;
    use russh::keys::{Algorithm, PrivateKey};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    fn write_key(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn loads_unencrypted_openssh_key() {
        let key = ed25519();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        let loaded = SshKeyBackend::new().load(f.path(), None).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
    }

    #[test]
    fn loads_encrypted_key_with_correct_passphrase() {
        let key = ed25519().encrypt(&mut rand::rng(), "s3cret").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        assert!(SshKeyBackend::new().load(f.path(), Some("s3cret")).is_ok());
    }

    #[test]
    fn encrypted_key_without_passphrase_needs_passphrase() {
        let key = ed25519().encrypt(&mut rand::rng(), "pw").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        match SshKeyBackend::new().load(f.path(), None) {
            Err(BackendError::KeyNeedsPassphrase) => {}
            other => panic!("expected KeyNeedsPassphrase, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_key_with_wrong_passphrase_is_wrong_passphrase() {
        let key = ed25519().encrypt(&mut rand::rng(), "right").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        match SshKeyBackend::new().load(f.path(), Some("wrong")) {
            Err(BackendError::KeyWrongPassphrase) => {}
            other => panic!("expected KeyWrongPassphrase, got {other:?}"),
        }
    }

    #[test]
    fn missing_file_is_key_file_error() {
        match SshKeyBackend::new().load(Path::new("/no/such/transit/key"), None) {
            Err(BackendError::KeyFile { detail }) => {
                assert!(detail.contains("/no/such/transit/key"))
            }
            other => panic!("expected KeyFile, got {other:?}"),
        }
    }

    #[test]
    fn garbage_is_unparseable_without_ppk_hint() {
        let f = write_key(b"this is not a key at all\n");
        match SshKeyBackend::new().load(f.path(), None) {
            Err(BackendError::KeyUnparseable { detail }) => assert!(!detail.contains("puttygen")),
            other => panic!("expected KeyUnparseable, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_ppk_gets_puttygen_hint() {
        // A PuTTY header with a junk body: russh recognizes the header,
        // fails to parse the body, and we surface the conversion hint.
        let f =
            write_key(b"PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: x\nbogus\n");
        match SshKeyBackend::new().load(f.path(), None) {
            Err(BackendError::KeyUnparseable { detail }) => assert!(detail.contains("puttygen")),
            other => panic!("expected KeyUnparseable with puttygen hint, got {other:?}"),
        }
    }

    #[test]
    fn expand_tilde_resolves_home() {
        if home_dir().is_some() {
            let p = expand_tilde(Path::new("~/transit-key"));
            assert!(p.is_absolute());
            assert!(p.ends_with("transit-key"));
            assert_ne!(p.to_string_lossy(), "~/transit-key");
        }
        // A non-tilde path is returned unchanged.
        assert_eq!(expand_tilde(Path::new("/abs/key")), Path::new("/abs/key"));
    }

    // ---- probe (read-only verdict for the import wizard) -----------

    #[test]
    fn probe_unencrypted_key_is_unencrypted() {
        let key = ed25519();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        assert_eq!(
            SshKeyBackend::new().probe(f.path()),
            KeyProbeVerdict::Unencrypted
        );
    }

    #[test]
    fn probe_encrypted_key_is_encrypted() {
        let key = ed25519().encrypt(&mut rand::rng(), "pw").unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let f = write_key(pem.as_bytes());
        // `Encrypted` carries no detail field at all, so it is
        // structurally impossible for the verdict to leak the key.
        assert_eq!(
            SshKeyBackend::new().probe(f.path()),
            KeyProbeVerdict::Encrypted
        );
    }

    #[test]
    fn probe_garbage_is_unparseable_and_leaks_no_contents() {
        // A recognizable marker in the file body must NOT surface in the
        // verdict — the probe is verdict-only and contents-free.
        let f = write_key(b"TOTALLY-NOT-A-KEY secretmarker-7f3a\n");
        match SshKeyBackend::new().probe(f.path()) {
            KeyProbeVerdict::Unparseable { hint } => {
                assert!(!hint.contains("puttygen"));
                assert!(
                    !hint.contains("secretmarker-7f3a"),
                    "verdict hint leaked file contents"
                );
            }
            other => panic!("expected Unparseable, got {other:?}"),
        }
    }

    #[test]
    fn probe_unparseable_ppk_gets_puttygen_hint() {
        let f =
            write_key(b"PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: x\nbogus\n");
        match SshKeyBackend::new().probe(f.path()) {
            KeyProbeVerdict::Unparseable { hint } => assert!(hint.contains("puttygen")),
            other => panic!("expected Unparseable with puttygen hint, got {other:?}"),
        }
    }

    #[test]
    fn probe_missing_file_is_unreadable() {
        match SshKeyBackend::new().probe(Path::new("/no/such/transit/key")) {
            KeyProbeVerdict::Unreadable { detail } => {
                assert!(detail.contains("/no/such/transit/key"))
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }
}
