//! `op` backend — 1Password CLI passthrough.
//!
//! We shell out to `op read <reference>`, capture stdout, and wrap
//! the bytes in a `SecretString`. The original `Vec<u8>` from the
//! subprocess is zeroized after the copy — see `read_op` below.
//!
//! Detection at construct time runs a PATH scan plus a platform check
//! for 1Password.app, so the registry can return three different
//! `BackendAvailability` states:
//!   - `Ready`: both 1Password.app and `op` present. The absolute path
//!     to `op` is captured so every later spawn uses the same binary
//!     regardless of the runtime PATH — load-bearing on macOS, where
//!     GUI-launched bundles inherit a minimal PATH that doesn't
//!     include `/opt/homebrew/bin`.
//!   - `NeedsInstall { hint: "install op CLI..." }`: 1Password.app is
//!     present, `op` isn't.
//!   - `NeedsInstall { hint: "install 1Password and op CLI..." }`:
//!     neither is present.
//!
//! Resolve-time errors are classified into [`BackendError::OpAuth`]
//! (signed out / vault access) vs [`BackendError::ResolveFailed`]
//! (transport / decoding) so the UI shows actionable messages.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use secrecy::SecretString;
use tokio::process::Command;
use transit_core::inventory::SecretRef;
use zeroize::Zeroize;

use crate::{BackendAvailability, BackendError, SecretBackend};

const KIND: &str = "op";

/// Canonical absolute paths to `op` on macOS when the PATH lookup
/// fails. macOS apps launched via Launch Services (Finder, `open`,
/// the Dock) inherit only `/usr/bin:/bin:/usr/sbin:/sbin` plus
/// `/etc/paths` entries — Homebrew's `/opt/homebrew/bin` (Apple
/// Silicon) is not in that set, so a cask-installed `op` is invisible
/// to a plain `$PATH` scan. Since `brew install --cask 1password-cli`
/// is the macOS install path we advertise in `install_op_hint`, we
/// must look in the cask's canonical bin locations as a fallback.
#[cfg(target_os = "macos")]
const MACOS_OP_FALLBACK_PATHS: &[&str] = &["/opt/homebrew/bin/op", "/usr/local/bin/op"];

pub(crate) struct OpBackend {
    availability: BackendAvailability,
    /// Resolved absolute path to `op`, captured at detection time.
    /// `Some` iff `availability` is `Ready`. Spawning by absolute path
    /// — not by bare name — is what lets `op read` succeed in a
    /// GUI-launched bundle whose runtime PATH wouldn't find it.
    op_path: Option<PathBuf>,
}

impl OpBackend {
    pub(crate) fn new() -> Self {
        let op_path = locate_op();
        let availability = match (&op_path, onepassword_app_present()) {
            (Some(_), _) => BackendAvailability::Ready,
            (None, true) => BackendAvailability::NeedsInstall {
                hint: install_op_hint().to_string(),
            },
            (None, false) => BackendAvailability::NeedsInstall {
                hint: install_both_hint().to_string(),
            },
        };
        Self {
            availability,
            op_path,
        }
    }

    pub(crate) fn availability(&self) -> BackendAvailability {
        self.availability.clone()
    }
}

/// Locate the `op` binary as an absolute path. Checks every entry of
/// `$PATH` first; on macOS, falls back to the cask's canonical install
/// locations so a Launch-Services-launched bundle can still find a
/// cask-installed CLI.
fn locate_op() -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH");
    let fallbacks: &[&str] = {
        #[cfg(target_os = "macos")]
        {
            MACOS_OP_FALLBACK_PATHS
        }
        #[cfg(not(target_os = "macos"))]
        {
            &[]
        }
    };
    locate_op_with(path_env.as_deref(), fallbacks)
}

/// PATH-and-fallback search, parameterised so it's unit-testable
/// without mucking with the process environment or filesystem layout.
fn locate_op_with(path_env: Option<&std::ffi::OsStr>, fallbacks: &[&str]) -> Option<PathBuf> {
    if let Some(path) = path_env {
        for dir in std::env::split_paths(path) {
            let candidate = dir.join("op");
            if candidate.is_file() {
                return Some(candidate);
            }
            if cfg!(windows) {
                for ext in ["exe", "cmd", "bat"] {
                    let with_ext = candidate.with_extension(ext);
                    if with_ext.is_file() {
                        return Some(with_ext);
                    }
                }
            }
        }
    }
    for known in fallbacks {
        let candidate = PathBuf::from(known);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Heuristic detection of 1Password.app presence. Used to tailor the
/// install hint — installing 1Password.app and installing the CLI are
/// separate steps the user might be unaware of.
fn onepassword_app_present() -> bool {
    if cfg!(target_os = "macos") {
        Path::new("/Applications/1Password.app").exists()
    } else if cfg!(target_os = "windows") {
        // Default install paths for 1Password 8 on Windows.
        Path::new(r"C:\Program Files\1Password").exists()
            || Path::new(r"C:\Users\Public\Desktop\1Password.lnk").exists()
    } else {
        // On Linux 1Password ships as a flatpak / .deb / AppImage —
        // detection is fragile. Treat as "unknown / probably absent";
        // the install hint covers both install steps.
        false
    }
}

fn install_op_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "1Password is installed, but the op CLI isn't. Install with `brew install --cask 1password-cli` \
         or download from https://developer.1password.com/docs/cli/get-started/."
    } else if cfg!(target_os = "windows") {
        "1Password is installed, but the op CLI isn't. Install with `winget install 1password-cli` \
         or `scoop install 1password-cli`."
    } else {
        "1Password is installed, but the op CLI isn't. \
         See https://developer.1password.com/docs/cli/get-started/ for install instructions."
    }
}

fn install_both_hint() -> &'static str {
    "1Password CLI not found. Install 1Password and the op CLI from \
     https://1password.com/downloads/ and https://developer.1password.com/docs/cli/get-started/, \
     or pick another backend."
}

/// Run `op read <reference>`, return the value as `SecretString`.
/// The subprocess stdout `Vec<u8>` is zeroized after the value is
/// copied, so the bytes survive in our process only briefly.
///
/// `op_path` is the absolute path captured at startup. Spawning by
/// absolute path is what makes the call work in macOS GUI bundles
/// whose runtime PATH doesn't include `/opt/homebrew/bin`.
async fn read_op(op_path: &Path, reference: &str) -> Result<SecretString, BackendError> {
    let output = Command::new(op_path)
        .arg("read")
        .arg(reference)
        .output()
        .await
        .map_err(|e| BackendError::ResolveFailed {
            detail: format!("failed to spawn `op`: {e}"),
        })?;

    if !output.status.success() {
        // `op` writes useful error context to stderr; classify the
        // common cases so the UI can surface "sign in" vs "no access"
        // distinctly. The classification is regex-on-stderr — fragile
        // to op CLI version drift. Pin a minimum `op` version when we
        // make this user-facing.
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stderr_lower = stderr.to_lowercase();
        if stderr_lower.contains("not currently signed in")
            || stderr_lower.contains("no biometric")
            || stderr_lower.contains("authentication required")
            || stderr_lower.contains("session has expired")
        {
            return Err(BackendError::OpAuth {
                detail: "op CLI not signed in. Run `op signin` and try again.".into(),
            });
        }
        if stderr_lower.contains("no vault matched") || stderr_lower.contains("isn't a vault") {
            return Err(BackendError::OpAuth {
                detail: format!("Vault in {reference} not found or not accessible."),
            });
        }
        if stderr_lower.contains("more than one item matches") {
            return Err(BackendError::ResolveFailed {
                detail: format!(
                    "Multiple 1Password items match the name in {reference}. \
                     Disambiguate by renaming one in 1Password, or replace the \
                     item-name segment with the item's UUID: list with \
                     `op item list --vault <vault>` and use \
                     `op://<vault>/<UUID>/password`."
                ),
            });
        }
        return Err(BackendError::ResolveFailed {
            detail: format!("op exited with code {}: {stderr}", output.status),
        });
    }

    // `op read` emits the value followed by a trailing newline. Trim
    // the trailing whitespace before wrapping; the rest of the buffer
    // is the secret. Do the trim by clipping the slice (no allocation).
    let mut bytes = output.stdout;
    let end = bytes
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map(|i| i + 1)
        .unwrap_or(0);
    bytes.truncate(end);

    let secret = match String::from_utf8(bytes.clone()) {
        Ok(s) => SecretString::from(s),
        Err(_) => {
            bytes.zeroize();
            return Err(BackendError::ResolveFailed {
                detail: "op returned non-UTF-8 bytes".into(),
            });
        }
    };
    // Source buffer no longer needed — scrub it.
    bytes.zeroize();
    Ok(secret)
}

#[async_trait]
impl SecretBackend for OpBackend {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn supports(&self, refp: &SecretRef) -> bool {
        matches!(refp, SecretRef::Op { .. })
    }

    async fn resolve_value(&self, refp: &SecretRef) -> Result<SecretString, BackendError> {
        let SecretRef::Op { reference } = refp else {
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
        // Invariant: availability == Ready ⇒ op_path is Some, set in
        // `new()`. `expect` makes a construction-logic break loud
        // rather than masking it as a generic resolve failure.
        let op_path = self
            .op_path
            .as_deref()
            .expect("op_path is Some when availability is Ready");
        read_op(op_path, reference).await
    }

    async fn enroll(&self, _refp: &SecretRef, _value: SecretString) -> Result<(), BackendError> {
        // The user manages 1Password items in 1Password, not in
        // Transit. Surfaced clearly in the UI: no Set-value button on
        // op-backed profiles.
        Err(BackendError::unsupported(KIND, "enroll"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use tempfile::TempDir;

    /// Touch an executable file (mode 0755 on Unix) so `is_file`
    /// passes. The content is irrelevant — we never spawn it.
    fn touch_executable(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }
        path
    }

    fn join_paths(dirs: &[&Path]) -> OsString {
        std::env::join_paths(dirs.iter().copied()).unwrap()
    }

    #[test]
    fn locates_op_via_path() {
        let tmp = TempDir::new().unwrap();
        let op = touch_executable(tmp.path(), "op");
        let path = join_paths(&[tmp.path()]);
        let found = locate_op_with(Some(path.as_os_str()), &[]);
        assert_eq!(found.as_deref(), Some(op.as_path()));
    }

    #[test]
    fn falls_back_to_known_path_when_path_misses() {
        // Simulates a macOS GUI launch: PATH contains only entries
        // without `op`, but a canonical absolute path does.
        let empty_dir = TempDir::new().unwrap();
        let fallback_dir = TempDir::new().unwrap();
        let op = touch_executable(fallback_dir.path(), "op");
        let op_str = op.to_string_lossy().into_owned();
        let path = join_paths(&[empty_dir.path()]);
        let found = locate_op_with(Some(path.as_os_str()), &[&op_str]);
        assert_eq!(found.as_deref(), Some(op.as_path()));
    }

    #[test]
    fn path_lookup_takes_precedence_over_fallback() {
        let path_dir = TempDir::new().unwrap();
        let path_op = touch_executable(path_dir.path(), "op");
        let fallback_dir = TempDir::new().unwrap();
        let fallback_op = touch_executable(fallback_dir.path(), "op");
        let fallback_str = fallback_op.to_string_lossy().into_owned();
        let path = join_paths(&[path_dir.path()]);
        let found = locate_op_with(Some(path.as_os_str()), &[&fallback_str]);
        assert_eq!(found.as_deref(), Some(path_op.as_path()));
    }

    #[test]
    fn returns_none_when_neither_path_nor_fallback_has_op() {
        let empty_dir = TempDir::new().unwrap();
        let path = join_paths(&[empty_dir.path()]);
        let found = locate_op_with(Some(path.as_os_str()), &["/definitely/not/a/real/path/op"]);
        assert!(found.is_none());
    }

    #[test]
    fn returns_none_when_path_env_missing_and_no_fallbacks() {
        let found = locate_op_with(None, &[]);
        assert!(found.is_none());
    }

    #[test]
    fn fallback_consulted_when_path_env_missing() {
        let fallback_dir = TempDir::new().unwrap();
        let op = touch_executable(fallback_dir.path(), "op");
        let op_str = op.to_string_lossy().into_owned();
        let found = locate_op_with(None, &[&op_str]);
        assert_eq!(found.as_deref(), Some(op.as_path()));
    }
}
