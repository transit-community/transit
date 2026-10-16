//! Phase 8b — session scrollback export.
//!
//! Saves the current scrollback for an open session to disk, with
//! the redaction filter **re-run on the bytes about to be written**.
//! This is defense in depth: the in-memory scrollback contains raw
//! device output (the redactor only runs at the agent boundary, on
//! the LLM-facing path). Without re-redacting at export time, an
//! export workflow could leak PEM blocks / passwords / cloud
//! credentials that were never supposed to leave the device.
//!
//! Two encryption modes:
//!   - **None** — plaintext file, redaction applied.
//!   - **AgePassphrase** — `age`-encrypted with the user's
//!     passphrase. Decryptable later via `age -d file.age` from
//!     the CLI. Uses scrypt KDF + ChaCha20-Poly1305 internally.
//!
//! The destination path is chosen by the frontend (via
//! `tauri-plugin-dialog`'s native Save dialog) and passed in.
//! Files are written atomically — tempfile next to the target,
//! then `rename` — so a half-written file never lands on disk
//! even if the process dies mid-write.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::State;
use transit_agent::RedactionFilter;

use crate::commands::AppState;
use crate::console::ConsoleState;

#[derive(Debug, Deserialize)]
pub struct ExportSessionArgs {
    pub session_id: String,
    pub destination: PathBuf,
    #[serde(default)]
    pub encryption: ExportEncryption,
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportEncryption {
    #[default]
    None,
    /// Encrypt the redacted output with `age`'s passphrase recipient
    /// (scrypt KDF + ChaCha20-Poly1305). The frontend collects the
    /// passphrase via a modal and sends it once, in a `SecretString`-
    /// shaped field. The string is dropped after the writer flushes.
    AgePassphrase { passphrase: String },
}

#[derive(Debug, Serialize)]
pub struct ExportResult {
    pub bytes_written: u64,
    pub path: PathBuf,
}

/// Export an open session's scrollback to disk.
///
/// Fall-through across SSH + console state, same shape as the
/// `send_input` / `disconnect_session` commands. Either map can
/// supply the scrollback bytes.
#[tauri::command]
pub async fn export_session(
    state: State<'_, AppState>,
    console_state: State<'_, Arc<ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    args: ExportSessionArgs,
) -> Result<ExportResult, String> {
    let ExportSessionArgs {
        session_id,
        destination,
        encryption,
    } = args;

    // 1. Snapshot scrollback. Either transport works; UUIDs are
    //    unique so only one map will own this id.
    let scrollback_bytes =
        lookup_scrollback(&state, &console_state, &local_state, &session_id).await?;

    // 2. Re-run redaction at the export boundary. UTF-8 lossy is
    //    safe — device output occasionally has stray bytes from
    //    control sequences and we want to write a text file, not
    //    propagate the lossy markers downstream. The redaction
    //    filter accepts &str so the lossy step is mandatory anyway.
    let text = String::from_utf8_lossy(&scrollback_bytes).into_owned();
    let redacted = RedactionFilter::standard().redact(&text);

    // 3. Optionally encrypt.
    let final_bytes: Vec<u8> = match encryption {
        ExportEncryption::None => redacted.into_bytes(),
        ExportEncryption::AgePassphrase { passphrase } => {
            encrypt_with_age_passphrase(&redacted, passphrase)
                .map_err(|e| format!("age encryption failed: {e}"))?
        }
    };

    // 4. Atomic write. tempfile in the same directory + rename so
    //    a partial write never lands on disk. Persisting to a
    //    pre-existing file overwrites it.
    write_atomic(&destination, &final_bytes).map_err(|e| format!("write failed: {e}"))?;

    Ok(ExportResult {
        bytes_written: final_bytes.len() as u64,
        path: destination,
    })
}

async fn lookup_scrollback(
    state: &State<'_, AppState>,
    console_state: &State<'_, Arc<ConsoleState>>,
    local_state: &State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: &str,
) -> Result<Vec<u8>, String> {
    {
        let guard = state.ssh.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.scrollback.snapshot());
        }
    }
    {
        let guard = console_state.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.scrollback.snapshot());
        }
    }
    {
        let guard = local_state.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.scrollback.snapshot());
        }
    }
    Err(format!("session {session_id} not found"))
}

/// Wrap `text` in an age passphrase-encrypted envelope. The
/// resulting bytes are the standard `age` binary format (decryptable
/// via `age -d file.age` from the CLI).
///
/// `SecretString::from(String)` is the secrecy-0.10 constructor that
/// `age` 0.11 takes. age 0.11 tracks secrecy 0.10 — the same major as
/// the workspace's `transit_auth` — so the two no longer coexist as
/// separate versions in the dep graph; cargo dedupes them.
fn encrypt_with_age_passphrase(text: &str, passphrase: String) -> std::io::Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(passphrase));
    let mut out = Vec::with_capacity(text.len() + 256);
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    writer.write_all(text.as_bytes())?;
    writer.finish()?;
    Ok(out)
}

/// Atomic write via tempfile + rename. Same pattern as
/// `transit_core::inventory::mutator::write_atomic`, lifted inline
/// because this module's input is a plain `&[u8]` rather than a
/// `DocumentMut`.
fn write_atomic(target: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no parent directory",
        )
    })?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(contents)?;
    tmp.flush()?;
    tmp.persist(target).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, b"old").unwrap();
        write_atomic(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn age_encrypt_round_trip() {
        // Encrypt with passphrase, decrypt with the same — should
        // round-trip the bytes exactly. Validates the encryptor
        // wiring without depending on the CLI.
        let plaintext = "scrollback contents to encrypt";
        let passphrase = String::from("test-only-passphrase");
        let cipher = encrypt_with_age_passphrase(plaintext, passphrase.clone()).unwrap();

        // age 0.11's Decryptor::new returns a struct (not the old
        // Recipients/Passphrase enum). A passphrase file decrypts with
        // a scrypt::Identity; is_scrypt() confirms the header is
        // passphrase-based rather than a recipients header.
        let identity = age::scrypt::Identity::new(SecretString::from(passphrase));
        let decryptor = age::Decryptor::new(&cipher[..]).unwrap();
        assert!(decryptor.is_scrypt(), "expected passphrase header");
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut decrypted = String::new();
        use std::io::Read;
        reader.read_to_string(&mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn age_encrypt_rejects_wrong_passphrase() {
        let cipher = encrypt_with_age_passphrase("secret", "right-passphrase".into()).unwrap();
        let wrong = age::scrypt::Identity::new(SecretString::from("wrong-passphrase"));
        let decryptor = age::Decryptor::new(&cipher[..]).unwrap();
        assert!(decryptor.is_scrypt(), "expected passphrase header");
        let result = decryptor
            .decrypt(std::iter::once(&wrong as &dyn age::Identity))
            .map(|_| ());
        assert!(result.is_err(), "wrong passphrase must not decrypt");
    }
}
