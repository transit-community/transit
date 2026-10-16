//! Phase 3 — command-output capture + comparison.
//!
//! Runs a command in an open SSH session and saves its output as a named
//! *capture*; two captures can then be diffed — `show run` over time, or one
//! device against another (config-drift detection).
//!
//! # Not policy-gated
//! This is **human input** — the user asked to run this command, exactly like
//! typing it or firing a button-bar macro — so it does NOT pass the agent
//! policy gate (the gate is agent-only, Inviolable Rule 3). It adds no agent
//! tool; the surface stays four (Rule 2).
//!
//! # Redaction (T22)
//! The output is redacted before it is written to disk, like
//! [`crate::session_export`]. Unlike streaming logs, a capture is a single
//! command's output captured as one block, so redaction runs on the whole
//! block — no per-chunk best-effort gap.
//!
//! Captures are SSH-only for now (the executor resolves SSH sessions); a
//! console-capture path can follow.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use transit_agent::RedactionFilter;
use transit_core::diff::{diff_lines, DiffResult};

use crate::agent_dispatch::{
    SessionExecutor, SshSessionExecutor, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_QUIESCENCE,
};
use crate::commands::AppState;

/// Metadata for a saved capture (the list view; excludes the content).
#[derive(Debug, Clone, Serialize)]
pub struct CaptureMeta {
    pub id: String,
    pub device_id: String,
    pub command: String,
    /// RFC-3339 UTC timestamp of when the capture was taken.
    pub captured_at: String,
}

/// On-disk capture record (one `<id>.json` file per capture).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CaptureRecord {
    id: String,
    device_id: String,
    command: String,
    captured_at: String,
    content: String,
}

impl CaptureRecord {
    fn meta(&self) -> CaptureMeta {
        CaptureMeta {
            id: self.id.clone(),
            device_id: self.device_id.clone(),
            command: self.command.clone(),
            captured_at: self.captured_at.clone(),
        }
    }
}

fn captures_dir() -> Result<PathBuf, String> {
    Ok(dirs::config_dir()
        .ok_or("no OS config directory")?
        .join("TransitCommunity")
        .join("captures"))
}

/// Filesystem-safe id: sanitized timestamp + device slug. The sub-second
/// timestamp keeps rapid re-captures of the same device distinct.
fn make_id(device_id: &str, captured_at: &str) -> String {
    let ts = sanitize(captured_at);
    let dev = sanitize(device_id);
    format!("{ts}__{dev}")
}

/// Keep `[A-Za-z0-9._-]`, replace everything else with `-`. Prevents a
/// device id or timestamp from escaping the captures directory.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn save_record(record: &CaptureRecord) -> Result<(), String> {
    let dir = captures_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create captures dir: {e}"))?;
    let path = dir.join(format!("{}.json", record.id));
    let json = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("cannot write capture: {e}"))
}

fn read_record(id: &str) -> Result<CaptureRecord, String> {
    // Guard against a caller-supplied id escaping the directory.
    if id != sanitize(id) {
        return Err("invalid capture id".to_string());
    }
    let path = captures_dir()?.join(format!("{id}.json"));
    let bytes = std::fs::read(&path).map_err(|e| format!("capture not found: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("corrupt capture: {e}"))
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("unknown"))
}

/// Run one command in an SSH session, redact the output, save it as a
/// capture, and return the record. Shared by `capture_command` (one) and
/// `run_collection` (many). Human-initiated — NOT policy-gated.
async fn capture_one(
    ssh: &Arc<crate::ssh::SshState>,
    session_id: &str,
    command: &str,
) -> Result<CaptureRecord, String> {
    let device_id = {
        let guard = ssh.sessions.lock().await;
        guard
            .get(session_id)
            .map(|e| e.device_id.clone())
            .ok_or_else(|| format!("session {session_id} not found or not an SSH session"))?
    };

    let executor = SshSessionExecutor {
        ssh: Arc::clone(ssh),
    };
    // Terminal capture ignores the v6.1.x CaptureEnd reason — this is
    // the HUMAN capture/diff feature; the annotation is agent-envelope
    // vocabulary.
    let (raw, _end) = executor
        .run_command(
            session_id,
            command,
            DEFAULT_CAPTURE_TIMEOUT,
            DEFAULT_QUIESCENCE,
        )
        .await
        .map_err(|e| e.to_string())?;

    // Redact the whole captured block before it hits disk (T22).
    let content = RedactionFilter::standard().redact(&raw);
    let captured_at = now_rfc3339();
    let record = CaptureRecord {
        id: make_id(&device_id, &captured_at),
        device_id,
        command: command.to_string(),
        captured_at,
        content,
    };
    save_record(&record)?;
    Ok(record)
}

/// Run `command` in an open SSH session, redact the output, and save it as a
/// capture. Human-initiated — NOT policy-gated (see module docs).
#[tauri::command]
pub async fn capture_command(
    state: State<'_, AppState>,
    session_id: String,
    command: String,
) -> Result<CaptureMeta, String> {
    Ok(capture_one(&state.ssh, &session_id, &command).await?.meta())
}

/// Run a *collection* — an ordered set of commands — in one session,
/// sequentially (each capture waits for the previous to quiesce), saving each
/// as a capture. Human-initiated and NOT policy-gated: exactly like firing the
/// same commands from the button bar, just sequenced with output capture (no
/// new agent tool; Rules 2/3 hold). A failing command is collected and skipped
/// so one bad command does not abort the sweep; an error propagates only if
/// EVERY command failed.
#[tauri::command]
pub async fn run_collection(
    state: State<'_, AppState>,
    session_id: String,
    commands: Vec<String>,
) -> Result<Vec<CaptureMeta>, String> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for command in &commands {
        if command.trim().is_empty() {
            continue;
        }
        match capture_one(&state.ssh, &session_id, command).await {
            Ok(rec) => out.push(rec.meta()),
            Err(e) => errors.push(format!("{command}: {e}")),
        }
    }
    if out.is_empty() && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(out)
}

/// All saved captures, newest first.
#[tauri::command]
pub async fn list_captures() -> Result<Vec<CaptureMeta>, String> {
    let dir = match captures_dir() {
        Ok(d) => d,
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path()) {
                if let Ok(rec) = serde_json::from_slice::<CaptureRecord>(&bytes) {
                    out.push(rec.meta());
                }
            }
        }
    }
    // Newest first (RFC-3339 sorts lexicographically by time).
    out.sort_by(|a, b| b.captured_at.cmp(&a.captured_at));
    Ok(out)
}

/// The redacted content of a saved capture.
#[tauri::command]
pub async fn read_capture(id: String) -> Result<String, String> {
    Ok(read_record(&id)?.content)
}

/// Delete a saved capture.
#[tauri::command]
pub async fn delete_capture(id: String) -> Result<(), String> {
    if id != sanitize(&id) {
        return Err("invalid capture id".to_string());
    }
    let path = captures_dir()?.join(format!("{id}.json"));
    std::fs::remove_file(&path).map_err(|e| format!("cannot delete capture: {e}"))
}

/// Line-diff two saved captures (old = `a`, new = `b`).
#[tauri::command]
pub async fn diff_captures(a: String, b: String) -> Result<DiffResult, String> {
    let old = read_record(&a)?;
    let new = read_record(&b)?;
    Ok(diff_lines(&old.content, &new.content))
}

/// Absolute path of the captures directory — surfaced in the dialog footer
/// so the user can find their saved captures on disk.
#[tauri::command]
pub async fn captures_dir_path() -> Result<String, String> {
    Ok(captures_dir()?.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_and_shell_chars() {
        assert_eq!(sanitize("2026-07-23T14:32:01.5Z"), "2026-07-23T14-32-01.5Z");
        assert_eq!(sanitize("../../etc/passwd"), "..-..-etc-passwd");
        assert_eq!(sanitize("core rtr/1"), "core-rtr-1");
    }

    #[test]
    fn make_id_is_filesystem_safe() {
        let id = make_id("edge rtr:1", "2026-07-23T14:32:01Z");
        assert_eq!(id, sanitize(&id), "id must be its own sanitized form");
        assert!(id.contains("__"));
    }

    #[test]
    fn read_record_rejects_traversal_ids() {
        assert!(read_record("../secrets").is_err());
        assert!(read_record("a/b").is_err());
    }

    #[test]
    fn capture_record_round_trips_through_json() {
        let rec = CaptureRecord {
            id: "t__dev".into(),
            device_id: "dev".into(),
            command: "show run".into(),
            captured_at: "2026-07-23T00:00:00Z".into(),
            content: "line1\nline2\n".into(),
        };
        let json = serde_json::to_vec_pretty(&rec).unwrap();
        let back: CaptureRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.content, rec.content);
        assert_eq!(back.meta().command, "show run");
    }
}
