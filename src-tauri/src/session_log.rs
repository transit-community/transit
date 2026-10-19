//! Phase 3 — continuous session logging.
//!
//! A passive **second** subscriber on a session's output broadcast that
//! streams each chunk to a user-chosen file, optionally prefixing every
//! line with a UTC timestamp. "Log this session".
//!
//! # Why a second subscriber is safe
//! `Session::subscribe()` hands out an independent `broadcast::Receiver`.
//! The reader task's `send` is fire-and-forget, and a slow/lagging
//! receiver only ever sees `RecvError::Lagged` on *its own* receiver —
//! it never backpressures the PTY or the terminal's own subscriber. So a
//! slow disk degrades the log (a dropped-lines marker), never the session.
//!
//! # Redaction (T22 / T_SESSION_LOG)
//! Like [`crate::session_export`], the redaction filter runs on the bytes
//! **before** they hit disk, so a log never writes a device secret in
//! cleartext. Unlike export (a one-shot snapshot of the whole scrollback),
//! logging is a stream, so redaction runs **per broadcast chunk**. That is
//! best-effort for a secret that straddles a chunk boundary — e.g. a
//! multi-line PEM block split across two `recv()`s can slip through — the
//! same best-effort framing as the agent boundary. A device's own operator
//! is the audience, they already see the raw bytes on screen, and starting
//! a log is an explicit user action to a path they choose; per-chunk
//! redaction removes the common single-burst secret (a `show run` password
//! line) without pretending to be a guarantee.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{broadcast, Mutex};
use transit_agent::RedactionFilter;

use crate::commands::AppState;
use crate::console::ConsoleState;

/// Frontend invalidates its `["sessionLogs"]` query on this event. Emitted
/// when a logger self-terminates (session ended / disk error) so the
/// recording indicator clears without the user stopping the log by hand.
const LOG_CHANGED_EVENT: &str = "session-log:changed";

/// Managed state: the set of sessions currently being logged. The map is
/// `Arc`-shared into each writer task so a task can remove its own entry
/// when the session ends.
pub struct SessionLogState {
    loggers: Arc<Mutex<HashMap<String, LogHandle>>>,
}

impl Default for SessionLogState {
    fn default() -> Self {
        Self {
            loggers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct LogHandle {
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct StartLogArgs {
    pub session_id: String,
    pub destination: PathBuf,
    /// Prefix each line with a UTC timestamp. Defaults to `true` — a
    /// timestamped log is the network-engineer expectation.
    #[serde(default = "default_true")]
    pub timestamped: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionLogInfo {
    pub session_id: String,
    pub path: PathBuf,
}

/// Start logging an open session's output to `destination`.
///
/// Fall-through across SSH + console state, same shape as
/// [`crate::session_export::export_session`]. The file is opened
/// create+append so re-starting a log on the same path continues it
/// rather than truncating a prior capture.
#[tauri::command]
pub async fn start_session_log(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    console_state: State<'_, Arc<ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    log_state: State<'_, SessionLogState>,
    args: StartLogArgs,
) -> Result<SessionLogInfo, String> {
    let StartLogArgs {
        session_id,
        destination,
        timestamped,
    } = args;

    let mut loggers = log_state.loggers.lock().await;
    if loggers.contains_key(&session_id) {
        return Err(format!("session {session_id} is already being logged"));
    }

    let rx = lookup_subscribe(&state, &console_state, &local_state, &session_id).await?;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&destination)
        .map_err(|e| format!("cannot open log file: {e}"))?;

    let task = tokio::spawn(writer_loop(
        app,
        Arc::clone(&log_state.loggers),
        session_id.clone(),
        rx,
        file,
        timestamped,
    ));
    loggers.insert(
        session_id.clone(),
        LogHandle {
            task,
            path: destination.clone(),
        },
    );
    Ok(SessionLogInfo {
        session_id,
        path: destination,
    })
}

/// Stop logging a session (user-initiated). Aborts the writer task and
/// drops its handle. A no-op if the session wasn't being logged.
#[tauri::command]
pub async fn stop_session_log(
    log_state: State<'_, SessionLogState>,
    session_id: String,
) -> Result<(), String> {
    let mut loggers = log_state.loggers.lock().await;
    if let Some(handle) = loggers.remove(&session_id) {
        handle.task.abort();
    }
    Ok(())
}

/// The sessions currently being logged (drives the recording indicator).
#[tauri::command]
pub async fn list_session_logs(
    log_state: State<'_, SessionLogState>,
) -> Result<Vec<SessionLogInfo>, String> {
    let loggers = log_state.loggers.lock().await;
    Ok(loggers
        .iter()
        .map(|(id, h)| SessionLogInfo {
            session_id: id.clone(),
            path: h.path.clone(),
        })
        .collect())
}

/// Resolve a session id to a fresh broadcast receiver. Mirrors
/// [`crate::session_export`]'s `lookup_scrollback` fall-through: a UUID is
/// unique to one transport, so only one map owns it.
async fn lookup_subscribe(
    state: &State<'_, AppState>,
    console_state: &State<'_, Arc<ConsoleState>>,
    local_state: &State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: &str,
) -> Result<broadcast::Receiver<Bytes>, String> {
    {
        let guard = state.ssh.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.subscribe());
        }
    }
    {
        let guard = console_state.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.subscribe());
        }
    }
    {
        let guard = local_state.sessions.lock().await;
        if let Some(entry) = guard.get(session_id) {
            return Ok(entry.session.subscribe());
        }
    }
    Err(format!("session {session_id} not found"))
}

async fn writer_loop(
    app: tauri::AppHandle,
    loggers: Arc<Mutex<HashMap<String, LogHandle>>>,
    session_id: String,
    mut rx: broadcast::Receiver<Bytes>,
    file: std::fs::File,
    timestamped: bool,
) {
    let filter = RedactionFilter::standard();
    let mut writer = std::io::BufWriter::new(file);
    // Partial trailing line carried across chunks so a timestamp only ever
    // prefixes a complete line.
    let mut pending = String::new();

    loop {
        match rx.recv().await {
            Ok(bytes) => {
                // Redact per chunk (see module docs), then timestamp.
                let text = String::from_utf8_lossy(&bytes);
                let redacted = filter.redact(&text);
                if let Err(e) = write_chunk(&mut writer, &redacted, timestamped, &mut pending) {
                    let _ = writeln!(
                        writer,
                        "\n[transit-log: write error: {e} — logging stopped]"
                    );
                    let _ = writer.flush();
                    break;
                }
                // Flush eagerly — a crash shouldn't lose the tail. Ignore
                // transient flush errors; the next write surfaces a hard one.
                let _ = writer.flush();
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let _ = writeln!(
                    writer,
                    "\n[transit-log: dropped {n} message(s) — logger fell behind]"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Session ended: flush the trailing partial line + exit.
                if !pending.is_empty() {
                    let _ = writeln!(writer, "{pending}");
                }
                let _ = writer.flush();
                break;
            }
        }
    }

    // Self-remove so the recording indicator clears, then nudge the
    // frontend to re-fetch. `remove` on an already-running task just drops
    // the handle (no abort-of-self); stop_session_log is the abort path.
    loggers.lock().await.remove(&session_id);
    let _ = app.emit(LOG_CHANGED_EVENT, &session_id);
}

/// Append `text` to `writer`. When `timestamped`, every complete line
/// (terminated by `\n`) is prefixed with a UTC RFC-3339 timestamp;
/// incomplete trailing text is buffered in `pending` until its newline
/// arrives in a later chunk. Pure so it can be unit-tested without I/O.
fn write_chunk(
    writer: &mut impl Write,
    text: &str,
    timestamped: bool,
    pending: &mut String,
) -> std::io::Result<()> {
    if !timestamped {
        return writer.write_all(text.as_bytes());
    }
    let mut buf = std::mem::take(pending);
    buf.push_str(text);
    let bytes = buf.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            // `start` and `i` both sit on ASCII boundaries (`\n` / after
            // a `\n`), so slicing the String by these byte offsets is safe.
            write!(writer, "[{}] {}", now_rfc3339(), &buf[start..=i])?;
            start = i + 1;
        }
    }
    *pending = buf[start..].to_string();
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("????"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_mode_writes_bytes_verbatim() {
        let mut out: Vec<u8> = Vec::new();
        let mut pending = String::new();
        write_chunk(
            &mut out,
            "show version\r\nCisco IOS\r\n",
            false,
            &mut pending,
        )
        .unwrap();
        assert_eq!(out, b"show version\r\nCisco IOS\r\n");
        assert!(pending.is_empty());
    }

    #[test]
    fn timestamped_mode_prefixes_each_complete_line() {
        let mut out: Vec<u8> = Vec::new();
        let mut pending = String::new();
        write_chunk(&mut out, "line one\nline two\n", true, &mut pending).unwrap();
        let s = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line carries a bracketed timestamp prefix + the content.
        assert!(lines[0].starts_with('['), "missing timestamp: {}", lines[0]);
        assert!(lines[0].ends_with("line one"));
        assert!(lines[1].ends_with("line two"));
        assert!(pending.is_empty());
    }

    #[test]
    fn timestamped_mode_buffers_partial_line_across_chunks() {
        let mut out: Vec<u8> = Vec::new();
        let mut pending = String::new();
        // First chunk ends mid-line — nothing written yet, buffered.
        write_chunk(&mut out, "parti", true, &mut pending).unwrap();
        assert!(out.is_empty());
        assert_eq!(pending, "parti");
        // Second chunk completes the line.
        write_chunk(&mut out, "al line\n", true, &mut pending).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.ends_with("partial line\n"));
        assert!(pending.is_empty());
    }

    #[test]
    fn redaction_runs_before_write() {
        // A single-chunk secret is redacted (proves the filter is wired;
        // the streaming caller redacts each chunk before write_chunk).
        let filter = RedactionFilter::standard();
        let redacted = filter.redact("enable secret 0 SuperSecret123\n");
        assert!(
            !redacted.contains("SuperSecret123"),
            "secret leaked: {redacted}"
        );
    }
}
