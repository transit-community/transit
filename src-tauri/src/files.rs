//! v5.0.0 — Tauri wiring for `transit_files` (the Files / SFTP surface).
//!
//! Design: the files pane sftp design notes (not included in this repository) (connection path) and
//! §6 (this IPC surface). Threat model: T43.
//!
//! A Files session opens its **own** SSH connection (SecureFX behavior)
//! through the same `transit_ssh` machinery a terminal tab uses — same
//! cipher policy, same host-key TOFU + changed-key modal, same weak-crypto
//! opt-in, same auth-profile resolution — and then requests the `sftp`
//! subsystem instead of a PTY. The shared piece is
//! [`crate::ssh::establish_connection`]; the `pending_tofu` /
//! `pending_weak_crypto` responder maps and their `verify_host_key` /
//! `weak_crypto_decision` IPC are **shared, not cloned**, so both dialogs
//! work here unchanged. Those maps are single-slot keyed `(host, port)`, so
//! Files launches must stay strictly sequential — exactly like bulk SSH
//! connect.
//!
//! Events:
//! - `files:transfer:update` — one topic for every transfer, all sessions.
//! - `files:{session_id}:closed` — the synthesized closed signal (the
//!   stream-level EOF/error watch in `transit_files::sftp`), so the pane can
//!   show a reconnect banner instead of a live browser over a dead socket.
//!
//! Per Rule 1 nothing any command returns is a credential: session ids,
//! paths, entry metadata, transfer counts.
//!
//! # Agent-blindness (load-bearing — plan §2, threat model T43)
//!
//! File transfer is a HUMAN surface, the exact classification of the local
//! terminal (T42), the button bar, and the broadcast bar. [`FilesState`] is
//! passed to **no** agent-side constructor: it appears in neither
//! `UnifiedScrollbackSource` nor `UnifiedSessionExecutor` (rebuilt per chat
//! turn in `chat.rs`), and `scoped_session_view` wraps only those unified
//! types. Files sessions also join **no** shared transport dispatch —
//! `send_input` / `resize_pty` / `clear_scrollback` / `disconnect_session` /
//! `list_open_sessions` / `session_log` / `session_export` / `capture` have
//! no files arm — so no terminal-shaped command can reach one either.
//! Belt and braces at the dependency-graph level: `deny.toml` bans any
//! dependency on `transit_files` outside `transit_app`.
//!
//! **Do NOT pass `FilesState` (or a `FilesSession`) to any agent-side
//! seam.** Rule 2's tool surface has no Files arm.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use transit_files::{
    DirListing, Direction, FilesConfig, FilesSession, LocalRoot, OverwritePolicy,
    TransferDescriptor, TransferEvent, TransferItem,
};
use transit_ssh::Connection;
use uuid::Uuid;

use crate::commands::AppState;
use crate::ssh::{
    establish_connection_chain, lookup_connect_params, ResolvedConnectParams, SshState,
};

/// Bound on `request_subsystem` + the SFTP INIT handshake (plan §4
/// "Timeouts"). The authenticated connection is already up at this point, so
/// this only covers the two channel round-trips; a device that accepts the
/// subsystem but never speaks SFTP must not hang the launch.
const SUBSYSTEM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// One topic for every transfer in every session — the frontend keeps an
/// event-built mirror keyed by transfer id.
const TRANSFER_TOPIC: &str = "files:transfer:update";

pub struct FilesState {
    pub sessions: Mutex<HashMap<String, FilesSessionEntry>>,
}

pub struct FilesSessionEntry {
    pub session: Arc<FilesSession>,
    /// Inventory id of the device — the tab label and what `files_reconnect`
    /// re-resolves (the frontend never re-sends it). Doubles as the label:
    /// the removed `label` field was a never-read duplicate of this (D3).
    pub device_id: String,
    /// The `Arc<Connection>` is held ONLY to keep the russh handle alive:
    /// dropping it aborts the connect actor and kills every channel
    /// instantly, including this session's SFTP channel (the lesson
    /// `SessionEntry._connection` already learned).
    pub _connection: Arc<Connection>,
    /// Forwards engine transfer events to `files:transfer:update`. NOT
    /// aborted on teardown: it must stay alive to drain the `Cancelled`
    /// events `close()` produces, and it ends by itself when the session
    /// (and thus the event sender) drops.
    pub forwarder: tokio::task::JoinHandle<()>,
    /// Emits `files:{id}:closed` once. Aborted before a deliberate
    /// disconnect/reconnect so a *user-driven* teardown can't masquerade as
    /// a dropped link.
    pub closed_bridge: tokio::task::JoinHandle<()>,
}

impl FilesState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for FilesState {
    fn default() -> Self {
        Self::new()
    }
}

/// Stash the state on the app. Called from `lib.rs::setup` alongside
/// `local_shell::install`. No watchers — a Files session has no hot-plug.
pub fn install(app: &AppHandle) {
    app.manage(Arc::new(FilesState::new()));
}

// ---------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct FilesConnectResult {
    pub session_id: String,
    /// Tab label — the inventory id the user chose ("vEX1").
    pub label: String,
    /// The server's canonical login directory, so the remote pane opens
    /// somewhere useful.
    pub home: String,
}

#[derive(Debug, Serialize)]
pub struct FilesReconnectResult {
    pub home: String,
}

/// `files:transfer:update` payload: the engine's event plus the session it
/// belongs to (the engine itself is deliberately identity-free).
#[derive(Debug, Serialize, Clone)]
struct TransferUpdatePayload {
    session_id: String,
    #[serde(flatten)]
    event: TransferEvent,
}

#[derive(Debug, Serialize, Clone)]
struct FilesClosedPayload {
    session_id: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
pub struct FilesEnqueueArgs {
    pub session_id: String,
    pub direction: Direction,
    pub items: Vec<TransferItem>,
    pub policy: OverwritePolicy,
}

#[derive(Debug, Deserialize)]
pub struct FilesConflictArgs {
    pub session_id: String,
    pub direction: Direction,
    pub items: Vec<TransferItem>,
}

// ---------------------------------------------------------------------
// Connect / reconnect / disconnect
// ---------------------------------------------------------------------

/// Open a Files (SFTP) session against an inventory device.
///
/// May emit `host-key:confirm` / `weak-crypto:confirm` mid-flight and block
/// on the user's verdict, exactly like `connect_device` — the responder maps
/// are shared.
#[tauri::command]
pub async fn files_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    files: State<'_, Arc<FilesState>>,
    device_id: String,
) -> Result<FilesConnectResult, String> {
    // Defense in depth: the frontend also hides the rail, but a disabled
    // (MDM / DLP-locked) deployment must refuse the direct IPC call too.
    ensure_files_enabled()?;
    // Same HRT dance as `connect_device` (ssh.rs): the russh handshake +
    // `request_subsystem` sequence captures borrows whose `Send` derivation
    // rustc can't pin to a higher-ranked lifetime inside the
    // `tauri::command` macro, so the whole flow is handed to
    // `tauri::async_runtime::spawn` (a plain `'static` Send bound) and the
    // result comes back over a oneshot.
    let secrets = Arc::clone(&state.secrets);
    let ssh = Arc::clone(&state.ssh);
    let files = Arc::clone(&*files);
    let params = lookup_connect_params(&state, &device_id).await?;
    let (tx, rx) = oneshot::channel();
    tauri::async_runtime::spawn(async move {
        let result = do_files_connect(app, secrets, ssh, files, device_id, params).await;
        let _ = tx.send(result);
    });
    rx.await
        .map_err(|_| "files connect task panicked".to_string())?
}

// Private indirection between the `tauri::command` and the actual russh
// flow; the boxed future sidesteps the macro's HRT auto-Send analysis.
#[allow(clippy::type_complexity)]
fn do_files_connect(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    files: Arc<FilesState>,
    device_id: String,
    params: ResolvedConnectParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<FilesConnectResult, String>> + Send>>
{
    Box::pin(do_files_connect_inner(
        app, secrets, ssh, files, device_id, params,
    ))
}

async fn do_files_connect_inner(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    files: Arc<FilesState>,
    device_id: String,
    params: ResolvedConnectParams,
) -> Result<FilesConnectResult, String> {
    let session_id = Uuid::new_v4().to_string();
    let (session, connection, home) =
        open_sftp_session(&app, secrets, ssh, &device_id, params).await?;

    let (forwarder, closed_bridge) = spawn_bridges(&app, &session_id, &session);
    let entry = FilesSessionEntry {
        session,
        device_id: device_id.clone(),
        _connection: connection,
        forwarder,
        closed_bridge,
    };
    files
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), entry);

    tracing::info!(session = %session_id, device = %device_id, "files session opened");
    Ok(FilesConnectResult {
        session_id,
        label: device_id,
        home,
    })
}

/// Re-establish a session **under the same id**, so the pane's tab, cwds and
/// event topics all survive (`files:{id}:*` are unchanged). Mirrors
/// `restart_local_shell`'s in-place swap.
///
/// The queue is NOT resumed: the old session's transfers are cancelled and
/// report `Cancelled` (v1 — plan §5).
#[tauri::command]
pub async fn files_reconnect(
    app: AppHandle,
    state: State<'_, AppState>,
    files: State<'_, Arc<FilesState>>,
    session_id: String,
) -> Result<FilesReconnectResult, String> {
    // Same off-switch as `files_connect`: if config flips the surface off
    // mid-session, don't re-establish even for an existing tab.
    ensure_files_enabled()?;
    let device_id = {
        let guard = files.sessions.lock().await;
        let Some(entry) = guard.get(&session_id) else {
            return Err(format!("session {session_id} not found"));
        };
        entry.device_id.clone()
    };

    let secrets = Arc::clone(&state.secrets);
    let ssh = Arc::clone(&state.ssh);
    let files = Arc::clone(&*files);
    let params = lookup_connect_params(&state, &device_id).await?;
    let (tx, rx) = oneshot::channel();
    tauri::async_runtime::spawn(async move {
        let result =
            do_files_reconnect(app, secrets, ssh, files, session_id, device_id, params).await;
        let _ = tx.send(result);
    });
    rx.await
        .map_err(|_| "files reconnect task panicked".to_string())?
}

#[allow(clippy::type_complexity)]
fn do_files_reconnect(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    files: Arc<FilesState>,
    session_id: String,
    device_id: String,
    params: ResolvedConnectParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<FilesReconnectResult, String>> + Send>>
{
    Box::pin(do_files_reconnect_inner(
        app, secrets, ssh, files, session_id, device_id, params,
    ))
}

async fn do_files_reconnect_inner(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    files: Arc<FilesState>,
    session_id: String,
    device_id: String,
    params: ResolvedConnectParams,
) -> Result<FilesReconnectResult, String> {
    // Build the replacement BEFORE touching the live entry: a failed
    // reconnect must leave the existing (dead) session in place so the pane
    // keeps its banner instead of losing the tab.
    let (session, connection, home) =
        open_sftp_session(&app, secrets, ssh, &device_id, params).await?;
    let (forwarder, closed_bridge) = spawn_bridges(&app, &session_id, &session);

    let mut guard = files.sessions.lock().await;
    let Some(entry) = guard.get_mut(&session_id) else {
        // Closed by the user between the two locks — discard what we built.
        drop(guard);
        closed_bridge.abort();
        if let Ok(session) = Arc::try_unwrap(session) {
            session.close().await;
        }
        forwarder.abort();
        return Err(format!("session {session_id} was closed"));
    };

    // Abort the OLD closed-bridge before the old session drops: its watch
    // sender disappearing would otherwise emit `files:{id}:closed` for an id
    // that is live again, and the pane would re-raise its banner on top of a
    // successful reconnect.
    entry.closed_bridge.abort();
    let old_session = std::mem::replace(&mut entry.session, session);
    let _old_forwarder = std::mem::replace(&mut entry.forwarder, forwarder);
    entry.closed_bridge = closed_bridge;

    // Finding A4: cancel the old session's transfers BEFORE the old
    // `Arc<Connection>` drops. Dropping the connection aborts the connect
    // actor and kills the SFTP channel instantly, so an in-flight transfer
    // would fail its next op as a transport Error instead of the Cancelled we
    // want (and, combined with the atomic upload in A1, a reconnect-
    // interrupted upload then cleans up its temp rather than a truncated real
    // file). cancel_all is synchronous, so it is safe under the lock.
    old_session.cancel_all();
    let old_connection = std::mem::replace(&mut entry._connection, connection);
    drop(guard);

    // The old session's transfers report `Cancelled` through the OLD
    // forwarder, so leave it running — it self-terminates when the old
    // session (and thus its event sender) drops. Finding A5: do NOT abort the
    // forwarder here, or those terminal `Cancelled` events never reach
    // `files:transfer:update` and the queue rows stay live forever.
    match Arc::try_unwrap(old_session) {
        Ok(session) => session.close().await,
        Err(_) => {
            tracing::warn!(
                session = %session_id,
                "previous files session had outstanding references at reconnect; \
                 relying on Drop to clean up"
            );
        }
    }
    // Release the old connection only AFTER the drain, so the winding-down
    // transfers observe cancellation over a live channel (A4).
    drop(old_connection);

    tracing::info!(session = %session_id, device = %device_id, "files session reconnected");
    Ok(FilesReconnectResult { home })
}

/// Cancel this session's transfers, close the SFTP session, and drop the
/// connection.
///
/// Deliberately NOT reachable from `ssh::disconnect_session`: Files sessions
/// join no shared transport dispatch (plan decision 7).
#[tauri::command]
pub async fn files_disconnect(
    files: State<'_, Arc<FilesState>>,
    session_id: String,
) -> Result<(), String> {
    let entry = files.sessions.lock().await.remove(&session_id);
    let Some(entry) = entry else {
        return Err(format!("session {session_id} not found"));
    };
    // A user-driven close is not a dropped link — don't emit `:closed`.
    entry.closed_bridge.abort();
    entry.session.cancel_all();
    match Arc::try_unwrap(entry.session) {
        // `close()` drains the queue so each parked transfer emits
        // `Cancelled` through the still-live forwarder.
        Ok(session) => session.close().await,
        Err(_) => {
            // Finding A5: do NOT abort the forwarder. It is the only path
            // from the engine to `files:transfer:update`; aborting it drops
            // the `Cancelled` events the outstanding session still produces
            // and leaves the queue rows live forever (inflating the quit
            // veto). It self-terminates once the last session ref (and its
            // event sender) drops — exactly why the Ok path never aborts it.
            tracing::warn!(
                session = %session_id,
                "files session had outstanding references at disconnect; \
                 relying on Drop to clean up"
            );
        }
    }
    tracing::info!(session = %session_id, "files session closed");
    Ok(())
}

// ---------------------------------------------------------------------
// Remote pane
// ---------------------------------------------------------------------

// All remote ops gate on `ensure_files_enabled()?` too, not just
// connect/reconnect (finding A7): flipping `[files] enabled = false` must
// fully disable the surface — including operations on an already-open
// session — or the DLP off-switch has a hole. This matches the local-op
// half (`files_local_*`) and the DLP claim in T43.

#[tauri::command]
pub async fn files_list_dir(
    files: State<'_, Arc<FilesState>>,
    session_id: String,
    path: String,
) -> Result<DirListing, String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &session_id).await?;
    session.list_dir(&path).await.map_err(|e| e.to_string())
}

// `files_stat` (D2) was registered + wrapped but had no production caller —
// removed. `RemoteFs::stat` / `FilesSession::stat` stay (used by the
// roundtrip tests and reserved for the properties-panel fast-follow).

#[tauri::command]
pub async fn files_mkdir(
    files: State<'_, Arc<FilesState>>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &session_id).await?;
    session.mkdir(&path).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_rename(
    files: State<'_, Arc<FilesState>>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &session_id).await?;
    session.rename(&from, &to).await.map_err(|e| e.to_string())
}

/// Permanent delete (no trash in v1) — `recursive` is required for a
/// non-empty directory, and the frontend's confirm names the directory.
#[tauri::command]
pub async fn files_delete(
    files: State<'_, Arc<FilesState>>,
    session_id: String,
    path: String,
    recursive: bool,
) -> Result<(), String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &session_id).await?;
    session
        .delete(&path, recursive)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Local pane
// ---------------------------------------------------------------------
//
// Rust-side `std::fs` in `spawn_blocking` — never `tauri-plugin-fs` (absent
// from the project; the capability surface grants only dialog open/save and
// stays that way). All five are gated by the same `[files] enabled`
// off-switch: a DLP-locked deployment turns the WHOLE surface off, so these
// must not remain a live filesystem API when the rail is hidden (the
// `list_available_shells` precedent).

#[tauri::command]
pub async fn files_local_list_dir(path: Option<String>) -> Result<DirListing, String> {
    ensure_files_enabled()?;
    transit_files::local::list_dir(path.as_deref(), FilesConfig::default().max_entries)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_local_roots() -> Result<Vec<LocalRoot>, String> {
    ensure_files_enabled()?;
    transit_files::local::roots()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_local_mkdir(path: String) -> Result<(), String> {
    ensure_files_enabled()?;
    transit_files::local::mkdir(&path)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_local_rename(from: String, to: String) -> Result<(), String> {
    ensure_files_enabled()?;
    transit_files::local::rename(&from, &to)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_local_delete(path: String, recursive: bool) -> Result<(), String> {
    ensure_files_enabled()?;
    transit_files::local::delete(&path, recursive)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------

/// Destinations that already exist — the pre-flight behind the single
/// Overwrite-all / Skip-existing / Cancel dialog.
#[tauri::command]
pub async fn files_check_conflicts(
    files: State<'_, Arc<FilesState>>,
    args: FilesConflictArgs,
) -> Result<Vec<String>, String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &args.session_id).await?;
    session
        .check_conflicts(args.direction, &args.items)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn files_enqueue(
    files: State<'_, Arc<FilesState>>,
    args: FilesEnqueueArgs,
) -> Result<Vec<TransferDescriptor>, String> {
    ensure_files_enabled()?;
    let session = session_of(&files, &args.session_id).await?;
    session
        .enqueue(args.direction, args.items, args.policy)
        .map_err(|e| e.to_string())
}

/// Cancel a queued or running transfer. Transfer ids are session-agnostic
/// on the wire (the queue strip is global), so this asks each session in
/// turn — only one owns any given id.
#[tauri::command]
pub async fn files_cancel(
    files: State<'_, Arc<FilesState>>,
    transfer_id: String,
) -> Result<(), String> {
    ensure_files_enabled()?;
    let sessions: Vec<Arc<FilesSession>> = files
        .sessions
        .lock()
        .await
        .values()
        .map(|e| Arc::clone(&e.session))
        .collect();
    for session in sessions {
        if session.cancel_transfer(&transfer_id) {
            return Ok(());
        }
    }
    Err(format!("transfer {transfer_id} not found"))
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// The off-switch gate. Split from the pure [`ensure_files_enabled_at`] so a
/// test can inject the bool and assert the refusal path, not just the Ok
/// path (finding B5).
fn ensure_files_enabled() -> Result<(), String> {
    ensure_files_enabled_at(crate::commands::resolve_files_enabled())
}

fn ensure_files_enabled_at(enabled: bool) -> Result<(), String> {
    if enabled {
        Ok(())
    } else {
        Err("file transfer is disabled by configuration".to_string())
    }
}

/// Clone the session `Arc` out of the map and drop the guard before any
/// transport await — holding the global table across a wedged SFTP request
/// would freeze every other Files session (the `send_input` lesson).
///
/// Takes `&FilesState` (not `&State<'_, …>`) so it is unit-testable against a
/// plain, empty `FilesState` (finding B5); the `#[tauri::command]` callers
/// pass `&files`, which deref-coerces from `&State<'_, Arc<FilesState>>`.
async fn session_of(files: &FilesState, session_id: &str) -> Result<Arc<FilesSession>, String> {
    let guard = files.sessions.lock().await;
    guard
        .get(session_id)
        .map(|e| Arc::clone(&e.session))
        // Byte-identical to every other transport's not-found error.
        .ok_or_else(|| format!("session {session_id} not found"))
}

/// The shared connect body: authenticate exactly like a terminal connect,
/// then take the `sftp` subsystem instead of a PTY.
async fn open_sftp_session(
    app: &AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    device_id: &str,
    params: ResolvedConnectParams,
) -> Result<(Arc<FilesSession>, Arc<Connection>, String), String> {
    // `vendor` is unused here: SFTP has no vendor-specific behavior (unlike
    // the PTY path's paging init).
    let (connection, _vendor) =
        establish_connection_chain(app.clone(), secrets, ssh, device_id.to_string(), params)
            .await?;
    let connection = Arc::new(connection);

    let session = tokio::time::timeout(SUBSYSTEM_CONNECT_TIMEOUT, async {
        let stream = connection
            .open_subsystem_stream("sftp")
            .await
            .map_err(|e| e.to_string())?;
        FilesSession::connect(stream, FilesConfig::default())
            .await
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| {
        "timed out starting the SFTP subsystem — the device accepted the connection but did \
         not start its SFTP server"
            .to_string()
    })??;

    let home = session.home().await.map_err(|e| e.to_string())?;
    Ok((Arc::new(session), connection, home))
}

/// Spawn the two per-session tasks: the transfer-event forwarder and the
/// closed-signal bridge.
fn spawn_bridges(
    app: &AppHandle,
    session_id: &str,
    session: &Arc<FilesSession>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let forwarder = match session.take_events() {
        Some(rx) => spawn_transfer_forwarder(app.clone(), session_id.to_string(), rx),
        // Unreachable in practice (a fresh session always yields its
        // receiver once); a no-op task keeps the entry shape uniform.
        None => {
            tracing::warn!(session = %session_id, "files session had no event receiver");
            tokio::spawn(async {})
        }
    };
    let closed_bridge =
        spawn_closed_bridge(app.clone(), session_id.to_string(), session.closed_rx());
    (forwarder, closed_bridge)
}

fn spawn_transfer_forwarder(
    app: AppHandle,
    session_id: String,
    mut rx: mpsc::UnboundedReceiver<TransferEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let payload = TransferUpdatePayload {
                session_id: session_id.clone(),
                event,
            };
            if let Err(e) = app.emit(TRANSFER_TOPIC, payload) {
                tracing::warn!(?e, "failed to emit files transfer update");
            }
        }
    })
}

/// Emit `files:{id}:closed` exactly once, when the stream dies.
///
/// Level-triggered first (`borrow_and_update`), then edge: the session may
/// already be finished before this task first runs, and a `Notify`-style
/// edge-only wait would lose that flip forever — the
/// `spawn_output_bridge` bug (ssh.rs:885) in a new place.
fn spawn_closed_bridge(
    app: AppHandle,
    session_id: String,
    mut closed_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let topic = format!("files:{session_id}:closed");
    tokio::spawn(async move {
        let emit = |reason: &str| {
            let payload = FilesClosedPayload {
                session_id: session_id.clone(),
                reason: reason.to_string(),
            };
            if let Err(e) = app.emit(&topic, payload) {
                tracing::warn!(?e, "failed to emit files closed");
            }
        };
        if *closed_rx.borrow_and_update() {
            emit("the file-transfer connection closed");
            return;
        }
        // `Err` = the sender dropped, i.e. the session is gone. A deliberate
        // disconnect/reconnect aborts this task first, so reaching here
        // means the link itself failed.
        let _ = closed_rx.changed().await;
        emit("the file-transfer connection closed");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `session_of` on an empty state returns the shared not-found wording —
    /// exercising the REAL function (finding B5: the old test only compared
    /// two `format!` strings and never touched `session_of`). The wording is
    /// byte-identical to every other transport's so no caller can
    /// distinguish "no such session" from "a different kind of session".
    #[tokio::test]
    async fn session_of_returns_the_shared_not_found_wording() {
        let files = FilesState::new();
        // `.err()` drops the Ok value, so we don't need `FilesSession: Debug`.
        let err = session_of(&files, "abc-123")
            .await
            .err()
            .expect("an empty state has no sessions");
        assert_eq!(err, "session abc-123 not found");
    }

    /// The injectable gate refuses when disabled and passes when enabled
    /// (finding A7/B5: assert the Err path, not just the Ok default).
    #[test]
    fn ensure_files_enabled_gate_refuses_when_disabled() {
        assert!(ensure_files_enabled_at(true).is_ok());
        let err = ensure_files_enabled_at(false).expect_err("disabled must refuse");
        assert!(
            err.contains("disabled by configuration"),
            "unexpected message: {err}"
        );
    }

    /// The `files:transfer:update` payload flattens the engine event beside
    /// `session_id` — pinning the wire shape the frontend's event mirror
    /// keys on (a nested `event` object would silently break it).
    #[test]
    fn transfer_payload_flattens_the_engine_event() {
        let payload = TransferUpdatePayload {
            session_id: "s1".to_string(),
            event: TransferEvent {
                id: "t1".to_string(),
                direction: Direction::Download,
                state: transit_files::TransferState::Running,
                name: "juniper.conf".to_string(),
                bytes_done: 10,
                bytes_total: Some(20),
                files_done: 0,
                files_total: None,
                rate_bps: Some(100),
                skipped: 0,
                warnings: Vec::new(),
                error: None,
            },
        };
        let json = serde_json::to_value(&payload).expect("payload serializes");
        assert_eq!(json["session_id"], "s1");
        assert_eq!(json["id"], "t1");
        assert_eq!(json["direction"], "download");
        assert_eq!(json["state"], "running");
        assert_eq!(json["bytes_total"], 20);
        assert!(json["files_total"].is_null());
        assert!(
            json.get("event").is_none(),
            "the engine event must be flattened, not nested"
        );
    }

    #[test]
    fn closed_payload_carries_the_session_and_a_reason() {
        let json = serde_json::to_value(FilesClosedPayload {
            session_id: "s2".to_string(),
            reason: "the file-transfer connection closed".to_string(),
        })
        .expect("payload serializes");
        assert_eq!(json["session_id"], "s2");
        assert!(json["reason"].as_str().unwrap().contains("closed"));
    }

    /// The off-switch gate is a single predicate reused by every entry
    /// point; with no config present the surface is ON (free by default).
    #[test]
    fn ensure_files_enabled_follows_the_config_default() {
        // No `[files]` table anywhere in this test environment → default on.
        assert!(ensure_files_enabled().is_ok());
    }

    /// Deserialization of the enqueue argument bundle — the frontend sends
    /// one object, and the policy/direction spellings are the contract.
    #[test]
    fn enqueue_args_deserialize_from_the_frontend_shape() {
        let args: FilesEnqueueArgs = serde_json::from_value(serde_json::json!({
            "session_id": "s1",
            "direction": "upload",
            "policy": "skip",
            "items": [{ "source_path": "/tmp/a.conf", "dest_dir": "/var/tmp" }],
        }))
        .expect("args deserialize");
        assert_eq!(args.session_id, "s1");
        assert_eq!(args.direction, Direction::Upload);
        assert_eq!(args.policy, OverwritePolicy::Skip);
        assert_eq!(args.items.len(), 1);
        assert_eq!(args.items[0].dest_dir, "/var/tmp");
    }
}
