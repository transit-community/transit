//! Phase 7b C18 — Tauri wiring for `transit_console`.
//!
//! Three IPC commands and one event channel:
//!
//! - `list_console_cables() -> Vec<SerialPortInfo>` — snapshot of
//!   currently-attached USB-to-serial cables.
//! - `connect_console_cable(args) -> ConsoleConnectResult` — open a
//!   session on a given port; returns the backend-assigned session
//!   id + a sidebar label the frontend stashes on the tab.
//! - `disconnect_console_session(session_id) -> ()` — tear down.
//! - `console:plug` event — fires on every hot-plug change so the
//!   frontend can invalidate its TanStack query for the cable list.
//!
//! `send_input`, `disconnect_session`, and `resize_pty` are extended
//! in `ssh.rs` to fall through to `ConsoleState.sessions` when the
//! id isn't an SSH session — so the frontend's standard tab-close /
//! keystroke / resize flow doesn't need to know which transport
//! backs each session id.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use transit_console::{
    driver_status, start_hotplug, ConnectParams, ConsoleError, DriverStatus, HotplugEvent,
    HotplugWatcher, SerialPortInfo, Session,
};
use uuid::Uuid;

use crate::ssh::spawn_output_bridge;

pub struct ConsoleState {
    pub hotplug: HotplugWatcher,
    pub sessions: Mutex<HashMap<String, ConsoleSessionEntry>>,
}

pub struct ConsoleSessionEntry {
    pub session: Arc<Session>,
    /// Bridge task — translates the session's broadcast output into
    /// `pty:{id}:output` events. Aborted on disconnect.
    pub bridge: tokio::task::JoinHandle<()>,
    /// Sidebar label for this session ("FTDI FT232R (A99BCXAG)" etc.)
    /// — stored here so the merged `list_open_sessions` (a follow-up
    /// after smoke test) doesn't have to rebuild it from
    /// `SerialPortInfo`.
    pub label: String,
    /// The params this session was opened with — kept so auto-reconnect
    /// can re-open the same port under the same session id on replug.
    pub params: ConnectParams,
}

impl ConsoleState {
    pub fn new() -> Self {
        Self {
            hotplug: start_hotplug(),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for ConsoleState {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire it up: spawn the hot-plug forwarder and stash the state on
/// the app. Called from `lib.rs::setup`.
pub fn install(app: &AppHandle) {
    let state = Arc::new(ConsoleState::new());

    // Forward HotplugEvents to the frontend as `console:plug` events.
    // The frontend's `useConsoleCables()` query subscribes to this
    // and refetches `list_console_cables` on every fire — the event
    // payload could carry the diff directly, but a refetch keeps the
    // TanStack cache the single source of truth and avoids races
    // between snapshot + event paths.
    let mut rx = state.hotplug.subscribe();
    let app_for_forwarder = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Err(e) = app_for_forwarder.emit("console:plug", ev) {
                        tracing::warn!(?e, "failed to emit console:plug");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "console:plug subscriber lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Auto-reconnect: a SECOND hot-plug consumer. When a cable reappears,
    // re-open any DROPPED console session bound to that port under its
    // original session id (the tab + pane resume). Edge-triggered on Added
    // → one attempt per physical replug, no retry storm. A user-closed
    // session is gone from the map, so only unexpected drops reconnect.
    let mut reconnect_rx = state.hotplug.subscribe();
    let reconnect_state = Arc::clone(&state);
    let app_for_reconnect = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match reconnect_rx.recv().await {
                Ok(HotplugEvent::Added(info)) => {
                    reconnect_dropped_sessions(
                        &app_for_reconnect,
                        &reconnect_state,
                        &info.port_path,
                    )
                    .await;
                }
                Ok(HotplugEvent::Removed(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    app.manage(state);
}

/// Re-open any dropped console session bound to `port_path` (a cable just
/// reappeared) under its original session id, so the frontend tab + pane
/// resume without a manual reconnect.
async fn reconnect_dropped_sessions(app: &AppHandle, state: &Arc<ConsoleState>, port_path: &str) {
    // Snapshot dropped sessions on this port; Session::open runs on the
    // blocking pool, so don't hold the sessions lock across it.
    let candidates: Vec<(String, ConnectParams)> = {
        let guard = state.sessions.lock().await;
        guard
            .iter()
            .filter(|(_, e)| e.params.port_path == port_path && *e.session.closed_rx().borrow())
            .map(|(id, e)| (id.clone(), e.params.clone()))
            .collect()
    };

    for (session_id, params) in candidates {
        let opened = tokio::task::spawn_blocking(move || Session::open(params)).await;
        let new_session = match opened {
            Ok(Ok(s)) => s,
            _ => {
                tracing::warn!(session = %session_id, "console auto-reconnect: re-open failed");
                continue;
            }
        };
        let new_bridge = spawn_output_bridge(
            app.clone(),
            new_session.subscribe(),
            new_session.closed_rx(),
            session_id.clone(),
        );
        let mut guard = state.sessions.lock().await;
        match guard.get_mut(&session_id) {
            Some(entry) => {
                entry.bridge.abort();
                entry.session = Arc::new(new_session);
                entry.bridge = new_bridge;
                drop(guard);
                let _ = app.emit("console:reconnected", &session_id);
                tracing::info!(session = %session_id, "console session auto-reconnected");
            }
            None => {
                // Closed by the user between snapshot and re-open — discard.
                drop(guard);
                new_bridge.abort();
                let _ = new_session.close().await;
            }
        }
    }
}

// ---------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------

/// Currently-attached cables. Synchronous cached snapshot — no I/O.
#[tauri::command]
pub fn list_console_cables(state: State<'_, Arc<ConsoleState>>) -> Vec<SerialPortInfo> {
    state.hotplug.current()
}

/// Phase 7b C22 — report USB-to-serial chips present on the bus
/// that have no working VCP driver. Shells out to `system_profiler`
/// on macOS (a few-hundred-ms subprocess call); empty list
/// elsewhere. Async + `spawn_blocking` because Tauri 2 runs *sync*
/// commands on the main thread — a synchronous version froze the
/// UI for the duration of the subprocess. Callers should still
/// treat it as a TanStack query rather than wire it to every render.
#[tauri::command]
pub async fn list_console_driver_status() -> DriverStatus {
    tokio::task::spawn_blocking(driver_status)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(?e, "driver-status task panicked; reporting empty");
            DriverStatus::default()
        })
}

#[derive(Debug, Deserialize)]
pub struct ConsoleConnectArgs {
    #[serde(flatten)]
    pub params: ConnectParams,
}

#[derive(Debug, Serialize)]
pub struct ConsoleConnectResult {
    pub session_id: String,
    /// Sidebar label the frontend uses when adding the tab — typically
    /// the cable's chip name + USB serial suffix.
    pub label: String,
}

#[tauri::command]
pub async fn connect_console_cable(
    app: AppHandle,
    state: State<'_, Arc<ConsoleState>>,
    args: ConsoleConnectArgs,
) -> Result<ConsoleConnectResult, String> {
    let port_path = args.params.port_path.clone();

    // Synthesize a stable-ish label from the SerialPortInfo for the
    // tab + session-info panel. Falls back to the bare path if the
    // OS didn't classify the device as USB.
    let label = state
        .hotplug
        .current()
        .into_iter()
        .find(|p| p.port_path == port_path)
        .map(|p| p.sidebar_label())
        .unwrap_or_else(|| port_path.clone());

    // `Session::open` performs the blocking serial-port open
    // syscalls (the tokio wrapper only makes the *stream* async);
    // run it on the blocking pool so a slow USB stack can't stall a
    // runtime worker. The reader/writer tasks it spawns land on the
    // runtime as usual — `spawn_blocking` threads keep the runtime
    // context.
    let params = args.params.clone();
    let session = tokio::task::spawn_blocking(move || Session::open(args.params))
        .await
        .map_err(|e| format!("console open task panicked: {e}"))?
        .map_err(|e: ConsoleError| e.to_string())?;
    let session_id = Uuid::new_v4().to_string();

    let bridge = spawn_output_bridge(
        app.clone(),
        session.subscribe(),
        session.closed_rx(),
        session_id.clone(),
    );

    let entry = ConsoleSessionEntry {
        session: Arc::new(session),
        bridge,
        label: label.clone(),
        params,
    };

    state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), entry);

    Ok(ConsoleConnectResult { session_id, label })
}

/// Send a serial BREAK to a console session (interrupt a boot sequence /
/// reach ROMMON). Console-only — there is no SSH analog.
#[tauri::command]
pub async fn console_send_break(
    state: State<'_, Arc<ConsoleState>>,
    session_id: String,
) -> Result<(), String> {
    let guard = state.sessions.lock().await;
    let entry = guard
        .get(&session_id)
        .ok_or_else(|| format!("console session {session_id} not found"))?;
    entry.session.send_break().await.map_err(|e| e.to_string())
}

/// Direct disconnect — symmetric with `connect_console_cable`. The
/// frontend's standard tab-close flow uses `ssh::disconnect_session`
/// which falls through to console; this command exists for callers
/// that already know the session is console-backed.
#[tauri::command]
pub async fn disconnect_console_session(
    state: State<'_, Arc<ConsoleState>>,
    session_id: String,
) -> Result<(), String> {
    let entry = state.sessions.lock().await.remove(&session_id);
    let Some(entry) = entry else {
        return Err(format!("console session {session_id} not found"));
    };
    entry.bridge.abort();
    match Arc::try_unwrap(entry.session) {
        Ok(session) => session.close().await.map_err(|e| e.to_string())?,
        Err(_) => {
            tracing::warn!(
                "console session {session_id} had outstanding Arc refs at disconnect; \
                 relying on Drop to clean up"
            );
        }
    }
    Ok(())
}
