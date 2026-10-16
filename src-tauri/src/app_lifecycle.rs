//! App-exit / window-close interception (v1.4.0 "warn before quit").
//!
//! Quitting Transit — via Cmd+Q (`RunEvent::ExitRequested`) or the window
//! close button (`WindowEvent::CloseRequested`) — while SSH / serial sessions
//! are open should confirm first instead of silently dropping the
//! connections. The liveness/count decision + the styled dialog live in the
//! frontend (it knows which tabs are `ended`); this module only does the
//! native interception that JS can't reach (Cmd+Q never surfaces a JS
//! `CloseRequested`): if a session is still actively connected (its channel
//! is alive — a `logout`/`exit`-ed-but-open tab is not), veto the exit once
//! and emit `app:confirm-quit` for the frontend to resolve. After the
//! user confirms, `confirm_quit` flips an `AtomicBool` and calls
//! `app.exit(0)`, so the re-entrant exit sails through. Driven entirely
//! Rust-side, so no window/process capability is added to the JS surface.

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};

/// One-shot "the user already confirmed quitting" latch. Managed in Tauri
/// state; read by the run-event handler, set by `confirm_quit`.
#[derive(Default)]
pub struct ExitState {
    confirmed: AtomicBool,
}

impl ExitState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Frontend reply to `app:confirm-quit`: the user chose to quit anyway.
/// Latches the confirm flag so the re-triggered exit isn't vetoed again,
/// then exits.
#[tauri::command]
pub fn confirm_quit(app: AppHandle, exit_state: State<'_, ExitState>) {
    exit_state.confirmed.store(true, Ordering::SeqCst);
    app.exit(0);
}

/// Run-event handler installed on `App::run`. Vetoes Cmd+Q and the window
/// close button while backend sessions remain, handing the decision to the
/// frontend confirm dialog.
pub fn handle_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        RunEvent::ExitRequested { api, .. } if should_block_exit(app) => {
            api.prevent_exit();
            let _ = app.emit("app:confirm-quit", ());
        }
        RunEvent::WindowEvent {
            event: WindowEvent::CloseRequested { api, .. },
            ..
        } if should_block_exit(app) => {
            api.prevent_close();
            let _ = app.emit("app:confirm-quit", ());
        }
        // v6.0.0 — the exit is going through: bring down any capture
        // still recording. A root-privileged `tcpdump` that outlives
        // Transit keeps recording the network with no UI left to stop it,
        // which is precisely what threat-model T44 promises cannot
        // happen. Best-effort and bounded (each stop has its own 5s
        // grace), so a wedged capture process cannot hang the quit.
        RunEvent::Exit => {
            if let Some(state) = app.try_state::<std::sync::Arc<crate::pcap::PcapState>>() {
                let state = std::sync::Arc::clone(&state);
                tauri::async_runtime::block_on(async move {
                    crate::pcap::stop_all(&state).await;
                });
            }
        }
        _ => {}
    }
}

/// Veto the exit pending a frontend confirm iff the user hasn't already
/// confirmed AND a session is still actively connected.
fn should_block_exit(app: &AppHandle) -> bool {
    if let Some(exit_state) = app.try_state::<ExitState>() {
        if exit_state.confirmed.load(Ordering::SeqCst) {
            return false;
        }
    }
    has_active_session(app)
}

/// Whether any SSH / serial-console session is still **actively connected**,
/// or any Files session has work in flight.
///
/// Anchors the warning to true liveness (the rule: a tab the user
/// `logout`/`exit`-ed from is safe to drop — its channel is dead even though
/// the tab lingers). Each concrete `Session` carries a `watch::Receiver<bool>`
/// that flips to `true` the instant its channel closes — `Eof`/`Close`, which
/// is exactly what `logout` sends — so a logged-out-but-open tab is NOT
/// counted here. The frontend's `!ended` filter is the matching mirror.
///
/// **Files sessions are transfer-aware, deliberately asymmetric** (v5.0.0,
/// plan §6): an *idle* Files session never vetoes quit — it holds no
/// unsaved state and reconnects trivially — while one with a queued or
/// running transfer does, because quitting there loses real data mid-copy.
/// (Local shells are absent entirely, like T42 — the frontend's `!ended`
/// filter covers them.)
///
/// Runs in the sync run-event closure, so it `try_lock`s the tokio-guarded
/// session maps (same rationale as `SshScrollbackSource::snapshot`) and reads
/// each session's closed-state via `watch::Receiver::borrow()` (non-blocking).
/// Momentary lock contention is treated as "busy" → err toward prompting
/// rather than quitting out from under an in-flight connect.
fn has_active_session(app: &AppHandle) -> bool {
    if let Some(state) = app.try_state::<crate::commands::AppState>() {
        match state.ssh.sessions.try_lock() {
            Ok(guard) => {
                if guard.values().any(|e| !*e.session.closed_rx().borrow()) {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    if let Some(console) = app.try_state::<std::sync::Arc<crate::console::ConsoleState>>() {
        match console.sessions.try_lock() {
            Ok(guard) => {
                if guard.values().any(|e| !*e.session.closed_rx().borrow()) {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    if let Some(files) = app.try_state::<std::sync::Arc<crate::files::FilesState>>() {
        match files.sessions.try_lock() {
            // Transfer-aware, NOT liveness-aware: an idle Files session is
            // safe to drop, a mid-transfer one is not.
            Ok(guard) => {
                if guard.values().any(|e| e.session.has_active_transfers()) {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    false
}
