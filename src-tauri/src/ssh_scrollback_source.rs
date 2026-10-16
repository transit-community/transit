//! `transit_agent::ScrollbackSource` impl backed by [`SshState`].
//!
//! The agent's `read_scrollback` and `list_open_sessions` tools need
//! a way to enumerate open sessions and snapshot their PTY-output
//! ring buffers without taking a dependency on Tauri or the
//! `tauri::State` wrapper. `SshScrollbackSource` adapts our concrete
//! SSH state to the trait so `transit_agent::DefaultDispatcher` can
//! consume it.
//!
//! Vendor on `SessionMeta` (Phase 6 C0) means we no longer have to
//! re-read the inventory per snapshot — the Session's `meta()`
//! already carries the vendor that was set at connect time.

use std::sync::Arc;

use transit_agent::{ScrollbackSource, SessionKind, SessionMeta as AgentSessionMeta, Snapshot};

use crate::ssh::SshState;

/// Adapter from `Arc<SshState>` to `ScrollbackSource`.
pub struct SshScrollbackSource {
    pub ssh: Arc<SshState>,
}

impl SshScrollbackSource {
    pub fn new(ssh: Arc<SshState>) -> Self {
        Self { ssh }
    }
}

impl ScrollbackSource for SshScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        // The `Mutex` on `SshState.sessions` is async (tokio); the
        // `ScrollbackSource` trait is sync. The trait is consumed
        // inside `tokio::spawn`-ed loop tasks (see `AgentLoop`), so
        // we can safely `block_in_place` to acquire the lock — the
        // current-thread runtime path the desktop uses for the
        // chat task is multi-thread-friendly via tauri's runtime.
        //
        // For an in-memory lookup that completes in microseconds,
        // `try_lock`-with-poll is fine; if a contention spike ever
        // becomes a real issue we'd swap to an std::sync::Mutex
        // since the inner `HashMap` operations are non-async.
        let guard = self.ssh.sessions.try_lock().ok()?;
        let entry = guard.get(session_id)?;
        let ring = &entry.session.scrollback;
        // FULL ring contents — no byte budget at this layer. The
        // dispatcher redacts FIRST and applies the `read_scrollback`
        // window AFTER, as a tail-keep trim on redacted text (a
        // pre-redaction head-drop here could decapitate a PEM block
        // so its tail sails past the matcher). `truncated` reports
        // ring-level eviction only; the ring keeps no explicit
        // eviction flag, so at-cap is the conservative stand-in.
        let full = ring.snapshot();
        let truncated =
            ring.len_bytes() >= ring.max_bytes() || ring.line_count() >= ring.max_lines();
        let text = String::from_utf8_lossy(&full).into_owned();
        Some(Snapshot {
            text,
            truncated,
            json: false,
        })
    }

    fn list(&self) -> Vec<AgentSessionMeta> {
        let Ok(guard) = self.ssh.sessions.try_lock() else {
            return Vec::new();
        };
        let mut out: Vec<AgentSessionMeta> = guard
            .iter()
            .map(|(session_id, entry)| {
                let m = entry.session.meta();
                AgentSessionMeta {
                    session_id: session_id.clone(),
                    // The inventory id stashed on SessionEntry at
                    // connect time — the connection name the user
                    // chose ("R1"), which is how they reference the
                    // device in chat. transit_ssh::SessionMeta stays
                    // inventory-free (host/port/user/term/vendor).
                    device_id: entry.device_id.clone(),
                    vendor: m.vendor.clone(),
                    kind: SessionKind::Ssh,
                    opened_at: m
                        .opened_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    api_endpoints: Vec::new(),
                    // Aliases + command counts are per-chat facts; the
                    // chat's ScopedScrollbackSource populates them.
                    alias: None,
                    commands_run: None,
                    // v6.1.x — cheap ring occupancy so the roster can say
                    // whether a read is worth proposing. try_len_bytes:
                    // this `list()` is non-blocking by contract (the
                    // sessions map is behind try_lock above), so the
                    // occupancy read must not block on a busy ring or
                    // panic on a poisoned one — omit the hint instead.
                    scrollback_bytes: entry.session.scrollback.try_len_bytes(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        out
    }
}
