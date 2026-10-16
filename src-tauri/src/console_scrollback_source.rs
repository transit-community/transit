//! `transit_agent::ScrollbackSource` + `SessionExecutor` impls backed
//! by [`ConsoleState`].
//!
//! Parallel of `ssh_scrollback_source.rs` for the serial-console
//! transport. The agent's `read_scrollback` and `list_open_sessions`
//! tools need to see console sessions too, and `propose_command`
//! needs an executor that can run a command on a console session
//! and capture quiescent output the same way the SSH executor does.
//!
//! The composite types ([`UnifiedScrollbackSource`] +
//! [`UnifiedSessionExecutor`]) glue the SSH + console halves into one
//! object so the agent's dispatcher takes a single `Arc<dyn …>` and
//! doesn't have to know which transport backs a given session id.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use transit_agent::{
    AgentError, ScrollbackSource, SessionKind, SessionMeta as AgentSessionMeta, Snapshot,
};
use transit_core::inventory::Vendor;

use crate::agent_dispatch::{CaptureEnd, SessionExecutor};
use crate::console::ConsoleState;
use crate::ssh_scrollback_source::SshScrollbackSource;

/// Adapter from `Arc<ConsoleState>` to `ScrollbackSource`.
pub struct ConsoleScrollbackSource {
    pub console: Arc<ConsoleState>,
}

impl ConsoleScrollbackSource {
    pub fn new(console: Arc<ConsoleState>) -> Self {
        Self { console }
    }
}

impl ScrollbackSource for ConsoleScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        // See `SshScrollbackSource::snapshot` for the `try_lock`
        // rationale (async Mutex, sync trait consumed inside
        // spawn-ed loop tasks) AND the full-contents contract: the
        // dispatcher redacts FIRST and tail-trims AFTER, so no byte
        // budget applies at this layer. `truncated` reports ring
        // eviction only (at-cap as the conservative stand-in).
        let guard = self.console.sessions.try_lock().ok()?;
        let entry = guard.get(session_id)?;
        let ring = &entry.session.scrollback;
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
        let Ok(guard) = self.console.sessions.try_lock() else {
            return Vec::new();
        };
        let mut out: Vec<AgentSessionMeta> = guard
            .iter()
            .map(|(session_id, entry)| {
                let m = entry.session.meta();
                AgentSessionMeta {
                    session_id: session_id.clone(),
                    // The sidebar label ("FTDI FT232R (A99BCXAG)" or
                    // bare path) doubles as the agent-visible device
                    // id. There's no inventory entry for a console
                    // cable, so the chip name is the most useful
                    // human-readable handle.
                    device_id: entry.label.clone(),
                    vendor: m.vendor.clone(),
                    kind: SessionKind::Console,
                    opened_at: m
                        .opened_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    api_endpoints: Vec::new(),
                    // Per-chat facts — populated by ScopedScrollbackSource.
                    alias: None,
                    commands_run: None,
                    // try_len_bytes: non-blocking/non-panicking, per the
                    // try_lock contract of this list() (see SSH source).
                    scrollback_bytes: entry.session.scrollback.try_len_bytes(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        out
    }
}

/// Production [`SessionExecutor`] for console sessions. Mirrors
/// `SshSessionExecutor` — subscribe before sending, capture until
/// quiescent.
pub struct ConsoleSessionExecutor {
    pub console: Arc<ConsoleState>,
}

#[async_trait]
impl SessionExecutor for ConsoleSessionExecutor {
    async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
        let guard = self.console.sessions.lock().await;
        guard
            .get(session_id)
            .map(|e| e.session.meta().vendor.clone())
    }

    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
        timeout: Duration,
        quiescence: Duration,
    ) -> Result<(String, CaptureEnd), AgentError> {
        // Defense in depth: the policy gate already denies commands
        // containing control characters (one gated "line" would
        // execute as several). Refuse here too so a future gate
        // refactor can't silently re-open the executor — mirrors
        // `SshSessionExecutor::run_command`.
        if command.chars().any(|c| c.is_control()) {
            return Err(AgentError::Dispatcher(
                "refusing to send command containing control characters".into(),
            ));
        }
        let session = {
            let guard = self.console.sessions.lock().await;
            guard
                .get(session_id)
                .ok_or_else(|| AgentError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?
                .session
                .clone()
        };
        let rx = session.subscribe();
        let mut payload = command.as_bytes().to_vec();
        payload.push(b'\n');
        session
            .send_input(Bytes::from(payload))
            .await
            .map_err(|e| AgentError::Dispatcher(format!("send_input failed: {e}")))?;

        // Shared quiescence loop (see agent_dispatch::capture_until_quiet)
        // — one definition so SSH and console classify terminators
        // identically.
        Ok(crate::agent_dispatch::capture_until_quiet(rx, timeout, quiescence).await)
    }
}

// ---------------------------------------------------------------------
// Unified types — composite over SSH + console.
// ---------------------------------------------------------------------

/// Composite `ScrollbackSource` that delegates to whichever transport
/// owns a given session id. `list()` concatenates both transports'
/// sessions so the agent's `list_open_sessions` tool sees the full
/// set.
pub struct UnifiedScrollbackSource {
    pub ssh: SshScrollbackSource,
    pub console: ConsoleScrollbackSource,
    /// v4.0.0 — API (controller) sessions. Read-only for the agent
    /// (`read_scrollback` / `list_open_sessions`). There is deliberately no
    /// matching arm in `UnifiedSessionExecutor` below, AND the per-chat
    /// `ScopedSessionExecutor` requires the inner executor to own a session
    /// before returning a vendor — so a controller id yields `vendor_for →
    /// None`, the byte-identical "session not found" refusal, and
    /// `propose_command` (a PTY tool) can never target a controller. A REST
    /// GET reaches a controller only through the gated `propose_api_call`.
    pub api: crate::api_scrollback_source::ApiScrollbackSource,
}

impl ScrollbackSource for UnifiedScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        self.ssh
            .snapshot(session_id)
            .or_else(|| self.console.snapshot(session_id))
            .or_else(|| self.api.snapshot(session_id))
    }

    fn list(&self) -> Vec<AgentSessionMeta> {
        let mut out = self.ssh.list();
        out.extend(self.console.list());
        out.extend(self.api.list());
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        out
    }
}

/// Composite `SessionExecutor` that delegates to whichever transport
/// owns a given session id. `vendor_for` returns the first non-None
/// answer; `run_command` tries SSH first and falls through to console
/// if the SSH side reports `SessionNotFound`.
pub struct UnifiedSessionExecutor {
    pub ssh: crate::agent_dispatch::SshSessionExecutor,
    pub console: ConsoleSessionExecutor,
}

#[async_trait]
impl SessionExecutor for UnifiedSessionExecutor {
    async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
        if let Some(v) = self.ssh.vendor_for(session_id).await {
            return Some(v);
        }
        self.console.vendor_for(session_id).await
    }

    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
        timeout: Duration,
        quiescence: Duration,
    ) -> Result<(String, CaptureEnd), AgentError> {
        match self
            .ssh
            .run_command(session_id, command, timeout, quiescence)
            .await
        {
            // Fall through to console only on the specific
            // "session id unknown here" error. Any other failure
            // (network drop, broken pipe) IS the failure the user
            // should see, even if the console side happens to have
            // a session with the same id (which shouldn't happen
            // since UUIDs).
            Err(AgentError::SessionNotFound { .. }) => {
                self.console
                    .run_command(session_id, command, timeout, quiescence)
                    .await
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    //! The agent-visibility invariant for the HUMAN-only surfaces.
    //!
    //! Both the v4.4.0 local-terminal plan (T42) and the v5.0.0 Files plan
    //! (T43) rest on the same structural claim: the agent reaches sessions
    //! through exactly two composition points — [`UnifiedScrollbackSource`]
    //! (`list_open_sessions` / `read_scrollback`) and
    //! [`UnifiedSessionExecutor`] (`propose_command`) — and neither one has
    //! an arm for a local shell or a Files session. This test pins that: a
    //! LIVE local shell is invisible to both.
    //!
    //! Files is blind *a fortiori* — no `ScrollbackSource` implementation
    //! for it exists to compose in the first place, and `deny.toml` bans any
    //! dependency on `transit_files` outside `transit_app`, so one can't be
    //! written inside `transit_agent` either. If a future refactor adds a
    //! `local`/`files` field to either unified type, this test starts
    //! failing (the local session appears) and the reviewer is forced to
    //! read T42/T43 before landing it.

    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex as AsyncMutex;
    use transit_core::inventory::Vendor;
    use transit_ssh::HostKeyStore;

    use crate::api_scrollback_source::ApiScrollbackSource;
    use crate::api_session::ApiSessionState;
    use crate::console::ConsoleState;
    use crate::local_shell::{LocalPtyState, LocalSessionEntry};
    use crate::ssh::SshState;
    use crate::ssh_scrollback_source::SshScrollbackSource;

    /// An `SshState` with no sessions, pointed at a throwaway known-hosts
    /// path so the test never touches the developer's real store.
    async fn empty_ssh_state() -> Arc<SshState> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts.toml");
        std::mem::forget(dir);
        Arc::new(SshState {
            sessions: AsyncMutex::new(HashMap::new()),
            host_keys: Arc::new(HostKeyStore::open(path).await.expect("open store")),
            pending_tofu: Arc::new(AsyncMutex::new(HashMap::new())),
            pending_weak_crypto: Arc::new(AsyncMutex::new(HashMap::new())),
            pending_kbi: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    /// A one-shot shell that prints a marker and exits — portable across the
    /// CI matrix, and enough to have a genuinely live `LocalPtyState` entry.
    fn marker_params() -> transit_localpty::OpenParams {
        #[cfg(not(target_os = "windows"))]
        let (program, args) = (
            "/bin/sh".to_string(),
            vec!["-c".to_string(), "printf transit-marker".to_string()],
        );
        #[cfg(target_os = "windows")]
        let (program, args) = (
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "echo transit-marker".to_string()],
        );
        transit_localpty::OpenParams {
            program,
            args,
            cwd: None,
            env: Vec::new(),
            label: "invariant".to_string(),
            cols: 80,
            rows: 24,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_session_list_omits_local_shells_and_files_sessions() {
        // A live local shell, registered exactly as `open_local_shell` does
        // (minus the output bridge, which needs an AppHandle).
        let local_state = Arc::new(LocalPtyState::new());
        let local_session =
            transit_localpty::Session::open(marker_params()).expect("open local pty");
        let local_id = "local-session-under-test".to_string();
        local_state.sessions.lock().await.insert(
            local_id.clone(),
            LocalSessionEntry {
                session: Arc::new(local_session),
                bridge: tokio::spawn(async {}),
                label: "invariant".to_string(),
                params: marker_params(),
            },
        );
        assert_eq!(
            local_state.sessions.lock().await.len(),
            1,
            "the local shell really is registered — the omission below is not vacuous"
        );

        // An API session so `list()` has something to return: this proves
        // the source enumerates at all, so an empty local result can't be a
        // false pass.
        let api_state = Arc::new(ApiSessionState::new());
        let vendor = Vendor::Custom("unifi".into());
        api_state.open("controller-1", "Controller", &vendor);

        let unified = UnifiedScrollbackSource {
            ssh: SshScrollbackSource::new(empty_ssh_state().await),
            console: ConsoleScrollbackSource::new(Arc::new(ConsoleState::new())),
            api: ApiScrollbackSource::new(Arc::clone(&api_state)),
        };

        let listed: Vec<String> = unified.list().into_iter().map(|m| m.session_id).collect();
        assert_eq!(
            listed,
            vec!["controller-1".to_string()],
            "the agent's session list must contain ONLY ssh/console/api sessions"
        );
        assert!(
            !listed.contains(&local_id),
            "a local shell must never appear in the agent's session list (T42)"
        );
        assert!(
            unified.snapshot(&local_id).is_none(),
            "read_scrollback must not resolve a local shell's id (T42)"
        );

        // `propose_command`'s seam is just as blind: no vendor, and the
        // executor refuses with the byte-identical not-found error.
        let executor = UnifiedSessionExecutor {
            ssh: crate::agent_dispatch::SshSessionExecutor {
                ssh: empty_ssh_state().await,
            },
            console: ConsoleSessionExecutor {
                console: Arc::new(ConsoleState::new()),
            },
        };
        assert!(
            executor.vendor_for(&local_id).await.is_none(),
            "the executor must not resolve a local shell's vendor (T42)"
        );
        let refused = executor
            .run_command(
                &local_id,
                "show version",
                Duration::from_millis(50),
                Duration::from_millis(10),
            )
            .await;
        assert!(
            matches!(refused, Err(AgentError::SessionNotFound { .. })),
            "propose_command must not reach a local shell, got {refused:?}"
        );

        // Teardown: the local session dies with the state map.
        let entry = local_state.sessions.lock().await.remove(&local_id);
        if let Some(entry) = entry {
            entry.bridge.abort();
            if let Ok(session) = Arc::try_unwrap(entry.session) {
                let _ = session.close().await;
            }
        }
    }
}
