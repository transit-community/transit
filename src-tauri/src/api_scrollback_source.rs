//! `transit_agent::ScrollbackSource` impl backed by [`ApiSessionState`].
//!
//! Mirrors `ssh_scrollback_source.rs` / `console_scrollback_source.rs` for
//! API (controller) sessions, so the agent's `list_open_sessions` +
//! `read_scrollback` see a controller's request/response history the same
//! way they see SSH/console output — redacted by the dispatcher on the way
//! to the LLM (`DefaultDispatcher`).
//!
//! There is deliberately NO `SessionExecutor` here: `propose_command` (a PTY
//! command) must never target a controller. Two things enforce that together:
//! (1) API sessions are absent from `UnifiedSessionExecutor` (it has an SSH +
//! console arm, no API arm), and (2) the per-chat `ScopedSessionExecutor`
//! requires the INNER executor to own a session before it returns a vendor —
//! so a controller id, though visible for reads, yields `vendor_for → None`,
//! the byte-identical "session not found" refusal (`scoped_session_view.rs`).
//! The agent's ONLY path to a controller is the GET-only `propose_api_call`,
//! gated separately.
//!
//! `device_id` is the STABLE inventory id (`api_session_id`), NOT the display
//! name: per-chat scope (T31) filters on `device_id`, so it must be unique and
//! rename-stable — exactly as the SSH source uses the inventory device id. Two
//! controllers may share a display name; they never share an id.

use std::sync::Arc;

use transit_agent::{ScrollbackSource, SessionKind, SessionMeta as AgentSessionMeta, Snapshot};

use crate::api_session::ApiSessionState;

/// Adapter from `Arc<ApiSessionState>` to `ScrollbackSource`.
pub struct ApiScrollbackSource {
    pub api: Arc<ApiSessionState>,
}

impl ApiScrollbackSource {
    pub fn new(api: Arc<ApiSessionState>) -> Self {
        Self { api }
    }
}

impl ScrollbackSource for ApiScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        let guard = self.api.sessions.lock().ok()?;
        let entry = guard.get(session_id)?;
        let ring = &entry.ring;
        // FULL ring contents — no byte budget here. The dispatcher redacts
        // FIRST and windows AFTER (a pre-redaction trim could decapitate a
        // multi-line secret). `truncated` reports ring eviction (at-cap as
        // the conservative stand-in), same as the SSH/console sources.
        let full = ring.snapshot();
        let truncated =
            ring.len_bytes() >= ring.max_bytes() || ring.line_count() >= ring.max_lines();
        Some(Snapshot {
            text: String::from_utf8_lossy(&full).into_owned(),
            truncated,
            // v4.1.0 — API responses are JSON; route to redact_json so a
            // bare hex hostId/consoleId (needed to build the next path)
            // survives while key-labeled secrets stay redacted.
            json: true,
        })
    }

    fn list(&self) -> Vec<AgentSessionMeta> {
        let Ok(guard) = self.api.sessions.lock() else {
            return Vec::new();
        };
        let mut out: Vec<AgentSessionMeta> = guard
            .values()
            .map(|entry| AgentSessionMeta {
                session_id: entry.api_session_id.clone(),
                // STABLE inventory id, not the display name (T31 scope keys
                // on device_id — see the module header). For a controller
                // there is one session, so session_id == device_id.
                device_id: entry.api_session_id.clone(),
                vendor: entry.vendor.clone(),
                kind: SessionKind::Api,
                opened_at: entry
                    .opened_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                // #12 Phase 2b: the controller's collection GET endpoints, so
                // the prompt's known-endpoints section can list them.
                api_endpoints: entry.known_endpoints.clone(),
                // Per-chat facts — populated by ScopedScrollbackSource.
                alias: None,
                commands_run: None,
                // API sessions keep no ring — their "scrollback" is the
                // formatted request/response log built on demand. Omitted
                // from the roster rather than estimated.
                scrollback_bytes: None,
            })
            .collect();
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_session::ApiSessionState;
    use std::sync::Mutex;
    use transit_agent::{
        ConversationRedactor, DefaultDispatcher, ReadScrollbackInput, ScrollbackSource, ToolCall,
        ToolDispatcher, ToolResult,
    };
    use transit_core::inventory::Vendor;

    #[test]
    fn snapshot_marks_api_content_as_json() {
        // The one non-obvious literal: API scrollback must be JSON-tagged
        // so the dispatcher routes it through redact_json (skips the
        // bare-hex identifier net) rather than the CLI `redact`.
        let st = Arc::new(ApiSessionState::new());
        let v = Vendor::Custom("unifi".into());
        st.open("c", "C", &v);
        st.record_exchange("c", "C", &v, "GET", "/v1/hosts", 200, "{}");
        let snap = ApiScrollbackSource::new(st)
            .snapshot("c")
            .expect("session open");
        assert!(snap.json, "API scrollback must be JSON-tagged");
    }

    #[tokio::test]
    async fn read_scrollback_over_api_keeps_hostid_but_redacts_secret() {
        // End-to-end: reading an API session's scrollback surfaces the
        // hostId (needed for the next path) but still strips a keyed PSK.
        let st = Arc::new(ApiSessionState::new());
        let v = Vendor::Custom("unifi".into());
        st.open("c", "C", &v);
        let host_id = "900a6f00a1b2c3d4e5f60718293a4b5c6d7e8f90";
        st.record_exchange(
            "c",
            "C",
            &v,
            "GET",
            "/v1/hosts",
            200,
            &format!(r#"{{"hostId":"{host_id}","x_passphrase":"WifiPass99"}}"#),
        );

        let src: Arc<dyn ScrollbackSource> = Arc::new(ApiScrollbackSource::new(st));
        let redactor = Arc::new(Mutex::new(ConversationRedactor::new()));
        let out = DefaultDispatcher::new(src, redactor)
            .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                session_id: "c".into(),
                max_bytes: 64 * 1024,
                match_: None,
                context_lines: 2,
            }))
            .await
            .expect("read ok");

        let ToolResult::ReadScrollback(o) = out else {
            panic!("wrong tool result variant");
        };
        assert!(
            o.text.contains(host_id),
            "hostId survives the API read path"
        );
        assert!(
            !o.text.contains("WifiPass99"),
            "keyed secret still redacted end-to-end"
        );
    }
}
