//! Per-chat device scope — the structural enforcement layer (T31).
//!
//! A chat may be restricted to a user-selected set of devices. Rather
//! than filtering in the UI, the restriction is enforced by wrapping
//! the two seams every agent tool flows through, per-turn in
//! `chat::chat_send_message`:
//!
//! - [`ScopedScrollbackSource`] wraps the unified `ScrollbackSource`.
//!   Injected at BOTH consumption points — the `DefaultDispatcher`
//!   (`list_open_sessions` / `read_scrollback`) and the
//!   `Conversation` (whose `system_prompt()` enumerates open sessions
//!   and scopes the rendered PolicySummary to their vendors) — so the
//!   tools and the prompt present one coherent, filtered world.
//! - [`ScopedSessionExecutor`] wraps the unified `SessionExecutor`
//!   (`propose_command`'s vendor lookup + run path). It answers
//!   membership and vendor from the SCOPED source's list, so both
//!   derive from a single consistent snapshot.
//!
//! Out-of-scope answers are BYTE-IDENTICAL to closed/unknown sessions
//! (`vendor_for` → `None` → the dispatcher's structured
//! `"session not found: {id}" / executed:false`; `snapshot` → `None`
//! → `AgentError::SessionNotFound`). Deliberate: injected content in
//! one session's scrollback gets no oracle to detect that a hidden
//! session exists. Do NOT add a distinct "out of scope" error string.
//!
//! Scope is FORWARD-LOOKING only: it gates the read/execute surface
//! from this moment on; prior-turn tool outputs already replayed into
//! the conversation history (redacted + capped when produced) are not
//! retroactively pruned. See `docs/security/threat-model.md` T31.
//!
//! Fail-closed flake note: the underlying sources use `try_lock` and
//! return an empty list under contention, so a membership check here
//! can spuriously miss and refuse an in-scope session (the model
//! retries; the refusal is structured). That is the safe direction.
//! Do not "fix" it by holding the scope or session lock across an
//! await.
//!
//! v6.1.1 — session ALIASES ([`SessionLedger`]). The agent's view of a
//! session never needed the backend registry key (a 36-char UUID local
//! models demonstrably mangle under multi-session load), only a stable
//! roster. The chat's ledger allocates short ordinals (`s1`, `s2`, …)
//! per session, in first-listed order, monotonic and never reused
//! within a chat (API-session nuance: a controller's registry id is
//! its STABLE inventory id, so re-opening the same controller
//! re-derives the same alias — for a controller the session identity
//! IS the device). Allocation happens ONLY inside
//! [`ScopedScrollbackSource::list`] — whichever caller invokes it, the
//! scope filter has already run — so an out-of-scope session never
//! gets an alias and alias existence reveals nothing beyond what
//! listing already revealed (the T31 no-oracle property: an
//! out-of-scope alias or UUID fails with the same bytes as a closed
//! session). Raw registry ids remain accepted everywhere for backward
//! compatibility. Precedence on resolve is alias-map first, raw id
//! second, EVERYWHERE (executor path and envelope framing must never
//! disagree); the allocator additionally skips ordinals that collide
//! with a currently-listed registry id, so alias-shadows-raw-id needs
//! a LATER-opened colliding name and stays deterministic when it
//! happens. Documented here and in threat-model T31.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use transit_agent::{AgentError, ScrollbackSource, SessionMeta, Snapshot};
use transit_core::inventory::Vendor;

use crate::agent_dispatch::{ApiExecutor, ApiGate, CaptureEnd, SessionExecutor};

/// A chat's live device scope, shared between the `ChatSession` (the
/// sole writer, via `chat_set_scope`) and the per-turn wrappers.
///
/// `None` = unscoped (every session visible — the default);
/// `Some(set)` = only sessions whose `device_id` is in the set;
/// `Some(∅)` = the agent sees no sessions at all (legal — the UI
/// warns loudly).
///
/// The public surface is READ-ONLY (`allows`); the setter is
/// `pub(crate)` and called only from `chat.rs`. That asymmetry is
/// structural: no future dispatcher change can grow a scope-write
/// path without an obvious diff here. The agent has no tool that
/// touches scope (Rule 2's six tools are unchanged).
#[derive(Clone)]
pub struct SharedScope(Arc<Mutex<Option<HashSet<String>>>>);

impl SharedScope {
    /// A fresh, unscoped handle (all devices visible).
    pub fn new_unscoped() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    /// Whether `device_id` is inside the current scope. Never holds
    /// the lock across an await (callers are sync).
    pub fn allows(&self, device_id: &str) -> bool {
        // A poisoned lock only means a panic elsewhere while held;
        // the guarded value is a plain assignment target, so the
        // recovered data is always the last fully-written value.
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            None => true,
            Some(set) => set.contains(device_id),
        }
    }

    /// Replace the scope. `None` = unscoped. Crate-only: the ONE
    /// caller is the `chat_set_scope` IPC command — user-driven,
    /// never agent-driven.
    pub(crate) fn set(&self, device_ids: Option<Vec<String>>) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard = device_ids.map(|v| v.into_iter().collect());
    }
}

/// A chat's session ledger — alias allocation + executed-command
/// counts (v6.1.1), shared between the `ChatSession` (owner), the
/// per-turn [`ScopedScrollbackSource`] (allocates + decorates), and the
/// `ApprovalDispatcher` (resolves inputs, records executions).
///
/// Like [`SharedScope`]: in-memory, Arc-shared, dies with the chat,
/// and the agent has no tool that touches it (Rule 2 unchanged). The
/// mutating surface is `pub(crate)` — allocation happens only through
/// the scoped list, counting only through the command dispatcher.
#[derive(Clone)]
pub struct SessionLedger(Arc<Mutex<LedgerInner>>);

struct LedgerInner {
    /// registry session id → alias (`s1`, `s2`, …).
    alias_by_id: HashMap<String, String>,
    /// alias → registry session id (reverse index for tool-input
    /// resolution). Entries are never removed: a closed session's
    /// alias stays retired-but-resolvable, which keeps the refusal
    /// path for "s2 after it closed" byte-identical to any other
    /// closed session (the resolved id fails membership downstream).
    id_by_alias: HashMap<String, String>,
    /// Monotonic allocator. Never decremented, never reused within a
    /// chat — a re-opened SSH/console session has a fresh UUID and gets
    /// a NEW alias. API-session exception: a controller's registry id
    /// IS its stable inventory id, so closing and re-opening the same
    /// controller re-derives the same alias — deliberate, since for a
    /// controller the session identity IS the device.
    next: u32,
    /// registry session id → commands EXECUTED this chat: propose_command
    /// runs and propose_api_call GETs (gate-denied / user-denied /
    /// failed-before-run don't count).
    commands_run: HashMap<String, u32>,
}

impl SessionLedger {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(LedgerInner {
            alias_by_id: HashMap::new(),
            id_by_alias: HashMap::new(),
            next: 0,
            commands_run: HashMap::new(),
        })))
    }

    /// Decorate an already-scope-filtered listing: allocate an alias for
    /// any first-seen session (in listing order) and stamp alias +
    /// executed-command count onto each meta. Idempotent; the sole
    /// allocation site — every caller reaches it through the scoped
    /// `list()`, so allocation is always strictly post-scope-filter.
    ///
    /// Allocation SKIPS an ordinal whose alias string equals any
    /// registry id in the current listing (an API session's registry id
    /// is its inventory name, so a controller literally named `s2`
    /// would otherwise collide with the alias namespace). A collision
    /// with a LATER-opened raw id remains possible; resolution is
    /// alias-map-first everywhere, so that case stays deterministic.
    fn decorate(&self, metas: &mut [SessionMeta]) {
        // Owned (not borrowed) so the loop below can mutate the metas.
        let listed_ids: std::collections::HashSet<String> =
            metas.iter().map(|m| m.session_id.clone()).collect();
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for m in metas.iter_mut() {
            let alias = match inner.alias_by_id.get(&m.session_id) {
                Some(a) => a.clone(),
                None => {
                    // `next` is monotonic and NEVER decremented, and map
                    // entries are NEVER removed — that pair is what makes
                    // a freshly formatted `s{next}` unable to collide
                    // with an already-allocated alias. Do not add a prune
                    // without re-deriving that argument.
                    let a = loop {
                        inner.next += 1;
                        let candidate = format!("s{}", inner.next);
                        if !listed_ids.contains(candidate.as_str()) {
                            break candidate;
                        }
                    };
                    debug_assert!(
                        inner.next as usize > inner.alias_by_id.len(),
                        "alias allocator desynced below the map size"
                    );
                    inner.alias_by_id.insert(m.session_id.clone(), a.clone());
                    inner.id_by_alias.insert(a.clone(), m.session_id.clone());
                    a
                }
            };
            let count = inner.commands_run.get(&m.session_id).copied().unwrap_or(0);
            m.alias = Some(alias);
            m.commands_run = Some(count);
        }
    }

    /// Resolve a tool-input session string to a registry id. Alias map
    /// first (the vocabulary the model was shown), raw id passthrough
    /// second (cloud prompts, old transcripts, tests). Unknown strings
    /// pass through unchanged so downstream membership checks produce
    /// the standard `"session not found: {input}"` bytes echoing the
    /// model's own string — no resolution-shaped oracle.
    pub(crate) fn resolve(&self, input: &str) -> String {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .id_by_alias
            .get(input)
            .cloned()
            .unwrap_or_else(|| input.to_string())
    }

    /// The alias previously allocated for a registry id, if any — used
    /// to frame result envelopes in the model's own vocabulary.
    pub(crate) fn alias_of(&self, session_id: &str) -> Option<String> {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.alias_by_id.get(session_id).cloned()
    }

    /// Test-only visibility into the executed-command counter.
    #[cfg(test)]
    pub(crate) fn executed_count(&self, session_id: &str) -> u32 {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.commands_run.get(session_id).copied().unwrap_or(0)
    }

    /// Record one EXECUTED command against a registry id — a
    /// propose_command run or a propose_api_call GET. Called by the
    /// dispatcher strictly after the executor returned output
    /// (approval + gate + scope re-check all passed).
    pub(crate) fn record_executed(&self, session_id: &str) {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *inner
            .commands_run
            .entry(session_id.to_string())
            .or_insert(0) += 1;
    }
}

impl Default for SessionLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// `ScrollbackSource` filter: hides sessions whose device is outside
/// the chat's scope from `list()` (→ `list_open_sessions` + the
/// system prompt) and from `snapshot()` (→ `read_scrollback`), and
/// (v6.1.1) decorates in-scope listings with the chat's aliases +
/// executed-command counts.
pub struct ScopedScrollbackSource {
    pub inner: Arc<dyn ScrollbackSource>,
    pub scope: SharedScope,
    /// The chat's alias/command ledger. Allocation happens ONLY in
    /// `list()` — after the scope filter — so out-of-scope sessions
    /// never get an alias (T31: no oracle).
    pub ledger: SessionLedger,
}

impl ScrollbackSource for ScopedScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        // Aliases are resolved here (alias-map first, raw id
        // passthrough) so `read_scrollback` accepts both vocabularies;
        // an unknown/retired alias resolves to a string that fails the
        // membership check below — same None as a closed session.
        let registry_id = self.ledger.resolve(session_id);
        // Membership via the same list the agent sees: the session
        // must exist AND its device must be in scope. Returning None
        // (→ SessionNotFound upstream) is indistinguishable from a
        // closed session by design (no out-of-scope oracle).
        let visible = self
            .inner
            .list()
            .into_iter()
            .any(|m| m.session_id == registry_id && self.scope.allows(&m.device_id));
        if !visible {
            return None;
        }
        self.inner.snapshot(&registry_id)
    }

    fn list(&self) -> Vec<SessionMeta> {
        let mut metas: Vec<SessionMeta> = self
            .inner
            .list()
            .into_iter()
            .filter(|m| self.scope.allows(&m.device_id))
            .collect();
        self.ledger.decorate(&mut metas);
        metas
    }
}

/// `SessionExecutor` filter for `propose_command`. Holds the SCOPED
/// source (not the scope directly): membership and vendor both come
/// from one filtered `list()` snapshot, so the executor can never
/// disagree with what the prompt/tools present.
pub struct ScopedSessionExecutor {
    pub inner: Arc<dyn SessionExecutor>,
    /// The chat's [`ScopedScrollbackSource`] (as a trait object).
    pub sessions: Arc<dyn ScrollbackSource>,
}

impl ScopedSessionExecutor {
    fn visible_meta(&self, session_id: &str) -> Option<SessionMeta> {
        self.sessions
            .list()
            .into_iter()
            .find(|m| m.session_id == session_id)
    }
}

#[async_trait]
impl SessionExecutor for ScopedSessionExecutor {
    async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
        // Two conditions, both required — `None` on either drives
        // `handle_propose_command`'s structured refusal ("session not
        // found: {id}", executed: false):
        //
        //   1. IN SCOPE — `visible_meta` answers from the scoped
        //      scrollback list.
        //   2. EXECUTABLE — the INNER executor (the SSH+console
        //      `Unified` pair) must actually own a PTY for this id.
        //
        // Condition 2 is load-bearing since v4.0.0: the scoped
        // scrollback list now ALSO includes API/controller sessions
        // (vendor `Custom("unifi")`), which exist for `read_scrollback`
        // but have no PTY and are absent from the inner executor. Without
        // this check `vendor_for` would return `Some(unifi)` for a
        // controller id and `propose_command` would run the policy gate
        // (and, under a permissive user `unifi.yaml`, pop an approval
        // modal) against a target it can never execute on. Requiring
        // inner ownership makes a controller id byte-identical to an
        // unknown session — so `propose_command` (a PTY-command tool)
        // structurally cannot target a controller. A REST GET reaches a
        // controller only through the separately-gated `propose_api_call`.
        let meta = self.visible_meta(session_id)?;
        self.inner.vendor_for(session_id).await?;
        Some(meta.vendor)
    }

    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
        timeout: Duration,
        quiescence: Duration,
    ) -> Result<(String, CaptureEnd), AgentError> {
        // Re-checked HERE, after the approval modal resolved: a scope
        // shrink while the modal was open (or mid-checkpoint-pause)
        // must block execution even for an approved command.
        if self.visible_meta(session_id).is_none() {
            return Err(AgentError::SessionNotFound {
                session_id: session_id.to_string(),
            });
        }
        self.inner
            .run_command(session_id, command, timeout, quiescence)
            .await
    }
}

/// `ApiExecutor` filter for `propose_api_call` — the T31 analog of
/// [`ScopedSessionExecutor`]. Membership comes from the SCOPED scrollback
/// list (a controller must be an OPEN, in-scope session — the same
/// filtered view the tools + prompt present); the inner executor does the
/// endpoint resolution + GET-only confine + send.
///
/// The two-layer split mirrors the command path: this wrapper answers
/// visibility+scope (a controller absent from the scoped list → the
/// byte-identical "session not found" refusal, no oracle), and the inner
/// [`AppApiExecutor`] resolves the endpoint from inventory and adjudicates
/// the GET. `run_get` RE-checks scope after the modal, so a descope during
/// the approval window blocks an approved GET.
///
/// [`AppApiExecutor`]: crate::agent_dispatch::AppApiExecutor
pub struct ScopedApiExecutor {
    pub inner: Arc<dyn ApiExecutor>,
    /// The chat's [`ScopedScrollbackSource`] (as a trait object) — one
    /// coherent filtered view, shared with the tools/prompt/command path.
    pub sessions: Arc<dyn ScrollbackSource>,
}

impl ScopedApiExecutor {
    /// Whether `session_id` is an OPEN, in-scope controller: it must appear
    /// in the scoped scrollback list (which already filters by scope). For
    /// an API session `session_id == device_id`, so this is exact.
    fn visible(&self, session_id: &str) -> bool {
        self.sessions
            .list()
            .into_iter()
            .any(|m| m.session_id == session_id)
    }
}

#[async_trait]
impl ApiExecutor for ScopedApiExecutor {
    async fn gate(&self, session_id: &str, path: &str) -> ApiGate {
        // Not an open, in-scope controller → byte-identical to unknown
        // (no oracle). Only THEN adjudicate the GET+confine via the inner.
        if !self.visible(session_id) {
            return ApiGate::SessionNotFound;
        }
        self.inner.gate(session_id, path).await
    }

    async fn run_get(&self, session_id: &str, path: &str) -> Result<String, AgentError> {
        // Re-check scope AFTER the modal — a descope (or the session
        // closing) while the approval was open must block the GET, exactly
        // like `ScopedSessionExecutor::run_command`.
        if !self.visible(session_id) {
            return Err(AgentError::SessionNotFound {
                session_id: session_id.to_string(),
            });
        }
        self.inner.run_get(session_id, path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use transit_agent::testing::{MockDispatcher, MockScrollbackSource};
    use transit_agent::{Conversation, ConversationRedactor};
    use transit_policy::PolicyEngine;

    fn meta(session_id: &str, device_id: &str, vendor: Vendor) -> SessionMeta {
        SessionMeta {
            session_id: session_id.into(),
            device_id: device_id.into(),
            vendor,
            kind: transit_agent::SessionKind::Ssh,
            opened_at: "2026-07-10T00:00:00Z".into(),
            api_endpoints: Vec::new(),
            alias: None,
            commands_run: None,
            scrollback_bytes: None,
        }
    }

    /// v6.1.1 — fixture REGISTRY ids are uuid-shaped so they can never
    /// collide with the alias namespace (`s1`, `s2`, …) the ledger
    /// allocates in these same tests. `SID_VEX1` sorts before
    /// `SID_CORE1` (MockScrollbackSource lists in session_id order), so
    /// with both in scope the allocation is s1→vEX1, s2→core1.
    const SID_VEX1: &str = "aaaa1111-0000-4000-8000-00000000vex1";
    const SID_CORE1: &str = "bbbb2222-0000-4000-8000-0000000core1";

    /// Two live sessions on distinct devices/vendors — the standard
    /// fixture: `SID_VEX1` on device `vEX1` (Junos), `SID_CORE1` on
    /// `core1` (NX-OS).
    fn two_session_source() -> Arc<dyn ScrollbackSource> {
        Arc::new(
            MockScrollbackSource::new()
                .with_session(meta(SID_VEX1, "vEX1", Vendor::Junos), "junos scrollback")
                .with_session(meta(SID_CORE1, "core1", Vendor::NxOs), "nxos scrollback"),
        )
    }

    fn scoped(
        inner: Arc<dyn ScrollbackSource>,
        scope: &SharedScope,
    ) -> Arc<ScopedScrollbackSource> {
        Arc::new(ScopedScrollbackSource {
            inner,
            scope: scope.clone(),
            ledger: SessionLedger::new(),
        })
    }

    /// Inner executor that records every run_command; vendor_for is
    /// deliberately permissive (Some for any id) so a test failure
    /// can only come from the SCOPED layer, not the stub.
    struct RecordingExecutor {
        run_calls: Arc<StdMutex<Vec<String>>>,
    }

    impl RecordingExecutor {
        fn new() -> (Arc<Self>, Arc<StdMutex<Vec<String>>>) {
            let calls = Arc::new(StdMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    run_calls: Arc::clone(&calls),
                }),
                calls,
            )
        }
    }

    #[async_trait]
    impl SessionExecutor for RecordingExecutor {
        async fn vendor_for(&self, _session_id: &str) -> Option<Vendor> {
            Some(Vendor::Junos)
        }
        async fn run_command(
            &self,
            session_id: &str,
            command: &str,
            _timeout: Duration,
            _quiescence: Duration,
        ) -> Result<(String, CaptureEnd), AgentError> {
            self.run_calls
                .lock()
                .unwrap()
                .push(format!("{session_id}: {command}"));
            Ok(("ran".into(), CaptureEnd::Quiescence))
        }
    }

    /// Inner executor that owns SSH ids but NOT controller ids — mirrors
    /// the real `UnifiedSessionExecutor`, which has an SSH + console arm
    /// but NO API arm. `vendor_for` → `None` and `run_command` →
    /// `SessionNotFound` for any `api…` id, exactly as the unified
    /// executor does for a session id it doesn't own.
    struct ApiPartitionedExecutor;

    #[async_trait]
    impl SessionExecutor for ApiPartitionedExecutor {
        async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
            if session_id.starts_with("api") {
                None
            } else {
                Some(Vendor::Junos)
            }
        }
        async fn run_command(
            &self,
            session_id: &str,
            _command: &str,
            _timeout: Duration,
            _quiescence: Duration,
        ) -> Result<(String, CaptureEnd), AgentError> {
            if session_id.starts_with("api") {
                Err(AgentError::SessionNotFound {
                    session_id: session_id.to_string(),
                })
            } else {
                Ok(("ran".into(), CaptureEnd::Quiescence))
            }
        }
    }

    fn scoped_executor(
        scope: &SharedScope,
    ) -> (Arc<ScopedSessionExecutor>, Arc<StdMutex<Vec<String>>>) {
        let (inner, calls) = RecordingExecutor::new();
        let sessions = scoped(two_session_source(), scope);
        (Arc::new(ScopedSessionExecutor { inner, sessions }), calls)
    }

    // ---- ScopedScrollbackSource ---------------------------------------

    #[test]
    fn unscoped_none_passes_everything_through() {
        let scope = SharedScope::new_unscoped();
        let src = scoped(two_session_source(), &scope);
        assert_eq!(src.list().len(), 2);
        assert!(src.snapshot(SID_VEX1).is_some());
        assert!(src.snapshot(SID_CORE1).is_some());
    }

    #[test]
    fn list_filters_to_scoped_devices() {
        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let src = scoped(two_session_source(), &scope);
        let listed = src.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, SID_VEX1);
        assert_eq!(listed[0].device_id, "vEX1");
        // v6.1.1 — the in-scope listing carries the allocated alias +
        // a zero command count.
        assert_eq!(listed[0].alias.as_deref(), Some("s1"));
        assert_eq!(listed[0].commands_run, Some(0));
    }

    #[test]
    fn snapshot_of_descoped_session_returns_none() {
        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let src = scoped(two_session_source(), &scope);
        assert!(src.snapshot(SID_VEX1).is_some());
        // Identical to an unknown/closed session — no oracle.
        assert!(src.snapshot(SID_CORE1).is_none());
        assert!(src.snapshot("never-existed").is_none());
    }

    #[test]
    fn empty_scope_hides_all_sessions() {
        let scope = SharedScope::new_unscoped();
        scope.set(Some(Vec::new()));
        let src = scoped(two_session_source(), &scope);
        assert!(src.list().is_empty());
        assert!(src.snapshot(SID_VEX1).is_none());
    }

    #[test]
    fn scope_update_applies_to_existing_wrappers() {
        // The live-update pin: the wrapper holds the SAME SharedScope
        // the chat session mutates, so a mid-turn set() is visible on
        // the very next call — no rebuild needed.
        let scope = SharedScope::new_unscoped();
        let src = scoped(two_session_source(), &scope);
        assert_eq!(src.list().len(), 2);
        scope.set(Some(vec!["core1".into()]));
        let listed = src.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, SID_CORE1);
        scope.set(None);
        assert_eq!(src.list().len(), 2);
    }

    // ---- SessionLedger (v6.1.1 aliases + per-session command counts) ---

    /// Source whose session set can change mid-test (open/close/re-open)
    /// — MockScrollbackSource is build-once, and alias retirement is
    /// precisely about the set changing.
    struct MutableSource {
        sessions: StdMutex<Vec<SessionMeta>>,
    }

    impl ScrollbackSource for MutableSource {
        fn snapshot(&self, session_id: &str) -> Option<transit_agent::Snapshot> {
            self.sessions
                .lock()
                .unwrap()
                .iter()
                .any(|m| m.session_id == session_id)
                .then(|| transit_agent::Snapshot {
                    text: String::new(),
                    truncated: false,
                    json: false,
                })
        }
        fn list(&self) -> Vec<SessionMeta> {
            self.sessions.lock().unwrap().clone()
        }
    }

    #[test]
    fn alias_allocation_stable_across_listings_first_listed_order() {
        let scope = SharedScope::new_unscoped();
        let src = scoped(two_session_source(), &scope);
        let first = src.list();
        assert_eq!(first[0].alias.as_deref(), Some("s1"));
        assert_eq!(first[0].device_id, "vEX1");
        assert_eq!(first[1].alias.as_deref(), Some("s2"));
        assert_eq!(first[1].device_id, "core1");
        // Idempotent: the same roster on every later listing.
        let second = src.list();
        assert_eq!(second[0].alias.as_deref(), Some("s1"));
        assert_eq!(second[1].alias.as_deref(), Some("s2"));
    }

    #[test]
    fn snapshot_resolves_alias_after_listing() {
        let scope = SharedScope::new_unscoped();
        let src = scoped(two_session_source(), &scope);
        // Before any listing no alias exists — "s1" is just an unknown
        // string (byte-identical refusal shape).
        assert!(src.snapshot("s1").is_none());
        src.list();
        // After listing, both vocabularies reach the same session.
        assert_eq!(
            src.snapshot("s1").map(|s| s.text),
            src.snapshot(SID_VEX1).map(|s| s.text)
        );
        assert!(src.snapshot("s99").is_none());
    }

    #[test]
    fn closed_alias_retired_and_reopened_device_gets_new_alias() {
        const SID_CORE1B: &str = "cccc3333-0000-4000-8000-000000core1b";
        let inner = Arc::new(MutableSource {
            sessions: StdMutex::new(vec![
                meta(SID_VEX1, "vEX1", Vendor::Junos),
                meta(SID_CORE1, "core1", Vendor::NxOs),
            ]),
        });
        let scope = SharedScope::new_unscoped();
        let src = ScopedScrollbackSource {
            inner: Arc::clone(&inner) as Arc<dyn ScrollbackSource>,
            scope: scope.clone(),
            ledger: SessionLedger::new(),
        };
        let listed = src.list();
        assert_eq!(listed[0].alias.as_deref(), Some("s1"));
        assert_eq!(listed[1].alias.as_deref(), Some("s2"));

        // core1's session closes: its alias must go dark like a closed
        // session (same bytes as never-existed — no oracle)…
        inner
            .sessions
            .lock()
            .unwrap()
            .retain(|m| m.session_id != SID_CORE1);
        assert_eq!(src.list().len(), 1);
        assert!(src.snapshot("s2").is_none());

        // …and when the DEVICE re-connects under a new registry id, it
        // gets a NEW alias (a new session is a new fact) — s2 is never
        // reused within the chat.
        inner
            .sessions
            .lock()
            .unwrap()
            .push(meta(SID_CORE1B, "core1", Vendor::NxOs));
        let relisted = src.list();
        let core1 = relisted
            .iter()
            .find(|m| m.device_id == "core1")
            .expect("re-opened device listed");
        assert_eq!(core1.alias.as_deref(), Some("s3"));
        // vEX1 kept s1 through all of it.
        let vex1 = relisted.iter().find(|m| m.device_id == "vEX1").unwrap();
        assert_eq!(vex1.alias.as_deref(), Some("s1"));
        // The retired alias still refuses.
        assert!(src.snapshot("s2").is_none());
    }

    #[test]
    fn allocation_skips_ordinals_colliding_with_listed_raw_ids() {
        // An API session's registry id IS its inventory device id
        // (api_scrollback_source.rs), so a user can name a controller
        // literally `s1`. The allocator refuses to hand out an ordinal
        // that collides with a currently-listed registry id — so both
        // vocabularies stay unambiguous: the raw name `s1` reaches the
        // controller, and no alias ever equals a listed raw id.
        let scope = SharedScope::new_unscoped();
        let src = scoped(
            Arc::new(
                MockScrollbackSource::new()
                    // "aaaa…" sorts before "s1".
                    .with_session(meta(SID_VEX1, "vEX1", Vendor::Junos), "ssh bytes")
                    .with_session(
                        meta("s1", "s1", Vendor::Custom("unifi".into())),
                        "api bytes",
                    ),
            ),
            &scope,
        );
        let listed = src.list();
        // s1 is skipped (a listed raw id); the SSH box gets s2, the
        // controller s3.
        assert_eq!(listed[0].session_id, SID_VEX1);
        assert_eq!(listed[0].alias.as_deref(), Some("s2"));
        assert_eq!(listed[1].session_id, "s1");
        assert_eq!(listed[1].alias.as_deref(), Some("s3"));
        // Every spelling reaches exactly the session it names.
        assert_eq!(src.snapshot("s1").unwrap().text, "api bytes");
        assert_eq!(src.snapshot("s2").unwrap().text, "ssh bytes");
        assert_eq!(src.snapshot("s3").unwrap().text, "api bytes");
    }

    #[test]
    fn late_opening_raw_id_collision_stays_alias_first_and_consistent() {
        // The allocator can only skip collisions it can SEE: a session
        // whose raw id equals an ALREADY-allocated alias can still open
        // later. Resolution is alias-map-first everywhere, so the alias
        // holder wins deterministically — and the envelope's meta
        // lookup (two-pass, alias-first) agrees with the bytes.
        const SID_CTRL: &str = "s1"; // hostile/unlucky inventory name
        let inner = Arc::new(MutableSource {
            sessions: StdMutex::new(vec![meta(SID_VEX1, "vEX1", Vendor::Junos)]),
        });
        let scope = SharedScope::new_unscoped();
        let src = ScopedScrollbackSource {
            inner: Arc::clone(&inner) as Arc<dyn ScrollbackSource>,
            scope: scope.clone(),
            ledger: SessionLedger::new(),
        };
        // vEX1 allocates s1 while it is the only session.
        assert_eq!(src.list()[0].alias.as_deref(), Some("s1"));
        // A controller literally named `s1` opens afterwards.
        inner.sessions.lock().unwrap().push(meta(
            SID_CTRL,
            SID_CTRL,
            Vendor::Custom("unifi".into()),
        ));
        let listed = src.list();
        let ctrl = listed.iter().find(|m| m.session_id == SID_CTRL).unwrap();
        assert_eq!(ctrl.alias.as_deref(), Some("s2"));
        // "s1" resolves to the ALIAS holder (vEX1), not the raw name —
        // deterministic, and identical to what the roster taught.
        let resolved = src.ledger.resolve("s1");
        assert_eq!(resolved, SID_VEX1);
        // The controller stays reachable through its own alias.
        assert_eq!(src.ledger.resolve("s2"), SID_CTRL);
    }

    #[test]
    fn allocation_strictly_after_scope_filter_no_counting_oracle() {
        // The T31 property the docs claim: an out-of-scope session
        // NEVER consumes an ordinal, even when it would sort first.
        // (A refactor hoisting decorate() above the scope filter would
        // hand hidden sessions ordinals — a counting oracle for how
        // many sessions exist outside scope. This fixture makes the
        // in-scope session sort SECOND so that refactor fails here.)
        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["core1".into()])); // SID_CORE1 sorts after SID_VEX1
        let src = scoped(two_session_source(), &scope);
        let listed = src.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].alias.as_deref(),
            Some("s1"),
            "the ONLY in-scope session takes the FIRST ordinal — a hidden \
             session must not have consumed it"
        );
        // Widening scope later: the previously-hidden session allocates
        // NOW, after the first — first-LISTED order, not sort order.
        scope.set(None);
        let listed = src.list();
        let vex1 = listed.iter().find(|m| m.device_id == "vEX1").unwrap();
        assert_eq!(vex1.alias.as_deref(), Some("s2"));
    }

    #[tokio::test]
    async fn read_envelope_names_the_session_the_bytes_came_from() {
        // The v6.1.1 review's headline bug: the envelope's meta lookup
        // must use the SAME precedence as the resolver (alias-map
        // first), or the id/device attributes can name a different
        // session than the bytes they wrap. Adversarial world: a
        // controller raw-named like an alias, opening AFTER that alias
        // was allocated, and sorting before its holder in the list.
        use transit_agent::{
            ConversationRedactor, DefaultDispatcher, ReadScrollbackInput, ToolCall, ToolDispatcher,
            ToolResult,
        };

        let inner = Arc::new(MutableSource {
            sessions: StdMutex::new(vec![meta(SID_VEX1, "vEX1", Vendor::Junos)]),
        });
        let scope = SharedScope::new_unscoped();
        let src = Arc::new(ScopedScrollbackSource {
            inner: Arc::clone(&inner) as Arc<dyn ScrollbackSource>,
            scope: scope.clone(),
            ledger: SessionLedger::new(),
        });
        src.list(); // vEX1 → s1
        inner.sessions.lock().unwrap().insert(
            0,
            meta("s1", "s1", Vendor::Custom("unifi".into())), // raw id == live alias
        );
        // MutableSource snapshots are empty-text; what we pin is the
        // ENVELOPE attributes agreeing with the resolver.
        let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
        let d = DefaultDispatcher::new(Arc::clone(&src) as Arc<dyn ScrollbackSource>, redactor);
        let res = d
            .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                session_id: "s1".into(),
                max_bytes: 4096,
                match_: None,
                context_lines: 2,
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ReadScrollback(o) => {
                // Resolution is alias-first → the bytes are vEX1's; the
                // envelope must say so, NOT pick the raw-named
                // controller off list order.
                assert!(
                    o.text.starts_with("<session id=\"s1\" device=\"vEX1\">\n"),
                    "envelope must name the alias holder the bytes came from, got: {}",
                    o.text
                );
            }
            _ => panic!("expected ReadScrollback"),
        }
    }

    #[test]
    fn ledger_counts_ride_listings() {
        let scope = SharedScope::new_unscoped();
        let src = scoped(two_session_source(), &scope);
        src.ledger.record_executed(SID_VEX1);
        src.ledger.record_executed(SID_VEX1);
        let listed = src.list();
        let vex1 = listed.iter().find(|m| m.device_id == "vEX1").unwrap();
        let core1 = listed.iter().find(|m| m.device_id == "core1").unwrap();
        assert_eq!(vex1.commands_run, Some(2));
        assert_eq!(core1.commands_run, Some(0));
    }

    // ---- ScopedSessionExecutor ----------------------------------------

    #[tokio::test]
    async fn vendor_for_none_for_descoped_session() {
        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let (exec, _) = scoped_executor(&scope);
        // In-scope: vendor answered from the scoped list's meta (the
        // REAL vendor, not the stub's), out-of-scope: None.
        assert_eq!(exec.vendor_for(SID_VEX1).await, Some(Vendor::Junos));
        assert_eq!(exec.vendor_for(SID_CORE1).await, None);
    }

    #[tokio::test]
    async fn run_command_descoped_errors_session_not_found_without_delegating() {
        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let (exec, calls) = scoped_executor(&scope);
        let err = exec
            .run_command(
                SID_CORE1,
                "show version",
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
            .expect_err("descoped session must not run");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
        assert!(
            calls.lock().unwrap().is_empty(),
            "inner executor must never see a descoped command"
        );
        // In-scope still delegates.
        let out = exec
            .run_command(
                SID_VEX1,
                "show version",
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
            .expect("in-scope command runs");
        assert_eq!(out.0, "ran");
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn scope_shrink_between_check_and_run_blocks_execution() {
        // Simulates a descope landing while the approval modal was
        // open: vendor_for succeeded earlier, but run_command's OWN
        // re-check must refuse.
        let scope = SharedScope::new_unscoped();
        let (exec, calls) = scoped_executor(&scope);
        assert_eq!(exec.vendor_for(SID_CORE1).await, Some(Vendor::NxOs));
        scope.set(Some(vec!["vEX1".into()]));
        let err = exec
            .run_command(
                SID_CORE1,
                "show version",
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
            .expect_err("descoped-after-approval must not run");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn vendor_for_none_for_visible_but_non_executable_api_session() {
        // T31/Rule-3 partition (v4.0.0): an API/controller session is
        // VISIBLE in the scoped scrollback list (read_scrollback +
        // list_open_sessions see it) but the inner executor owns no PTY
        // for it. propose_command must treat it as "session not found" —
        // byte-identical to unknown — so it can never target a controller.
        let scope = SharedScope::new_unscoped();
        let src: Arc<dyn ScrollbackSource> = Arc::new(
            MockScrollbackSource::new()
                .with_session(meta(SID_VEX1, "vEX1", Vendor::Junos), "junos scrollback")
                .with_session(
                    // A controller: device_id == session_id (the stable
                    // inventory id), per api_scrollback_source.rs.
                    meta("api1", "api1", Vendor::Custom("unifi".into())),
                    "> GET /v1/sites -> HTTP 200",
                ),
        );
        let sessions: Arc<dyn ScrollbackSource> = Arc::new(ScopedScrollbackSource {
            inner: src,
            scope: scope.clone(),
            ledger: SessionLedger::new(),
        });
        let exec = ScopedSessionExecutor {
            inner: Arc::new(ApiPartitionedExecutor),
            sessions,
        };

        // The controller IS visible for reads...
        assert!(
            exec.sessions.snapshot("api1").is_some(),
            "controller readable via read_scrollback"
        );
        // ...but NOT executable: vendor_for is None (byte-identical to
        // unknown), so propose_command short-circuits to "session not
        // found" before the gate or modal.
        assert_eq!(exec.vendor_for("api1").await, None);
        assert_eq!(exec.vendor_for(SID_VEX1).await, Some(Vendor::Junos));
        // Even if run_command is reached, it must not execute on a
        // controller — the inner executor rejects it, same error shape.
        let err = exec
            .run_command(
                "api1",
                "show version",
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
            .expect_err("controller must not run a PTY command");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
    }

    // ---- System-prompt coherence --------------------------------------

    #[test]
    fn system_prompt_omits_descoped_session_and_its_vendor_policy() {
        // The same scoped source handed to the Conversation drives the
        // prompt: OpenSessions lists only in-scope sessions, and the
        // PolicySummary section (keyed on open-session vendors) drops
        // the descoped vendor entirely.
        let policies_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cargo manifest has a parent")
            .join("policies");
        let engine = PolicyEngine::load_from_dir(&policies_dir).expect("policies load");
        let policies: Vec<_> = engine
            .vendors()
            .into_iter()
            .filter_map(|v| engine.summary(&v).map(|s| (v, s)))
            .collect();

        let scope = SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let src: Arc<dyn ScrollbackSource> = scoped(two_session_source(), &scope);
        let conversation = Conversation::new(
            Arc::new(MockDispatcher::new()),
            src,
            Arc::new(StdMutex::new(ConversationRedactor::new())),
            policies,
        );
        let rendered = conversation.system_prompt().render();

        // v6.1.1 — the roster line renders the ALIAS (allocated only
        // for the in-scope listing) rather than the registry id.
        assert!(
            rendered.contains("session_id: s1"),
            "in-scope session listed under its alias"
        );
        assert!(rendered.contains("vEX1"), "in-scope device named");
        assert!(rendered.contains("junos"), "in-scope vendor policy present");
        assert!(
            !rendered.contains(SID_VEX1),
            "registry ids never reach the prompt — the alias replaces them"
        );
        assert!(
            !rendered.contains(SID_CORE1) && !rendered.contains("core1"),
            "descoped session must not appear anywhere in the prompt"
        );
        assert!(
            !rendered.contains("nxos"),
            "descoped vendor's policy summary must not be rendered"
        );
    }

    // ---- ScopedApiExecutor (v4.0.0 — propose_api_call scope) ----------

    /// Inner API executor that always allows + records run_get calls, so a
    /// test failure can only come from the SCOPED layer, not the stub.
    /// `(session_id, path)` pairs run_get was called with.
    type ApiRunLog = Arc<StdMutex<Vec<(String, String)>>>;

    struct RecordingApiExecutor {
        run_calls: ApiRunLog,
    }

    impl RecordingApiExecutor {
        fn new() -> (Arc<Self>, ApiRunLog) {
            let calls = Arc::new(StdMutex::new(Vec::new()));
            (
                Arc::new(Self {
                    run_calls: Arc::clone(&calls),
                }),
                calls,
            )
        }
    }

    #[async_trait]
    impl ApiExecutor for RecordingApiExecutor {
        async fn gate(&self, _session_id: &str, _path: &str) -> ApiGate {
            ApiGate::Allow
        }
        async fn run_get(&self, session_id: &str, path: &str) -> Result<String, AgentError> {
            self.run_calls
                .lock()
                .unwrap()
                .push((session_id.into(), path.into()));
            Ok("{}".into())
        }
    }

    #[tokio::test]
    async fn scoped_api_gate_and_run_refuse_out_of_scope() {
        // A controller (device_id == session_id) visible in the scoped
        // scrollback list: in scope → gate Allow + run_get delegates; out
        // of scope → both are the byte-identical "session not found", and
        // the inner executor never sees a descoped GET.
        let scope = SharedScope::new_unscoped();
        let (inner, calls) = RecordingApiExecutor::new();
        let source: Arc<dyn ScrollbackSource> = Arc::new(MockScrollbackSource::new().with_session(
            meta("c1", "c1", Vendor::Custom("unifi".into())),
            "> GET /v1/sites -> HTTP 200",
        ));
        let exec = ScopedApiExecutor {
            inner,
            sessions: Arc::new(ScopedScrollbackSource {
                inner: source,
                scope: scope.clone(),
                ledger: SessionLedger::new(),
            }),
        };

        // In scope (unscoped) → allow + delegate once.
        assert!(matches!(exec.gate("c1", "/v1/sites").await, ApiGate::Allow));
        assert!(exec.run_get("c1", "/v1/sites").await.is_ok());
        assert_eq!(calls.lock().unwrap().len(), 1);

        // Descope every device: gate + run_get both refuse, inner untouched.
        scope.set(Some(Vec::new()));
        assert!(matches!(
            exec.gate("c1", "/v1/sites").await,
            ApiGate::SessionNotFound
        ));
        let err = exec
            .run_get("c1", "/v1/sites")
            .await
            .expect_err("descoped run_get must fail");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "inner executor never saw the descoped GET"
        );

        // An unknown controller is likewise SessionNotFound (no oracle).
        scope.set(None);
        assert!(matches!(
            exec.gate("never-existed", "/v1/sites").await,
            ApiGate::SessionNotFound
        ));
    }
}
