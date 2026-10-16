//! Phase 6 dispatcher — wraps `transit_agent::DefaultDispatcher`
//! with the policy-gate + UI-modal flow for `propose_command` and
//! the inline-question channel for `ask_user`.
//!
//! Both ends are abstracted behind small traits so the dispatcher
//! is unit-testable without an `AppHandle` or a live SSH session:
//! - [`ApprovalChannel`] — surfaces approve/deny modals + inline
//!   questions back to the UI. Production impl wraps `AppHandle` +
//!   the pending-responder maps; tests use a stub.
//! - [`SessionExecutor`] — runs a command in a session and captures
//!   its quiescent output. Production impl wraps `SshState`; tests
//!   use a stub that yields canned bytes.
//!
//! Inviolable Rule 3 (CLAUDE.md §3) lives here: every
//! `propose_command` runs through BOTH the policy gate AND the UI
//! modal. The "always allow" regex affordance only suppresses the
//! modal step for commands the gate ALREADY permits — the gate runs
//! every time. The allowlist is per-`(chat_id, session_id)`,
//! in-memory only, never persisted (Decision D6).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use uuid::Uuid;

use transit_agent::{
    AgentError, AskUserInput, AskUserOutput, ConversationRedactor, DefaultDispatcher,
    ProposeApiCallInput, ProposeApiCallOutput, ProposeCommandInput, ProposeCommandOutput,
    ScrollbackSource, ToolCall, ToolDispatcher, ToolResult,
};
use transit_core::inventory::Vendor;
use transit_policy::{Decision, PolicyEngine};

// ---------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------

/// Total time we'll wait for command output before declaring the
/// capture complete. A long-running `show route` on a busy box can
/// stream for many seconds; the quiescence timeout below stops the
/// capture sooner once the device goes quiet.
pub const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the device must be silent for us to consider the
/// command's output complete. 800ms is generous enough for
/// human-paced typing pauses (the prompt re-display) and tight
/// enough that the model isn't waiting on a spurious blank period.
pub const DEFAULT_QUIESCENCE: Duration = Duration::from_millis(800);

// ---------------------------------------------------------------------
// User-facing verdicts
// ---------------------------------------------------------------------

/// Verdict returned from the propose-command modal.
#[derive(Debug, Clone)]
pub enum ProposeVerdict {
    Approve,
    Deny,
    /// Approve + remember a regex pattern. Subsequent commands in
    /// the same chat+session that match the regex skip the modal
    /// (the policy gate STILL runs every time — Rule 3).
    AlwaysAllowRegex(Regex),
}

// ---------------------------------------------------------------------
// Trait: the UI-modal channel
// ---------------------------------------------------------------------

#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Emit a `propose-command:request` event and await the user's
    /// verdict. The implementation generates a unique `request_id`
    /// (uuid) so the IPC reply can find the right oneshot in the
    /// pending-approvals map.
    async fn request_command_approval(
        &self,
        chat_id: &str,
        session_id: &str,
        command: &str,
        gate_decision: &str,
        allow_auto_approve: bool,
    ) -> Result<ProposeVerdict, AgentError>;

    /// Emit an `ask-user:request` event and await the user's reply.
    async fn request_user_input(&self, chat_id: &str, question: &str)
        -> Result<String, AgentError>;

    /// Emit a `propose-api-call:request` event and await the user's
    /// verdict. Mirrors [`request_command_approval`] but for a GET-only
    /// controller call: there is NO auto-approve affordance (API sessions
    /// are custom-vendor UniFi, which structurally refuse the shortcut),
    /// so the only meaningful verdicts are Approve / Deny. Reuses the same
    /// `pending_approvals` map + `respond_propose_command` reply path.
    ///
    /// [`request_command_approval`]: ApprovalChannel::request_command_approval
    async fn request_api_call_approval(
        &self,
        chat_id: &str,
        session_id: &str,
        path: &str,
        gate_decision: &str,
    ) -> Result<ProposeVerdict, AgentError>;
}

// ---------------------------------------------------------------------
// Trait: the SSH-side seam (vendor lookup + run-command)
// ---------------------------------------------------------------------

/// Why a `propose_command` capture stopped (v6.1.x #2).
///
/// `Quiescence` is the normal end — the device went quiet — but quiet
/// is NOT proof the command finished: a slow ping emits a line per
/// second and the 800 ms window closes between packets, which is how
/// the 2026-08-14 live smoke produced fabricated ping results. The
/// dispatcher pairs this reason with a prompt-tail check and annotates
/// the result envelope when the output looks unfinished, so the model
/// re-reads instead of inventing the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureEnd {
    /// The quiescence window elapsed with no new bytes.
    Quiescence,
    /// The overall capture timeout elapsed — the device was still
    /// producing output when the window closed.
    Timeout,
    /// The session channel closed mid-capture.
    Closed,
}

#[async_trait]
pub trait SessionExecutor: Send + Sync {
    /// Vendor of the device backing `session_id`. None when the
    /// session id doesn't match an open session.
    async fn vendor_for(&self, session_id: &str) -> Option<Vendor>;

    /// Send `command\n` and capture quiescent output. Returns raw
    /// bytes (the dispatcher redacts before handing to the model)
    /// plus WHY the capture stopped (v6.1.x — the envelope's
    /// `capture="…"` annotation). Errors when the session is unknown
    /// or closed.
    async fn run_command(
        &self,
        session_id: &str,
        command: &str,
        timeout: Duration,
        quiescence: Duration,
    ) -> Result<(String, CaptureEnd), AgentError>;
}

/// The quiescence capture loop, shared by the SSH and console
/// executors (both subscribe to a `broadcast::Receiver<Bytes>`; only
/// the subscribe/send differ by session type, so only the loop is
/// factored). Captures until the device goes quiet for `quiescence`,
/// the overall `timeout` elapses, or the channel closes — returning
/// the accumulated text and WHY it stopped (`CaptureEnd`). A single
/// definition so a terminator-classification change lands once, not
/// twice (the console copy silently diverging is the risk this
/// removes).
pub(crate) async fn capture_until_quiet(
    mut rx: tokio::sync::broadcast::Receiver<Bytes>,
    timeout: Duration,
    quiescence: Duration,
) -> (String, CaptureEnd) {
    let start = Instant::now();
    let mut last_byte_at = Instant::now();
    let mut accumulated: Vec<u8> = Vec::new();
    let end;
    loop {
        if start.elapsed() >= timeout {
            end = CaptureEnd::Timeout;
            break;
        }
        let remaining_for_quiet = quiescence.saturating_sub(last_byte_at.elapsed());
        if remaining_for_quiet.is_zero() {
            end = CaptureEnd::Quiescence;
            break;
        }
        match tokio::time::timeout(remaining_for_quiet, rx.recv()).await {
            // bytes arrived
            Ok(Ok(b)) => {
                accumulated.extend_from_slice(&b);
                last_byte_at = Instant::now();
            }
            // Lagged is recoverable — the broadcast ring overwrote `n`
            // chunks while we were slow. Mark the gap visibly and keep
            // capturing (output IS flowing, so the quiescence window
            // resets).
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                accumulated.extend_from_slice(
                    format!("\n[transit: output gap — {n} chunks dropped]\n").as_bytes(),
                );
                last_byte_at = Instant::now();
                continue;
            }
            // session closed
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                end = CaptureEnd::Closed;
                break;
            }
            // quiescence expired
            Err(_) => {
                end = CaptureEnd::Quiescence;
                break;
            }
        }
    }
    (String::from_utf8_lossy(&accumulated).into_owned(), end)
}

/// Whether captured output ENDS in something that looks like a CLI
/// prompt — the conservative test behind the `capture="silence"`
/// annotation. Loose about vendor prompt shapes (`>`, `#`, `$`, `%`)
/// and biased toward false NEGATIVES: a missed annotation is exactly
/// pre-v6.1.x behavior, while a false positive only adds a harmless
/// re-read hint to a finished capture.
fn tail_looks_like_prompt(output: &str) -> bool {
    let Some(last) = output.lines().rev().find(|l| !l.trim().is_empty()) else {
        return false;
    };
    let t = last.trim_end();
    // A prompt is short; a 200-char line ending in '>' is data.
    t.len() <= 120 && (t.ends_with('>') || t.ends_with('#') || t.ends_with('$') || t.ends_with('%'))
}

// ---------------------------------------------------------------------
// Trait: the API-session seam (GET-only gate + run) — propose_api_call
// ---------------------------------------------------------------------

/// Verdict of the GET-only API gate. The "policy" here is the structural
/// GET+confine floor in `transit_api::gate` (a GET can't mutate; the path
/// must confine to the controller's pinned base), NOT the CLI regex
/// engine — see the original design notes (not included in this repository) and CLAUDE.md §3.
#[derive(Debug, Clone)]
pub enum ApiGate {
    /// Open + in-scope controller AND the path confines to its pinned
    /// base as a GET.
    Allow,
    /// Open + in-scope, but the path escapes the base (or, defensively,
    /// isn't a GET). Surfaces as "Transit's policy gate denied this request — {reason}".
    Deny { reason: String },
    /// Not an open, in-scope controller — byte-identical to unknown
    /// (no oracle that a hidden/out-of-scope controller exists).
    SessionNotFound,
}

/// The API-session seam for `propose_api_call` — the controller analog of
/// [`SessionExecutor`]. Two methods mirroring the command path's
/// `vendor_for`/`run_command` split: `gate` adjudicates (membership +
/// GET-only confine, no side effects) and `run_get` executes the confined
/// GET. The key is injected downstream in `transit_api`, never here and
/// never in `transit_agent`.
#[async_trait]
pub trait ApiExecutor: Send + Sync {
    /// Membership + GET-only path confinement — the WHOLE read-only floor.
    /// No key resolution, no HTTP.
    async fn gate(&self, session_id: &str, path: &str) -> ApiGate;

    /// Execute the confined GET: re-gate (fail-closed), resolve the key,
    /// send, append to the controller's ring, return the RAW body (the
    /// dispatcher redacts before the model sees it). Errors on an unknown
    /// session / transport failure / a re-gate denial.
    async fn run_get(&self, session_id: &str, path: &str) -> Result<String, AgentError>;
}

// ---------------------------------------------------------------------
// Pending-responder maps + Tauri-side ApprovalChannel impl
// ---------------------------------------------------------------------

/// Keyed by request_id (uuid). The value pairs the owning `chat_id`
/// with the oneshot sender the IPC reply commands look up to deliver
/// the verdict. The chat_id lets `cancel_chat_approvals` scope a
/// cancel to one chat (v2.5.0 multi-chat) instead of draining all
/// chats' pending entries.
pub type PendingApprovals =
    Arc<AsyncMutex<HashMap<String, (String, oneshot::Sender<ProposeVerdict>)>>>;
pub type PendingQuestions = Arc<AsyncMutex<HashMap<String, (String, oneshot::Sender<String>)>>>;

/// State managed by Tauri at app startup. C8's IPC commands
/// (`respond_propose_command`, `respond_ask_user`) drain these
/// maps when the user clicks Approve / Deny / Send.
pub struct ApprovalState {
    pub pending_approvals: PendingApprovals,
    pub pending_questions: PendingQuestions,
}

impl ApprovalState {
    pub fn new() -> Self {
        Self {
            pending_approvals: Arc::new(AsyncMutex::new(HashMap::new())),
            pending_questions: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }
}

impl Default for ApprovalState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct ProposeCommandRequestPayload {
    pub request_id: String,
    pub chat_id: String,
    pub session_id: String,
    pub command: String,
    pub gate_decision: String,
    /// Phase 8b — true when the vendor's policy is `mode: unrestricted`.
    /// Drives the amber warning banner. (Hiding the auto-approve
    /// affordance is driven by `allow_auto_approve`, not this — a
    /// custom vendor is gated but also has no auto-approve.)
    #[serde(default)]
    pub unrestricted: bool,
    /// Warning string from the unrestricted policy file. Rendered in
    /// the amber banner verbatim. None on gated vendors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// True when the auto-approve ("remember this regex") affordance is
    /// permitted for this command's vendor — i.e. the vendor has a
    /// shipped read-only floor. False for `unrestricted` (Linux) AND
    /// custom (BYOP) vendors, both of which require a per-command click
    /// with no regex shortcut. The frontend hides the affordance when
    /// false; the dispatcher independently refuses any regex verdict
    /// that slips through (defense in depth — see
    /// `handle_propose_command`).
    #[serde(default)]
    pub allow_auto_approve: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct AskUserRequestPayload {
    pub request_id: String,
    pub chat_id: String,
    pub question: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProposeCommandCancelPayload {
    pub request_id: String,
    /// Owning chat — lets a per-chat modal / notification card filter
    /// cancels to its own chat (v2.5.0 multi-chat).
    pub chat_id: String,
}

/// Emitted on `propose-api-call:request` (v4.0.0). The GET-only analog of
/// [`ProposeCommandRequestPayload`]: it carries a `path` (not a `command`)
/// and has NO `unrestricted`/`warning`/`allow_auto_approve` fields — an
/// agent controller call is always a per-call approval with no
/// auto-approve shortcut (custom-vendor UniFi). The reply comes back
/// through the shared `respond_propose_command` path.
#[derive(Debug, Serialize, Clone)]
pub struct ProposeApiCallRequestPayload {
    pub request_id: String,
    pub chat_id: String,
    pub session_id: String,
    /// The GET path the agent proposes (e.g. `/v1/sites`). GET is
    /// implicit — the tool input carries no method.
    pub path: String,
    /// Gate result text ("allow (GET)" by the time the modal renders — a
    /// denied path short-circuits before the modal). Present for UI
    /// symmetry with propose_command.
    pub gate_decision: String,
}

// No dedicated `propose-api-call:cancel` event: `cancel_chat_approvals`
// drains the shared `pending_approvals` map and emits
// `propose-command:cancel` for EVERY entry (command or api — it can't tell
// them apart, and needn't). The frontend clears BOTH the command and api
// pending slots for that chat on `propose-command:cancel`, so an api modal
// is torn down correctly with no extra event.

/// Production [`ApprovalChannel`] — writes to the
/// `propose-command:request` and `ask-user:request` Tauri event
/// topics, sleeps on a oneshot until the C8 IPC reply lands.
pub struct TauriApprovalChannel {
    pub app: AppHandle,
    pub pending_approvals: PendingApprovals,
    pub pending_questions: PendingQuestions,
}

#[async_trait]
impl ApprovalChannel for TauriApprovalChannel {
    async fn request_command_approval(
        &self,
        chat_id: &str,
        session_id: &str,
        command: &str,
        gate_decision: &str,
        allow_auto_approve: bool,
    ) -> Result<ProposeVerdict, AgentError> {
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_approvals.lock().await;
            pending.insert(request_id.clone(), (chat_id.to_string(), tx));
        }
        // Phase 8b — split the gate_decision string into structured
        // fields. `gate_decision_text` from the dispatcher is
        // "unrestricted: <warning>" for unrestricted vendors and
        // "allow" / "deny: <reason>" otherwise. The frontend doesn't
        // need to sniff that prefix — it gets the boolean + warning
        // directly.
        let (unrestricted, warning) = gate_decision
            .strip_prefix("unrestricted: ")
            .map(|w| (true, Some(w.to_string())))
            .unwrap_or((false, None));
        let payload = ProposeCommandRequestPayload {
            request_id: request_id.clone(),
            chat_id: chat_id.to_string(),
            session_id: session_id.to_string(),
            command: command.to_string(),
            gate_decision: gate_decision.to_string(),
            unrestricted,
            warning,
            allow_auto_approve,
        };
        if let Err(e) = self.app.emit("propose-command:request", payload) {
            // Failed to surface the modal — treat as a dispatcher
            // error rather than a denial, since the user never got
            // to weigh in.
            self.pending_approvals.lock().await.remove(&request_id);
            return Err(AgentError::Dispatcher(format!(
                "failed to emit propose-command:request: {e}"
            )));
        }
        rx.await.map_err(|_| {
            AgentError::Dispatcher(
                "propose-command modal closed before user replied (chat ended?)".into(),
            )
        })
    }

    async fn request_user_input(
        &self,
        chat_id: &str,
        question: &str,
    ) -> Result<String, AgentError> {
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_questions.lock().await;
            pending.insert(request_id.clone(), (chat_id.to_string(), tx));
        }
        let payload = AskUserRequestPayload {
            request_id: request_id.clone(),
            chat_id: chat_id.to_string(),
            question: question.to_string(),
        };
        if let Err(e) = self.app.emit("ask-user:request", payload) {
            self.pending_questions.lock().await.remove(&request_id);
            return Err(AgentError::Dispatcher(format!(
                "failed to emit ask-user:request: {e}"
            )));
        }
        rx.await.map_err(|_| {
            AgentError::Dispatcher(
                "ask-user inline card closed before user replied (chat ended?)".into(),
            )
        })
    }

    async fn request_api_call_approval(
        &self,
        chat_id: &str,
        session_id: &str,
        path: &str,
        gate_decision: &str,
    ) -> Result<ProposeVerdict, AgentError> {
        // Same request_id + shared `pending_approvals` map as
        // `request_command_approval`, so `respond_propose_command` (the one
        // reply IPC) resolves this too — the only difference is the event
        // topic + payload the frontend renders.
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_approvals.lock().await;
            pending.insert(request_id.clone(), (chat_id.to_string(), tx));
        }
        let payload = ProposeApiCallRequestPayload {
            request_id: request_id.clone(),
            chat_id: chat_id.to_string(),
            session_id: session_id.to_string(),
            path: path.to_string(),
            gate_decision: gate_decision.to_string(),
        };
        if let Err(e) = self.app.emit("propose-api-call:request", payload) {
            self.pending_approvals.lock().await.remove(&request_id);
            return Err(AgentError::Dispatcher(format!(
                "failed to emit propose-api-call:request: {e}"
            )));
        }
        rx.await.map_err(|_| {
            AgentError::Dispatcher(
                "propose-api-call modal closed before user replied (chat ended?)".into(),
            )
        })
    }
}

// ---------------------------------------------------------------------
// SshState-backed SessionExecutor
// ---------------------------------------------------------------------

use crate::ssh::SshState;
use bytes::Bytes;

/// Production [`SessionExecutor`] backed by `SshState.sessions`.
pub struct SshSessionExecutor {
    pub ssh: Arc<SshState>,
}

#[async_trait]
impl SessionExecutor for SshSessionExecutor {
    async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
        let guard = self.ssh.sessions.lock().await;
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
        // containing control characters (a "show ver\nconf t" gates
        // as one line but would execute as two). Refuse here too so
        // a future gate refactor can't silently re-open the
        // executor to embedded newlines.
        if command.chars().any(|c| c.is_control()) {
            return Err(AgentError::Dispatcher(
                "refusing to send command containing control characters".into(),
            ));
        }
        // Subscribe BEFORE sending so we don't miss the head of
        // the response. Then send command + capture until either
        // the device goes quiet for `quiescence` or `timeout`
        // elapses.
        let session = {
            let guard = self.ssh.sessions.lock().await;
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

        Ok(capture_until_quiet(rx, timeout, quiescence).await)
    }
}

// ---------------------------------------------------------------------
// AppHandle-backed ApiExecutor (production propose_api_call path)
// ---------------------------------------------------------------------

/// Production [`ApiExecutor`]. Holds only an `AppHandle`; resolves the
/// controller's endpoint (inventory), key (`transit_auth` via the
/// `SecretRegistry`), the shared `ApiClient`, and the ring LIVE via
/// `app.state::<AppState>()` at call time — so a controller edited
/// mid-chat is picked up next turn, and no secret is cached here.
///
/// The GET-only gate is `transit_api::evaluate_agent_get`, whose `Allow`
/// carries the already-confined URL; `run_get` hands THAT url straight to
/// `ApiClient::get` (GET hard-coded, key injected inside `transit_api`),
/// so there is no check-then-send gap and no path by which the agent can
/// reach a non-GET, a foreign host, or the raw key. This type lives in
/// `transit_app` and touches `transit_auth`/`transit_api`; the agent crate
/// only ever sees the abstract [`ApiExecutor`] trait (firewall intact).
pub struct AppApiExecutor {
    pub app: AppHandle,
}

impl AppApiExecutor {
    /// Resolve a controller's endpoint + the pieces `run_get` needs, or
    /// `None` if it isn't in inventory. Live read; the inventory lock is
    /// released before we return (never held across the HTTP call).
    async fn resolve(
        &self,
        session_id: &str,
    ) -> Option<(
        transit_api::Endpoint,
        transit_core::inventory::AuthScheme,
        Option<transit_core::inventory::SecretRef>,
        String,
        Vendor,
    )> {
        let state = self.app.state::<crate::commands::AppState>();
        crate::commands::resolve_api_session_endpoint(&state, session_id)
            .await
            // `.ok()` deliberately folds EVERY resolution failure (session
            // missing, `InventoryState::Broken`, a stored host that no longer
            // parses) into `None` → `SessionNotFound`. Fail-closed, and part
            // of the no-oracle property: a broken inventory must not surface a
            // distinct signal to the agent. A genuinely broken inventory is
            // surfaced to the USER elsewhere (`list_devices` + the mutators).
            .ok()
    }
}

#[async_trait]
impl ApiExecutor for AppApiExecutor {
    async fn gate(&self, session_id: &str, path: &str) -> ApiGate {
        let Some((endpoint, ..)) = self.resolve(session_id).await else {
            return ApiGate::SessionNotFound;
        };
        match transit_api::evaluate_agent_get(&endpoint, "GET", path) {
            transit_api::ApiDecision::Allow { .. } => ApiGate::Allow,
            // Do NOT echo the raw confine-error reason to the agent — it
            // becomes a tool result → the cloud LLM, and `HostEscape` names
            // the controller's pinned origin (a LAN IP), `PathEscape` the
            // base path (incl. the console id). A generic reason keeps the
            // no-oracle property AND leaks no device identifier the agent
            // would gain only via the error; it's enough for the model to
            // pivot to a valid path. (Every agent-path deny is a confine
            // failure — GET is the only method sent.)
            transit_api::ApiDecision::Deny { .. } => ApiGate::Deny {
                reason: "path is outside this controller's read-only API surface".to_string(),
            },
        }
    }

    async fn run_get(&self, session_id: &str, path: &str) -> Result<String, AgentError> {
        let (endpoint, auth_scheme, secret_ref, name, vendor) = self
            .resolve(session_id)
            .await
            .ok_or_else(|| AgentError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;
        // Re-gate (fail-closed): re-adjudicate AFTER the modal, so a
        // controller edited — or a path that no longer confines — during
        // the approval window can't execute. `Allow` carries the confined
        // URL, so we send EXACTLY what was re-adjudicated (no gap).
        let url = match transit_api::evaluate_agent_get(&endpoint, "GET", path) {
            transit_api::ApiDecision::Allow { url } => url,
            // Generic reason (same as `gate`) — never echo the confine
            // error's IP / console-id / base to the agent.
            transit_api::ApiDecision::Deny { .. } => {
                return Err(AgentError::Dispatcher(
                    "path is outside this controller's read-only API surface".to_string(),
                ));
            }
        };
        let state = self.app.state::<crate::commands::AppState>();
        // Map the controller's configured auth scheme → AppliedAuth (secret
        // resolved server-side; `none` sends no auth). The error is generic —
        // it forwards to the model, so it must leak no backend detail.
        let auth = crate::commands::build_applied_auth(&state, &auth_scheme, secret_ref.as_ref())
            .await
            .map_err(|_| AgentError::Dispatcher("api auth setup failed".to_string()))?;
        // Replay the session auth header the HUMAN established (ACI's
        // APIC-cookie, vManage's JSESSIONID, Apstra's AuthToken). Those are
        // captured session tokens, not keychain-backed `AppliedAuth`, so
        // without this every agent GET against a login-flow controller 403s
        // while the human pane works. The agent RIDES the human's session; it
        // cannot create one (login is a POST, and the tool is GET-only).
        // Origin-scoped: a controller whose base URL was edited to another
        // host must not have the previous host's session cookie replayed to it.
        let origin = endpoint.api_base().origin().ascii_serialization();
        let extra: Vec<(String, String)> =
            match state.api_sessions.session_auth(session_id, &origin) {
                Some((name, value)) => {
                    use secrecy::ExposeSecret;
                    vec![(name, value.expose_secret().to_string())]
                }
                None => Vec::new(),
            };
        let resp = state
            .api_client
            .get_with_headers(url, &extra, &auth)
            .await
            .map_err(|e| {
                // Classify WITHOUT echoing the URL/host — `ApiError::Transport`'s
                // Display names it, a device identifier the agent would gain
                // only via the error. Timeout vs generic is enough to pivot on.
                let kind = match &e {
                    transit_api::ApiError::Timeout => "timed out",
                    _ => "failed",
                };
                AgentError::Dispatcher(format!("api request to the controller {kind}"))
            })?;
        // Record the agent's GET into the controller's ring — visible to
        // the human via read_scrollback + audited, exactly like a human
        // send. RAW bytes; redaction is the dispatcher's job downstream.
        state.api_sessions.record_exchange(
            session_id,
            &name,
            &vendor,
            "GET",
            path,
            resp.status,
            &resp.body,
        );
        Ok(resp.body)
    }
}

// ---------------------------------------------------------------------
// ApprovalDispatcher
// ---------------------------------------------------------------------

/// Per-(chat_id, session_id) regex allowlist. **Owned by the chat
/// session** (`ChatState`), not by the dispatcher: a fresh
/// `ApprovalDispatcher` is built for every `chat_send_message`, but
/// they all share the chat's one `AlwaysAllowMap`, so an allowlist
/// entry persists across messages for the life of the chat and is
/// dropped only when the chat is destroyed. The `(chat_id,
/// session_id)` key keeps entries scoped per chat AND per open
/// session even though one chat's dispatchers all carry the same
/// chat_id.
pub type AlwaysAllowMap = Arc<std::sync::Mutex<HashMap<(String, String), Vec<Regex>>>>;

/// Construct an empty [`AlwaysAllowMap`] for a new chat session.
pub fn new_always_allow_map() -> AlwaysAllowMap {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

/// Per-chat "auto-approve all agent GETs" flag for `propose_api_call`.
/// Owned by the `ChatSession`, Arc-cloned into every per-message dispatcher
/// so an opt-in persists for the life of the chat (dropped — cleared — when
/// the chat is destroyed). In-memory only, never persisted; the ONLY writer
/// is the user-driven `chat_set_auto_approve_gets` IPC (the agent has no path
/// to it — Rule 2's tools are unchanged).
///
/// Unlike the command path's regex allowlist — refused for custom vendors
/// because a regex could green-light a WRITE with no shipped read-only floor
/// (T18) — this is a single bool and is SAFE by construction:
/// `propose_api_call` is structurally GET-only (no `method` field; the gate
/// and `ApiClient::get` both hard-enforce GET), so "auto-approve all GETs"
/// can only ever auto-approve READS. The GET+confine gate STILL runs on
/// every call; this only suppresses the approval modal.
///
/// A newtype (not a bare `Arc<AtomicBool>`) so the SETTER is crate-private —
/// the ONE caller is the user-driven `chat_set_auto_approve_gets` IPC. This
/// mirrors `SharedScope` and makes "only the IPC writes it" a type-enforced
/// property rather than a comment.
#[derive(Clone)]
pub struct SharedAutoApproveApiGets(Arc<std::sync::atomic::AtomicBool>);

impl SharedAutoApproveApiGets {
    /// Whether the chat is currently auto-approving the agent's GETs.
    pub fn is_enabled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the flag. Crate-only: the ONE caller is `chat_set_auto_approve_gets`
    /// (user-driven — the agent has no path to a `tauri::command`).
    pub(crate) fn set(&self, enabled: bool) {
        self.0.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A fresh, opt-OUT auto-approve-GET flag for a new chat.
pub fn new_auto_approve_api_gets() -> SharedAutoApproveApiGets {
    SharedAutoApproveApiGets(Arc::new(std::sync::atomic::AtomicBool::new(false)))
}

/// Per-conversation dispatcher that adjudicates `propose_command`
/// and `ask_user`, delegating read-only tools to the inner
/// `DefaultDispatcher`.
pub struct ApprovalDispatcher {
    inner: DefaultDispatcher,
    policy: Arc<PolicyEngine>,
    redactor: Arc<std::sync::Mutex<ConversationRedactor>>,
    channel: Arc<dyn ApprovalChannel>,
    executor: Arc<dyn SessionExecutor>,
    /// v4.0.0 — the controller seam for `propose_api_call` (GET-only).
    /// Production is a `ScopedApiExecutor` over `AppApiExecutor`; the
    /// same shared redactor + channel adjudicate it.
    api_executor: Arc<dyn ApiExecutor>,
    chat_id: String,
    always_allow: AlwaysAllowMap,
    /// v4.0.0 — the chat's opt-in "auto-approve all agent GETs" flag
    /// (`propose_api_call`). Shared with the `ChatSession`, so a mid-chat
    /// opt-in applies to every later GET. The gate still runs; this only
    /// suppresses the modal. Safe because the tool is structurally GET-only.
    auto_approve_api_gets: SharedAutoApproveApiGets,
    /// v6.1.1 — the chat's session-alias + executed-command ledger
    /// (shared with the `ChatSession` and the scoped source). The two
    /// propose handlers resolve alias-or-raw inputs to registry ids
    /// through it BEFORE the always-allow key, the gate, and the modal
    /// — so the UI keeps real ids, one session never grows two
    /// allowlist keys, and an unknown alias refuses with the standard
    /// "session not found" bytes echoing the model's own string.
    ledger: crate::scoped_session_view::SessionLedger,
    /// v6.1.1 — the chat's SCOPED scrollback source (the same Arc the
    /// tools + prompt see), used ONLY to look up a session's device_id
    /// for the result-envelope `device="…"` echo. Read-only; carries no
    /// new capability (the inner `DefaultDispatcher` already holds the
    /// same Arc for the read-only tools).
    sessions: Arc<dyn ScrollbackSource>,
}

impl ApprovalDispatcher {
    /// Construct.
    ///
    /// `inner` is the read-only-tools dispatcher; this wrapper only
    /// touches the `redactor` for its own command-output redaction.
    /// The two MUST share an `Arc<Mutex<ConversationRedactor>>` so
    /// per-Conversation ordinals stay stable across both surfaces.
    ///
    /// `always_allow` is the chat's shared allowlist (owned by
    /// `ChatState`, cloned in per message). Passing it in — rather
    /// than creating a fresh map here — is what makes an "auto-approve
    /// this regex" verdict persist across messages for the life of the
    /// chat instead of resetting every turn.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inner: DefaultDispatcher,
        policy: Arc<PolicyEngine>,
        redactor: Arc<std::sync::Mutex<ConversationRedactor>>,
        channel: Arc<dyn ApprovalChannel>,
        executor: Arc<dyn SessionExecutor>,
        api_executor: Arc<dyn ApiExecutor>,
        chat_id: impl Into<String>,
        always_allow: AlwaysAllowMap,
        auto_approve_api_gets: SharedAutoApproveApiGets,
        ledger: crate::scoped_session_view::SessionLedger,
        sessions: Arc<dyn ScrollbackSource>,
    ) -> Self {
        Self {
            inner,
            policy,
            redactor,
            channel,
            executor,
            api_executor,
            chat_id: chat_id.into(),
            always_allow,
            auto_approve_api_gets,
            ledger,
            sessions,
        }
    }

    /// The envelope pair (display id, device) for an EXECUTED command's
    /// result, from ONE scoped-list snapshot so the two halves can never
    /// skew. Fallbacks are Transit-authored only: if the list read races
    /// a `try_lock` (or the session closed between run and framing), the
    /// id falls back to the ledger's alias — which cannot race — and
    /// then to the resolved REGISTRY id, never to the model's raw input
    /// spelling; the device attribute is omitted rather than invented.
    fn envelope_pair_of(&self, registry_id: &str) -> (String, Option<String>) {
        let meta = self
            .sessions
            .list()
            .into_iter()
            .find(|m| m.session_id == registry_id);
        let display_id = meta
            .as_ref()
            .and_then(|m| m.alias.clone())
            .or_else(|| self.ledger.alias_of(registry_id))
            .unwrap_or_else(|| registry_id.to_string());
        (display_id, meta.map(|m| m.device_id))
    }

    fn matches_always_allow(&self, session_id: &str, command: &str) -> bool {
        let map = self
            .always_allow
            .lock()
            .expect("always-allow mutex poisoned");
        let key = (self.chat_id.clone(), session_id.to_string());
        let Some(regexes) = map.get(&key) else {
            return false;
        };
        regexes.iter().any(|re| re.is_match(command))
    }

    fn record_always_allow(&self, session_id: &str, regex: Regex) {
        let mut map = self
            .always_allow
            .lock()
            .expect("always-allow mutex poisoned");
        let key = (self.chat_id.clone(), session_id.to_string());
        map.entry(key).or_default().push(regex);
    }

    async fn handle_propose_command(
        &self,
        input: ProposeCommandInput,
    ) -> Result<ToolResult, AgentError> {
        let ProposeCommandInput {
            session_id,
            command,
        } = input;

        // ---- 0. Alias resolution (v6.1.1) ---------------------
        // The model's vocabulary is the roster alias (`s1`); raw
        // registry ids stay accepted. Resolution happens BEFORE the
        // always-allow key, the gate, and the modal so every layer
        // below (and the UI) works in registry-id space and one
        // session can never grow two allowlist keys. An unknown alias
        // passes through unchanged and fails the vendor lookup below
        // — the refusal echoes the model's own string (no oracle).
        let registry_id = self.ledger.resolve(&session_id);

        // ---- 1. Vendor lookup ---------------------------------
        let vendor = match self.executor.vendor_for(&registry_id).await {
            Some(v) => v,
            None => {
                return Ok(ToolResult::ProposeCommand(ProposeCommandOutput {
                    output: format!("session not found: {session_id}"),
                    executed: false,
                }));
            }
        };

        // ---- 2. Policy gate (always runs — Rule 3) -----------
        let decision = self.policy.evaluate(&vendor, &command);
        // Phase 8b — the gate text the modal renders. For unrestricted
        // vendors this becomes "unrestricted: <warning>" so the
        // frontend can detect the mode and render the amber banner
        // without sniffing the prefix. Deny short-circuits below.
        let gate_decision_text = match &decision {
            Decision::Allow => "allow".to_string(),
            Decision::AllowUnrestricted { warning } => format!("unrestricted: {warning}"),
            Decision::Deny { reason, .. } => format!("deny: {reason}"),
        };
        if let Decision::Deny { reason, .. } = &decision {
            // Structured "policy denied" goes back as a successful
            // tool call with executed=false so the model can pivot,
            // NOT as an AgentError (which would terminate the loop's
            // tool dispatch step). v6.1.x #3: the refusal points back
            // at the vendor's policy section — the engine's reason
            // already names the matched pattern; this names where the
            // allowed surface is documented, so the pivot is informed
            // rather than a guess. "Transit's … the device never
            // received it" is load-bearing (2026-08-14 smoke): a local
            // model read the bare "policy gate denied" as DEVICE
            // behavior and went hunting for firewall filters on the
            // box — the refusal must name its own source.
            return Ok(ToolResult::ProposeCommand(ProposeCommandOutput {
                output: format!(
                    "Transit's policy gate denied this command — the device never \
                     received it. {reason}. See Policies §{} in your instructions \
                     for what this vendor allows.",
                    vendor.as_str()
                ),
                executed: false,
            }));
        }
        // Phase 8b — `AllowUnrestricted` keeps the gate's "no
        // always-allow shortcut" invariant: per-step approval is
        // the structural safety property when we can't enumerate
        // the safe surface. See `policies/linux.README.md` §"How
        // the unrestricted carve-out preserves Rule 3".
        let unrestricted = matches!(decision, Decision::AllowUnrestricted { .. });
        // BYOP Phase 2b — a CUSTOM (user-defined) vendor has no shipped
        // read-only floor (only the user's own policy gates it), so it
        // gets the same compensating control as an unrestricted vendor:
        // the always-allow regex shortcut is structurally refused, and
        // every command requires a per-command click. See T_USER_POLICY.
        let custom_vendor = matches!(vendor, Vendor::Custom(_));
        // v6.1.0 — a SHELL-BACKED vendor. UniFi ships a `gated` policy
        // (so the allowlist still refuses a bad command before any human
        // sees it), but its CLI is a busybox shell: the safe surface is a
        // judgement call, not an enumerable command tree. That is enough
        // to keep the floor and NOT enough to hand out a regex that
        // auto-approves future commands unseen.
        //
        // Separating this from `unrestricted` is the point: "has a
        // shipped floor" and "is safe to auto-approve against" are
        // different properties, and UniFi is the first vendor where they
        // diverge. Any future shell-over-SSH vendor belongs here too.
        let shell_backed = matches!(vendor, Vendor::UniFi);
        let refuse_always_allow = unrestricted || custom_vendor || shell_backed;

        // ---- 3. Always-allow check ---------------------------
        // Skip the cache entirely for unrestricted/custom vendors — the
        // contract is per-command approval, every command. Keyed on the
        // REGISTRY id: alias and raw-id spellings of one session share
        // one allowlist entry.
        let pre_approved =
            !refuse_always_allow && self.matches_always_allow(&registry_id, &command);

        // ---- 4. Modal (skipped if pre_approved) --------------
        let verdict = if pre_approved {
            ProposeVerdict::Approve
        } else {
            // `!refuse_always_allow` becomes the payload's
            // `allow_auto_approve`: the frontend shows the auto-approve
            // regex affordance only for vendors with a shipped read-only
            // floor (hidden for unrestricted Linux AND custom BYOP
            // vendors). The backend still defends in depth below.
            // Registry id on the wire — the UI maps it to its own tab
            // labels; aliases are agent-facing vocabulary only.
            self.channel
                .request_command_approval(
                    &self.chat_id,
                    &registry_id,
                    &command,
                    &gate_decision_text,
                    !refuse_always_allow,
                )
                .await?
        };

        match verdict {
            ProposeVerdict::Deny => Ok(ToolResult::ProposeCommand(ProposeCommandOutput {
                output: "user denied execution".into(),
                executed: false,
            })),
            ProposeVerdict::Approve | ProposeVerdict::AlwaysAllowRegex(_) => {
                if let ProposeVerdict::AlwaysAllowRegex(re) = &verdict {
                    // Structural refusal: unrestricted AND custom
                    // vendors must not let the user trade per-command
                    // approval for a regex shortcut (neither has a
                    // shipped read-only floor). Frontend hides the
                    // checkbox; backend defends in depth by ignoring
                    // any verdict that slips through.
                    if !refuse_always_allow {
                        self.record_always_allow(&registry_id, re.clone());
                    } else {
                        tracing::warn!(
                            session = %registry_id,
                            unrestricted,
                            custom_vendor,
                            "ignoring AlwaysAllowRegex on a no-floor vendor — \
                             frontend should not have offered the option"
                        );
                    }
                }
                // ---- 5. Run command + capture output ---------
                // A post-modal SessionNotFound (scope shrank / session
                // closed while the modal was open) is remapped to echo
                // the MODEL'S OWN input spelling: the resolved registry
                // id must never reach the model (the UUID this release
                // removes), and the error bytes must stay identical to
                // every other not-found refusal — no oracle
                // distinguishing "was in scope until a moment ago".
                let (raw_output, capture_end) = self
                    .executor
                    .run_command(
                        &registry_id,
                        &command,
                        DEFAULT_CAPTURE_TIMEOUT,
                        DEFAULT_QUIESCENCE,
                    )
                    .await
                    .map_err(|e| match e {
                        AgentError::SessionNotFound { .. } => AgentError::SessionNotFound {
                            session_id: session_id.clone(),
                        },
                        other => other,
                    })?;
                // v6.1.1 — one more executed command on this session's
                // per-chat ledger (rendered in the prompt roster).
                // Strictly AFTER run_command returned: denied / gate-
                // blocked / failed-before-run proposals never count.
                self.ledger.record_executed(&registry_id);
                // ---- 6. Redact -------------------------------
                let redacted = self
                    .redactor
                    .lock()
                    .expect("redactor mutex poisoned")
                    .redact(&raw_output);
                // ---- 7. Cap (strictly post-redact) -----------
                // Bound a single command's output so one huge capture
                // (`show tech-support`, a full route table) doesn't
                // ride every later turn. Runs only on already-redacted
                // text, so it can never reintroduce a secret.
                const PROPOSE_COMMAND_MAX_BYTES: usize = 16 * 1024;
                let capped = transit_agent::cap_head_tail(&redacted, PROPOSE_COMMAND_MAX_BYTES);
                // ---- 8. Frame (v6.0.1; device echo v6.1.1) ---
                // Same `<session id>` framing `read_scrollback` gets, for
                // the same reason: these are device bytes, attacker-
                // influenceable (a crafted banner, an injected log line),
                // and the Injection Guard marks everything inside the
                // tags untrusted. Only the EXECUTED path frames — the
                // deny reasons above are Transit-authored text the model
                // should treat as instruction, not device output. Rule 3
                // (gate + modal) remains the primary control; this is
                // the defense-in-depth layer the 2026-08 contract review
                // found missing (findings doc §3, approved by the maintainer
                // 2026-08-10).
                //
                // v6.1.1: the id is the ALIAS when one exists (even for a
                // raw-id input — every result re-teaches the roster
                // vocabulary), and the envelope carries `device="…"` so a
                // narrate-X-run-Y binding slip is self-evident in the
                // transcript. Attribute values are Transit-authored
                // (inventory device_id / allocated alias), never device
                // bytes — redact-then-cap ordering is unaffected.
                let (display_id, device) = self.envelope_pair_of(&registry_id);
                // v6.1.x #2 — the capture-terminator annotation. Silence
                // without a prompt-looking tail is the fabrication trap
                // (slow pings); timeout means output was still flowing;
                // a prompt-terminated quiescent capture is the normal
                // case and stays unannotated. The heuristic runs on the
                // CAPPED text — tail-keep preserves the end — and the
                // attribute value is a Transit-authored constant.
                let capture_attr = match capture_end {
                    CaptureEnd::Timeout => Some(("capture", "timeout")),
                    CaptureEnd::Closed => Some(("capture", "session-closed")),
                    CaptureEnd::Quiescence => {
                        if tail_looks_like_prompt(&capped) {
                            None
                        } else {
                            Some(("capture", "silence"))
                        }
                    }
                };
                let extra: Vec<(&str, &str)> = capture_attr.into_iter().collect();
                let framed =
                    transit_agent::frame_session(&display_id, device.as_deref(), &extra, &capped);
                Ok(ToolResult::ProposeCommand(ProposeCommandOutput {
                    output: framed,
                    executed: true,
                }))
            }
        }
    }

    async fn handle_ask_user(&self, input: AskUserInput) -> Result<ToolResult, AgentError> {
        let answer = self
            .channel
            .request_user_input(&self.chat_id, &input.question)
            .await?;
        Ok(ToolResult::AskUser(AskUserOutput { answer }))
    }

    /// The GET-only controller path (v4.0.0). Structurally mirrors
    /// [`handle_propose_command`](Self::handle_propose_command): the gate
    /// ALWAYS runs, a deny short-circuits to `executed:false` (byte-
    /// identical no-oracle for unknown/out-of-scope), then the per-call
    /// modal, then execute → redact → cap. Difference: the "policy" is the
    /// structural GET+confine floor (not the CLI engine). The per-call modal
    /// is the default, but the chat may OPT IN to auto-approving GETs
    /// (`auto_approve_api_gets`) — SAFE, because the tool is structurally
    /// GET-only, so it can only ever auto-approve reads and the gate STILL
    /// runs every call. (This is where the command path's regex allowlist is
    /// REFUSED for custom vendors, T18: a regex could green-light a write,
    /// but a GET cannot mutate — so the concern doesn't transfer.)
    async fn handle_propose_api_call(
        &self,
        input: ProposeApiCallInput,
    ) -> Result<ToolResult, AgentError> {
        let ProposeApiCallInput { session_id, path } = input;

        // ---- 0. Alias resolution (v6.1.1) — same contract as the
        // command path: alias-or-raw in, registry id below this line,
        // unknown strings pass through to the byte-identical refusal.
        let registry_id = self.ledger.resolve(&session_id);

        // ---- 1. Gate (membership + GET-only confine — ALWAYS runs) ----
        match self.api_executor.gate(&registry_id, &path).await {
            // Byte-identical to propose_command's unknown-session refusal —
            // an out-of-scope / closed controller reveals nothing.
            ApiGate::SessionNotFound => {
                return Ok(ToolResult::ProposeApiCall(ProposeApiCallOutput {
                    output: format!("session not found: {session_id}"),
                    executed: false,
                }));
            }
            // Path escapes the pinned base — structured refusal (the model
            // can pivot), NOT an AgentError (which aborts the dispatch step).
            // Same source-naming as the command path: the refusal is
            // Transit's, not the controller's.
            ApiGate::Deny { reason } => {
                return Ok(ToolResult::ProposeApiCall(ProposeApiCallOutput {
                    output: format!(
                        "Transit's policy gate denied this request — the controller \
                         never received it. {reason}"
                    ),
                    executed: false,
                }));
            }
            ApiGate::Allow => {}
        }

        // ---- 2. Modal — skipped IFF the chat opted into auto-approving
        // GETs (`auto_approve_api_gets`, user-driven `chat_set_auto_approve_gets`).
        // Safe: the tool is structurally GET-only, so this only ever
        // auto-approves reads, and the gate above STILL ran. Chat-scoped,
        // in-memory, dies with the chat. ----
        let verdict = if self.auto_approve_api_gets.is_enabled() {
            ProposeVerdict::Approve
        } else {
            self.channel
                .request_api_call_approval(&self.chat_id, &registry_id, &path, "allow (GET)")
                .await?
        };

        match verdict {
            ProposeVerdict::Deny => Ok(ToolResult::ProposeApiCall(ProposeApiCallOutput {
                output: "user denied execution".into(),
                executed: false,
            })),
            // `AlwaysAllowRegex` can never be offered for a controller (the
            // frontend shows no such affordance; custom vendor). Any that
            // slips through is treated as a plain Approve — run the GET,
            // record NOTHING to an allowlist (defense in depth, mirrors
            // handle_propose_command's no-floor branch). The auto-approve-GET
            // opt-in flows through `auto_approve_api_gets` above, NOT a
            // verdict, so the shared verdict enum + command path are untouched.
            ProposeVerdict::Approve | ProposeVerdict::AlwaysAllowRegex(_) => {
                // ---- 3. Execute the confined GET ----
                // Same post-modal remap as the command path: a descope
                // while the modal was open must echo the model's own
                // spelling, never the resolved registry id.
                let raw = self
                    .api_executor
                    .run_get(&registry_id, &path)
                    .await
                    .map_err(|e| match e {
                        AgentError::SessionNotFound { .. } => AgentError::SessionNotFound {
                            session_id: session_id.clone(),
                        },
                        other => other,
                    })?;
                // v6.1.1 — an executed GET is one more command on this
                // session's per-chat ledger. Without this, an API
                // controller reads `commands this chat: 0` forever and
                // the roster header's "check it before declaring a
                // device inspected" drives re-runs / false
                // not-inspected claims on exactly the sessions the
                // model DID inspect.
                self.ledger.record_executed(&registry_id);
                // ---- 4. Redact (device→LLM boundary) ----
                // The GET response is a structured API body → redact_json,
                // which skips ONLY the bare-hex identifier catch-all so a
                // hostId/consoleId survives (the agent needs it for the next
                // path). Every key-anchored secret pattern + PEM + base64-blob
                // still run, and these responses always key-label secrets.
                let redacted = self
                    .redactor
                    .lock()
                    .expect("redactor mutex poisoned")
                    .redact_json(&raw);
                // ---- 5. Cap (strictly post-redact) ----
                // JSON-aware: keep whole array items + a "narrow with a query"
                // note so a large body stays VALID/parseable instead of being
                // byte-chopped mid-structure (falls back to head/tail for
                // non-JSON). 32K headroom — larger than the SSH command cap
                // because API JSON is denser, and item-truncation keeps it lean.
                const PROPOSE_API_CALL_MAX_BYTES: usize = 32 * 1024;
                let capped =
                    transit_agent::cap_json_response(&redacted, PROPOSE_API_CALL_MAX_BYTES);
                Ok(ToolResult::ProposeApiCall(ProposeApiCallOutput {
                    output: capped,
                    executed: true,
                }))
            }
        }
    }
}

#[async_trait]
impl ToolDispatcher for ApprovalDispatcher {
    async fn dispatch(&self, call: ToolCall) -> Result<ToolResult, AgentError> {
        match call {
            // Read-only tools go straight through to the inner
            // DefaultDispatcher. `query_capture` (v6.0.0) belongs here
            // and NOT with the approval-gated arms below: it reads a
            // local capture file the user opened, touches no device, and
            // changes nothing — there is nothing for a gate to
            // adjudicate, and a modal would be approval theatre (T18).
            ToolCall::ListOpenSessions(_)
            | ToolCall::ReadScrollback(_)
            | ToolCall::QueryCapture(_) => self.inner.dispatch(call).await,
            ToolCall::ProposeCommand(input) => self.handle_propose_command(input).await,
            ToolCall::AskUser(input) => self.handle_ask_user(input).await,
            // v4.0.0 — the GET-only controller path: gate (GET+confine) →
            // per-call modal → confined GET → redact → cap. Rule 3 holds
            // (both gate AND modal, every call); Rule 2's fifth tool.
            ToolCall::ProposeApiCall(input) => self.handle_propose_api_call(input).await,
        }
    }
}

// ---------------------------------------------------------------------
// IPC commands (C8) — `respond_propose_command` + `respond_ask_user`
// ---------------------------------------------------------------------

/// Wire shape for `respond_propose_command`'s verdict argument.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposeVerdictWire {
    Approve,
    Deny,
    AlwaysAllowRegex { regex: String },
}

#[derive(Debug, Deserialize)]
pub struct ProposeCommandResponse {
    pub request_id: String,
    pub verdict: ProposeVerdictWire,
}

/// Reply path for `propose-command:request`. The frontend dialog
/// calls this with the user's verdict; the matching oneshot fires
/// inside `TauriApprovalChannel::request_command_approval`.
#[tauri::command]
pub async fn respond_propose_command(
    state: tauri::State<'_, ApprovalState>,
    args: ProposeCommandResponse,
) -> Result<(), String> {
    respond_propose_command_inner(&state.pending_approvals, args).await
}

/// Body of [`respond_propose_command`], split out so it's testable
/// without a `tauri::State`.
///
/// Ordering matters: the user-supplied regex is compiled BEFORE the
/// responder is removed from the pending map. The frontend validates
/// with JS regex syntax, which accepts patterns the Rust engine
/// rejects (e.g. lookahead `(?=…)`); compiling after removal would
/// consume the responder on the error path and kill the modal with
/// no way to answer it. With this ordering the command returns
/// `Err("invalid regex: …")`, the modal stays up, and the user can
/// fix the pattern or plain-approve.
pub(crate) async fn respond_propose_command_inner(
    pending_approvals: &PendingApprovals,
    args: ProposeCommandResponse,
) -> Result<(), String> {
    let verdict = match args.verdict {
        ProposeVerdictWire::Approve => ProposeVerdict::Approve,
        ProposeVerdictWire::Deny => ProposeVerdict::Deny,
        ProposeVerdictWire::AlwaysAllowRegex { regex } => {
            let re = Regex::new(&regex).map_err(|e| format!("invalid regex: {e}"))?;
            ProposeVerdict::AlwaysAllowRegex(re)
        }
    };
    let mut pending = pending_approvals.lock().await;
    let (_chat_id, responder) = pending
        .remove(&args.request_id)
        .ok_or_else(|| format!("no pending approval for {}", args.request_id))?;
    responder
        .send(verdict)
        .map_err(|_| "responder consumed".to_string())
}

#[derive(Debug, Deserialize)]
pub struct AskUserResponseArgs {
    pub request_id: String,
    pub answer: String,
}

#[tauri::command]
pub async fn respond_ask_user(
    state: tauri::State<'_, ApprovalState>,
    args: AskUserResponseArgs,
) -> Result<(), String> {
    let mut pending = state.pending_questions.lock().await;
    let (_chat_id, responder) = pending
        .remove(&args.request_id)
        .ok_or_else(|| format!("no pending question for {}", args.request_id))?;
    responder
        .send(args.answer)
        .map_err(|_| "responder consumed".to_string())
}

/// Cancel the pending propose-command modals + questions tied to
/// `chat_id`. `chat_cancel` and `chat_destroy` call this so a
/// half-open dialog for THAT chat dismisses itself instead of
/// accepting a stale click — and, crucially, so cancelling one chat
/// does NOT drain another concurrent chat's pending approvals
/// (v2.5.0 multi-chat). Entries are scoped by the `chat_id` stored
/// alongside each responder.
pub async fn cancel_chat_approvals(
    state: &tauri::State<'_, ApprovalState>,
    app: &AppHandle,
    chat_id: &str,
) {
    let cancelled_ids =
        drain_chat_approvals_inner(&state.pending_approvals, &state.pending_questions, chat_id)
            .await;
    // Emit a chat-scoped cancel for each removed approval so its modal /
    // notification card dismisses. Questions need no event — AskUserCard
    // dismisses on the chat's own `chat:{id}:completed`.
    for id in cancelled_ids {
        let _ = app.emit(
            "propose-command:cancel",
            ProposeCommandCancelPayload {
                request_id: id,
                chat_id: chat_id.to_string(),
            },
        );
    }
}

/// Remove `chat_id`'s pending approvals + questions from the maps and
/// return the removed approval request-ids (so the caller can emit the
/// cancel events). Split out from [`cancel_chat_approvals`] so the
/// chat-scoping can be unit-tested without a Tauri `AppHandle`/`State`.
/// Other chats' entries are left untouched — the multi-chat invariant.
pub(crate) async fn drain_chat_approvals_inner(
    pending_approvals: &PendingApprovals,
    pending_questions: &PendingQuestions,
    chat_id: &str,
) -> Vec<String> {
    let mut approvals = pending_approvals.lock().await;
    let ids: Vec<String> = approvals
        .iter()
        .filter(|(_, (owner, _))| owner == chat_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in &ids {
        approvals.remove(id);
    }
    drop(approvals);
    pending_questions
        .lock()
        .await
        .retain(|_, (owner, _)| owner != chat_id);
    ids
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex as TokioMutex;

    use transit_agent::{
        AskUserInput, ProposeCommandInput, ReadScrollbackInput, ScrollbackSource, SessionMeta,
        Snapshot,
    };
    use transit_core::inventory::Vendor;

    // ---- Test stubs ---------------------------------------------------

    struct StubScrollbackSource;
    impl ScrollbackSource for StubScrollbackSource {
        fn snapshot(&self, _session_id: &str) -> Option<Snapshot> {
            None
        }
        fn list(&self) -> Vec<SessionMeta> {
            vec![]
        }
    }

    /// Verdict the stub returns when `request_command_approval` is
    /// called. Wrapped in Option so a single channel can be re-armed.
    struct StubChannel {
        verdict: TokioMutex<Option<ProposeVerdict>>,
        answer: TokioMutex<Option<String>>,
        approval_calls: StdMutex<Vec<(String, String, String)>>,
        question_calls: StdMutex<Vec<String>>,
    }

    impl StubChannel {
        fn approve() -> Self {
            Self {
                verdict: TokioMutex::new(Some(ProposeVerdict::Approve)),
                answer: TokioMutex::new(None),
                approval_calls: StdMutex::new(Vec::new()),
                question_calls: StdMutex::new(Vec::new()),
            }
        }
        fn deny() -> Self {
            Self {
                verdict: TokioMutex::new(Some(ProposeVerdict::Deny)),
                answer: TokioMutex::new(None),
                approval_calls: StdMutex::new(Vec::new()),
                question_calls: StdMutex::new(Vec::new()),
            }
        }
        fn always_allow(re: &str) -> Self {
            Self {
                verdict: TokioMutex::new(Some(ProposeVerdict::AlwaysAllowRegex(
                    Regex::new(re).unwrap(),
                ))),
                answer: TokioMutex::new(None),
                approval_calls: StdMutex::new(Vec::new()),
                question_calls: StdMutex::new(Vec::new()),
            }
        }
        fn answers(s: &str) -> Self {
            Self {
                verdict: TokioMutex::new(None),
                answer: TokioMutex::new(Some(s.to_string())),
                approval_calls: StdMutex::new(Vec::new()),
                question_calls: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ApprovalChannel for StubChannel {
        async fn request_command_approval(
            &self,
            chat_id: &str,
            session_id: &str,
            command: &str,
            _gate_decision: &str,
            _allow_auto_approve: bool,
        ) -> Result<ProposeVerdict, AgentError> {
            self.approval_calls.lock().unwrap().push((
                chat_id.to_string(),
                session_id.to_string(),
                command.to_string(),
            ));
            self.verdict
                .lock()
                .await
                .take()
                .ok_or_else(|| AgentError::Dispatcher("stub channel exhausted".into()))
        }

        async fn request_user_input(
            &self,
            _chat_id: &str,
            question: &str,
        ) -> Result<String, AgentError> {
            self.question_calls.lock().unwrap().push(question.into());
            self.answer
                .lock()
                .await
                .take()
                .ok_or_else(|| AgentError::Dispatcher("stub channel exhausted".into()))
        }

        async fn request_api_call_approval(
            &self,
            chat_id: &str,
            session_id: &str,
            path: &str,
            _gate_decision: &str,
        ) -> Result<ProposeVerdict, AgentError> {
            // Records into the SAME approval_calls log (third element is the
            // path here, the command there) and returns the same armed
            // verdict — so a StubChannel::approve()/deny() drives both.
            self.approval_calls.lock().unwrap().push((
                chat_id.to_string(),
                session_id.to_string(),
                path.to_string(),
            ));
            self.verdict
                .lock()
                .await
                .take()
                .ok_or_else(|| AgentError::Dispatcher("stub channel exhausted".into()))
        }
    }

    /// Stub executor — canned output per session_id.
    struct StubExecutor {
        vendors: HashMap<String, Vendor>,
        outputs: StdMutex<HashMap<String, String>>,
        run_calls: StdMutex<Vec<(String, String)>>,
        /// What every run reports as its capture terminator —
        /// re-armable so one stub can exercise the annotation matrix.
        capture_end: StdMutex<CaptureEnd>,
    }

    impl StubExecutor {
        fn new() -> Self {
            Self {
                vendors: HashMap::new(),
                outputs: StdMutex::new(HashMap::new()),
                run_calls: StdMutex::new(Vec::new()),
                capture_end: StdMutex::new(CaptureEnd::Quiescence),
            }
        }
        fn with_session(mut self, session_id: &str, vendor: Vendor, output: &str) -> Self {
            self.vendors.insert(session_id.into(), vendor);
            self.outputs
                .lock()
                .unwrap()
                .insert(session_id.into(), output.into());
            self
        }
        fn set_capture_end(&self, end: CaptureEnd) {
            *self.capture_end.lock().unwrap() = end;
        }
    }

    #[async_trait]
    impl SessionExecutor for StubExecutor {
        async fn vendor_for(&self, session_id: &str) -> Option<Vendor> {
            self.vendors.get(session_id).cloned()
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
                .push((session_id.into(), command.into()));
            self.outputs
                .lock()
                .unwrap()
                .get(session_id)
                .cloned()
                .map(|out| (out, *self.capture_end.lock().unwrap()))
                .ok_or_else(|| AgentError::SessionNotFound {
                    session_id: session_id.into(),
                })
        }
    }

    /// Stub API executor — canned gate + body per session_id. Mirrors
    /// `StubExecutor` for the propose_api_call path.
    struct StubApiExecutor {
        gates: HashMap<String, ApiGate>,
        outputs: StdMutex<HashMap<String, String>>,
        run_calls: StdMutex<Vec<(String, String)>>,
    }

    impl StubApiExecutor {
        fn new() -> Self {
            Self {
                gates: HashMap::new(),
                outputs: StdMutex::new(HashMap::new()),
                run_calls: StdMutex::new(Vec::new()),
            }
        }
        /// Register a controller: `gate` is what `gate()` returns and
        /// `output` is the RAW body `run_get()` yields on Approve.
        fn with_session(mut self, session_id: &str, gate: ApiGate, output: &str) -> Self {
            self.gates.insert(session_id.into(), gate);
            self.outputs
                .lock()
                .unwrap()
                .insert(session_id.into(), output.into());
            self
        }
        /// Register a controller whose `gate()` answers but whose `run_get()`
        /// FAILS (no output → `SessionNotFound`) — models a path that
        /// confined at gate-time but not at run-time (the production
        /// `AppApiExecutor` re-gate), or a controller deleted mid-approval.
        fn with_gate_only(mut self, session_id: &str, gate: ApiGate) -> Self {
            self.gates.insert(session_id.into(), gate);
            self
        }
    }

    #[async_trait]
    impl ApiExecutor for StubApiExecutor {
        async fn gate(&self, session_id: &str, _path: &str) -> ApiGate {
            // Missing → SessionNotFound (an unregistered controller is
            // byte-identical to unknown), matching production.
            self.gates
                .get(session_id)
                .cloned()
                .unwrap_or(ApiGate::SessionNotFound)
        }
        async fn run_get(&self, session_id: &str, path: &str) -> Result<String, AgentError> {
            self.run_calls
                .lock()
                .unwrap()
                .push((session_id.into(), path.into()));
            self.outputs
                .lock()
                .unwrap()
                .get(session_id)
                .cloned()
                .ok_or_else(|| AgentError::SessionNotFound {
                    session_id: session_id.into(),
                })
        }
    }

    fn build_dispatcher(
        channel: Arc<dyn ApprovalChannel>,
        executor: Arc<dyn SessionExecutor>,
    ) -> ApprovalDispatcher {
        // Each dispatcher gets its own fresh allowlist — equivalent to
        // a single chat turn. The persistence test uses
        // `build_dispatcher_with_map` to share one map across two
        // dispatchers (two turns of the same chat).
        build_dispatcher_with_map(channel, executor, new_always_allow_map())
    }

    fn build_dispatcher_with_map(
        channel: Arc<dyn ApprovalChannel>,
        executor: Arc<dyn SessionExecutor>,
        always_allow: AlwaysAllowMap,
    ) -> ApprovalDispatcher {
        // Default no-op API executor (every controller unknown) — the
        // command-path tests never exercise propose_api_call.
        build_dispatcher_full(
            channel,
            executor,
            Arc::new(StubApiExecutor::new()),
            always_allow,
            new_auto_approve_api_gets(),
        )
    }

    /// propose_api_call tests use this to inject a specific API executor.
    fn build_dispatcher_with_api(
        channel: Arc<dyn ApprovalChannel>,
        api_executor: Arc<dyn ApiExecutor>,
    ) -> ApprovalDispatcher {
        build_dispatcher_full(
            channel,
            Arc::new(StubExecutor::new()),
            api_executor,
            new_always_allow_map(),
            new_auto_approve_api_gets(),
        )
    }

    /// Like `build_dispatcher_with_api` but with the chat's auto-approve-GET
    /// flag pre-set ON (the opt-in), for the auto-approve tests.
    fn build_dispatcher_with_api_autoapprove(
        channel: Arc<dyn ApprovalChannel>,
        api_executor: Arc<dyn ApiExecutor>,
    ) -> ApprovalDispatcher {
        let flag = new_auto_approve_api_gets();
        flag.set(true);
        build_dispatcher_full(
            channel,
            Arc::new(StubExecutor::new()),
            api_executor,
            new_always_allow_map(),
            flag,
        )
    }

    fn build_dispatcher_full(
        channel: Arc<dyn ApprovalChannel>,
        executor: Arc<dyn SessionExecutor>,
        api_executor: Arc<dyn ApiExecutor>,
        always_allow: AlwaysAllowMap,
        auto_approve_api_gets: SharedAutoApproveApiGets,
    ) -> ApprovalDispatcher {
        build_dispatcher_full_with_ledger(
            channel,
            executor,
            api_executor,
            always_allow,
            auto_approve_api_gets,
            crate::scoped_session_view::SessionLedger::new(),
        )
    }

    fn build_dispatcher_full_with_ledger(
        channel: Arc<dyn ApprovalChannel>,
        executor: Arc<dyn SessionExecutor>,
        api_executor: Arc<dyn ApiExecutor>,
        always_allow: AlwaysAllowMap,
        auto_approve_api_gets: SharedAutoApproveApiGets,
        ledger: crate::scoped_session_view::SessionLedger,
    ) -> ApprovalDispatcher {
        let source: Arc<dyn ScrollbackSource> = Arc::new(StubScrollbackSource);
        let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
        let inner = DefaultDispatcher::new(Arc::clone(&source), Arc::clone(&redactor));
        // Empty PolicyEngine = default-deny everything; tests
        // override per-case by loading the real engine if needed.
        // For simplicity we stub the policy via a real load-from-dir
        // at the workspace `policies/` path so policy denial works
        // against the canonical Junos / Cisco rules.
        let policy = Arc::new(load_real_policy());
        ApprovalDispatcher::new(
            inner,
            policy,
            redactor,
            channel,
            executor,
            api_executor,
            "chat-test".to_string(),
            always_allow,
            auto_approve_api_gets,
            ledger,
            source,
        )
    }

    fn load_real_policy() -> PolicyEngine {
        // Load from the workspace `policies/` directory so
        // adjudication uses real Junos / Cisco / NX-OS rules.
        // The path resolves relative to the cargo manifest at
        // src-tauri/Cargo.toml — `policies/` is one level up.
        let policies_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cargo manifest has a parent")
            .join("policies");
        PolicyEngine::load_from_dir(&policies_dir).expect("policies must load for tests")
    }

    // ---- Read-only tools delegate to inner ----------------------------

    #[tokio::test]
    async fn read_only_tools_delegate_to_inner() {
        // ListOpenSessions returns the inner's empty list (StubScrollbackSource).
        let dispatcher =
            build_dispatcher(Arc::new(StubChannel::deny()), Arc::new(StubExecutor::new()));
        let res = dispatcher
            .dispatch(ToolCall::ListOpenSessions(Default::default()))
            .await
            .unwrap();
        match res {
            ToolResult::ListOpenSessions(out) => assert!(out.sessions.is_empty()),
            _ => panic!("expected ListOpenSessions"),
        }
        // ReadScrollback against an unknown session bubbles up
        // SessionNotFound from the inner.
        let err = dispatcher
            .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                session_id: "nope".into(),
                max_bytes: 1024,
                match_: None,
                context_lines: 2,
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
    }

    // ---- propose_command ---------------------------------------------

    #[tokio::test]
    async fn propose_command_unknown_session_returns_executed_false() {
        let dispatcher = build_dispatcher(
            Arc::new(StubChannel::approve()),
            Arc::new(StubExecutor::new()),
        );
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "ghost".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(out.output.contains("session not found"));
            }
            _ => panic!("expected ProposeCommand"),
        }
    }

    #[tokio::test]
    async fn policy_denied_returns_executed_false_with_reason() {
        // `request system reboot` is on Junos's blocklist (shell
        // escape). Should never reach the modal.
        let channel = Arc::new(StubChannel::approve());
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "ignored"));
        let dispatcher = build_dispatcher(channel.clone(), executor);
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "request system reboot".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(
                    out.output.starts_with("Transit's policy gate denied"),
                    "expected policy denial, got: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
        // The modal was never invoked — Rule 3's gate-first
        // ordering means a denial short-circuits before the user
        // sees anything.
        assert!(channel.approval_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn policy_allow_then_user_deny_returns_executed_false() {
        let channel = Arc::new(StubChannel::deny());
        let executor =
            Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "PROMPT> show version"));
        let dispatcher = build_dispatcher(channel.clone(), executor);
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(out.output.contains("user denied"));
            }
            _ => panic!("expected ProposeCommand"),
        }
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn policy_allow_then_user_approve_runs_and_redacts() {
        // Output contains a fake AWS key so the redactor has something
        // to mark — verifies the redact step runs on captured bytes.
        let raw = "config:\n  aws_access_key=AKIAIOSFODNN7EXAMPLE\n";
        let channel = Arc::new(StubChannel::approve());
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, raw));
        let dispatcher = build_dispatcher(channel, executor);
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(out.executed);
                assert!(
                    !out.output.contains("AKIAIOSFODNN7EXAMPLE"),
                    "AWS key must be redacted: {}",
                    out.output
                );
                assert!(
                    out.output.contains("[REDACTED:"),
                    "expected redaction marker: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
    }

    #[tokio::test]
    async fn executed_command_output_framed_as_untrusted_session_bytes() {
        // v6.0.1 (findings doc §3): an executed command's output is
        // device bytes — the same trust class as read_scrollback — so it
        // gets the same `<session id>` framing the Injection Guard keys
        // on. Deny paths stay UNframed: their text is Transit-authored
        // (gate reason / user verdict), instruction rather than device
        // output.
        let channel = Arc::new(StubChannel::approve());
        let executor =
            Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "uptime 12 days\n"));
        let dispatcher = build_dispatcher(channel, executor);
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(out.executed);
                // v6.1.x: the stub's output has no prompt-looking tail
                // and ends on quiescence, so the envelope carries the
                // silence annotation (the fabricated-ping killer).
                assert!(
                    out.output
                        .starts_with("<session id=\"s1\" capture=\"silence\">\n"),
                    "executed output must open with session framing: {}",
                    out.output
                );
                assert!(
                    out.output.ends_with("\n</session>"),
                    "executed output must close the framing: {}",
                    out.output
                );
                assert!(out.output.contains("uptime 12 days"));
            }
            _ => panic!("expected ProposeCommand"),
        }

        // The deny path — Transit's own text — must NOT be framed.
        let deny_channel = Arc::new(StubChannel::deny());
        let deny_executor =
            Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "unused"));
        let deny_dispatcher = build_dispatcher(deny_channel, deny_executor);
        let res = deny_dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(
                    !out.output.contains("<session"),
                    "deny reason is Transit-authored — no framing: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
    }

    #[tokio::test]
    async fn propose_command_output_capped_after_redaction() {
        // A huge command output with a secret near the top: it must be
        // (a) executed, (b) redacted, (c) trimmed by the source-side
        // cap, with the secret surviving as a [REDACTED] marker. The
        // cap runs strictly AFTER redaction, so it can never resurface
        // the secret.
        //
        // The filler must look like ordinary show-output — a bare
        // "AAAA…" run is pure hex chars and the redaction
        // catalogue's high-entropy hex-blob catch-all would collapse
        // it below the cap, defeating the point of the test.
        let raw = format!(
            "config:\n  aws_access_key=AKIAIOSFODNN7EXAMPLE\n{}",
            "interface ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n".repeat(800)
        );
        let channel = Arc::new(StubChannel::approve());
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, &raw));
        let dispatcher = build_dispatcher(channel, executor);
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show tech-support".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(out.executed);
                assert!(
                    !out.output.contains("AKIAIOSFODNN7EXAMPLE"),
                    "AWS key must be redacted even after capping"
                );
                assert!(
                    out.output.contains("[REDACTED:"),
                    "redaction marker must survive the cap: {}",
                    out.output
                );
                assert!(
                    out.output.contains("bytes elided by Transit output cap"),
                    "the source-side cap must have fired"
                );
                assert!(
                    out.output.len() < 17 * 1024,
                    "capped output must be bounded, got {} bytes",
                    out.output.len()
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
    }

    #[tokio::test]
    async fn always_allow_regex_skips_modal_on_subsequent_match() {
        let channel = Arc::new(StubChannel::always_allow(r"^show "));
        let executor = Arc::new(StubExecutor::new().with_session(
            "s1",
            Vendor::Junos,
            "PROMPT> show interfaces\n",
        ));
        let dispatcher = build_dispatcher(channel.clone(), executor);

        // First call: modal fires, AlwaysAllowRegex verdict + run.
        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show interfaces".into(),
            }))
            .await
            .unwrap();
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);

        // Second call matching the regex — modal must NOT fire.
        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show route".into(),
            }))
            .await
            .unwrap();
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);

        // Third call NOT matching the regex — modal SHOULD fire,
        // but stub channel is exhausted so we get a Dispatcher
        // error. That's the right behavior — the test asserts the
        // regex didn't over-broadly suppress.
        let err = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "configure".into(),
            }))
            .await;
        match err {
            // Either a policy denial (configure is blocked) OR a
            // Dispatcher exhaustion (modal tried to fire). Both are
            // acceptable evidence the regex didn't auto-approve.
            Ok(ToolResult::ProposeCommand(out)) => {
                assert!(
                    !out.executed,
                    "configure must not have executed: {}",
                    out.output
                );
            }
            Err(AgentError::Dispatcher(_)) => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn always_allow_persists_across_dispatcher_rebuilds() {
        // The allowlist is owned by the chat (a shared AlwaysAllowMap),
        // not the per-message dispatcher. Simulate two user messages:
        // dispatcher #1 records an "^show " auto-approve; dispatcher #2
        // — a fresh ApprovalDispatcher sharing the SAME map, like the
        // next turn — must honor it WITHOUT firing the modal.
        let shared = new_always_allow_map();

        // ---- turn 1: user approves-and-remembers `^show ` ----
        let channel1 = Arc::new(StubChannel::always_allow(r"^show "));
        let executor1 = Arc::new(StubExecutor::new().with_session(
            "s1",
            Vendor::Junos,
            "PROMPT> show interfaces\n",
        ));
        let d1 = build_dispatcher_with_map(channel1.clone(), executor1, Arc::clone(&shared));
        let _ = d1
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show interfaces".into(),
            }))
            .await
            .unwrap();
        assert_eq!(channel1.approval_calls.lock().unwrap().len(), 1);

        // ---- turn 2: fresh dispatcher, SAME chat allowlist ----
        // StubChannel::deny() WOULD deny if the modal fired; a cache
        // hit skips the modal and yields Approve -> executed=true.
        let channel2 = Arc::new(StubChannel::deny());
        let executor2 =
            Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "PROMPT> show route\n"));
        let d2 = build_dispatcher_with_map(channel2.clone(), executor2, Arc::clone(&shared));
        let res = d2
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show route".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => assert!(
                out.executed,
                "persisted allowlist must auto-approve in the next turn: {}",
                out.output
            ),
            _ => panic!("expected ProposeCommand"),
        }
        assert!(
            channel2.approval_calls.lock().unwrap().is_empty(),
            "modal must not fire — the chat's allowlist persisted across the dispatcher rebuild"
        );
    }

    #[tokio::test]
    async fn unrestricted_vendor_always_runs_modal_even_with_always_allow_verdict() {
        // Phase 8b — Rule 3 spirit on the unrestricted path:
        // even if the LLM/UI somehow sends an AlwaysAllowRegex
        // verdict, the dispatcher must NOT cache it for the
        // session, AND a subsequent call must still hit the
        // modal. The StubChannel returns AlwaysAllowRegex(".*")
        // once and a plain Approve next; if the cache had taken,
        // the second call would short-circuit before consuming
        // the second verdict.

        // Channel returns AlwaysAllowRegex first, then Approve.
        let channel = Arc::new(StubChannel::always_allow(".*"));
        // Replace the verdict slot's initial-only "always_allow"
        // with a two-shot via the mutex directly.
        {
            let mut v = channel.verdict.lock().await;
            *v = Some(ProposeVerdict::AlwaysAllowRegex(Regex::new(".*").unwrap()));
        }
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::Linux, "ok\n"));
        let dispatcher = build_dispatcher(channel.clone(), executor);

        // First call — modal fires, returns AlwaysAllowRegex.
        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "ls".into(),
            }))
            .await
            .unwrap();
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);

        // Re-arm the channel for the second call (StubChannel is
        // one-shot). Set Approve this time.
        {
            let mut v = channel.verdict.lock().await;
            *v = Some(ProposeVerdict::Approve);
        }

        // Second call — modal MUST fire again (no cache hit despite
        // the .* allowlist verdict from call 1).
        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "cat /etc/hostname".into(),
            }))
            .await
            .unwrap();
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            2,
            "unrestricted vendor must require per-command approval; \
             always-allow shortcut must be structurally refused"
        );
    }

    #[tokio::test]
    async fn shell_backed_vendor_refuses_the_always_allow_shortcut() {
        // v6.1.0 — UniFi ships a GATED policy (unlike Linux), so the
        // read-only floor does run. What it must NOT get is the
        // always-allow regex: its CLI is a busybox shell, so the
        // allowlist's completeness is a judgement call, and a regex that
        // auto-approves FUTURE commands unseen is a much stronger bet
        // than a floor that refuses known-bad ones.
        //
        // Same structure as the unrestricted test above: if the cache had
        // taken, the second call would short-circuit and never consume
        // the second verdict.
        let channel = Arc::new(StubChannel::always_allow(".*"));
        {
            let mut v = channel.verdict.lock().await;
            *v = Some(ProposeVerdict::AlwaysAllowRegex(Regex::new(".*").unwrap()));
        }
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::UniFi, "ok\n"));
        let dispatcher = build_dispatcher(channel.clone(), executor);

        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "info".into(),
            }))
            .await
            .unwrap();
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);

        {
            let mut v = channel.verdict.lock().await;
            *v = Some(ProposeVerdict::Approve);
        }

        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "uptime".into(),
            }))
            .await
            .unwrap();
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            2,
            "a shell-backed vendor must require per-command approval; \
             the always-allow shortcut is structurally refused"
        );
    }

    #[tokio::test]
    async fn shell_backed_vendor_still_enforces_its_shipped_floor() {
        // The other half: refusing the shortcut must not have quietly
        // turned UniFi into an unrestricted vendor. A blocked command
        // still fails the gate BEFORE any modal.
        let channel = Arc::new(StubChannel::approve());
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::UniFi, "ok\n"));
        let dispatcher = build_dispatcher(channel.clone(), executor);

        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "reboot".into(),
            }))
            .await
            .unwrap();

        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed, "a gate-denied command must not execute");
            }
            other => panic!("expected ProposeCommand result, got {other:?}"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "gate denial short-circuits before the modal"
        );
    }

    #[tokio::test]
    async fn always_allow_does_not_skip_policy_gate() {
        // Even with a wide-open allowlist, the gate runs. A future
        // command the gate denies must still come back as
        // executed=false with the policy reason — never approved.
        let channel = Arc::new(StubChannel::always_allow(r".*"));
        let executor = Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "ok\n"));
        let dispatcher = build_dispatcher(channel.clone(), executor);
        // Seed the allowlist with one matching call.
        let _ = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        // Now try a gate-denied command. The .* allowlist would
        // match — but the gate runs FIRST.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "request system reboot".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(out.output.starts_with("Transit's policy gate denied"));
            }
            _ => panic!("expected ProposeCommand"),
        }
    }

    // ---- control characters (headline fix, end-to-end) ----------------

    /// Pins the CRITICAL multi-line command-smuggling fix at the
    /// dispatcher: even with a wildcard always-allow regex
    /// registered for the chat+session, a command containing a
    /// control character must be denied BY THE GATE — modal never
    /// invoked, executor never called, executed=false with a
    /// control-character reason.
    ///
    /// NOTE: this asserts the transit_policy gate change (deny
    /// commands containing control characters) landing in the same
    /// security-review batch; it fails against the pre-fix gate by
    /// design. Do NOT weaken it to pass against the unfixed gate.
    #[tokio::test]
    async fn control_characters_denied_even_with_wildcard_always_allow() {
        let channel = Arc::new(StubChannel::approve());
        let executor =
            Arc::new(StubExecutor::new().with_session("s1", Vendor::Junos, "MUST NEVER RUN"));
        let dispatcher = build_dispatcher(channel.clone(), executor.clone());
        // Register the wildcard directly — the same scope the
        // modal's always-allow checkbox would have written.
        dispatcher.record_always_allow("s1", Regex::new(".*").unwrap());

        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version\nconfigure terminal".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed, "control-char command must not execute");
                assert!(
                    out.output.starts_with("Transit's policy gate denied"),
                    "must be denied by the GATE, got: {}",
                    out.output
                );
                assert!(
                    out.output.to_lowercase().contains("control character"),
                    "deny reason must mention control characters, got: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "modal must never fire for a gate-denied command"
        );
        assert!(
            executor.run_calls.lock().unwrap().is_empty(),
            "executor must never run a gate-denied command"
        );
    }

    // ---- respond_propose_command regex ordering ------------------------

    /// A Rust-invalid always-allow regex (the frontend validates with
    /// JS semantics, which accept lookahead) must NOT consume the
    /// pending responder: the command errors, the modal stays up,
    /// and the same request_id is still answerable.
    #[tokio::test]
    async fn invalid_always_allow_regex_does_not_consume_responder() {
        let pending: PendingApprovals = Arc::new(AsyncMutex::new(HashMap::new()));
        let (tx, mut verdict_rx) = oneshot::channel();
        pending
            .lock()
            .await
            .insert("req-1".to_string(), ("chat-1".to_string(), tx));

        // Valid JS regex, invalid in Rust's regex crate (lookahead).
        let err = respond_propose_command_inner(
            &pending,
            ProposeCommandResponse {
                request_id: "req-1".into(),
                verdict: ProposeVerdictWire::AlwaysAllowRegex {
                    regex: "^show (?=ver)".into(),
                },
            },
        )
        .await
        .expect_err("Rust-invalid regex must be rejected");
        assert!(err.contains("invalid regex"), "got: {err}");

        // The pending approval survived the bad regex…
        assert!(
            pending.lock().await.contains_key("req-1"),
            "responder must still be pending after the regex error"
        );
        // …and is still answerable.
        respond_propose_command_inner(
            &pending,
            ProposeCommandResponse {
                request_id: "req-1".into(),
                verdict: ProposeVerdictWire::Approve,
            },
        )
        .await
        .expect("modal still answerable after the bad regex");
        let verdict = verdict_rx.try_recv().expect("verdict delivered");
        assert!(matches!(verdict, ProposeVerdict::Approve));
    }

    // ---- v2.5.0 multi-chat: cancel scopes to one chat ------------------

    /// `drain_chat_approvals_inner` must remove ONLY the target chat's
    /// pending approvals + questions and leave every other concurrent
    /// chat's entries intact. Regression guard for the pre-v2.5.0
    /// behavior where cancelling one chat drained ALL chats.
    #[tokio::test]
    async fn cancel_scopes_pending_to_one_chat() {
        let approvals: PendingApprovals = Arc::new(AsyncMutex::new(HashMap::new()));
        let questions: PendingQuestions = Arc::new(AsyncMutex::new(HashMap::new()));

        let (tx_a, mut rx_a) = oneshot::channel::<ProposeVerdict>();
        let (tx_b, mut rx_b) = oneshot::channel::<ProposeVerdict>();
        approvals
            .lock()
            .await
            .insert("req-a".to_string(), ("chat-a".to_string(), tx_a));
        approvals
            .lock()
            .await
            .insert("req-b".to_string(), ("chat-b".to_string(), tx_b));
        let (q_a, _q_rx_a) = oneshot::channel::<String>();
        let (q_b, _q_rx_b) = oneshot::channel::<String>();
        questions
            .lock()
            .await
            .insert("q-a".to_string(), ("chat-a".to_string(), q_a));
        questions
            .lock()
            .await
            .insert("q-b".to_string(), ("chat-b".to_string(), q_b));

        let cancelled = drain_chat_approvals_inner(&approvals, &questions, "chat-a").await;

        // Only chat-a's approval id is returned for cancellation.
        assert_eq!(cancelled, vec!["req-a".to_string()]);
        // chat-a's entries are gone; chat-b's survive.
        assert!(!approvals.lock().await.contains_key("req-a"));
        assert!(approvals.lock().await.contains_key("req-b"));
        assert!(!questions.lock().await.contains_key("q-a"));
        assert!(questions.lock().await.contains_key("q-b"));
        // chat-a's responder was dropped (its loop's rx.await errors);
        // chat-b's is still live and answerable.
        assert!(rx_a.try_recv().is_err());
        let (_owner, responder_b) = approvals.lock().await.remove("req-b").unwrap();
        responder_b.send(ProposeVerdict::Approve).unwrap();
        assert!(matches!(rx_b.try_recv(), Ok(ProposeVerdict::Approve)));
    }

    // ---- ask_user -----------------------------------------------------

    #[tokio::test]
    async fn ask_user_relays_question_and_returns_answer() {
        let channel = Arc::new(StubChannel::answers("vEX1"));
        let dispatcher = build_dispatcher(channel.clone(), Arc::new(StubExecutor::new()));
        let res = dispatcher
            .dispatch(ToolCall::AskUser(AskUserInput {
                question: "Which device?".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::AskUser(out) => assert_eq!(out.answer, "vEX1"),
            _ => panic!("expected AskUser"),
        }
        assert_eq!(
            channel.question_calls.lock().unwrap().as_slice(),
            &["Which device?".to_string()]
        );
    }

    // ---- v2.7.0 per-chat device scope (T31) -----------------------------

    /// v6.1.1 — scoped-world REGISTRY ids are uuid-shaped so they can
    /// never collide with (or coincidentally equal) the alias namespace
    /// the ledger allocates over the same listing. `SID_VEX1` sorts
    /// first → alias s1→vEX1, s2→core1 when both are in scope.
    const SID_VEX1: &str = "aaaa1111-0000-4000-8000-00000000vex1";
    const SID_CORE1: &str = "bbbb2222-0000-4000-8000-0000000core1";

    fn junos_meta(session_id: &str, device_id: &str) -> SessionMeta {
        SessionMeta {
            session_id: session_id.into(),
            device_id: device_id.into(),
            vendor: Vendor::Junos,
            kind: transit_agent::SessionKind::Ssh,
            opened_at: "2026-07-10T00:00:00Z".into(),
            api_endpoints: Vec::new(),
            alias: None,
            commands_run: None,
            scrollback_bytes: None,
        }
    }

    /// Scoped executor over the standard two-session world (`s1` on
    /// `vEX1`, `s2` on `core1`), with the inner stub kept for asserts.
    fn scoped_world(
        scope: &crate::scoped_session_view::SharedScope,
    ) -> (Arc<dyn SessionExecutor>, Arc<StubExecutor>) {
        use crate::scoped_session_view::{ScopedScrollbackSource, ScopedSessionExecutor};
        use transit_agent::testing::MockScrollbackSource;

        let scoped_source: Arc<dyn ScrollbackSource> = Arc::new(ScopedScrollbackSource {
            inner: Arc::new(
                MockScrollbackSource::new()
                    .with_session(junos_meta(SID_VEX1, "vEX1"), "")
                    .with_session(junos_meta(SID_CORE1, "core1"), ""),
            ),
            scope: scope.clone(),
            ledger: crate::scoped_session_view::SessionLedger::new(),
        });
        let inner = Arc::new(
            StubExecutor::new()
                .with_session(SID_VEX1, Vendor::Junos, "s1 output")
                .with_session(SID_CORE1, Vendor::Junos, "s2 output"),
        );
        let exec: Arc<dyn SessionExecutor> = Arc::new(ScopedSessionExecutor {
            inner: Arc::clone(&inner) as Arc<dyn SessionExecutor>,
            sessions: scoped_source,
        });
        (exec, inner)
    }

    #[tokio::test]
    async fn scoped_executor_out_of_scope_propose_refuses_before_gate_and_modal() {
        // A propose against a session OUTSIDE the chat's scope gets the
        // structured "session not found" refusal — the approval modal
        // never fires and the inner executor never runs. Byte-identical
        // to a closed session (no out-of-scope oracle for injections).
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let (exec, inner) = scoped_world(&scope);
        let channel = Arc::new(StubChannel::approve());
        let dispatcher = build_dispatcher(channel.clone(), exec);

        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: SID_CORE1.into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(!out.executed);
                assert!(
                    out.output.contains("session not found"),
                    "expected the standard not-found refusal, got: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "out-of-scope propose must never reach the approval modal"
        );
        assert!(inner.run_calls.lock().unwrap().is_empty());
    }

    /// Channel simulating a user who DESCOPES the device while the
    /// approval modal is open, then clicks Approve.
    struct DescopeThenApproveChannel {
        scope: crate::scoped_session_view::SharedScope,
        approval_calls: StdMutex<Vec<String>>,
    }

    #[async_trait]
    impl ApprovalChannel for DescopeThenApproveChannel {
        async fn request_command_approval(
            &self,
            _chat_id: &str,
            _session_id: &str,
            command: &str,
            _gate_decision: &str,
            _allow_auto_approve: bool,
        ) -> Result<ProposeVerdict, AgentError> {
            self.approval_calls.lock().unwrap().push(command.into());
            // The user pulls every device out of scope, THEN approves.
            self.scope.set(Some(Vec::new()));
            Ok(ProposeVerdict::Approve)
        }

        async fn request_user_input(
            &self,
            _chat_id: &str,
            _question: &str,
        ) -> Result<String, AgentError> {
            Err(AgentError::Dispatcher("unused".into()))
        }

        async fn request_api_call_approval(
            &self,
            _chat_id: &str,
            _session_id: &str,
            path: &str,
            _gate_decision: &str,
        ) -> Result<ProposeVerdict, AgentError> {
            self.approval_calls.lock().unwrap().push(path.into());
            // Same descope-then-approve as the command path, so an API
            // scope test can reuse this channel.
            self.scope.set(Some(Vec::new()));
            Ok(ProposeVerdict::Approve)
        }
    }

    #[tokio::test]
    async fn scope_shrink_while_modal_open_blocks_execution() {
        // The live-scope pin at the dispatcher level: vendor lookup and
        // the gate pass while the session is in scope, but run_command
        // re-checks AFTER the verdict — an approval clicked after a
        // descope must not execute.
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let (exec, inner) = scoped_world(&scope);
        let channel = Arc::new(DescopeThenApproveChannel {
            scope: scope.clone(),
            approval_calls: StdMutex::new(Vec::new()),
        });
        let dispatcher = build_dispatcher(channel.clone(), exec);

        let err = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: SID_VEX1.into(),
                command: "show version".into(),
            }))
            .await
            .expect_err("approved-but-descoped command must not run");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            1,
            "the modal fired (session was in scope at propose time)"
        );
        assert!(
            inner.run_calls.lock().unwrap().is_empty(),
            "inner executor must never see the descoped command"
        );
    }

    // ---- v6.1.1 session aliases + device echo + ledger ------------------

    /// The production wiring in miniature: ONE ledger shared by the
    /// scoped source and the dispatcher (as `chat_send_message` wires
    /// them), so alias allocation (listing) and alias resolution
    /// (dispatch) see the same map.
    fn alias_world(
        scope: &crate::scoped_session_view::SharedScope,
        channel: Arc<dyn ApprovalChannel>,
    ) -> (
        ApprovalDispatcher,
        Arc<StubExecutor>,
        Arc<dyn ScrollbackSource>,
    ) {
        use crate::scoped_session_view::{
            ScopedScrollbackSource, ScopedSessionExecutor, SessionLedger,
        };
        use transit_agent::testing::MockScrollbackSource;

        let ledger = SessionLedger::new();
        let scoped_source: Arc<dyn ScrollbackSource> = Arc::new(ScopedScrollbackSource {
            inner: Arc::new(
                MockScrollbackSource::new()
                    .with_session(junos_meta(SID_VEX1, "vEX1"), "")
                    .with_session(junos_meta(SID_CORE1, "core1"), ""),
            ),
            scope: scope.clone(),
            ledger: ledger.clone(),
        });
        let inner = Arc::new(
            StubExecutor::new()
                // Prompt-tailed outputs: these fixtures pin the
                // alias/device envelope halves; the capture-terminator
                // annotation has its own matrix test below.
                .with_session(SID_VEX1, Vendor::Junos, "vex1 output\nalice@vEX1>")
                .with_session(SID_CORE1, Vendor::Junos, "core1 output\ncore1#"),
        );
        let exec: Arc<dyn SessionExecutor> = Arc::new(ScopedSessionExecutor {
            inner: Arc::clone(&inner) as Arc<dyn SessionExecutor>,
            sessions: Arc::clone(&scoped_source),
        });
        let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
        let inner_dispatcher =
            DefaultDispatcher::new(Arc::clone(&scoped_source), Arc::clone(&redactor));
        let dispatcher = ApprovalDispatcher::new(
            inner_dispatcher,
            Arc::new(load_real_policy()),
            redactor,
            channel,
            exec,
            Arc::new(StubApiExecutor::new()),
            "chat-test".to_string(),
            new_always_allow_map(),
            new_auto_approve_api_gets(),
            ledger,
            Arc::clone(&scoped_source),
        );
        (dispatcher, inner, scoped_source)
    }

    #[tokio::test]
    async fn propose_command_resolves_alias_and_frames_alias_plus_device() {
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let channel = Arc::new(StubChannel::approve());
        let (dispatcher, inner, source) = alias_world(&scope, channel.clone());
        // The prompt roster lists sessions before any tool call — that
        // listing is what allocates aliases in production too.
        source.list();

        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(out.executed);
                assert!(
                    out.output
                        .starts_with("<session id=\"s1\" device=\"vEX1\">\n"),
                    "envelope must carry alias + device echo, got: {}",
                    out.output
                );
                assert!(out.output.contains("vex1 output"));
            }
            _ => panic!("expected ProposeCommand"),
        }
        // The inner executor received the REGISTRY id (aliases stop at
        // the dispatch boundary)…
        assert_eq!(inner.run_calls.lock().unwrap()[0].0, SID_VEX1);
        // …and so did the modal payload (the UI keeps its own labels).
        assert_eq!(channel.approval_calls.lock().unwrap()[0].1, SID_VEX1);
    }

    #[tokio::test]
    async fn propose_command_raw_registry_id_accepted_and_framed_with_alias() {
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let channel = Arc::new(StubChannel::approve());
        let (dispatcher, inner, source) = alias_world(&scope, channel);
        source.list();

        // Backward compat: a cloud model (or an old transcript) sends
        // the raw registry id. It must work — and the envelope answers
        // in the roster vocabulary, re-teaching the alias.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: SID_VEX1.into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(out) => {
                assert!(out.executed);
                assert!(
                    out.output
                        .starts_with("<session id=\"s1\" device=\"vEX1\">\n"),
                    "raw-id input still frames the alias, got: {}",
                    out.output
                );
            }
            _ => panic!("expected ProposeCommand"),
        }
        assert_eq!(inner.run_calls.lock().unwrap()[0].0, SID_VEX1);
    }

    #[tokio::test]
    async fn unallocated_alias_refuses_with_standard_bytes_no_modal() {
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        scope.set(Some(vec!["vEX1".into()]));
        let channel = Arc::new(StubChannel::approve());
        let (dispatcher, inner, source) = alias_world(&scope, channel.clone());
        source.list(); // allocates s1 (vEX1) only — core1 is descoped

        // An alias that was never allocated ("s2" — its session is out
        // of scope), the descoped registry id itself, and pure garbage
        // must all refuse with the SAME byte shape, echoing the model's
        // own string: no oracle distinguishes them.
        for input in ["s2", SID_CORE1, "never-existed"] {
            let res = dispatcher
                .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                    session_id: input.into(),
                    command: "show version".into(),
                }))
                .await
                .unwrap();
            match res {
                ToolResult::ProposeCommand(out) => {
                    assert!(!out.executed);
                    // Byte-identical across every not-found class
                    // (unallocated alias / descoped id / garbage) — no
                    // oracle. The roster-suffix experiment was removed in
                    // review (self-contradicting on wrong-transport;
                    // redundant with the in-prompt OpenSessions roster).
                    assert_eq!(out.output, format!("session not found: {input}"));
                }
                _ => panic!("expected ProposeCommand"),
            }
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "no refusal may reach the modal"
        );
        assert!(inner.run_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn always_allow_key_unifies_alias_and_registry_spellings() {
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        // Single-shot verdict: if a SECOND modal fired, the exhausted
        // stub would error the dispatch — passing proves no modal.
        let channel = Arc::new(StubChannel::always_allow("^show .*"));
        let (dispatcher, inner, source) = alias_world(&scope, channel.clone());
        source.list();

        // First propose via the ALIAS: modal fires once, user answers
        // approve-and-remember.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(res, ToolResult::ProposeCommand(ref o) if o.executed));
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);

        // Second propose via the RAW registry id: the allowlist entry is
        // keyed on the registry id, so both spellings share ONE entry —
        // no second modal, command still gate-checked and executed.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: SID_VEX1.into(),
                command: "show interfaces terse".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(res, ToolResult::ProposeCommand(ref o) if o.executed));
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            1,
            "one allowlist key per session — the raw-id spelling must not re-prompt"
        );
        assert_eq!(inner.run_calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn post_modal_descope_refusal_echoes_the_models_alias_not_the_uuid() {
        // v6.1.1 review fix: run_command's post-modal SessionNotFound
        // carries the RESOLVED registry id; the dispatcher must remap
        // it to the model's own input spelling — otherwise the 36-char
        // UUID reaches the model AND a mid-modal descope becomes
        // byte-distinguishable from an unallocated alias (an oracle).
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let channel = Arc::new(DescopeThenApproveChannel {
            scope: scope.clone(),
            approval_calls: StdMutex::new(Vec::new()),
        });
        let (dispatcher, inner, source) = alias_world(&scope, channel);
        source.list();

        let err = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .expect_err("approved-but-descoped command must not run");
        match err {
            AgentError::SessionNotFound { session_id } => {
                assert_eq!(
                    session_id, "s1",
                    "the refusal must echo the model's spelling, never the registry id"
                );
            }
            other => panic!("expected SessionNotFound, got {other:?}"),
        }
        assert!(inner.run_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn executed_api_get_increments_the_ledger() {
        // v6.1.1 review fix: without this, an API controller reads
        // `commands this chat: 0` forever and the roster header's
        // "check it before declaring a device inspected" drives
        // re-runs / false not-inspected claims.
        let ledger = crate::scoped_session_view::SessionLedger::new();
        let api =
            Arc::new(StubApiExecutor::new().with_session("c1", ApiGate::Allow, r#"{"sites":[]}"#));
        let dispatcher = build_dispatcher_full_with_ledger(
            Arc::new(StubChannel::approve()),
            Arc::new(StubExecutor::new()),
            api,
            new_always_allow_map(),
            new_auto_approve_api_gets(),
            ledger.clone(),
        );
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("c1", "/v1/sites")))
            .await
            .unwrap();
        assert!(matches!(res, ToolResult::ProposeApiCall(ref o) if o.executed));
        assert_eq!(
            ledger.executed_count("c1"),
            1,
            "an executed GET is a command on the session's per-chat ledger"
        );
    }

    #[tokio::test]
    async fn capture_terminator_annotation_matrix() {
        // v6.1.x #2 — the fabricated-ping killer. Quiescence with a
        // prompt-looking tail = normal end, NO annotation; quiescence
        // without one = `capture="silence"`; timeout and close carry
        // their own values. Values are Transit-authored constants.
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let channel = Arc::new(StubChannel {
            verdict: TokioMutex::new(Some(ProposeVerdict::Approve)),
            answer: TokioMutex::new(None),
            approval_calls: StdMutex::new(Vec::new()),
            question_calls: StdMutex::new(Vec::new()),
        });
        let ledger = crate::scoped_session_view::SessionLedger::new();
        let source: Arc<dyn ScrollbackSource> =
            Arc::new(crate::scoped_session_view::ScopedScrollbackSource {
                inner: Arc::new(
                    transit_agent::testing::MockScrollbackSource::new()
                        .with_session(junos_meta(SID_VEX1, "vEX1"), ""),
                ),
                scope: scope.clone(),
                ledger: ledger.clone(),
            });
        source.list();
        let inner = Arc::new(StubExecutor::new().with_session(
            SID_VEX1,
            Vendor::Junos,
            "PING 10.0.0.1: 56 data bytes\n64 bytes from 10.0.0.1: icmp_seq=0",
        ));
        let exec: Arc<dyn SessionExecutor> =
            Arc::new(crate::scoped_session_view::ScopedSessionExecutor {
                inner: Arc::clone(&inner) as Arc<dyn SessionExecutor>,
                sessions: Arc::clone(&source),
            });
        let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
        let dispatcher = ApprovalDispatcher::new(
            DefaultDispatcher::new(Arc::clone(&source), Arc::clone(&redactor)),
            Arc::new(load_real_policy()),
            redactor,
            channel.clone(),
            exec,
            Arc::new(StubApiExecutor::new()),
            "chat-test".to_string(),
            new_always_allow_map(),
            new_auto_approve_api_gets(),
            ledger,
            Arc::clone(&source),
        );

        let run = |cmd: &'static str| {
            let d = &dispatcher;
            let ch = &channel;
            async move {
                *ch.verdict.lock().await = Some(ProposeVerdict::Approve);
                match d
                    .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                        session_id: "s1".into(),
                        command: cmd.into(),
                    }))
                    .await
                    .unwrap()
                {
                    ToolResult::ProposeCommand(o) => o.output,
                    _ => panic!("expected ProposeCommand"),
                }
            }
        };

        // Quiescence + ping-shaped tail (no prompt) → silence.
        let out = run("ping 10.0.0.1").await;
        assert!(
            out.starts_with("<session id=\"s1\" device=\"vEX1\" capture=\"silence\">\n"),
            "quiet-without-prompt must annotate: {out}"
        );

        // Timeout → output was still flowing.
        inner.set_capture_end(CaptureEnd::Timeout);
        let out = run("show version").await;
        assert!(
            out.contains("capture=\"timeout\""),
            "timeout must annotate: {out}"
        );

        // Session died mid-command.
        inner.set_capture_end(CaptureEnd::Closed);
        let out = run("show version").await;
        assert!(
            out.contains("capture=\"session-closed\""),
            "close must annotate: {out}"
        );
    }

    #[test]
    fn tail_looks_like_prompt_edges() {
        // Empty output is NOT a prompt → silence-annotated (an empty
        // quiescent capture is the worst fabrication trap, not a
        // completed one).
        assert!(!tail_looks_like_prompt(""));
        assert!(!tail_looks_like_prompt("   \n  "));
        // A real prompt tail suppresses the annotation…
        assert!(tail_looks_like_prompt("alice@vEX1>"));
        assert!(tail_looks_like_prompt("core1#"));
        // …but a 200-char line ending in '>' is data, not a prompt.
        assert!(!tail_looks_like_prompt(&format!("{}>", "x".repeat(200))));
    }

    #[tokio::test]
    async fn ledger_counts_only_executed_commands() {
        let scope = crate::scoped_session_view::SharedScope::new_unscoped();
        let channel = Arc::new(StubChannel::approve());
        let (dispatcher, _inner, source) = alias_world(&scope, channel);
        source.list();

        // Gate-denied (junos blocks `configure`): counts must NOT move.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "configure".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(res, ToolResult::ProposeCommand(ref o) if !o.executed));

        // Executed: counts move by one, on the right session only.
        let res = dispatcher
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(res, ToolResult::ProposeCommand(ref o) if o.executed));

        let listed = source.list();
        let vex1 = listed.iter().find(|m| m.device_id == "vEX1").unwrap();
        let core1 = listed.iter().find(|m| m.device_id == "core1").unwrap();
        assert_eq!(
            vex1.commands_run,
            Some(1),
            "only the EXECUTED command counts"
        );
        assert_eq!(core1.commands_run, Some(0));
    }

    // ---- propose_api_call (v4.0.0 — GET-only controller path) ---------

    fn api_input(session_id: &str, path: &str) -> ProposeApiCallInput {
        ProposeApiCallInput {
            session_id: session_id.into(),
            path: path.into(),
        }
    }

    #[tokio::test]
    async fn propose_api_call_unknown_session_is_session_not_found() {
        // Gate → SessionNotFound: no modal, no GET, and byte-identical to
        // the propose_command unknown-session refusal (no oracle that a
        // hidden / out-of-scope controller exists).
        let channel = Arc::new(StubChannel::approve()); // would approve IF asked
        let api = Arc::new(StubApiExecutor::new()); // no controllers registered
        let dispatcher = build_dispatcher_with_api(channel.clone(), api.clone());
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("nope", "/v1/sites")))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert_eq!(out.output, "session not found: nope");
                assert!(!out.executed);
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "modal must not fire for an unknown controller"
        );
        assert!(
            api.run_calls.lock().unwrap().is_empty(),
            "no GET for an unknown controller"
        );
    }

    #[tokio::test]
    async fn propose_api_call_gate_deny_short_circuits_before_modal() {
        // A path that escapes the pinned base is denied by the gate BEFORE
        // the modal — the model gets a structured refusal to pivot on.
        let channel = Arc::new(StubChannel::approve());
        let api = Arc::new(StubApiExecutor::new().with_session(
            "c1",
            ApiGate::Deny {
                reason: "path escapes base".into(),
            },
            "unused",
        ));
        let dispatcher = build_dispatcher_with_api(channel.clone(), api.clone());
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input(
                "c1",
                "../../etc/passwd",
            )))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert_eq!(out.output, "Transit's policy gate denied this request — the controller never received it. path escapes base");
                assert!(!out.executed);
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "a denied path never reaches the modal"
        );
        assert!(api.run_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn propose_api_call_approve_runs_get_and_redacts() {
        // The GET response is redacted on the SAME device→LLM boundary as
        // propose_command: a WLAN PSK in the body must not reach the model.
        let body = r#"{"name":"Guest","x_passphrase":"SuperSecretWiFiPass"}"#;
        let channel = Arc::new(StubChannel::approve());
        let api = Arc::new(StubApiExecutor::new().with_session("c1", ApiGate::Allow, body));
        let dispatcher = build_dispatcher_with_api(channel.clone(), api.clone());
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input(
                "c1",
                "/v1/sites/default/wlans",
            )))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert!(out.executed);
                assert!(
                    !out.output.contains("SuperSecretWiFiPass"),
                    "PSK must be redacted: {}",
                    out.output
                );
                assert!(
                    out.output.contains("[REDACTED:"),
                    "a redaction marker must be present: {}",
                    out.output
                );
                assert!(out.output.contains("Guest"), "benign field survives");
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            1,
            "the modal fired once"
        );
        let calls = api.run_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "the GET ran once");
        assert_eq!(
            calls[0],
            ("c1".to_string(), "/v1/sites/default/wlans".to_string())
        );
    }

    #[tokio::test]
    async fn propose_api_call_deny_verdict_does_not_run() {
        // Gate allows, but the user denies at the modal → no GET.
        let channel = Arc::new(StubChannel::deny());
        let api = Arc::new(StubApiExecutor::new().with_session("c1", ApiGate::Allow, "body"));
        let dispatcher = build_dispatcher_with_api(channel.clone(), api.clone());
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("c1", "/v1/sites")))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert_eq!(out.output, "user denied execution");
                assert!(!out.executed);
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert_eq!(
            channel.approval_calls.lock().unwrap().len(),
            1,
            "the modal fired"
        );
        assert!(
            api.run_calls.lock().unwrap().is_empty(),
            "a denied verdict runs no GET"
        );
    }

    #[tokio::test]
    async fn propose_api_call_run_get_failure_after_approval_is_not_false_success() {
        // Gate allows + the user approves, but run_get FAILS — models the
        // production re-gate (`AppApiExecutor::run_get`) rejecting a path
        // that no longer confines, or a controller deleted mid-approval. The
        // tool must NOT report `executed: true`; the error propagates.
        let channel = Arc::new(StubChannel::approve());
        let api = Arc::new(StubApiExecutor::new().with_gate_only("c1", ApiGate::Allow));
        let dispatcher = build_dispatcher_with_api(channel.clone(), api.clone());
        let err = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("c1", "/v1/sites")))
            .await
            .expect_err("a run_get failure after approval must not be a success");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));
        // The modal DID fire (gate allowed); the failure was at execute time.
        assert_eq!(channel.approval_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn propose_api_call_auto_approve_skips_modal_but_gate_still_runs() {
        // With the chat's auto-approve-GET flag ON: an allowed GET runs
        // WITHOUT the modal, but a gate-denied path is STILL refused. This is
        // THE safety property — the flag suppresses the modal, never the
        // gate; a GET can't mutate, so auto-approving reads is safe.
        let body = r#"{"sites":[]}"#;
        // `deny()` would DENY if the modal ever fired — proving it doesn't.
        let channel = Arc::new(StubChannel::deny());
        let api = Arc::new(
            StubApiExecutor::new()
                .with_session("c1", ApiGate::Allow, body)
                .with_session(
                    "bad",
                    ApiGate::Deny {
                        reason: "off base".into(),
                    },
                    "unused",
                )
                // gate Allow but no output → run_get fails (post-gate).
                .with_gate_only("fail", ApiGate::Allow),
        );
        let dispatcher = build_dispatcher_with_api_autoapprove(channel.clone(), api.clone());

        // Allowed GET runs WITHOUT the modal firing.
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("c1", "/v1/sites")))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert!(out.executed, "auto-approved GET must run: {}", out.output)
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "the modal must NOT fire when auto-approving GETs"
        );
        assert_eq!(api.run_calls.lock().unwrap().len(), 1);

        // The gate STILL runs: a denied path is refused — no GET, no modal.
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("bad", "../escape")))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert!(!out.executed);
                assert_eq!(out.output, "Transit's policy gate denied this request — the controller never received it. off base");
            }
            _ => panic!("expected ProposeApiCall"),
        }
        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "a gate-denied path never reaches a modal, even with auto-approve on"
        );
        assert_eq!(
            api.run_calls.lock().unwrap().len(),
            1,
            "the denied path runs no GET"
        );

        // Under the flag, an unknown / out-of-scope controller is STILL the
        // byte-identical "session not found" (no modal, no GET).
        let res = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("gone", "/v1/sites")))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeApiCall(out) => {
                assert!(!out.executed);
                assert_eq!(out.output, "session not found: gone");
            }
            _ => panic!("expected ProposeApiCall"),
        }

        // Under the flag, a POST-gate run_get failure (e.g. the run-time
        // re-gate rejecting, or the controller deleted mid-request) STILL
        // errors — never a false executed:true.
        let err = dispatcher
            .dispatch(ToolCall::ProposeApiCall(api_input("fail", "/v1/sites")))
            .await
            .expect_err("run_get failure must propagate even with auto-approve on");
        assert!(matches!(err, AgentError::SessionNotFound { .. }));

        assert!(
            channel.approval_calls.lock().unwrap().is_empty(),
            "no branch ever fired the modal under auto-approve"
        );
        // Only 'c1' (ran) and 'fail' (reached run_get, then errored) hit
        // run_get; 'bad'/'gone' were refused before it.
        assert_eq!(api.run_calls.lock().unwrap().len(), 2);
    }
}
