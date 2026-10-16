//! Chat sessions + IPC commands for the chat panel.
//!
//! Phase 5d.A5 ships a non-agentic chat surface: the user types, the
//! `LlmClient` streams text back, the assistant message is appended
//! to the session's message log. Phase 6 grafts the agent loop on
//! top — tool-use blocks (`propose_command`, `read_scrollback`, ...)
//! become messages in the same log, and the per-step approval modal
//! sits between the LLM and execution.
//!
//! State model: a single managed `ChatState` holds a
//! `HashMap<chat_id, ChatSession>`. Each session owns:
//!   - its message log (`Vec<ChatMessage>`),
//!   - its currently-selected model id (mutable mid-conversation
//!     via `chat_set_model`),
//!   - an abort handle for the in-flight stream task, if any.
//!
//! Wire format with the frontend:
//!
//!   commands:
//!     chat_create(model)                  -> chat_id
//!     chat_destroy(chat_id)
//!     chat_list()                         -> Vec<ChatListEntry>   (v6.3.0; runs lazy restore)
//!     chat_messages(chat_id)              -> Vec<ChatMessage>
//!     chat_set_model(chat_id, model)
//!     chat_send_message(chat_id, text)
//!     chat_cancel(chat_id)
//!
//!   events (per-session):
//!     chat:{chat_id}:text-delta  → { delta: String }
//!     chat:{chat_id}:completed   → { usage: ChatUsageWire }
//!     chat:{chat_id}:error       → { message: String }
//!
//! Cancellation: each `chat_send_message` spawns a streaming task
//! and stashes its `JoinHandle`. `chat_cancel` drops the handle's
//! `abort()`, which terminates the reqwest body stream cleanly.
//! Sending a new message also aborts any prior in-flight stream
//! for the same chat — only one stream per chat at a time, which
//! the agent loop in Phase 6 will rely on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use transit_agent::{
    standard_tool_schemas, AgentLoop, AgentLoopEvent, Conversation, ConversationRedactor,
    DefaultDispatcher, DirectAnthropic, DirectOpenAI, LlmClient, LoopBounds, OpenAiAuth,
    StopReason, TokenUsage,
};
use transit_policy::PolicySummary;
use uuid::Uuid;

use crate::agent_dispatch::{
    cancel_chat_approvals, new_always_allow_map, new_auto_approve_api_gets, AlwaysAllowMap,
    ApiExecutor, AppApiExecutor, ApprovalDispatcher, ApprovalState, SessionExecutor,
    SharedAutoApproveApiGets, SshSessionExecutor, TauriApprovalChannel,
};
use crate::api_scrollback_source::ApiScrollbackSource;
use crate::commands::AppState;
use crate::console::ConsoleState;
use crate::console_scrollback_source::{
    ConsoleScrollbackSource, ConsoleSessionExecutor, UnifiedScrollbackSource,
    UnifiedSessionExecutor,
};
use crate::scoped_session_view::{
    ScopedApiExecutor, ScopedScrollbackSource, ScopedSessionExecutor, SessionLedger, SharedScope,
};
use crate::ssh_scrollback_source::SshScrollbackSource;

/// Wire-format chat-thread entry. Phase 6 extends 5d.A5's
/// `User`/`Assistant` with tool-use entries so the chat panel can
/// render the per-call cards inline.
// `Deserialize` exists for ONE consumer: the v6.3.0 opt-in chat-history
// loader (`chat_history::load_all`), which treats the file as hostile
// input (UUID-stem filenames only, size + message caps, skip-on-error).
// No IPC command accepts a ChatMessage inbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ChatMessage {
    User {
        text: String,
    },
    Assistant {
        text: String,
    },
    /// One iteration's tool-use round, post-result. The frontend
    /// renders this as a chevron-collapsed card; clicking expands
    /// the input + (truncated) output. Phase 6 emits this when an
    /// `AgentLoopEvent::ToolUseEnd` fires and the result has been
    /// recorded into the loop's `Conversation`.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
        /// JSON-stringified `ToolResult` on success; the policy
        /// or dispatcher error message on failure.
        output: String,
        is_error: bool,
    },
}

/// Per-turn token usage shape pushed to the frontend at the end of
/// each stream. Mirrors `transit_agent::TokenUsage` 1:1 with the
/// snake_case names the rest of the cloud-side wire uses.
#[derive(Debug, Clone, Serialize)]
pub struct ChatUsageWire {
    pub input_uncached: u64,
    pub input_cache_write: u64,
    pub input_cache_read: u64,
    pub output: u64,
}

impl From<TokenUsage> for ChatUsageWire {
    fn from(u: TokenUsage) -> Self {
        Self {
            input_uncached: u.input_uncached,
            input_cache_write: u.input_cache_write,
            input_cache_read: u.input_cache_read,
            output: u.output,
        }
    }
}

pub struct ChatSession {
    /// Wire-format thread the frontend reads via `chat_messages`.
    /// Updated as the AgentLoop emits events (text deltas accumulate
    /// into a working assistant message; tool rounds append
    /// `ChatMessage::ToolUse`). Maintained alongside the per-turn
    /// `Conversation` rather than derived from it because the
    /// loop-driven `Conversation` discards turns when a fresh user
    /// message arrives.
    pub messages: Vec<ChatMessage>,
    pub model: String,
    /// v6.3.0 — ordering hint for `chat_list`: the history file's
    /// `saved_at` for a restored chat, unix-now for a fresh one. Display
    /// ordering ONLY (left-to-right tab order after a restore); carries
    /// no security meaning.
    pub saved_at_hint: u64,
    /// Set while a stream is in flight; aborted by `chat_cancel` or
    /// the next `chat_send_message`.
    pub in_flight: Option<JoinHandle<()>>,
    /// Shared cancel token between the spawned loop task and this
    /// session. `chat_cancel` notifies it so the loop terminates at
    /// the next await boundary (between SSE events, before tool
    /// dispatch, before the next LLM request).
    pub cancel: Arc<Notify>,
    /// Per-chat auto-approve regex allowlist, Arc-cloned into every
    /// per-message `ApprovalDispatcher` so an "auto-approve this regex"
    /// verdict persists across messages for the life of the chat
    /// (it is dropped — cleared — when the chat is destroyed). In-memory
    /// only, never persisted. The policy gate still runs on EVERY
    /// command regardless of what's stored here (Rule 3); this only
    /// suppresses the approval modal for gate-permitted matches.
    pub always_allow: AlwaysAllowMap,
    /// v2.7.0 — the chat's device scope (T31), cloned into every
    /// per-turn scoped wrapper so a `chat_set_scope` applies LIVE,
    /// even to a command whose approval modal is already open
    /// (`ScopedSessionExecutor::run_command` re-checks post-verdict).
    /// `None` = unscoped (all devices — the default). In-memory only,
    /// never persisted; dies with the chat. The ONLY writer is the
    /// `chat_set_scope` IPC command — user-driven, never the agent
    /// (`SharedScope`'s setter is crate-private; Rule 2's six tools
    /// are unchanged). Forward-looking: it gates reads/executes from
    /// now on, not the already-replayed conversation history.
    pub scope: SharedScope,
    /// v4.0.0 — the chat's opt-in "auto-approve all agent GETs" flag for
    /// `propose_api_call`, Arc-cloned into every per-turn `ApprovalDispatcher`
    /// so an opt-in persists for the chat's life (cleared when the chat is
    /// destroyed). In-memory only; the ONLY writer is `chat_set_auto_approve_gets`
    /// (user-driven — the agent has no path to it). SAFE because the tool is
    /// structurally GET-only: it can only ever auto-approve reads, and the
    /// GET+confine gate STILL runs every call (this only suppresses the modal).
    pub auto_approve_api_gets: SharedAutoApproveApiGets,
    /// v6.1.1 — the chat's session-alias + executed-command ledger,
    /// Arc-cloned into every per-turn scoped source (allocates aliases
    /// for in-scope listings) and `ApprovalDispatcher` (resolves tool
    /// inputs, records executions). In-memory only; dies with the chat.
    /// The agent has no tool that touches it (Rule 2 unchanged) — its
    /// mutating surface is crate-private, driven only by listing and by
    /// the post-approval execution path.
    pub ledger: SessionLedger,
}

/// Tauri-managed state. The inner `Arc` lets streaming tasks borrow
/// the session map without holding a `tauri::State<'_, _>` (which
/// can't be 'static, so it can't be moved into `tokio::spawn`).
pub struct ChatState {
    inner: Arc<ChatStateInner>,
}

struct ChatStateInner {
    sessions: Mutex<HashMap<String, ChatSession>>,
    /// Factory used to build a per-turn `LlmClient`. Production wiring
    /// returns the direct-provider / local impls; tests inject a mock.
    factory: Box<dyn LlmClientFactory>,
    /// v6.3.0 — one-shot lazy restore of persisted chats, run by the
    /// first `chat_list` call. Lazy is race-free by construction: the
    /// frontend only learns restored ids FROM `chat_list`, and every
    /// chat-create path funnels through the panel that issues it.
    restored: tokio::sync::OnceCell<()>,
}

/// Backend mirror of the frontend's `CHAT_TABS_MAX` (uiStore.ts) — a
/// restored backend session without a tab would be unreachable and
/// undestroyable, so the loader never materializes more than the panel
/// can show. Older files stay on disk untouched.
const RESTORE_TAB_CAP: usize = 8;

impl ChatStateInner {
    /// Insert restored chats into the live map (skipping ids already
    /// present — e.g. after a webview reload the backend sessions
    /// survive). Factored free of `self`/env so tests drive it with a
    /// tempdir and poke the map directly.
    fn restore_sessions(
        sessions: &mut HashMap<String, ChatSession>,
        restored: Vec<crate::chat_history::RestoredChat>,
    ) {
        for r in restored {
            if sessions.contains_key(&r.chat_id) {
                continue;
            }
            // Factory-fresh security state, deliberately: the
            // always-allow map (T18), device scope (T31), API
            // auto-approve, and ledger are in-memory-only by design and
            // are NOT represented in the history file at all.
            sessions.insert(
                r.chat_id.clone(),
                ChatSession {
                    messages: r.messages,
                    model: r.model,
                    saved_at_hint: r.saved_at,
                    in_flight: None,
                    cancel: Arc::new(Notify::new()),
                    always_allow: new_always_allow_map(),
                    scope: SharedScope::new_unscoped(),
                    auto_approve_api_gets: new_auto_approve_api_gets(),
                    ledger: SessionLedger::new(),
                },
            );
        }
    }

    async fn ensure_restored(&self) {
        // The enabled/config checks run BEFORE get_or_init on purpose:
        // OnceCell commits `()` even when the closure early-returns, so
        // checking inside would seal "ran while disabled" as "restored"
        // and a mid-session enable would restore nothing until relaunch
        // (review finding). A resolver error is a real misconfiguration —
        // log it (a silent return here plus the silent write-skips would
        // make the whole feature a no-op with zero diagnostics).
        let feature = match crate::commands::resolve_chat_history() {
            Ok(f) if f.enabled => f,
            Ok(_) => return,
            Err(e) => {
                warn!(error = %e, "chat history misconfigured; restore skipped");
                return;
            }
        };
        self.restored
            .get_or_init(|| async {
                // Restore into the ROOM the tab cap leaves, counting live
                // sessions too — chat_list must never return more chats
                // than the frontend can tab (an untabbed backend session
                // is unreachable and undestroyable). Live sessions exist
                // here when a webview reload preceded the first chat_list.
                let room = {
                    let guard = self.sessions.lock().await;
                    RESTORE_TAB_CAP.saturating_sub(guard.len())
                };
                if room == 0 {
                    return;
                }
                // load_all is synchronous fs IO (read + parse per file) —
                // keep it off the async workers.
                let dir = feature.dir.clone();
                let restored =
                    tokio::task::spawn_blocking(move || crate::chat_history::load_all(&dir, room))
                        .await
                        .unwrap_or_default();
                if restored.is_empty() {
                    return;
                }
                let mut guard = self.sessions.lock().await;
                Self::restore_sessions(&mut guard, restored);
            })
            .await;
    }
}

/// Build an `LlmClient` for the supplied model. The trait exists so
/// tests can substitute a stub that yields a deterministic stream
/// without any HTTP traffic.
#[async_trait::async_trait]
pub trait LlmClientFactory: Send + Sync {
    async fn build(&self, model: &str) -> Box<dyn LlmClient>;
    /// A turn ended in a provider error; the factory may react (the
    /// production impl drops a ChatGPT access token OpenAI just refused
    /// so the next send refreshes instead of replaying it for an hour).
    async fn on_provider_error(&self, _message: &str) {}
}

/// Production factory — routes a model id to the client that serves it.
///
/// Order: (1) the `ollama:` / `endpoint:` namespaces → the local (BYOM)
/// clients; (2) everything else → a direct provider client holding the
/// user's own key, read from the OS keychain at build time (per message,
/// so a key saved in Settings applies on the next send). No key enrolled
/// for the provider → a client whose first call fails with
/// `LlmError::MissingKey`, which the UI maps to "add your key in
/// Settings → API keys". There is no other path: this edition has no
/// proxy and no account.
pub struct DirectClientFactory {
    /// Sign-in-with-ChatGPT grant (tokens are read here, never by the
    /// agent crate). Consulted only when `[providers] openai_method` is
    /// `chatgpt`.
    chatgpt: Arc<crate::chatgpt_auth::ChatGptState>,
}

#[async_trait::async_trait]
impl LlmClientFactory for DirectClientFactory {
    async fn build(&self, model: &str) -> Box<dyn LlmClient> {
        // BYOM: the `ollama:` / `endpoint:` namespaces are checked FIRST
        // and use the SAME `is_local_model` predicate as pricing + bounds
        // (a divergence would zero-price a provider model and kill the
        // rounds/cost checkpoint; pinned in transit_agent::usage).
        if transit_agent::llm::is_local_model(model) {
            return build_local_client(model);
        }
        let provider = crate::provider_keys::Provider::for_model(model);
        // OpenAI on a ChatGPT plan: the bearer is the plan access token,
        // refreshed through the stored grant; no key is read at all.
        if provider == crate::provider_keys::Provider::Openai
            && crate::chatgpt_auth::read_openai_method()
                == crate::chatgpt_auth::OpenAiMethod::Chatgpt
        {
            // Strict TLS is re-resolved per build so a Settings change
            // applies on the next send.
            let strict_tls = crate::commands::resolve_strict_tls();
            return match self.chatgpt.access_token().await {
                Ok(token) => Box::new(DirectOpenAI::new(
                    OpenAiAuth::ChatGptPlan(token),
                    strict_tls,
                )),
                Err(crate::chatgpt_auth::PlanAuthError::Reauth) => Box::new(PlanReauthClient),
                Err(crate::chatgpt_auth::PlanAuthError::Other(message)) => {
                    Box::new(ErrLlmClient { message })
                }
            };
        }
        let key = match crate::provider_keys::read_key(provider) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Box::new(MissingKeyClient {
                    provider: provider.display_name(),
                })
            }
            Err(e) => {
                // A locked/denied keychain is a real failure, not "no
                // key": say so rather than steering the user to re-enter
                // a key they may already have saved.
                tracing::warn!(provider = ?provider, error = %e, "provider key read failed");
                return Box::new(ErrLlmClient {
                    message: format!(
                        "could not read the {} API key from the OS keychain: {e}",
                        provider.display_name()
                    ),
                });
            }
        };
        // Strict TLS (`[network] strict_tls`, T27) is re-resolved per
        // build so a Settings change applies on the next send.
        let strict_tls = crate::commands::resolve_strict_tls();
        match provider {
            crate::provider_keys::Provider::Anthropic => {
                Box::new(DirectAnthropic::new(key, strict_tls))
            }
            crate::provider_keys::Provider::Openai => {
                Box::new(DirectOpenAI::new(OpenAiAuth::ApiKey(key), strict_tls))
            }
        }
    }

    async fn on_provider_error(&self, message: &str) {
        if message.contains("plan_reauth_required") {
            self.chatgpt.invalidate_access().await;
        }
    }
}

/// Factory-infallibility shim for the ChatGPT-plan path with no usable
/// grant: every call fails with `PlanReauthRequired`, which the shell maps
/// to "sign in again".
struct PlanReauthClient;

#[async_trait::async_trait]
impl LlmClient for PlanReauthClient {
    async fn messages(
        &self,
        _req: transit_agent::llm::LlmRequest,
    ) -> transit_agent::llm::LlmResult<transit_agent::llm::LlmStream> {
        Err(transit_agent::llm::LlmError::PlanReauthRequired)
    }
}

/// Factory-infallibility shim for the no-key case: every call fails
/// with the typed `MissingKey` so the shell can route the user to
/// Settings → API keys.
struct MissingKeyClient {
    provider: &'static str,
}

#[async_trait::async_trait]
impl LlmClient for MissingKeyClient {
    async fn messages(
        &self,
        _req: transit_agent::llm::LlmRequest,
    ) -> transit_agent::llm::LlmResult<transit_agent::llm::LlmStream> {
        Err(transit_agent::llm::LlmError::MissingKey {
            provider: self.provider,
        })
    }
}

/// Build the local (BYOM) client for a namespaced model id. Config is
/// re-resolved per message (matching the per-message factory call) so
/// a Settings change applies on the next send — no restart. Transport
/// rules are enforced inside the clients (T35); bearer tokens are read
/// from the keychain HERE (transit_app is a deny.toml keyring wrapper;
/// transit_agent is not) and passed in by value.
fn build_local_client(model: &str) -> Box<dyn LlmClient> {
    use transit_agent::llm::{ollama, openai_compat, parse_endpoint_model, transport};

    if let Some((endpoint_id, _)) = parse_endpoint_model(model) {
        let Some(ep) = crate::commands::resolve_local_endpoints()
            .into_iter()
            .find(|e| e.id == endpoint_id)
        else {
            return Box::new(ErrLlmClient {
                message: format!(
                    "endpoint `{endpoint_id}` is no longer configured — pick another model \
                     in Settings → Local models"
                ),
            });
        };
        let http = transport::endpoint_http_client(&ep.base_url, None);
        return match ep.kind {
            crate::commands::LocalEndpointKind::Ollama => {
                Box::new(ollama::OllamaClient::for_endpoint(
                    http,
                    ollama::OllamaConfig {
                        base_url: ep.base_url,
                        num_ctx: ep.context_length,
                        keep_alive: crate::commands::resolve_local_models().cfg.keep_alive,
                    },
                ))
            }
            crate::commands::LocalEndpointKind::OpenaiCompat => {
                let bearer = crate::local_models::read_endpoint_token(&ep.id)
                    .ok()
                    .flatten();
                Box::new(openai_compat::OpenAiCompatClient::new(
                    http,
                    openai_compat::OpenAiCompatConfig {
                        base_url: ep.base_url,
                        bearer,
                        declared_context_length: ep.context_length,
                    },
                ))
            }
        };
    }
    // `ollama:` — the zero-config loopback client.
    Box::new(ollama::OllamaClient::new(
        crate::commands::resolve_local_models().cfg,
    ))
}

/// Factory-infallibility shim: a routing failure (e.g. a deleted
/// endpoint) surfaces as a stream error with user-shaped copy instead
/// of silently retargeting some other backend.
struct ErrLlmClient {
    message: String,
}

#[async_trait::async_trait]
impl LlmClient for ErrLlmClient {
    async fn messages(
        &self,
        _req: transit_agent::llm::LlmRequest,
    ) -> transit_agent::llm::LlmResult<transit_agent::llm::LlmStream> {
        Err(transit_agent::llm::LlmError::LocalProvider(
            self.message.clone(),
        ))
    }
}

/// BYOM send-gate. Local models are a free feature of this edition; the
/// only gate is the `[local_models] enabled` switch (the MDM/enterprise
/// off-switch). Kept as a function so the refusal copy stays pinned and
/// the chokepoint stays visible on the send path.
fn ensure_local_send_allowed(enabled: bool) -> Result<(), String> {
    if !enabled {
        return Err("Local models are turned off — enable them in Settings → Local models.".into());
    }
    Ok(())
}

impl ChatState {
    pub fn new(chatgpt: Arc<crate::chatgpt_auth::ChatGptState>) -> Self {
        Self::with_factory(Box::new(DirectClientFactory { chatgpt }))
    }

    pub fn with_factory(factory: Box<dyn LlmClientFactory>) -> Self {
        Self {
            inner: Arc::new(ChatStateInner {
                sessions: Mutex::new(HashMap::new()),
                factory,
                restored: tokio::sync::OnceCell::new(),
            }),
        }
    }
}

// ---------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------

#[tauri::command]
pub async fn chat_create(state: State<'_, ChatState>, model: String) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let mut guard = state.inner.sessions.lock().await;
    guard.insert(
        id.clone(),
        ChatSession {
            messages: Vec::new(),
            model,
            saved_at_hint: crate::chat_history::now_unix(),
            in_flight: None,
            cancel: Arc::new(Notify::new()),
            always_allow: new_always_allow_map(),
            scope: SharedScope::new_unscoped(),
            auto_approve_api_gets: new_auto_approve_api_gets(),
            ledger: SessionLedger::new(),
        },
    );
    Ok(id)
}

/// v6.3.0 — one row per live backend chat, restored chats included.
#[derive(Debug, Serialize)]
pub struct ChatListEntry {
    pub chat_id: String,
    pub model: String,
}

/// List the backend's chat sessions, lazily restoring persisted history
/// first (opt-in; a disabled feature restores nothing). The frontend
/// syncs its tab strip against this — adding missing tabs only — which
/// both restores history and heals webview-reload orphans. Ordered by
/// `saved_at_hint` ascending (left-to-right tab order).
#[tauri::command]
pub async fn chat_list(state: State<'_, ChatState>) -> Result<Vec<ChatListEntry>, String> {
    state.inner.ensure_restored().await;
    let guard = state.inner.sessions.lock().await;
    Ok(list_entries(&guard))
}

/// Total order: saved_at_hint is second-resolution, so ties are real
/// (two chats created in one second), and the underlying map iterates
/// in unstable order — without the id tie-break, restored tab order
/// could differ between launches.
fn list_entries(sessions: &HashMap<String, ChatSession>) -> Vec<ChatListEntry> {
    let mut rows: Vec<(u64, ChatListEntry)> = sessions
        .iter()
        .map(|(id, s)| {
            (
                s.saved_at_hint,
                ChatListEntry {
                    chat_id: id.clone(),
                    model: s.model.clone(),
                },
            )
        })
        .collect();
    rows.sort_by(|(a_hint, a), (b_hint, b)| a_hint.cmp(b_hint).then(a.chat_id.cmp(&b.chat_id)));
    rows.into_iter().map(|(_, e)| e).collect()
}

/// v2.7.0 — set (or clear, with `None`) the chat's device scope.
/// `device_ids: None` = unscoped (all devices); `Some([])` = the agent
/// sees no sessions. Applies live to any in-flight turn (the per-turn
/// wrappers share this handle). Wire note: the TS wrapper takes
/// `string[] | null` as a REQUIRED parameter — an optional param would
/// make a forgotten argument deserialize as `None` and silently
/// unscope the chat.
#[tauri::command]
pub async fn chat_set_scope(
    state: State<'_, ChatState>,
    chat_id: String,
    device_ids: Option<Vec<String>>,
) -> Result<(), String> {
    let guard = state.inner.sessions.lock().await;
    let session = guard.get(&chat_id).ok_or("chat not found")?;
    session.scope.set(device_ids);
    Ok(())
}

/// Opt the chat into (or out of) auto-approving the agent's read-only GETs
/// for `propose_api_call` — this suppresses the per-call approval modal
/// while the GET+confine gate STILL runs on every call. Safe because the
/// tool is structurally GET-only (it can only ever auto-approve reads, never
/// a write). User-driven ONLY (the agent has no path to this — Rule 2's
/// tools are unchanged); in-memory, chat-scoped, dies with the chat.
#[tauri::command]
pub async fn chat_set_auto_approve_gets(
    state: State<'_, ChatState>,
    chat_id: String,
    enabled: bool,
) -> Result<(), String> {
    let guard = state.inner.sessions.lock().await;
    let session = guard.get(&chat_id).ok_or("chat not found")?;
    session.auto_approve_api_gets.set(enabled);
    Ok(())
}

#[tauri::command]
pub async fn chat_destroy(
    app: AppHandle,
    state: State<'_, ChatState>,
    approval_state: State<'_, ApprovalState>,
    chat_id: String,
) -> Result<(), String> {
    // Scope-cancel this chat's pending approvals/questions FIRST so a
    // loop parked on `rx.await` (inside `request_command_approval`) is
    // freed and its modal/card dismisses — without draining any other
    // concurrent chat's pending entries (v2.5.0 multi-chat). Then drop
    // the session + abort its task.
    cancel_chat_approvals(&approval_state, &app, &chat_id).await;
    {
        let mut guard = state.inner.sessions.lock().await;
        if let Some(session) = guard.remove(&chat_id) {
            if let Some(h) = session.in_flight {
                h.abort();
            }
        }
    }
    // v6.3.0 — "close means gone" holds UNCONDITIONALLY: the history file
    // (if any) is deleted regardless of whether persistence is currently
    // enabled, so a chat closed while the feature was off can't resurrect
    // when it's re-enabled. Best-effort; the id is UUID-validated inside;
    // a misconfigured dir is LOGGED (a silent skip here re-opens the
    // resurrection path the comment above promises is closed).
    match crate::commands::resolve_chat_history() {
        Ok(feature) => {
            let dir = feature.dir;
            let id = chat_id.clone();
            let deleted =
                tokio::task::spawn_blocking(move || crate::chat_history::delete_chat(&dir, &id))
                    .await;
            match deleted {
                Ok(Err(e)) => warn!(chat_id, error = %e, "chat history delete failed"),
                Err(e) => warn!(chat_id, error = %e, "chat history delete task failed"),
                Ok(Ok(())) => {}
            }
        }
        Err(e) => {
            warn!(chat_id, error = %e, "chat history misconfigured; close-time delete skipped");
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn chat_messages(
    state: State<'_, ChatState>,
    chat_id: String,
) -> Result<Vec<ChatMessage>, String> {
    let guard = state.inner.sessions.lock().await;
    let session = guard.get(&chat_id).ok_or("chat not found")?;
    Ok(session.messages.clone())
}

#[tauri::command]
pub async fn chat_set_model(
    state: State<'_, ChatState>,
    chat_id: String,
    model: String,
) -> Result<(), String> {
    {
        let mut guard = state.inner.sessions.lock().await;
        let session = guard.get_mut(&chat_id).ok_or("chat not found")?;
        session.model = model;
    }
    // v6.3.0 — else a restored chat resurrects with a stale model.
    persist_chat_now(&state.inner, &chat_id).await;
    Ok(())
}

#[tauri::command]
pub async fn chat_cancel(
    app: AppHandle,
    state: State<'_, ChatState>,
    approval_state: State<'_, ApprovalState>,
    chat_id: String,
) -> Result<(), String> {
    let cancel = {
        let mut guard = state.inner.sessions.lock().await;
        let session = guard.get_mut(&chat_id).ok_or("chat not found")?;
        let abort = session.in_flight.take();
        if let Some(h) = abort {
            // `abort` covers the runtime case where the loop's
            // current await isn't waiting on the cancel notify
            // (e.g. inside a third-party SSE parser future). The
            // cleaner notify path is below — abort is belt-and-braces
            // so a hung await still drops.
            h.abort();
        }
        Arc::clone(&session.cancel)
    };
    cancel.notify_one();
    cancel_chat_approvals(&approval_state, &app, &chat_id).await;
    // v6.3.0 — an aborted task never reaches the Completed arm, so any
    // mid-turn ToolUse entries would sit unflushed until the NEXT turn
    // boundary; a quit right after a cancel would lose them.
    persist_chat_now(&state.inner, &chat_id).await;
    Ok(())
}

#[tauri::command]
pub async fn chat_send_message(
    app: AppHandle,
    state: State<'_, ChatState>,
    app_state: State<'_, AppState>,
    approval_state: State<'_, ApprovalState>,
    chat_id: String,
    text: String,
) -> Result<(), String> {
    // ---- 0. Config snapshot + BYOM send-gate (T32) -------------
    // ONE resolve per send (re-read each message so a config edit
    // applies on the next send): the same snapshot serves the BYOM
    // enabled-gate and the per-turn token ceiling below — two reads
    // could straddle a Settings save and gate on one generation of
    // the file while bounding with another.
    let local_models_cfg = crate::commands::resolve_local_models();
    if let Some(w) = &local_models_cfg.warning {
        // Surface a rejected config value on the send path too — the
        // Settings panel shows it, but a provider-only user tuning the
        // ceiling may never open that panel. Fact + rejected value
        // only (§10); never device or prompt content.
        tracing::warn!(warning = %w, "local-models config value rejected; using default");
    }
    // Runs BEFORE the user message is appended so a refused send
    // leaves the chat log untouched (no duplicate on retry). Every
    // local-model turn passes this chokepoint; provider models need
    // no gate here (a missing key surfaces from the factory).
    {
        let selected_model = {
            let guard = state.inner.sessions.lock().await;
            guard.get(&chat_id).ok_or("chat not found")?.model.clone()
        };
        if transit_agent::llm::is_local_model(&selected_model) {
            ensure_local_send_allowed(local_models_cfg.enabled)?;
        }
    }

    // ---- 1. Append user msg + snapshot the model + history ----
    let (model, prior_messages, cancel, always_allow, scope, auto_approve_api_gets, ledger) = {
        let mut guard = state.inner.sessions.lock().await;
        let session = guard.get_mut(&chat_id).ok_or("chat not found")?;
        // One loop per chat. Aborting now means a rapid-fire user
        // (Send → typo → Send again) doesn't get two assistants
        // racing into the same log. The fresh cancel ensures the
        // new run isn't immediately killed by a stale notify.
        if let Some(h) = session.in_flight.take() {
            h.abort();
        }
        session.cancel = Arc::new(Notify::new());
        session.messages.push(ChatMessage::User { text });
        (
            session.model.clone(),
            session.messages.clone(),
            Arc::clone(&session.cancel),
            Arc::clone(&session.always_allow),
            session.scope.clone(),
            session.auto_approve_api_gets.clone(),
            session.ledger.clone(),
        )
    };

    // ---- 2. Build the per-turn Conversation -------------------
    // Fresh Conversation per turn — tool_use_ids only matter
    // within one AgentLoop run, and rebuilding from the
    // `ChatMessage` log keeps the wire-format-vs-internal
    // boundary clean. The per-turn ApprovalDispatcher is handed the
    // chat's shared `always_allow` map (Arc-cloned above), so an
    // auto-approve regex set in an earlier turn still suppresses the
    // modal in this one — the allowlist lives as long as the chat,
    // not the turn.
    let policies = collect_policy_summaries(&app_state.policy);
    // Phase 7b — unify SSH + console transports under a single
    // ScrollbackSource / SessionExecutor pair so the agent's
    // read_scrollback / list_open_sessions / propose_command see
    // both kinds of sessions uniformly. `ConsoleState` is managed
    // as `Arc<ConsoleState>` by `console::install` so we can clone
    // the handle into both the source and the executor.
    let console_state: State<'_, Arc<ConsoleState>> = app.state::<Arc<ConsoleState>>();
    let console_arc: Arc<ConsoleState> = Arc::clone(console_state.inner());
    // v2.7.0 (T31): the unified source is wrapped in the chat's device
    // scope, and THIS scoped Arc is the one handed to BOTH consumers —
    // the DefaultDispatcher (list_open_sessions / read_scrollback) and
    // the Conversation (system prompt) — so tools and prompt present
    // one coherent filtered world. The executor below wraps the same
    // scoped source, closing the propose_command path too.
    let scrollback_source: Arc<dyn transit_agent::ScrollbackSource> =
        Arc::new(ScopedScrollbackSource {
            inner: Arc::new(UnifiedScrollbackSource {
                ssh: SshScrollbackSource::new(Arc::clone(&app_state.ssh)),
                console: ConsoleScrollbackSource::new(Arc::clone(&console_arc)),
                api: ApiScrollbackSource::new(Arc::clone(&app_state.api_sessions)),
            }),
            scope: scope.clone(),
            // v6.1.1 — the chat's ledger: in-scope listings get aliases
            // (s1, s2, …) + executed-command counts; the dispatcher below
            // shares the same handle for input resolution + counting.
            ledger: ledger.clone(),
        });
    let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
    // v6.0.0 PCaps. The ONLY agent-visible surface, and it is wired here
    // rather than composed into `UnifiedScrollbackSource` because a
    // capture is not a session: it has no scrollback, no vendor, and
    // nothing to propose a command against. Keeping it on its own seam
    // means `list_open_sessions` / `read_scrollback` / `propose_command`
    // cannot reach a capture, and `query_capture` cannot reach a device.
    //
    // Not scoped by the per-chat device scope (T31): a capture is a file
    // the user opened, not a device. Noted as a residual in threat-model
    // T45.
    //
    // ONE Arc serves both consumers (v6.0.1): the dispatcher answers
    // `query_capture` from it, and the Conversation renders the prompt's
    // "Open packet captures" roster from it — so the prompt describes
    // exactly the world the tool answers from (same shared-instance rule
    // as the redactor). `[pcap] agent_access = false` empties both views.
    let capture_source: Arc<dyn transit_agent::CaptureSource> =
        Arc::new(crate::pcap::PcapCaptureSource::new(Arc::clone(
            &*app.state::<Arc<crate::pcap::PcapState>>(),
        )));
    let inner_dispatcher =
        DefaultDispatcher::new(Arc::clone(&scrollback_source), Arc::clone(&redactor))
            .with_captures(Arc::clone(&capture_source));
    let channel = Arc::new(TauriApprovalChannel {
        app: app.clone(),
        pending_approvals: Arc::clone(&approval_state.pending_approvals),
        pending_questions: Arc::clone(&approval_state.pending_questions),
    });
    let executor: Arc<dyn SessionExecutor> = Arc::new(ScopedSessionExecutor {
        inner: Arc::new(UnifiedSessionExecutor {
            ssh: SshSessionExecutor {
                ssh: Arc::clone(&app_state.ssh),
            },
            console: ConsoleSessionExecutor {
                console: console_arc,
            },
        }),
        // The SCOPED source — membership + vendor come from the same
        // filtered view the tools/prompt see (out-of-scope propose →
        // the existing "session not found" structured refusal, and
        // run_command re-checks after the modal).
        sessions: Arc::clone(&scrollback_source),
    });
    // v4.0.0 — the GET-only controller path for propose_api_call. Same
    // shape as the executor above: AppApiExecutor (resolves endpoint/key/
    // client live from AppState) wrapped in the chat's device scope, so
    // membership + the post-modal re-check come from the same filtered
    // view (out-of-scope controller → byte-identical "session not found").
    let api_executor: Arc<dyn ApiExecutor> = Arc::new(ScopedApiExecutor {
        inner: Arc::new(AppApiExecutor { app: app.clone() }),
        sessions: Arc::clone(&scrollback_source),
    });
    let approval_dispatcher = Arc::new(ApprovalDispatcher::new(
        inner_dispatcher,
        Arc::clone(&app_state.policy),
        Arc::clone(&redactor),
        channel,
        executor,
        api_executor,
        chat_id.clone(),
        always_allow,
        auto_approve_api_gets,
        // v6.1.1 — the chat's ledger (alias resolution + executed-command
        // counts) and the same scoped source Arc (device_id lookup for the
        // result-envelope device echo).
        ledger.clone(),
        Arc::clone(&scrollback_source),
    ));

    let mut conversation = Conversation::new(
        approval_dispatcher,
        scrollback_source,
        Arc::clone(&redactor),
        policies,
    )
    // The same capture Arc as the dispatcher (see above): with a capture
    // open, the prompt names it and points at `query_capture`; with none
    // (or agent_access off), the section is absent.
    .with_captures(capture_source);
    // Replay prior messages into the Conversation so the LLM sees
    // the full thread. Tool-use entries from prior turns can't be
    // replayed faithfully (we'd need the original tool_use_ids,
    // which weren't persisted in ChatMessage); the model sees them
    // as plain assistant text. Acceptable for v1: the model still
    // has the SEMANTIC history; only the tool-use protocol round
    // breaks across user-message boundaries, which doesn't matter
    // because each turn is a fresh AgentLoop run.
    for msg in &prior_messages {
        match msg {
            ChatMessage::User { text } => conversation.record_user(text.clone()),
            ChatMessage::Assistant { text } => conversation.record_assistant_text(text.clone()),
            ChatMessage::ToolUse {
                name,
                input,
                output,
                is_error,
                ..
            } => {
                // Render as a synthetic assistant note so the model
                // has narrative continuity. C12+ may swap this for a
                // proper replay once we persist tool_use_ids.
                let blob = serde_json::json!({
                    "tool_called": name,
                    "input": input,
                    "result": output,
                    "is_error": is_error,
                });
                conversation.record_assistant_text(format!(
                    "[prior tool round]\n{}",
                    serde_json::to_string_pretty(&blob).unwrap_or_default()
                ));
            }
        }
    }

    // ---- 3. Build + spawn the AgentLoop -----------------------
    let client = state.inner.factory.build(&model).await;
    let agent_loop = AgentLoop {
        conversation,
        client,
        // Provider-aware: local (BYOM) models get the 600s stream
        // budget (cold load + full-window prompt eval + single-slot
        // queueing); cloud models keep the 90s default.
        bounds: LoopBounds::for_model(&model),
        tools: standard_tool_schemas(),
        model: model.clone(),
        // v6.1.1 — per-turn output-token ceiling (`[local_models]
        // turn_token_ceiling`, default 4096): ends the meta-question
        // thinking-loop a flowing stream never times out of. Local
        // clients min() this against their T34 half-window clamp
        // (raising the ceiling therefore SHRINKS the pre-send prompt
        // budget — the generation reservation comes out of the same
        // window); cloud Anthropic already defaulted to 4096, cloud
        // OpenAI gains the cap (and its parser now treats
        // `response.incomplete` as a truncated-but-usable turn). From
        // the step-0 snapshot, so gate + ceiling see one config
        // generation.
        max_tokens_per_turn: Some(local_models_cfg.turn_token_ceiling),
        cancel: Arc::clone(&cancel),
    };

    let inner = state.inner.clone();
    let chat_id_task = chat_id.clone();
    let app_task = app.clone();
    let task = tokio::spawn(async move {
        drive_loop(inner, app_task, chat_id_task, agent_loop).await;
    });

    let mut guard = state.inner.sessions.lock().await;
    if let Some(session) = guard.get_mut(&chat_id) {
        session.in_flight = Some(task);
    } else {
        warn!(chat_id, "chat session destroyed mid-send");
    }
    Ok(())
}

/// Snapshot per-vendor policy summaries for the system prompt.
/// Returns the full universe of LOADED vendors — bundled, merged, and
/// BYOP custom (Phase 2b) — by enumerating the engine itself
/// (`PolicyEngine::vendors`) rather than a hardcoded built-in list.
/// `system_prompt::build` scopes the *rendered* section to the vendors
/// of currently-open sessions (the scoped vendor policy and byop design notes (not included in this repository)
/// Phase 1), so the cached prefix keys on the open-vendor set and stops
/// scaling with the catalog; this is the universe it scopes from. The
/// volatile `OpenSessions` section carries a per-session
/// `(see Policies §<vendor>)` pointer that resolves into the scoped
/// section (open vendors with no policy get an explicit default-deny
/// note).
///
/// Enumerating the engine means a user's custom vendor (or a newly
/// shipped one) is surfaced to the model automatically once its policy
/// loads — no hardcoded list to keep in sync (see CLAUDE.md §7 step 8).
fn collect_policy_summaries(
    policy: &transit_policy::PolicyEngine,
) -> Vec<(transit_core::inventory::Vendor, PolicySummary)> {
    policy
        .vendors()
        .into_iter()
        .filter_map(|v| policy.summary(&v).map(|s| (v, s)))
        .collect()
}

async fn drive_loop(
    inner: Arc<ChatStateInner>,
    app: AppHandle,
    chat_id: String,
    agent_loop: AgentLoop,
) {
    let topic_text = format!("chat:{chat_id}:text-delta");
    let topic_completed = format!("chat:{chat_id}:completed");
    let topic_error = format!("chat:{chat_id}:error");
    let topic_tool_begin = format!("chat:{chat_id}:tool-use-begin");
    let topic_tool_end = format!("chat:{chat_id}:tool-use-end");
    let topic_iteration = format!("chat:{chat_id}:iteration");

    // Run the loop. The Conversation is owned by the loop itself;
    // we observe via the event stream and translate per-event into
    // ChatMessage entries on the session.
    let mut stream = agent_loop.run();

    // Working state: assistant text accumulating from TextDelta
    // events, plus any tool rounds we've recorded inside the
    // current iteration.
    let mut accumulated_text = String::new();

    while let Some(event) = stream.next().await {
        match event {
            AgentLoopEvent::TextDelta(t) => {
                accumulated_text.push_str(&t);
                let _ = app.emit(&topic_text, DeltaPayload { delta: t });
            }
            AgentLoopEvent::ToolUseBegin { id, call, .. } => {
                let _ = app.emit(
                    &topic_tool_begin,
                    ToolUseBeginPayload {
                        id,
                        // The structured tool name + input let the UI
                        // render the modal/inline preview from
                        // wire-side data alone. The agent's
                        // ToolCall serializes to JSON via its
                        // `serde(tag = "tool")` shape; convert here.
                        call: serde_json::to_value(&call).unwrap_or_default(),
                    },
                );
            }
            AgentLoopEvent::ToolUseEnd { id, result, .. } => {
                let (output, is_error) = match &result {
                    Ok(r) => (
                        serde_json::to_string(r).unwrap_or_default(),
                        // ProposeCommand with executed=false is a
                        // structured rejection (policy or user
                        // deny) — not a hard error, but the UI
                        // should style it differently. Surface
                        // executed=false as is_error so the UI
                        // can chevron-collapse the failed cards.
                        match r {
                            transit_agent::ToolResult::ProposeCommand(o) => !o.executed,
                            _ => false,
                        },
                    ),
                    Err(e) => (e.clone(), true),
                };
                // Append a wire-format ToolUse entry to the chat
                // log so subsequent `chat_messages` calls render
                // the round inline.
                {
                    let mut guard = inner.sessions.lock().await;
                    if let Some(session) = guard.get_mut(&chat_id) {
                        // Reach back into the loop's recorded
                        // AssistantWithTools message to recover the
                        // input bytes. The loop's `Conversation` is
                        // private to the spawned task; we received
                        // the `name` and `input` indirectly via the
                        // ToolUseBegin event's `call`. Cache them
                        // in working state instead — for now,
                        // record minimal metadata.
                        session.messages.push(ChatMessage::ToolUse {
                            id: id.clone(),
                            name: tool_name_for(&result),
                            input: serde_json::Value::Null,
                            output: output.clone(),
                            is_error,
                        });
                    }
                }
                let _ = app.emit(
                    &topic_tool_end,
                    ToolUseEndPayload {
                        id,
                        output,
                        is_error,
                    },
                );
            }
            AgentLoopEvent::IterationComplete {
                iteration,
                cumulative_usage,
            } => {
                let _ = app.emit(
                    &topic_iteration,
                    IterationPayload {
                        iteration,
                        cumulative_usage: cumulative_usage.into(),
                    },
                );
            }
            AgentLoopEvent::Completed {
                final_usage,
                stop_reason,
            } => {
                // Surface provider errors on the dedicated topic so
                // the chat panel can style them as failures even
                // though the loop technically reached `Completed`.
                if let StopReason::ProviderError(msg) = &stop_reason {
                    inner.factory.on_provider_error(msg).await;
                    let _ = app.emit(
                        &topic_error,
                        ErrorPayload {
                            message: user_facing_provider_error(msg),
                            kind: provider_error_kind(msg),
                        },
                    );
                }
                // Append any final assistant prose accumulated this
                // run. On a Checkpoint the loop records NO synthetic
                // message — the frontend renders a one-click Continue
                // from `stop_reason`; StreamTimeout and other reasons
                // are surfaced via `stop_reason` too, not thread text.
                if !accumulated_text.is_empty() {
                    let mut guard = inner.sessions.lock().await;
                    if let Some(session) = guard.get_mut(&chat_id) {
                        session.messages.push(ChatMessage::Assistant {
                            text: std::mem::take(&mut accumulated_text),
                        });
                        session.in_flight = None;
                    } else {
                        warn!(chat_id, "chat session vanished before completion");
                    }
                } else {
                    let mut guard = inner.sessions.lock().await;
                    if let Some(session) = guard.get_mut(&chat_id) {
                        session.in_flight = None;
                    }
                }
                let rounds = match &stop_reason {
                    StopReason::Checkpoint { rounds, .. } => *rounds,
                    _ => 0,
                };
                // Emit BEFORE the persist: the completed event is what
                // re-enables the composer, and the persist ends in an
                // fsync — the user shouldn't wait on disk for the
                // spinner to stop (review finding).
                let _ = app.emit(
                    &topic_completed,
                    CompletedPayload {
                        usage: final_usage.into(),
                        stop_reason: stop_reason_str(&stop_reason),
                        rounds,
                    },
                );
                // v6.3.0 write-through: the turn boundary is THE persist
                // point (provider errors arrive here too, as
                // `Completed{ProviderError}` — there is no separate error
                // arm).
                persist_chat_now(&inner, &chat_id).await;
                info!(chat_id, ?stop_reason, "agent loop complete");
                return;
            }
        }
    }
    // Stream ended without a Completed event — should not happen
    // (the loop always emits one) but guard against runtime panics.
    warn!(chat_id, "agent loop stream ended without Completed");
    clear_in_flight(&inner, &chat_id).await;
    // v6.3.0 — the fallthrough is a turn boundary too.
    persist_chat_now(&inner, &chat_id).await;
}

/// v6.3.0 write-through persistence hook (opt-in — resolves the
/// `[agent_chat]` feature PER CALL, so toggling it applies immediately).
/// Snapshots `(model, messages)` UNDER the sessions mutex and does the
/// file IO strictly AFTER dropping it — drive_loop and chat_send_message
/// contend on that lock — and on a `spawn_blocking` worker, because the
/// write is synchronous fs IO ending in an fsync: awaited inline it would
/// park an async worker, and `chat_cancel` awaits this (blocking Stop on
/// a hung network mount is the worst possible place to stall). Failures
/// are logged facts, never fatal: a full disk must not kill a live turn.
///
/// ⚠️ Destroy/persist race (review finding): this write runs outside any
/// lock, so `chat_destroy`'s remove+delete can interleave BETWEEN the
/// snapshot and the rename — recreating the file of a chat the user just
/// closed. The post-write re-check below makes both orderings converge on
/// "no file": if the session is gone by the time the write landed, the
/// file is deleted again here.
async fn persist_chat_now(inner: &Arc<ChatStateInner>, chat_id: &str) {
    let feature = match crate::commands::resolve_chat_history() {
        Ok(f) if f.enabled => f,
        Ok(_) => return,
        Err(e) => {
            warn!(chat_id, error = %e, "chat history misconfigured; write skipped");
            return;
        }
    };
    let snapshot = {
        let guard = inner.sessions.lock().await;
        guard
            .get(chat_id)
            .map(|s| (s.model.clone(), s.messages.clone()))
    };
    let Some((model, messages)) = snapshot else {
        return;
    };
    let dir = feature.dir.clone();
    let id = chat_id.to_string();
    let write = tokio::task::spawn_blocking(move || {
        crate::chat_history::persist_chat(&dir, &id, &model, messages)
    })
    .await;
    match write {
        Ok(Err(e)) => warn!(chat_id, error = %e, "chat history write failed"),
        Err(e) => warn!(chat_id, error = %e, "chat history write task failed"),
        Ok(Ok(())) => {
            // Post-write existence re-check (the race note above).
            let still_live = inner.sessions.lock().await.contains_key(chat_id);
            if !still_live {
                if let Err(e) = crate::chat_history::delete_chat(&feature.dir, chat_id) {
                    warn!(chat_id, error = %e, "post-destroy history cleanup failed");
                }
            }
        }
    }
}

fn stop_reason_str(s: &StopReason) -> &'static str {
    match s {
        StopReason::EndTurn => "end_turn",
        StopReason::Checkpoint { .. } => "checkpoint",
        StopReason::StreamTimeout => "stream_timeout",
        StopReason::UserAborted => "user_aborted",
        StopReason::ProviderError(_) => "provider_error",
    }
}

/// Map a raw provider-error string to concise user-facing copy.
///
/// The typed variants live in `transit_agent::llm::LlmError`, but by
/// the time the agent loop hands us a stop reason it has already been
/// flattened to a `StopReason::ProviderError(String)` — so we key off
/// the stable markers each variant's Display embeds (pinned by
/// `transit_agent::llm::tests::provider_error_displays_embed_stable_markers`).
/// Unknown messages pass through unchanged. NO dollar amounts ever.
fn user_facing_provider_error(raw: &str) -> String {
    if raw.contains("missing_provider_key") {
        return "No API key for this model's provider — add one in Settings → API keys, or \
                pick a local model."
            .into();
    }
    if raw.contains("provider_key_rejected") {
        return "The provider rejected your API key — check it in Settings → API keys.".into();
    }
    if raw.contains("rate_limit_exceeded") {
        return "Rate limited by the provider — retrying in a moment is usually enough.".into();
    }
    if raw.contains("provider_overloaded") {
        return "The provider is overloaded right now — resend to continue.".into();
    }
    if raw.contains("plan_cap_reached") {
        return "Your ChatGPT plan's usage limit for this app is reached — raise the weekly cap \
                in ChatGPT's settings, wait for it to reset, or switch the OpenAI method to an \
                API key in Settings → AI providers."
            .into();
    }
    if raw.contains("plan_not_eligible") {
        return "This ChatGPT account can't use its plan here (OpenAI reports it as ineligible). \
                Switch the OpenAI method to an API key in Settings → AI providers."
            .into();
    }
    if raw.contains("plan_reauth_required") {
        return "Your ChatGPT sign-in has expired — sign in again in Settings → AI providers."
            .into();
    }
    if raw.contains("plan_unsupported_capability") {
        return "The ChatGPT plan path rejected this request — try again, or switch the OpenAI \
                method to an API key in Settings → AI providers."
            .into();
    }
    if raw.contains("tls_trust") {
        return "The provider's TLS certificate isn't trusted on this network. If you are \
                behind a TLS-inspection proxy, install its CA in the OS trust store or \
                turn Strict TLS off in Settings → Network."
            .into();
    }
    // BYOM local-model errors arrive already user-shaped from
    // transit_agent (LocalProvider copy); only the context-budget
    // pair gets a next-step remap here.
    if raw.contains("context window exceeded") || raw.contains("context truncation detected") {
        return "This conversation no longer fits the local model's context window. Start a \
                new chat, or raise the context size in Settings → Local models."
            .into();
    }
    raw.to_owned()
}

/// Stable discriminator for a provider error so the frontend can route
/// UX without string-matching the human copy (a `missing_provider_key`
/// gets a Settings deep-link, a `provider_overloaded` an informational
/// toast). Keys off the same markers as `user_facing_provider_error`.
fn provider_error_kind(raw: &str) -> &'static str {
    if raw.contains("missing_provider_key") {
        "missing_provider_key"
    } else if raw.contains("provider_key_rejected") {
        "provider_key_rejected"
    } else if raw.contains("rate_limit_exceeded") {
        "rate_limited"
    } else if raw.contains("provider_overloaded") {
        "provider_overloaded"
    } else if raw.contains("plan_cap_reached") {
        "plan_cap_reached"
    } else if raw.contains("plan_not_eligible") {
        "plan_not_eligible"
    } else if raw.contains("plan_reauth_required") {
        "plan_reauth_required"
    } else if raw.contains("plan_unsupported_capability") {
        "plan_unsupported_capability"
    } else if raw.contains("tls_trust") {
        "tls_trust"
    } else if raw.contains("context window exceeded") || raw.contains("context truncation detected")
    {
        "local_context_overflow"
    } else if raw.contains("cannot reach Ollama") || raw.contains("cannot reach the endpoint") {
        "local_unreachable"
    } else {
        "other"
    }
}

fn tool_name_for(result: &Result<transit_agent::ToolResult, String>) -> String {
    use transit_agent::ToolResult as TR;
    match result {
        Ok(TR::ListOpenSessions(_)) => "list_open_sessions".into(),
        Ok(TR::ReadScrollback(_)) => "read_scrollback".into(),
        Ok(TR::ProposeCommand(_)) => "propose_command".into(),
        Ok(TR::AskUser(_)) => "ask_user".into(),
        Ok(TR::ProposeApiCall(_)) => "propose_api_call".into(),
        Ok(TR::QueryCapture(_)) => "query_capture".into(),
        Err(_) => "(error)".into(),
    }
}

async fn clear_in_flight(inner: &Arc<ChatStateInner>, chat_id: &str) {
    let mut guard = inner.sessions.lock().await;
    if let Some(session) = guard.get_mut(chat_id) {
        session.in_flight = None;
    }
}

// ---------------------------------------------------------------------
// Wire payloads
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct DeltaPayload {
    delta: String,
}

#[derive(Debug, Clone, Serialize)]
struct CompletedPayload {
    usage: ChatUsageWire,
    /// One of `end_turn` | `checkpoint` | `stream_timeout` |
    /// `user_aborted` | `provider_error`. The frontend keys its
    /// one-click Continue affordance off `checkpoint`.
    stop_reason: &'static str,
    /// Tool-rounds completed this run. Meaningful only when
    /// `stop_reason == "checkpoint"` (the Continue card labels itself
    /// with it); 0 otherwise. NO dollar/cost field is ever sent —
    /// spend stays internal to the loop.
    rounds: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorPayload {
    message: String,
    /// Stable error-kind discriminator (`missing_provider_key`, `rate_limited`,
    /// `rate_limited`, `model_not_allowed`, `other`) so the frontend
    /// routes UX without matching the human copy.
    kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ToolUseBeginPayload {
    id: String,
    /// Serialized `ToolCall` — `{tool: "<name>", ...input fields}`.
    call: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct ToolUseEndPayload {
    id: String,
    output: String,
    is_error: bool,
}

#[derive(Debug, Clone, Serialize)]
struct IterationPayload {
    iteration: u32,
    cumulative_usage: ChatUsageWire,
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Factory used by the no-op tests below — never actually
    /// vended because the tests don't drive a chat turn (that's
    /// `agent_loop::tests`'s job). Exists so `ChatState` is
    /// constructable.
    struct NopFactory;
    #[async_trait::async_trait]
    impl LlmClientFactory for NopFactory {
        async fn build(&self, _model: &str) -> Box<dyn LlmClient> {
            unreachable!("NopFactory must not vend a client in these tests")
        }
    }

    fn fresh_state() -> ChatState {
        ChatState::with_factory(Box::new(NopFactory))
    }

    fn fresh_session(model: &str) -> ChatSession {
        ChatSession {
            messages: Vec::new(),
            model: model.into(),
            saved_at_hint: 0,
            in_flight: None,
            cancel: Arc::new(Notify::new()),
            always_allow: new_always_allow_map(),
            scope: SharedScope::new_unscoped(),
            auto_approve_api_gets: new_auto_approve_api_gets(),
            ledger: SessionLedger::new(),
        }
    }

    /// v6.3.0 — the restore loader rebuilds sessions with restored
    /// messages/model and FACTORY-FRESH security state: unscoped scope,
    /// empty always-allow map, auto-approve off. The history file cannot
    /// even represent those fields; this pins the constructor side.
    #[tokio::test]
    async fn restore_inserts_sessions_with_fresh_security_state() {
        let state = fresh_state();
        let restored = vec![crate::chat_history::RestoredChat {
            chat_id: Uuid::new_v4().to_string(),
            model: "claude-opus-4-7".into(),
            saved_at: 42,
            messages: vec![ChatMessage::User { text: "hi".into() }],
        }];
        let id = restored[0].chat_id.clone();
        {
            let mut guard = state.inner.sessions.lock().await;
            ChatStateInner::restore_sessions(&mut guard, restored);
        }
        let guard = state.inner.sessions.lock().await;
        let s = guard.get(&id).expect("restored session inserted");
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.model, "claude-opus-4-7");
        assert_eq!(s.saved_at_hint, 42);
        assert!(s.in_flight.is_none());
        // Unscoped = every device id is allowed.
        assert!(s.scope.allows("any-device"), "restored chat is unscoped");
        assert!(
            s.always_allow.lock().unwrap().is_empty(),
            "restored chat has an EMPTY always-allow map"
        );
        assert!(
            !s.auto_approve_api_gets.is_enabled(),
            "restored chat has auto-approve OFF"
        );
    }

    #[tokio::test]
    async fn restore_skips_ids_already_in_the_map() {
        let state = fresh_state();
        let id = Uuid::new_v4().to_string();
        {
            let mut guard = state.inner.sessions.lock().await;
            let mut live = fresh_session("live-model");
            live.messages.push(ChatMessage::User {
                text: "live".into(),
            });
            guard.insert(id.clone(), live);
            ChatStateInner::restore_sessions(
                &mut guard,
                vec![crate::chat_history::RestoredChat {
                    chat_id: id.clone(),
                    model: "stale-model".into(),
                    saved_at: 1,
                    messages: vec![ChatMessage::User {
                        text: "stale".into(),
                    }],
                }],
            );
        }
        let guard = state.inner.sessions.lock().await;
        let s = guard.get(&id).unwrap();
        assert_eq!(s.model, "live-model", "a live session is never clobbered");
        assert!(matches!(&s.messages[0], ChatMessage::User { text } if text == "live"));
    }

    #[test]
    fn list_entries_orders_by_saved_at_then_id() {
        let mut sessions: HashMap<String, ChatSession> = HashMap::new();
        // Two ties at hint=5 (created in the same second) + one newer chat.
        // The id tie-break makes tab order identical across launches even
        // though HashMap iteration order is not.
        let mut a = fresh_session("m");
        a.saved_at_hint = 5;
        let mut b = fresh_session("m");
        b.saved_at_hint = 5;
        let mut c = fresh_session("m");
        c.saved_at_hint = 9;
        sessions.insert("bbbb".into(), b);
        sessions.insert("aaaa".into(), a);
        sessions.insert("cccc".into(), c);
        let ids: Vec<String> = list_entries(&sessions)
            .into_iter()
            .map(|e| e.chat_id)
            .collect();
        assert_eq!(ids, vec!["aaaa", "bbbb", "cccc"]);
    }

    #[tokio::test]
    async fn create_inserts_session_and_destroy_clears_it() {
        let state = fresh_state();
        let id = Uuid::new_v4().to_string();
        state
            .inner
            .sessions
            .lock()
            .await
            .insert(id.clone(), fresh_session("claude-sonnet-4-6"));
        assert!(state.inner.sessions.lock().await.contains_key(&id));

        // Manual destroy — chat_destroy needs an Arc<ChatState> via
        // tauri::State which we can't fabricate in a unit test.
        state.inner.sessions.lock().await.remove(&id);
        assert!(!state.inner.sessions.lock().await.contains_key(&id));
    }

    #[tokio::test]
    async fn cancel_notify_is_distinct_per_session() {
        // Notifying one session's cancel must not leak across to
        // another concurrent chat — the AgentLoop's drive() polls
        // its own Arc<Notify>, so cross-talk would abort the
        // wrong loop.
        let state = fresh_state();
        let id_a = Uuid::new_v4().to_string();
        let id_b = Uuid::new_v4().to_string();
        let mut g = state.inner.sessions.lock().await;
        g.insert(id_a.clone(), fresh_session("a"));
        g.insert(id_b.clone(), fresh_session("b"));
        let cancel_a = Arc::clone(&g.get(&id_a).unwrap().cancel);
        let cancel_b = Arc::clone(&g.get(&id_b).unwrap().cancel);
        drop(g);
        // Notify A; B's notified() should still pend.
        cancel_a.notify_one();
        let b_pending =
            tokio::time::timeout(std::time::Duration::from_millis(20), cancel_b.notified()).await;
        assert!(b_pending.is_err(), "B's cancel must not have fired");
    }

    #[tokio::test]
    async fn direct_factory_builds_a_client_for_every_model_shape() {
        // We can't downcast the returned Box<dyn LlmClient>, so this is
        // a smoke test: build() must not panic for representative ids
        // whether or not a key is enrolled on this machine (no key →
        // the MissingKey shim, never a panic).
        let f = DirectClientFactory {
            chatgpt: Arc::new(crate::chatgpt_auth::ChatGptState::new()),
        };
        let _claude = f.build("claude-opus-4-7").await;
        let _gpt = f.build("gpt-5.6-sol").await;
        let _o1 = f.build("o1-preview").await;
    }

    #[tokio::test]
    async fn missing_key_client_fails_with_the_typed_marker() {
        let c = MissingKeyClient {
            provider: "Anthropic",
        };
        let req = transit_agent::llm::LlmRequest {
            model: "claude-x".into(),
            system: None,
            messages: vec![],
            max_tokens: None,
            tools: None,
        };
        let err = c.messages(req).await.err().expect("must fail");
        assert!(err.to_string().contains("missing_provider_key"), "{err}");
    }

    #[test]
    fn chat_usage_wire_round_trips_token_usage() {
        let u = TokenUsage {
            input_uncached: 12,
            input_cache_write: 0,
            input_cache_read: 8,
            output: 4,
        };
        let w: ChatUsageWire = u.into();
        assert_eq!(w.input_uncached, 12);
        assert_eq!(w.input_cache_read, 8);
        assert_eq!(w.output, 4);
    }

    #[test]
    fn stop_reason_str_maps_checkpoint_and_stream_timeout() {
        assert_eq!(stop_reason_str(&StopReason::EndTurn), "end_turn");
        assert_eq!(
            stop_reason_str(&StopReason::Checkpoint {
                rounds: 50,
                cost_microdollars: 5_000_000,
            }),
            "checkpoint"
        );
        assert_eq!(
            stop_reason_str(&StopReason::StreamTimeout),
            "stream_timeout"
        );
        assert_eq!(stop_reason_str(&StopReason::UserAborted), "user_aborted");
        assert_eq!(
            stop_reason_str(&StopReason::ProviderError("x".into())),
            "provider_error"
        );
    }

    #[test]
    fn provider_error_mapping_yields_user_facing_copy() {
        // Inputs mirror the Display strings of the corresponding
        // transit_agent::llm::LlmError variants.
        let mapped =
            user_facing_provider_error("no Anthropic API key configured (missing_provider_key)");
        assert!(mapped.contains("Settings → API keys"), "{mapped}");
        let mapped =
            user_facing_provider_error("OpenAI rejected the API key (provider_key_rejected)");
        assert!(mapped.contains("rejected your API key"), "{mapped}");
        assert_eq!(
            user_facing_provider_error("OpenAI rate limit hit (rate_limit_exceeded)"),
            "Rate limited by the provider — retrying in a moment is usually enough."
        );
        assert_eq!(
            user_facing_provider_error("Anthropic is overloaded (provider_overloaded)"),
            "The provider is overloaded right now — resend to continue."
        );
        let mapped = user_facing_provider_error("TLS certificate not trusted (tls_trust)");
        assert!(mapped.contains("Strict TLS"), "{mapped}");
    }

    #[test]
    fn provider_error_mapping_passes_unknown_messages_through() {
        let raw = "HTTP transport error: connection reset by peer";
        assert_eq!(user_facing_provider_error(raw), raw);
    }

    #[test]
    fn provider_error_kind_discriminates_known_codes() {
        assert_eq!(
            provider_error_kind("no Anthropic API key configured (missing_provider_key)"),
            "missing_provider_key"
        );
        assert_eq!(
            provider_error_kind("OpenAI rejected the API key (provider_key_rejected)"),
            "provider_key_rejected"
        );
        assert_eq!(
            provider_error_kind("OpenAI rate limit hit (rate_limit_exceeded)"),
            "rate_limited"
        );
        assert_eq!(
            provider_error_kind("Anthropic is overloaded (provider_overloaded)"),
            "provider_overloaded"
        );
        assert_eq!(
            provider_error_kind("TLS certificate not trusted (tls_trust)"),
            "tls_trust"
        );
        assert_eq!(
            provider_error_kind("ChatGPT plan usage limit reached for this app (plan_cap_reached)"),
            "plan_cap_reached"
        );
        assert_eq!(
            provider_error_kind(
                "ChatGPT sign-in has expired — sign in again (plan_reauth_required)"
            ),
            "plan_reauth_required"
        );
        assert_eq!(provider_error_kind("HTTP transport error: boom"), "other");
    }

    #[test]
    fn provider_error_mapped_copy_never_contains_dollar_amounts() {
        // Product rule: the desktop UI never shows a $/cost
        // figure. The mapped strings are fixed copy — pin it.
        for marker in [
            "missing_provider_key",
            "provider_key_rejected",
            "rate_limit_exceeded",
            "provider_overloaded",
            "tls_trust",
            "plan_cap_reached",
            "plan_not_eligible",
            "plan_reauth_required",
            "plan_unsupported_capability",
        ] {
            assert!(
                !user_facing_provider_error(marker).contains('$'),
                "mapped copy for {marker} must not mention dollars"
            );
        }
    }

    #[test]
    fn completed_payload_carries_rounds_but_never_a_cost_field() {
        // The wire payload exposes `rounds` (for the Continue card) but
        // NEVER a dollar/cost field — spend stays internal to the loop.
        let p = CompletedPayload {
            usage: TokenUsage::default().into(),
            stop_reason: "checkpoint",
            rounds: 42,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"rounds\":42"));
        assert!(
            !json.contains("cost") && !json.contains("microdollar") && !json.contains("dollar"),
            "no spend field may appear on the wire: {json}"
        );
    }

    #[test]
    fn byom_send_gate_is_the_enabled_switch_only() {
        assert!(ensure_local_send_allowed(true).is_ok());
        let err = ensure_local_send_allowed(false).unwrap_err();
        assert!(err.contains("turned off"), "{err}");
        assert!(!err.contains('$'), "no dollars in gate copy: {err}");
    }

    #[test]
    fn local_error_copy_and_kinds_route_cleanly() {
        for raw in [
            "local model error: context window exceeded: conversation ≈9000 tokens does not fit the local model window of 4096",
            "local model error: context truncation detected: the local model evaluated 4000 tokens of a 4096-token window",
        ] {
            let mapped = user_facing_provider_error(raw);
            assert!(mapped.contains("Settings → Local models"), "{mapped}");
            assert_eq!(provider_error_kind(raw), "local_context_overflow");
        }
        let unreachable = "local model error: cannot reach Ollama at http://127.0.0.1:11434 — is `ollama serve` running?";
        assert_eq!(provider_error_kind(unreachable), "local_unreachable");
        // Already user-shaped — passes through unchanged.
        assert_eq!(user_facing_provider_error(unreachable), unreachable);
    }
}
