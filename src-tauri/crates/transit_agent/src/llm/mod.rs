//! `LlmClient` — typed boundary between the agent loop and the
//! underlying provider.
//!
//! Four production impls:
//!   - [`DirectAnthropic`] — POSTs to Anthropic's `/v1/messages` with the
//!     user's own key (`direct.rs`).
//!   - [`DirectOpenAI`]    — POSTs to OpenAI's `/v1/responses` with the
//!     user's own key (`direct.rs`).
//!   - [`OllamaClient`] — the local-model path; POSTs to a loopback
//!     Ollama `/api/chat` directly. No credentials of any kind (see
//!     `ollama.rs` module docs + threat-model T33–T35).
//!   - [`OpenAiCompatClient`] — user-configured OpenAI-compatible
//!     endpoints (vLLM, LM Studio, a self-hosted gateway).
//!
//! Every client talks ONLY to the host the user configured (or, for the
//! two direct clients, the one provider host each is hard-wired to).
//! There is no intermediary. Keys are handed in as `SecretString` by the
//! Tauri shell, which is the only crate that can read the keychain — this
//! crate cannot (`deny.toml` bans `keyring` here).
//!
//! ## Tool use (Phase 6)
//!
//! `LlmRequest::tools` advertises the four-tool surface to the model.
//! `None` keeps tool-use disabled — the non-agentic chat path still
//! works unchanged. When set, providers can emit tool_use blocks; the
//! parsers buffer per-index partial JSON and surface a single
//! [`LlmStreamEvent::ToolUseComplete`] when the JSON parses cleanly
//! (Decision D3 in the phase 6 plan design notes (not included in this repository) — partial JSON
//! never crosses the trait surface).

pub mod anthropic;
pub mod direct;
pub mod ollama;
pub mod openai;
pub mod openai_compat;
pub mod transport;

pub use direct::{DirectAnthropic, DirectOpenAI, ModelLevel, OpenAiAuth, ProviderModel};
pub use ollama::{
    is_local_model, parse_endpoint_model, wire_model_name, OllamaClient, OllamaConfig,
};
pub use openai_compat::{OpenAiCompatClient, OpenAiCompatConfig};
pub use transport::{endpoint_http_client, loopback_violation, transport_violation};

use futures::stream::BoxStream;
use thiserror::Error;

use crate::usage::TokenUsage;

/// One turn of input to the LLM.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub model: String,
    /// Optional system prompt. Anthropic sends as a top-level
    /// `system` field (string OR content-block array, the latter
    /// carrying per-section `cache_control` markers); OpenAI sends
    /// as the first `messages[]` entry with `role: "system"`,
    /// content flattened to a single string.
    pub system: Option<SystemPromptInput>,
    pub messages: Vec<LlmMessage>,
    /// Hard cap on assistant-emitted tokens for this turn. Anthropic
    /// requires this; OpenAI treats it as optional. The impls default
    /// Anthropic to 4096 if unset.
    pub max_tokens: Option<u32>,
    /// Tool surface advertised to the model. Phase 6 default for the
    /// agent loop is `Some(standard_tool_schemas())`; the
    /// non-agentic chat path passes `None` so the request body omits
    /// the `tools` field entirely (preserving 5d.A5 behavior).
    pub tools: Option<Vec<ToolSchema>>,
}

/// System prompt shape handed to an `LlmClient`. Two variants:
///
/// - **`Plain`** — a single text body. Used by the non-agentic chat
///   path and by tests that don't care about prompt caching.
/// - **`Sections`** — ordered sections with per-section
///   `cache_after` hints. The agent loop builds this from
///   [`crate::system_prompt::SystemPrompt`] so the Anthropic client
///   can emit `cache_control: ephemeral` markers at the canonical
///   layout's three breakpoints (CLAUDE.md §18). OpenAI flattens
///   `Sections` to the same string `Plain` would carry — there's no
///   equivalent breakpoint primitive in chat-completions.
///
/// `From<&str>` / `From<String>` impls let test sites continue to
/// write `Some("text".into())`; the variant lands as `Plain`.
#[derive(Debug, Clone)]
pub enum SystemPromptInput {
    Plain(String),
    Sections(Vec<SystemSection>),
}

#[derive(Debug, Clone)]
pub struct SystemSection {
    pub text: String,
    /// Anthropic-only hint: emit a `cache_control: { type: "ephemeral" }`
    /// annotation on the corresponding text block so the prefix up
    /// through here is cacheable. OpenAI ignores this; its
    /// auto-detection just looks at the longest matching prefix.
    pub cache_after: bool,
}

impl SystemPromptInput {
    /// Flatten any variant to a single string. The result is
    /// byte-identical to [`crate::system_prompt::SystemPrompt::render`]
    /// when the input was built from a `SystemPrompt`, so OpenAI's
    /// auto-cache prefix matching is preserved across the type
    /// change.
    pub fn as_plain_text(&self) -> String {
        match self {
            Self::Plain(s) => s.clone(),
            Self::Sections(secs) => {
                let mut out = String::new();
                for s in secs {
                    out.push_str(&s.text);
                    if !s.text.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push('\n');
                }
                out
            }
        }
    }
}

impl From<String> for SystemPromptInput {
    fn from(s: String) -> Self {
        Self::Plain(s)
    }
}
impl From<&str> for SystemPromptInput {
    fn from(s: &str) -> Self {
        Self::Plain(s.to_string())
    }
}

/// JSON-Schema-shaped tool descriptor handed to the model. Mirrors
/// Anthropic's tool-shape exactly (the OpenAI translator wraps this
/// in `{"type":"function","function":{...}}` at body-build time).
/// `input_schema` is a JSON Schema describing the corresponding
/// `*Input` struct for the agent's `ToolCall` variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Tool-use block emitted by the model. Always paired with a
/// follow-up [`LlmMessage::ToolResult`] in the next user turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUseBlock {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// Chronological chat-history entry. The non-agentic chat path uses
/// `User` / `Assistant` only; the Phase 6 agent loop appends
/// `AssistantWithTools` + `ToolResult` pairs as the iteration
/// progresses.
#[derive(Debug, Clone)]
pub enum LlmMessage {
    User(String),
    Assistant(String),
    /// Assistant turn that contained one or more `tool_use` blocks.
    /// `text` is any prose the model emitted alongside the tools
    /// (often empty for tool-only turns).
    AssistantWithTools {
        text: Option<String>,
        tool_uses: Vec<ToolUseBlock>,
    },
    /// Tool result feeding back to the model. `is_error` is set when
    /// the dispatcher returned an `AgentError` — the provider treats
    /// the content as a normal observation either way; the flag just
    /// surfaces "this was an error" to the model.
    ///
    /// On Anthropic, consecutive `ToolResult`s and any adjacent
    /// `User` text are folded into a single user-role turn with a
    /// content array (the API requires strict role alternation).
    /// On OpenAI, each `ToolResult` becomes its own `role: "tool"`
    /// message.
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// Streaming events produced by [`LlmClient::messages`]. Every
/// successful stream MUST end with exactly one `Completed(...)`
/// before closing — callers rely on this to know when usage
/// accounting is final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmStreamEvent {
    /// A chunk of assistant-emitted text. Concatenate in order to
    /// form the assistant turn.
    TextDelta(String),
    /// Tool-use block fully assembled — JSON parsed cleanly. The
    /// agent loop dispatches it directly. Partial JSON is buffered
    /// inside the parser so consumers never see it (Decision D3).
    ToolUseComplete {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Terminal event — the provider has reported its final usage
    /// numbers and the stream is about to close.
    Completed(TokenUsage),
}

/// Errors surfaced by `LlmClient::messages` and the returned stream.
///
/// The provider-facing variants embed a STABLE marker in their `Display`
/// (`missing_provider_key`, `provider_key_rejected`, `rate_limit_exceeded`,
/// `provider_overloaded`, `tls_trust`): the agent loop flattens errors to
/// a string before the Tauri shell sees them, and the shell's chat module
/// string-matches these markers to pick user copy + UX routing. Keep them
/// verbatim (pinned by `tests::provider_error_displays_embed_stable_markers`).
/// `Malformed` indicates a provider SSE regression worth surfacing as a
/// bug; `EarlyEnd` is a safety net for the "stream closed before usage
/// chunk" case.
#[derive(Debug, Error)]
pub enum LlmError {
    /// Underlying HTTP transport failure (DNS, connect, IO) on a direct
    /// provider call.
    #[error("HTTP transport error: {0}")]
    Http(reqwest::Error),
    /// The provider's TLS certificate failed validation — almost always a
    /// TLS-inspection proxy on the network whose CA we don't trust.
    /// Either Strict TLS is ON (deliberately refusing the inspection CA)
    /// or the corporate CA isn't in the OS trust store. See T27.
    #[error("TLS certificate not trusted (tls_trust)")]
    TlsTrust,
    /// No API key is enrolled for the provider this model routes to.
    #[error("no {provider} API key configured (missing_provider_key)")]
    MissingKey { provider: &'static str },
    /// 401/403 from the provider: the enrolled key is wrong or revoked.
    #[error("{provider} rejected the API key (provider_key_rejected)")]
    KeyRejected { provider: &'static str },
    /// 429 from the provider.
    #[error("{provider} rate limit hit (rate_limit_exceeded)")]
    RateLimited { provider: &'static str },
    /// 502/503/529 from the provider — transient; retry shortly.
    #[error("{provider} is overloaded (provider_overloaded)")]
    Overloaded { provider: &'static str },
    /// ChatGPT plan: the per-app or account usage cap is reached
    /// (`subscription_sharing_usage_limit_exceeded`). The user raises it
    /// in ChatGPT's settings; the app must not retry.
    #[error("ChatGPT plan usage limit reached for this app (plan_cap_reached)")]
    PlanCapReached,
    /// ChatGPT plan: this user / workspace / policy cannot share plan usage
    /// (`subscription_sharing_user_not_eligible`). Not an auth problem —
    /// re-running sign-in will not help.
    #[error("this ChatGPT account cannot use its plan here (plan_not_eligible)")]
    PlanNotEligible,
    /// ChatGPT plan: the grant is gone — consent revoked, refresh token
    /// expired/reused, or the subscriber context failed validation. The
    /// user signs in again.
    #[error("ChatGPT sign-in has expired — sign in again (plan_reauth_required)")]
    PlanReauthRequired,
    /// ChatGPT plan: the request used something the plan path doesn't
    /// support (`subscription_sharing_unsupported_capability`).
    #[error(
        "the ChatGPT plan path rejected this request: {message} (plan_unsupported_capability)"
    )]
    PlanUnsupported { message: String },
    /// Any other non-2xx. `message` is the provider's sanitized
    /// `error.message` (≤200 chars, control chars stripped).
    #[error("{provider} returned status {status}: {message}")]
    Status {
        provider: &'static str,
        status: u16,
        message: String,
    },
    #[error("provider returned malformed SSE: {0}")]
    Malformed(String),
    #[error("stream ended before a Completed event")]
    EarlyEnd,
    /// Local-endpoint (BYOM) failure — connection refused, non-2xx,
    /// a server-reported error line, or detected context truncation.
    /// The message is user-shaped where possible; chat.rs passes the
    /// stable copies through verbatim.
    #[error("local model error: {0}")]
    LocalProvider(String),
    /// The T34 pre-send guard refused the request: the conversation
    /// no longer fits the local model's context window. Refusing
    /// loudly is the defense against Ollama's SILENT truncation,
    /// which can shear the system prompt (injection guard included).
    #[error(
        "context window exceeded: conversation ≈{estimated_tokens} tokens does not fit the \
         local model window of {limit}. Recover context instead of retrying the same read: \
         use read_scrollback with a small max_bytes (or its match parameter) rather than \
         re-reading whole rings, and prefer commands whose output answers the question \
         directly"
    )]
    ContextOverflow { estimated_tokens: usize, limit: u32 },
}

pub type LlmResult<T> = std::result::Result<T, LlmError>;
pub type LlmStream = BoxStream<'static, LlmResult<LlmStreamEvent>>;

#[async_trait::async_trait]
pub trait LlmClient: Send + Sync {
    /// Open a streaming completion. The returned stream yields
    /// `TextDelta`s as the provider emits content, then a single
    /// terminal `Completed(usage)` before closing.
    async fn messages(&self, req: LlmRequest) -> LlmResult<LlmStream>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `transit_app::chat` string-matches these markers after the agent
    /// loop flattens the error — a renamed marker silently downgrades a
    /// routed error to the generic "other" path.
    #[test]
    fn provider_error_displays_embed_stable_markers() {
        assert!(LlmError::TlsTrust.to_string().contains("tls_trust"));
        assert!(LlmError::MissingKey {
            provider: "Anthropic"
        }
        .to_string()
        .contains("missing_provider_key"));
        assert!(LlmError::KeyRejected { provider: "OpenAI" }
            .to_string()
            .contains("provider_key_rejected"));
        assert!(LlmError::RateLimited { provider: "OpenAI" }
            .to_string()
            .contains("rate_limit_exceeded"));
        assert!(LlmError::Overloaded {
            provider: "Anthropic"
        }
        .to_string()
        .contains("provider_overloaded"));
        assert!(LlmError::PlanCapReached
            .to_string()
            .contains("plan_cap_reached"));
        assert!(LlmError::PlanNotEligible
            .to_string()
            .contains("plan_not_eligible"));
        assert!(LlmError::PlanReauthRequired
            .to_string()
            .contains("plan_reauth_required"));
        assert!(LlmError::PlanUnsupported {
            message: "x".into()
        }
        .to_string()
        .contains("plan_unsupported_capability"));
    }
}
