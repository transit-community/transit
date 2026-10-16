//! Ollama native `/api/chat` impl of [`crate::llm::LlmClient`] — the
//! BYOM local-model path (the byom local models design notes (not included in this repository)).
//!
//! Unlike the cloud impls this client talks to a **user-local**
//! endpoint and carries **no credential of any kind** — no Transit
//! token, no provider key of any kind. transit_agent's firewall
//! posture (no transit_auth, no keyring) is unchanged.
//!
//! Load-bearing invariants (threat-model T32–T35):
//!
//! - **Transport rules live in [`super::transport`].** The zero-config
//!   path ([`OllamaClient::new`] / [`probe`]) is loopback-pinned; a
//!   custom remote-Ollama endpoint ([`OllamaClient::for_endpoint`] /
//!   [`probe_with`]) follows the custom-endpoint rules instead (plain
//!   http loopback-only; https + OS-store trust elsewhere). Both are
//!   re-checked per request — defense in depth over the config layer.
//! - **No proxy, no redirects.** reqwest honors `HTTP_PROXY` by
//!   default and follows up to 10 redirects; either would let
//!   "local" conversation bytes transit another host. Pinned by the
//!   wiremock redirect test.
//! - **Context budget (T34).** Ollama silently truncates a prompt
//!   that exceeds `num_ctx` — the runner layer can shear the SYSTEM
//!   prompt (injection guard included). The **pre-send estimate** in
//!   `messages()` is the primary defense (it runs every round on the
//!   full already-redacted payload); the `prompt_eval_count` check at
//!   `done:true` is best-effort backup only — KV prefix caching makes
//!   it under-report on later rounds.
//! - **`:cloud` tags are not local (T33).** Cloud-tagged models proxy
//!   through ollama.com; `probe()` never lists them as selectable.
//!
//! Wire format: `/api/chat` streams **NDJSON** (one JSON object per
//! line), not SSE — `ndjson_lines` does the buffered line split;
//! `eventsource-stream` does not apply here.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::Deserialize;
use serde_json::json;

use super::transport;
use crate::llm::{
    LlmClient, LlmError, LlmMessage, LlmRequest, LlmResult, LlmStream, LlmStreamEvent,
};
use crate::usage::TokenUsage;

/// Default local endpoint — Ollama's stock bind.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";
/// Default context window we request. Deliberately larger than
/// Ollama's <24GiB-VRAM default (4096) — correctness over speed; the
/// Settings tab offers smaller values for slow machines.
pub const DEFAULT_NUM_CTX: u32 = 16_384;
/// Default model keep-alive. Longer than Ollama's stock 5m so a
/// user-paced investigation (modal waits included) doesn't pay a
/// cold-reload between rounds.
pub const DEFAULT_KEEP_ALIVE: &str = "15m";

/// `prompt_eval_count` this close to `num_ctx` is treated as evidence
/// of server-side truncation (backup check; see module docs).
const TRUNCATION_EPSILON_TOKENS: u64 = 256;

/// Minimum Ollama version whose `/api/show` reports `capabilities`
/// (so the picker can filter to tools-capable models). Surfaced by
/// the Settings UI when the probe sees an older server.
pub const MIN_SUPPORTED_VERSION: &str = "0.6.4";

/// `true` for model ids the LOCAL path owns. This is the single
/// routing/pricing/bounds predicate — `chat.rs::provider_route`,
/// `usage::pricing_for_model`, and `LoopBounds::for_model` MUST all
/// consult this same function. If routing and pricing ever diverge, a
/// cloud model could bill at zero and run with a dead $5 checkpoint
/// (pinned by `usage::tests::pricing_predicate_matches_local_routing`).
///
/// Two namespaces: `ollama:<model>` (the zero-config loopback Ollama)
/// and `endpoint:<id>/<model>` (custom endpoints — remote Ollama or
/// OpenAI-compat servers).
pub fn is_local_model(model: &str) -> bool {
    model.starts_with("ollama:") || model.starts_with("endpoint:")
}

/// Split an `endpoint:<id>/<model>` id into `(endpoint_id, model)`.
/// `None` for anything else (including a malformed endpoint id with an
/// empty half). The id charset is enforced at the config layer
/// (`[a-z0-9-]`), so `/` and `:` in the MODEL half stay unambiguous.
pub fn parse_endpoint_model(model: &str) -> Option<(&str, &str)> {
    let rest = model.strip_prefix("endpoint:")?;
    let (id, m) = rest.split_once('/')?;
    if id.is_empty() || m.is_empty() {
        return None;
    }
    Some((id, m))
}

/// Strip the BYOM namespace down to the provider-facing model name:
/// `ollama:qwen3:8b` → `qwen3:8b` (first prefix only — Ollama tags
/// contain colons); `endpoint:lab/qwen3:8b` → `qwen3:8b`; anything
/// else passes through unchanged.
pub fn wire_model_name(model: &str) -> &str {
    if let Some(rest) = model.strip_prefix("ollama:") {
        return rest;
    }
    if let Some((_, m)) = parse_endpoint_model(model) {
        return m;
    }
    model
}

/// Plain-data config for [`OllamaClient`]. transit_app resolves this
/// from `transit-config.toml` `[local_models]` and passes it in —
/// this crate never reads config or keychain state itself.
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Loopback-pinned on the zero-config path ([`OllamaClient::new`]);
    /// a remote-Ollama custom endpoint ([`OllamaClient::for_endpoint`])
    /// instead satisfies the custom-endpoint transport rules. Either
    /// way the client re-validates (defense in depth, T35).
    pub base_url: String,
    /// Context window requested via `options.num_ctx` on every call.
    /// Always explicit — Ollama's VRAM-tiered default is 4096 on
    /// <24GiB machines, far too small for the agent prompt.
    pub num_ctx: u32,
    /// `keep_alive` forwarded verbatim (Go duration string).
    pub keep_alive: String,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            num_ctx: DEFAULT_NUM_CTX,
            keep_alive: DEFAULT_KEEP_ALIVE.to_string(),
        }
    }
}

pub struct OllamaClient {
    http: reqwest::Client,
    cfg: OllamaConfig,
    /// `false` on the zero-config path (loopback pin applies); `true`
    /// for a custom remote-Ollama endpoint (the custom-endpoint
    /// transport rules apply instead — https off-loopback).
    remote_allowed: bool,
}

impl OllamaClient {
    /// Zero-config loopback client (the `[local_models]` path).
    pub fn new(cfg: OllamaConfig) -> Self {
        Self {
            http: transport::hardened_client(false, None),
            cfg,
            remote_allowed: false,
        }
    }

    /// Custom-endpoint client (`kind = "ollama"` endpoints, possibly
    /// remote). `http` comes from `transport::endpoint_http_client`
    /// so an https endpoint carries the OS-store trust config; the
    /// caller has already enforced the transport rules on
    /// `cfg.base_url` (re-checked per request here).
    pub fn for_endpoint(http: reqwest::Client, cfg: OllamaConfig) -> Self {
        Self {
            http,
            cfg,
            remote_allowed: true,
        }
    }
}

/// bytes/4 token estimate over everything the request will serialize
/// — the same heuristic as `system_prompt::cached_prefix_estimate_tokens`.
/// Operates on `to_llm_messages()` output, i.e. **already-redacted**
/// text (no ordering hazard with the redact-before-cap rule), and is
/// never logged with content. Under-counts pathological tokenizations
/// (hex dumps, CJK) by up to ~2× — the 10% headroom plus the
/// `prompt_eval_count` backup check absorb that.
pub(crate) fn estimate_request_tokens(req: &LlmRequest) -> usize {
    let mut bytes = 0usize;
    if let Some(s) = &req.system {
        bytes += s.as_plain_text().len();
    }
    for m in &req.messages {
        // Rough per-message framing overhead (role tokens etc.).
        bytes += 16;
        match m {
            LlmMessage::User(t) | LlmMessage::Assistant(t) => bytes += t.len(),
            LlmMessage::AssistantWithTools { text, tool_uses } => {
                bytes += text.as_deref().map_or(0, str::len);
                for tu in tool_uses {
                    bytes += tu.id.len() + tu.name.len();
                    bytes += serde_json::to_string(&tu.input).map_or(0, |s| s.len());
                }
            }
            LlmMessage::ToolResult {
                tool_use_id,
                content,
                ..
            } => bytes += tool_use_id.len() + content.len(),
        }
    }
    if let Some(tools) = &req.tools {
        for t in tools {
            bytes += t.name.len() + t.description.len();
            bytes += serde_json::to_string(&t.input_schema).map_or(0, |s| s.len());
        }
    }
    bytes / 4
}

/// Assistant-output budget for this request. `num_ctx` covers prompt
/// AND generation; letting generation run unbounded invites the same
/// mid-generation context shift T34 forbids, so the cap is clamped to
/// half the window on small configs.
fn num_predict_for(req: &LlmRequest, num_ctx: u32) -> u32 {
    req.max_tokens.unwrap_or(4096).min(num_ctx / 2).max(1)
}

/// Translate an [`LlmRequest`] into Ollama's native `/api/chat` body.
pub(crate) fn build_ollama_body(req: &LlmRequest, cfg: &OllamaConfig) -> serde_json::Value {
    // `ollama:qwen3:8b` → `qwen3:8b`; `endpoint:lab/qwen3:8b` →
    // `qwen3:8b` (remote-Ollama custom endpoints route here too).
    let model = wire_model_name(&req.model);

    let mut messages: Vec<serde_json::Value> = Vec::with_capacity(req.messages.len() + 1);
    if let Some(s) = &req.system {
        messages.push(json!({"role": "system", "content": s.as_plain_text()}));
    }
    // Native tool-result messages carry `tool_name`; our ToolResult
    // only carries the id, so reconstruct the name from the preceding
    // AssistantWithTools turns as we walk the history.
    let mut tool_names: HashMap<&str, &str> = HashMap::new();
    for m in &req.messages {
        match m {
            LlmMessage::User(t) => messages.push(json!({"role": "user", "content": t})),
            LlmMessage::Assistant(t) => messages.push(json!({"role": "assistant", "content": t})),
            LlmMessage::AssistantWithTools { text, tool_uses } => {
                let calls: Vec<serde_json::Value> = tool_uses
                    .iter()
                    .map(|tu| {
                        tool_names.insert(tu.id.as_str(), tu.name.as_str());
                        json!({
                            "id": tu.id,
                            "function": {"name": tu.name, "arguments": tu.input},
                        })
                    })
                    .collect();
                messages.push(json!({
                    "role": "assistant",
                    "content": text.clone().unwrap_or_default(),
                    "tool_calls": calls,
                }));
            }
            // `is_error` has no wire equivalent (same as the Responses
            // translator) — the dispatcher's error text is already in
            // `content`, which is how the model learns it failed.
            LlmMessage::ToolResult {
                tool_use_id,
                content,
                is_error: _,
            } => {
                let mut obj = serde_json::Map::new();
                obj.insert("role".into(), json!("tool"));
                obj.insert("content".into(), json!(content));
                // `tool_call_id` is the OpenAI-endpoint spelling; Go's
                // json decoding ignores unknown fields, so sending both
                // keeps us compatible across Ollama versions.
                obj.insert("tool_call_id".into(), json!(tool_use_id));
                if let Some(name) = tool_names.get(tool_use_id.as_str()) {
                    obj.insert("tool_name".into(), json!(name));
                }
                messages.push(serde_json::Value::Object(obj));
            }
        }
    }

    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(model));
    body.insert("messages".into(), json!(messages));
    body.insert("stream".into(), json!(true));
    body.insert("keep_alive".into(), json!(cfg.keep_alive));
    body.insert(
        "options".into(),
        json!({
            // Always explicit — see OllamaConfig::num_ctx.
            "num_ctx": cfg.num_ctx,
            "num_predict": num_predict_for(req, cfg.num_ctx),
        }),
    );
    if let Some(tools) = &req.tools {
        let wrapped: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                })
            })
            .collect();
        body.insert("tools".into(), json!(wrapped));
    }
    serde_json::Value::Object(body)
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn messages(&self, req: LlmRequest) -> LlmResult<LlmStream> {
        // Zero-config path: loopback pin. Endpoint path
        // (`for_endpoint`): the custom-endpoint transport rules
        // (https required off-loopback). Both re-checked per request
        // — defense in depth over the config-layer validation (T35).
        let violation = if self.remote_allowed {
            transport::transport_violation(&self.cfg.base_url)
        } else {
            transport::loopback_violation(&self.cfg.base_url)
        };
        if let Some(reason) = violation {
            return Err(LlmError::LocalProvider(reason));
        }
        // T34 primary guard — refuse before any bytes leave the
        // process. Runs every round, so tool-output growth
        // mid-conversation is caught the round it happens.
        let estimated_tokens = estimate_request_tokens(&req);
        let budget = (self.cfg.num_ctx as usize * 9 / 10)
            .saturating_sub(num_predict_for(&req, self.cfg.num_ctx) as usize);
        if estimated_tokens > budget {
            return Err(LlmError::ContextOverflow {
                estimated_tokens,
                limit: self.cfg.num_ctx,
            });
        }

        let body = build_ollama_body(&req, &self.cfg);
        let url = format!("{}/api/chat", self.cfg.base_url.trim_end_matches('/'));
        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| connect_error(&self.cfg.base_url, &e))?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(LlmError::LocalProvider(format!(
                "Ollama returned HTTP {}: {body_text}",
                status.as_u16()
            )));
        }
        Ok(parse_ollama_stream(ndjson_lines(response.bytes_stream()), self.cfg.num_ctx).boxed())
    }
}

fn connect_error(base_url: &str, e: &reqwest::Error) -> LlmError {
    if e.is_connect() {
        // Stable copy — chat.rs::user_facing_provider_error passes
        // this through as already user-shaped.
        LlmError::LocalProvider(format!(
            "cannot reach Ollama at {base_url} — is `ollama serve` running?"
        ))
    } else {
        LlmError::LocalProvider(format!("request to Ollama failed: {e}"))
    }
}

/// Split a raw byte stream into NDJSON lines. Buffers across chunk
/// boundaries (a chunk may split a line — or a UTF-8 code point — in
/// half), skips blank lines, and flushes a trailing unterminated line
/// at end-of-stream.
pub(crate) fn ndjson_lines<S, B, E>(
    bytes: S,
) -> impl futures::Stream<Item = LlmResult<String>> + Send + 'static
where
    S: futures::Stream<Item = Result<B, E>> + Send + 'static,
    B: AsRef<[u8]> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    struct State<S> {
        inner: S,
        buf: Vec<u8>,
        pending: VecDeque<LlmResult<String>>,
        done: bool,
    }

    fn drain_lines(buf: &mut Vec<u8>, pending: &mut VecDeque<LlmResult<String>>) {
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=pos).collect();
            line.pop(); // trailing \n
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            push_line(line, pending);
        }
    }

    fn push_line(line: Vec<u8>, pending: &mut VecDeque<LlmResult<String>>) {
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        match String::from_utf8(line) {
            Ok(s) => pending.push_back(Ok(s)),
            Err(e) => pending.push_back(Err(LlmError::Malformed(format!(
                "invalid UTF-8 in Ollama stream: {e}"
            )))),
        }
    }

    let init = State {
        inner: Box::pin(bytes),
        buf: Vec::new(),
        pending: VecDeque::new(),
        done: false,
    };
    stream::unfold(init, |mut state| async move {
        loop {
            if let Some(item) = state.pending.pop_front() {
                return Some((item, state));
            }
            if state.done {
                return None;
            }
            match state.inner.next().await {
                None => {
                    state.done = true;
                    let rest = std::mem::take(&mut state.buf);
                    push_line(rest, &mut state.pending);
                }
                Some(Err(e)) => {
                    state.done = true;
                    state
                        .pending
                        .push_back(Err(LlmError::LocalProvider(format!("stream error: {e}"))));
                }
                Some(Ok(chunk)) => {
                    state.buf.extend_from_slice(chunk.as_ref());
                    drain_lines(&mut state.buf, &mut state.pending);
                }
            }
        }
    })
}

/// Convert a stream of NDJSON lines into trait-level
/// [`LlmStreamEvent`]s. Generic over the line source so tests feed
/// synthetic lines (the NDJSON analogue of anthropic.rs's `ev()`).
pub(crate) fn parse_ollama_stream<S>(
    lines: S,
    num_ctx: u32,
) -> impl futures::Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'static
where
    S: futures::Stream<Item = LlmResult<String>> + Send + 'static,
{
    struct State {
        lines: BoxStream<'static, LlmResult<String>>,
        queue: VecDeque<LlmResult<LlmStreamEvent>>,
        num_ctx: u32,
        done: bool,
        completed_emitted: bool,
    }
    let init = State {
        lines: lines.boxed(),
        queue: VecDeque::new(),
        num_ctx,
        done: false,
        completed_emitted: false,
    };
    stream::unfold(init, |mut state| async move {
        loop {
            if let Some(item) = state.queue.pop_front() {
                match &item {
                    // Completed is terminal by contract; an error ends
                    // the stream the same way the SSE parsers do.
                    Ok(LlmStreamEvent::Completed(_)) => {
                        state.completed_emitted = true;
                        state.done = true;
                    }
                    Err(_) => state.done = true,
                    Ok(_) => {}
                }
                return Some((item, state));
            }
            if state.done {
                return None;
            }
            match state.lines.next().await {
                None => {
                    state.done = true;
                    if state.completed_emitted {
                        return None;
                    }
                    return Some((Err(LlmError::EarlyEnd), state));
                }
                Some(Err(e)) => {
                    state.done = true;
                    return Some((Err(e), state));
                }
                Some(Ok(line)) => handle_ollama_line(&line, state.num_ctx, &mut state.queue),
            }
        }
    })
}

fn handle_ollama_line(line: &str, num_ctx: u32, queue: &mut VecDeque<LlmResult<LlmStreamEvent>>) {
    let chunk: OllamaChunk = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => {
            queue.push_back(Err(LlmError::Malformed(format!("ollama chunk: {e}"))));
            return;
        }
    };
    if let Some(err) = chunk.error {
        queue.push_back(Err(LlmError::LocalProvider(format!("Ollama error: {err}"))));
        return;
    }
    if let Some(msg) = chunk.message {
        // `message.thinking` is deliberately not deserialized — local
        // reasoning traces never surface as TextDelta.
        if let Some(content) = msg.content {
            if !content.is_empty() {
                queue.push_back(Ok(LlmStreamEvent::TextDelta(content)));
            }
        }
        for tc in msg.tool_calls.unwrap_or_default() {
            let input = match normalize_arguments(tc.function.arguments, &tc.function.name) {
                Ok(v) => v,
                Err(e) => {
                    queue.push_back(Err(e));
                    return;
                }
            };
            let id = tc
                .id
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("ollama_{}", uuid::Uuid::new_v4()));
            queue.push_back(Ok(LlmStreamEvent::ToolUseComplete {
                id,
                name: tc.function.name,
                input,
            }));
        }
    }
    if chunk.done {
        // T34 backup check — best-effort only: KV prefix caching makes
        // prompt_eval_count under-report on later rounds (it counts
        // tokens evaluated THIS call). The pre-send estimate in
        // `messages()` is the primary guard.
        if let Some(pec) = chunk.prompt_eval_count {
            if pec.saturating_add(TRUNCATION_EPSILON_TOKENS) >= u64::from(num_ctx) {
                queue.push_back(Err(LlmError::LocalProvider(format!(
                    "context truncation detected: the local model evaluated {pec} tokens of a \
                     {num_ctx}-token window — earlier conversation (possibly including system \
                     instructions) was silently dropped. Raise the context window in Settings → \
                     Local models, or start a new chat."
                ))));
                return;
            }
        }
        queue.push_back(Ok(LlmStreamEvent::Completed(TokenUsage {
            input_uncached: chunk.prompt_eval_count.unwrap_or(0),
            input_cache_write: 0,
            input_cache_read: 0,
            output: chunk.eval_count.unwrap_or(0),
        })));
    }
}

/// Ollama sends `arguments` as a parsed JSON object; small models
/// behind some templates emit a stringified object instead. Accept
/// both, reject everything else — the agent loop's tool dispatch
/// treats the result as untrusted either way.
fn normalize_arguments(args: serde_json::Value, tool_name: &str) -> LlmResult<serde_json::Value> {
    match args {
        serde_json::Value::Object(_) => Ok(args),
        serde_json::Value::Null => Ok(json!({})),
        serde_json::Value::String(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(v @ serde_json::Value::Object(_)) => Ok(v),
            _ => Err(LlmError::Malformed(format!(
                "tool_call arguments for {tool_name}: string payload is not a JSON object"
            ))),
        },
        other => Err(LlmError::Malformed(format!(
            "tool_call arguments for {tool_name}: expected object, got {other}"
        ))),
    }
}

#[derive(Deserialize)]
struct OllamaChunk {
    #[serde(default)]
    message: Option<OllamaWireMessage>,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}
#[derive(Deserialize)]
struct OllamaWireMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OllamaWireToolCall>>,
}
#[derive(Deserialize)]
struct OllamaWireToolCall {
    #[serde(default)]
    id: Option<String>,
    function: OllamaWireToolFunction,
}
#[derive(Deserialize)]
struct OllamaWireToolFunction {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

// ---------------------------------------------------------------------
// Detection / model listing (`probe`) — consumed by transit_app's
// `local_models_status` IPC in phase A2. Lives here so all Ollama wire
// knowledge stays in one module and transit_app stays reqwest-free.
// ---------------------------------------------------------------------

/// Result of probing a local Ollama server.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OllamaProbe {
    pub version: String,
    /// Selectable (local, non-cloud) models. `tools_capable` comes
    /// from `/api/show`'s `capabilities` array (Ollama ≥ 0.6.4); an
    /// older server reports `false` for everything.
    pub models: Vec<OllamaModelInfo>,
    /// `:cloud`-tagged models found installed but NEVER selectable —
    /// they proxy inference through ollama.com (T33: "local" must
    /// mean local). Surfaced so the Settings UI can say why they're
    /// hidden.
    pub hidden_cloud_models: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OllamaModelInfo {
    pub name: String,
    pub size_bytes: u64,
    pub tools_capable: bool,
}

/// `true` for an Ollama cloud model — inference proxies through
/// ollama.com even though the model is listed by the local daemon, so
/// it must never appear as "local" (T33). Ollama's cloud naming puts
/// the marker on the TAG (the part after the last `:`): the common
/// form is a `-cloud` SUFFIX on the size tag (`gpt-oss:120b-cloud`,
/// `qwen3-coder:480b-cloud`, `deepseek-v3.1:671b-cloud`), and a bare
/// `:cloud` tag also appears. Match either, case-insensitively, on the
/// tag only. Erring toward exclusion is the safe direction for a
/// privacy backstop — at worst a genuinely-local model whose tag
/// happens to end in `-cloud` is hidden, never the reverse.
pub(crate) fn is_cloud_model(name: &str) -> bool {
    let tag = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
    tag == "cloud" || tag.ends_with("-cloud")
}

/// Probe the zero-config loopback Ollama server: version, installed
/// models, and per-model tool capability. Errors are user-shaped
/// strings (this feeds an IPC status surface, not the agent loop).
/// Nothing returned is a credential (Rule 1).
pub async fn probe(base_url: &str) -> Result<OllamaProbe, String> {
    if let Some(reason) = transport::loopback_violation(base_url) {
        return Err(reason);
    }
    let http = transport::hardened_client(false, Some(Duration::from_secs(5)));
    probe_with(&http, base_url).await
}

/// [`probe`] against a caller-supplied client — the remote-Ollama
/// custom-endpoint path probes over an OS-trust https client built by
/// `transport::endpoint_http_client`. The caller has already enforced
/// the transport rules on `base_url`.
pub async fn probe_with(http: &reqwest::Client, base_url: &str) -> Result<OllamaProbe, String> {
    let base = base_url.trim_end_matches('/');

    #[derive(Deserialize)]
    struct VersionResp {
        version: String,
    }
    let version: VersionResp = get_json(http, &format!("{base}/api/version"), base_url).await?;

    #[derive(Deserialize)]
    struct TagsResp {
        #[serde(default)]
        models: Vec<TagModel>,
    }
    #[derive(Deserialize)]
    struct TagModel {
        name: String,
        #[serde(default)]
        size: u64,
    }
    let tags: TagsResp = get_json(http, &format!("{base}/api/tags"), base_url).await?;

    let mut models = Vec::new();
    let mut hidden_cloud_models = Vec::new();
    for m in tags.models {
        // A cloud-tagged model runs on ollama.com, not this machine
        // (T33) — never selectable, no matter how tools-capable
        // /api/show claims it is.
        if is_cloud_model(&m.name) {
            hidden_cloud_models.push(m.name);
            continue;
        }
        let tools_capable = show_capabilities(http, base, &m.name)
            .await
            .is_ok_and(|caps| caps.iter().any(|c| c == "tools"));
        models.push(OllamaModelInfo {
            name: m.name,
            size_bytes: m.size,
            tools_capable,
        });
    }
    Ok(OllamaProbe {
        version: version.version,
        models,
        hidden_cloud_models,
    })
}

async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    base_url: &str,
) -> Result<T, String> {
    let resp = http.get(url).send().await.map_err(|e| {
        if e.is_connect() {
            format!("cannot reach Ollama at {base_url} — is `ollama serve` running?")
        } else {
            format!("request to Ollama failed: {e}")
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("Ollama returned HTTP {}", status.as_u16()));
    }
    resp.json::<T>()
        .await
        .map_err(|e| format!("unexpected Ollama response shape: {e}"))
}

async fn show_capabilities(
    http: &reqwest::Client,
    base: &str,
    model: &str,
) -> Result<Vec<String>, String> {
    #[derive(Deserialize)]
    struct ShowResp {
        #[serde(default)]
        capabilities: Vec<String>,
    }
    let resp = http
        .post(format!("{base}/api/show"))
        .json(&json!({"model": model}))
        .send()
        .await
        .map_err(|e| format!("request to Ollama failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Ollama returned HTTP {}", resp.status().as_u16()));
    }
    resp.json::<ShowResp>()
        .await
        .map(|s| s.capabilities)
        .map_err(|e| format!("unexpected /api/show shape: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{SystemPromptInput, ToolSchema, ToolUseBlock};
    use futures::StreamExt;

    fn tool_schema(name: &str) -> ToolSchema {
        ToolSchema {
            name: name.into(),
            description: format!("desc for {name}"),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    fn req_with(messages: Vec<LlmMessage>) -> LlmRequest {
        LlmRequest {
            model: "ollama:qwen3:8b".into(),
            system: None,
            messages,
            max_tokens: None,
            tools: None,
        }
    }

    // ----- routing predicate -------------------------------------------

    #[test]
    fn is_local_model_matches_both_byom_namespaces() {
        assert!(is_local_model("ollama:qwen3:8b"));
        assert!(is_local_model("ollama:claude-fake"));
        assert!(is_local_model("endpoint:lab-vllm/qwen3:8b"));
        // No colon → not the namespace, just a weird id.
        assert!(!is_local_model("ollama"));
        assert!(!is_local_model("my-ollama-model"));
        assert!(!is_local_model("gpt-ollama-distill"));
        assert!(!is_local_model("claude-opus-4-8"));
    }

    #[test]
    fn endpoint_model_parsing_and_wire_names() {
        assert_eq!(
            parse_endpoint_model("endpoint:lab-vllm/qwen3:8b"),
            Some(("lab-vllm", "qwen3:8b"))
        );
        // Only the FIRST slash splits — model names may carry slashes
        // (e.g. HF-style org/model ids on vLLM).
        assert_eq!(
            parse_endpoint_model("endpoint:lab/Qwen/Qwen3-8B"),
            Some(("lab", "Qwen/Qwen3-8B"))
        );
        for bad in [
            "endpoint:",
            "endpoint:noslash",
            "endpoint:/m",
            "endpoint:id/",
            "ollama:x",
        ] {
            assert_eq!(parse_endpoint_model(bad), None, "{bad}");
        }

        assert_eq!(wire_model_name("ollama:qwen3:8b"), "qwen3:8b");
        assert_eq!(wire_model_name("endpoint:lab/qwen3:8b"), "qwen3:8b");
        assert_eq!(wire_model_name("claude-opus-4-8"), "claude-opus-4-8");
    }

    // ----- body builder -------------------------------------------------

    #[test]
    fn build_body_strips_the_namespace_prefix_once() {
        // Ollama tags contain colons — only the leading `ollama:` goes.
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        assert_eq!(body.get("model").unwrap(), "qwen3:8b");
    }

    #[test]
    fn build_body_flattens_system_to_first_message() {
        let mut req = req_with(vec![LlmMessage::User("hi".into())]);
        req.system = Some(SystemPromptInput::Plain("be careful".into()));
        let body = build_ollama_body(&req, &OllamaConfig::default());
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs[0].get("role").unwrap(), "system");
        // Byte-equal to as_plain_text so OpenAI-style prefix caching
        // (and any future comparison) holds.
        assert_eq!(
            msgs[0].get("content").unwrap(),
            &json!(req.system.as_ref().unwrap().as_plain_text())
        );
        assert_eq!(msgs[1].get("role").unwrap(), "user");
    }

    #[test]
    fn build_body_maps_tool_history_to_native_shapes() {
        let req = req_with(vec![
            LlmMessage::User("read vEX1".into()),
            LlmMessage::AssistantWithTools {
                text: Some("Reading…".into()),
                tool_uses: vec![ToolUseBlock {
                    id: "tu_1".into(),
                    name: "read_scrollback".into(),
                    input: json!({"session_id": "s1"}),
                }],
            },
            LlmMessage::ToolResult {
                tool_use_id: "tu_1".into(),
                content: "[REDACTED:pem#1]".into(),
                is_error: false,
            },
        ]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 3);

        let assistant = &msgs[1];
        assert_eq!(assistant.get("role").unwrap(), "assistant");
        assert_eq!(assistant.get("content").unwrap(), "Reading…");
        let calls = assistant.get("tool_calls").unwrap().as_array().unwrap();
        assert_eq!(calls[0].get("id").unwrap(), "tu_1");
        let f = calls[0].get("function").unwrap();
        assert_eq!(f.get("name").unwrap(), "read_scrollback");
        assert_eq!(
            f.get("arguments").unwrap(),
            &json!({"session_id": "s1"}),
            "arguments stay a JSON object, never stringified"
        );

        let result = &msgs[2];
        assert_eq!(result.get("role").unwrap(), "tool");
        assert_eq!(result.get("content").unwrap(), "[REDACTED:pem#1]");
        assert_eq!(result.get("tool_call_id").unwrap(), "tu_1");
        // Name reconstructed from the preceding assistant turn.
        assert_eq!(result.get("tool_name").unwrap(), "read_scrollback");
    }

    #[test]
    fn build_body_wraps_tools_in_function_envelope() {
        let mut req = req_with(vec![LlmMessage::User("hi".into())]);
        req.tools = Some(vec![tool_schema("read_scrollback")]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        let tools = body.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools[0].get("type").unwrap(), "function");
        let f = tools[0].get("function").unwrap();
        assert_eq!(f.get("name").unwrap(), "read_scrollback");
        assert!(f.get("parameters").is_some(), "input_schema → parameters");
    }

    #[test]
    fn build_body_omits_tools_field_when_none() {
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn build_body_options_carry_explicit_num_ctx_and_clamped_num_predict() {
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        let opts = body.get("options").unwrap();
        assert_eq!(opts.get("num_ctx").unwrap(), &json!(DEFAULT_NUM_CTX));
        assert_eq!(opts.get("num_predict").unwrap(), &json!(4096));

        // Small window → generation budget clamps to half of it so the
        // prompt keeps room (T34: no mid-generation context shift).
        let small = OllamaConfig {
            num_ctx: 4096,
            ..OllamaConfig::default()
        };
        let body = build_ollama_body(&req, &small);
        assert_eq!(
            body.get("options").unwrap().get("num_predict").unwrap(),
            &json!(2048)
        );
    }

    #[test]
    fn build_body_carries_stream_and_keep_alive() {
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        let cfg = OllamaConfig {
            keep_alive: "42m".into(),
            ..OllamaConfig::default()
        };
        let body = build_ollama_body(&req, &cfg);
        assert_eq!(body.get("stream").unwrap(), &json!(true));
        assert_eq!(body.get("keep_alive").unwrap(), "42m");
    }

    #[test]
    fn build_body_full_request_snapshot() {
        let mut req = req_with(vec![
            LlmMessage::User("check the uplink on vEX1".into()),
            LlmMessage::AssistantWithTools {
                text: None,
                tool_uses: vec![ToolUseBlock {
                    id: "tu_1".into(),
                    name: "read_scrollback".into(),
                    input: json!({"session_id": "s1"}),
                }],
            },
            LlmMessage::ToolResult {
                tool_use_id: "tu_1".into(),
                content: "ge-0/0/0 up".into(),
                is_error: false,
            },
        ]);
        req.system = Some(SystemPromptInput::Plain("investigate only".into()));
        req.tools = Some(vec![tool_schema("read_scrollback")]);
        let body = build_ollama_body(&req, &OllamaConfig::default());
        insta::assert_yaml_snapshot!(body);
    }

    // ----- token estimate + pre-send guard ------------------------------

    #[test]
    fn estimate_counts_system_messages_and_tools() {
        let mut req = req_with(vec![LlmMessage::User("x".repeat(4000))]);
        let base = estimate_request_tokens(&req);
        assert!(base >= 1000, "4000 bytes ≈ ≥1000 tokens, got {base}");

        req.system = Some(SystemPromptInput::Plain("y".repeat(4000)));
        let with_system = estimate_request_tokens(&req);
        assert!(with_system >= base + 900, "system must count");

        req.tools = Some(vec![tool_schema("read_scrollback")]);
        assert!(
            estimate_request_tokens(&req) > with_system,
            "tool schemas must count"
        );
    }

    #[tokio::test]
    async fn messages_refuses_oversized_request_before_any_http() {
        // base_url points at a port nothing listens on: if the guard
        // failed and an HTTP attempt happened, we'd see the
        // "cannot reach Ollama" connect error instead of
        // ContextOverflow.
        let client = OllamaClient::new(OllamaConfig {
            base_url: "http://127.0.0.1:1".into(),
            num_ctx: 4096,
            ..OllamaConfig::default()
        });
        let req = req_with(vec![LlmMessage::User("z".repeat(64 * 1024))]);
        match client.messages(req).await {
            Err(LlmError::ContextOverflow {
                estimated_tokens,
                limit,
            }) => {
                assert!(estimated_tokens > 10_000);
                assert_eq!(limit, 4096);
            }
            Err(other) => panic!("expected ContextOverflow, got {other:?}"),
            Ok(_) => panic!("expected ContextOverflow, got a stream"),
        }
    }

    #[tokio::test]
    async fn messages_refuses_non_loopback_base_url() {
        let client = OllamaClient::new(OllamaConfig {
            base_url: "http://192.168.1.50:11434".into(),
            ..OllamaConfig::default()
        });
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        match client.messages(req).await {
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("non-loopback")),
            Err(other) => panic!("expected LocalProvider refusal, got {other:?}"),
            Ok(_) => panic!("expected LocalProvider refusal, got a stream"),
        }
    }

    #[tokio::test]
    async fn for_endpoint_applies_transport_rules_instead_of_loopback_pin() {
        // A custom endpoint may be remote — but plain HTTP off-loopback
        // is still refused (cleartext must never leave the machine).
        let client = OllamaClient::for_endpoint(
            transport::endpoint_http_client("http://192.168.1.50:11434", None),
            OllamaConfig {
                base_url: "http://192.168.1.50:11434".into(),
                ..OllamaConfig::default()
            },
        );
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        match client.messages(req).await {
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("unencrypted"), "{m}"),
            Err(other) => panic!("expected LocalProvider refusal, got {other:?}"),
            Ok(_) => panic!("expected LocalProvider refusal, got a stream"),
        }
    }

    // ----- NDJSON splitter ----------------------------------------------

    fn lines_from_chunks(
        chunks: Vec<&'static [u8]>,
    ) -> impl futures::Stream<Item = LlmResult<String>> {
        let items: Vec<Result<&'static [u8], std::convert::Infallible>> =
            chunks.into_iter().map(Ok).collect();
        ndjson_lines(futures::stream::iter(items))
    }

    #[tokio::test]
    async fn ndjson_splitter_reassembles_lines_across_chunk_boundaries() {
        // Second line is split mid-UTF-8 (é = 0xC3 0xA9) AND mid-line.
        let s = lines_from_chunks(vec![
            b"{\"a\":1}\n{\"b\":\"caf\xc3".as_ref(),
            b"\xa9\"}\n\n{\"c\":3}".as_ref(),
        ]);
        let got: Vec<String> = s.map(|r| r.unwrap()).collect().await;
        assert_eq!(got, vec![r#"{"a":1}"#, "{\"b\":\"café\"}", r#"{"c":3}"#]);
    }

    #[tokio::test]
    async fn ndjson_splitter_handles_crlf_and_blank_lines() {
        let s = lines_from_chunks(vec![b"{\"a\":1}\r\n\r\n{\"b\":2}\n".as_ref()]);
        let got: Vec<String> = s.map(|r| r.unwrap()).collect().await;
        assert_eq!(got, vec![r#"{"a":1}"#, r#"{"b":2}"#]);
    }

    // ----- stream parser --------------------------------------------------

    fn line(s: &str) -> LlmResult<String> {
        Ok(s.to_string())
    }

    async fn collect(
        lines: Vec<LlmResult<String>>,
        num_ctx: u32,
    ) -> Vec<LlmResult<LlmStreamEvent>> {
        parse_ollama_stream(futures::stream::iter(lines), num_ctx)
            .collect()
            .await
    }

    #[tokio::test]
    async fn parses_text_deltas_and_final_usage() {
        let events = collect(
            vec![
                line(r#"{"message":{"role":"assistant","content":"Hello"},"done":false}"#),
                line(r#"{"message":{"role":"assistant","content":" world"},"done":false}"#),
                line(
                    r#"{"message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":26,"eval_count":298}"#,
                ),
            ],
            16_384,
        )
        .await;
        let mut texts = Vec::new();
        let mut usage = None;
        for e in events {
            match e.unwrap() {
                LlmStreamEvent::TextDelta(t) => texts.push(t),
                LlmStreamEvent::Completed(u) => usage = Some(u),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(texts.join(""), "Hello world");
        let u = usage.expect("Completed event");
        assert_eq!(u.input_uncached, 26);
        assert_eq!(u.output, 298);
        assert_eq!(u.input_cache_write, 0);
        assert_eq!(u.input_cache_read, 0);
    }

    #[tokio::test]
    async fn tool_calls_arrive_as_complete_units() {
        let events = collect(
            vec![
                line(
                    r#"{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","function":{"name":"read_scrollback","arguments":{"session_id":"s1"}}}]},"done":false}"#,
                ),
                line(r#"{"done":true,"prompt_eval_count":10,"eval_count":7}"#),
            ],
            16_384,
        )
        .await;
        let mut tool = None;
        let mut completed = false;
        for e in events {
            match e.unwrap() {
                LlmStreamEvent::ToolUseComplete { id, name, input } => {
                    tool = Some((id, name, input));
                }
                LlmStreamEvent::Completed(_) => completed = true,
                LlmStreamEvent::TextDelta(_) => {}
            }
        }
        let (id, name, input) = tool.expect("ToolUseComplete");
        assert_eq!(id, "call_1");
        assert_eq!(name, "read_scrollback");
        assert_eq!(input.get("session_id").unwrap(), "s1");
        assert!(completed);
    }

    #[tokio::test]
    async fn tool_call_without_id_gets_a_synthesized_one() {
        let events = collect(
            vec![
                line(
                    r#"{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"list_open_sessions","arguments":{}}}]},"done":false}"#,
                ),
                line(r#"{"done":true,"prompt_eval_count":1,"eval_count":1}"#),
            ],
            16_384,
        )
        .await;
        let id = events
            .into_iter()
            .find_map(|e| match e.unwrap() {
                LlmStreamEvent::ToolUseComplete { id, .. } => Some(id),
                _ => None,
            })
            .expect("ToolUseComplete");
        assert!(id.starts_with("ollama_"), "synthesized id, got {id}");
    }

    #[tokio::test]
    async fn stringified_arguments_are_parsed_leniently() {
        // Some templates/small models emit arguments as a JSON string.
        let events = collect(
            vec![
                line(
                    r#"{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c","function":{"name":"read_scrollback","arguments":"{\"session_id\":\"s1\"}"}}]},"done":false}"#,
                ),
                line(r#"{"done":true,"prompt_eval_count":1,"eval_count":1}"#),
            ],
            16_384,
        )
        .await;
        let input = events
            .into_iter()
            .find_map(|e| match e.unwrap() {
                LlmStreamEvent::ToolUseComplete { input, .. } => Some(input),
                _ => None,
            })
            .expect("ToolUseComplete");
        assert_eq!(input.get("session_id").unwrap(), "s1");
    }

    #[tokio::test]
    async fn non_object_arguments_surface_as_malformed() {
        let events = collect(
            vec![line(
                r#"{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c","function":{"name":"read_scrollback","arguments":[1,2]}}]},"done":false}"#,
            )],
            16_384,
        )
        .await;
        match events.last().unwrap() {
            Err(LlmError::Malformed(m)) => assert!(m.contains("read_scrollback")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn thinking_only_chunks_emit_nothing() {
        let events = collect(
            vec![
                line(r#"{"message":{"role":"assistant","thinking":"hmm, let me plan"},"done":false}"#),
                line(r#"{"message":{"role":"assistant","content":"answer"},"done":false}"#),
                line(r#"{"done":true,"prompt_eval_count":1,"eval_count":1}"#),
            ],
            16_384,
        )
        .await;
        let texts: Vec<String> = events
            .into_iter()
            .filter_map(|e| match e.unwrap() {
                LlmStreamEvent::TextDelta(t) => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["answer"], "thinking must never surface");
    }

    #[tokio::test]
    async fn error_line_surfaces_as_local_provider_error() {
        let events = collect(vec![line(r#"{"error":"model 'nope' not found"}"#)], 16_384).await;
        match events.last().unwrap() {
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("not found")),
            other => panic!("expected LocalProvider, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unparseable_line_is_malformed() {
        let events = collect(vec![line("{not json")], 16_384).await;
        assert!(matches!(
            events.last().unwrap(),
            Err(LlmError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn stream_end_without_done_is_early_end() {
        let events = collect(
            vec![line(
                r#"{"message":{"role":"assistant","content":"abrupt"},"done":false}"#,
            )],
            16_384,
        )
        .await;
        assert!(matches!(events.last().unwrap(), Err(LlmError::EarlyEnd)));
    }

    #[tokio::test]
    async fn truncation_near_num_ctx_errors_instead_of_completing() {
        // prompt_eval_count within the epsilon of num_ctx ⇒ the server
        // truncated; the turn must end loudly, never with Completed.
        let events = collect(
            vec![
                line(r#"{"message":{"role":"assistant","content":"partial"},"done":false}"#),
                line(r#"{"done":true,"prompt_eval_count":4000,"eval_count":50}"#),
            ],
            4096,
        )
        .await;
        match events.last().unwrap() {
            Err(LlmError::LocalProvider(m)) => {
                assert!(m.contains("context truncation detected"), "{m}");
            }
            other => panic!("expected truncation error, got {other:?}"),
        }
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Ok(LlmStreamEvent::Completed(_)))),
            "no Completed after detected truncation"
        );
    }

    #[tokio::test]
    async fn done_chunk_with_trailing_content_emits_text_then_completed() {
        let events = collect(
            vec![line(
                r#"{"message":{"role":"assistant","content":"tail"},"done":true,"prompt_eval_count":5,"eval_count":2}"#,
            )],
            16_384,
        )
        .await;
        let kinds: Vec<&'static str> = events
            .iter()
            .map(|e| match e {
                Ok(LlmStreamEvent::TextDelta(_)) => "text",
                Ok(LlmStreamEvent::Completed(_)) => "completed",
                Ok(LlmStreamEvent::ToolUseComplete { .. }) => "tool",
                Err(_) => "err",
            })
            .collect();
        assert_eq!(kinds, vec!["text", "completed"]);
    }

    // ----- wiremock end-to-end -------------------------------------------

    #[tokio::test]
    async fn messages_end_to_end_happy_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let ndjson = concat!(
            r#"{"message":{"role":"assistant","content":"42"},"done":false}"#,
            "\n",
            r#"{"done":true,"prompt_eval_count":12,"eval_count":3}"#,
            "\n",
        );
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(ndjson, "application/x-ndjson"))
            .mount(&server)
            .await;

        let client = OllamaClient::new(OllamaConfig {
            base_url: server.uri(), // wiremock binds 127.0.0.1 — passes the loopback pin
            ..OllamaConfig::default()
        });
        let mut stream = client
            .messages(req_with(vec![LlmMessage::User("meaning of life?".into())]))
            .await
            .expect("stream opens");
        let mut text = String::new();
        let mut usage = None;
        while let Some(item) = stream.next().await {
            match item.unwrap() {
                LlmStreamEvent::TextDelta(t) => text.push_str(&t),
                LlmStreamEvent::Completed(u) => usage = Some(u),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(text, "42");
        assert_eq!(usage.unwrap().output, 3);
    }

    #[tokio::test]
    async fn non_2xx_maps_to_local_provider_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let client = OllamaClient::new(OllamaConfig {
            base_url: server.uri(),
            ..OllamaConfig::default()
        });
        match client
            .messages(req_with(vec![LlmMessage::User("hi".into())]))
            .await
        {
            Err(LlmError::LocalProvider(m)) => {
                assert!(m.contains("500"));
                assert!(m.contains("boom"));
            }
            Err(other) => panic!("expected LocalProvider, got {other:?}"),
            Ok(_) => panic!("expected LocalProvider, got a stream"),
        }
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        // Security pin: a rogue listener on the Ollama port must not be
        // able to 307 the conversation body to another host.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "http://198.51.100.1/steal"),
            )
            .mount(&server)
            .await;

        let client = OllamaClient::new(OllamaConfig {
            base_url: server.uri(),
            ..OllamaConfig::default()
        });
        match client
            .messages(req_with(vec![LlmMessage::User("hi".into())]))
            .await
        {
            // Policy::none() surfaces the 3xx as a plain non-success
            // status — the redirect target is never contacted.
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("307"), "{m}"),
            Err(other) => panic!("expected LocalProvider(307), got {other:?}"),
            Ok(_) => panic!("expected LocalProvider(307), got a stream"),
        }
    }

    #[tokio::test]
    async fn probe_lists_tool_capable_models_and_hides_cloud_tags() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "0.32.1"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [
                    {"name": "qwen3:8b", "size": 5_000_000_000u64},
                    {"name": "gemma4:12b", "size": 8_000_000_000u64},
                    // Cloud models in BOTH real Ollama spellings: the
                    // common `-cloud` size-tag suffix AND the bare
                    // `:cloud` tag. Neither may reach the selectable
                    // list (T33) — the `-cloud` suffix is the form the
                    // pre-fix filter missed.
                    {"name": "gpt-oss:120b-cloud", "size": 0},
                    {"name": "glm-5:cloud", "size": 0},
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/show"))
            .and(body_json(json!({"model": "qwen3:8b"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "capabilities": ["completion", "tools", "thinking"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/show"))
            .and(body_json(json!({"model": "gemma4:12b"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "capabilities": ["completion", "vision"]
            })))
            .mount(&server)
            .await;

        let probe = probe(&server.uri()).await.expect("probe succeeds");
        assert_eq!(probe.version, "0.32.1");
        assert_eq!(probe.models.len(), 2);
        let qwen = probe.models.iter().find(|m| m.name == "qwen3:8b").unwrap();
        assert!(qwen.tools_capable);
        let gemma = probe
            .models
            .iter()
            .find(|m| m.name == "gemma4:12b")
            .unwrap();
        assert!(!gemma.tools_capable);
        // No cloud model — either spelling — is tools-probed or
        // selectable; both land in hidden (T33). `/api/show` is never
        // even called for them (only qwen3/gemma4 mocks exist, so a
        // stray probe would 404 → tools_capable:false, still not proof
        // of exclusion — the length + hidden assertions are).
        assert!(
            !probe.models.iter().any(|m| m.name.contains("cloud")),
            "no cloud-tagged model may reach the selectable list"
        );
        assert_eq!(
            probe.hidden_cloud_models,
            vec!["gpt-oss:120b-cloud", "glm-5:cloud"]
        );
    }

    #[test]
    fn is_cloud_model_covers_both_ollama_spellings() {
        // The `-cloud` SIZE-TAG SUFFIX is Ollama's headline cloud form
        // (verified against ollama.com/blog/cloud-models) — the case
        // the first cut missed.
        for cloud in [
            "gpt-oss:120b-cloud",
            "qwen3-coder:480b-cloud",
            "deepseek-v3.1:671b-cloud",
            "glm-5:cloud",
            "GPT-OSS:120B-CLOUD", // case-insensitive
        ] {
            assert!(is_cloud_model(cloud), "{cloud} must be treated as cloud");
        }
        for local in [
            "qwen3:8b",
            "gemma4:12b",
            "gpt-oss:20b", // the LOCAL gpt-oss — no -cloud suffix
            "llama3.3:70b",
            "mistral", // no tag at all
        ] {
            assert!(!is_cloud_model(local), "{local} must stay local");
        }
    }

    #[tokio::test]
    async fn probe_refuses_non_loopback_urls() {
        let err = probe("http://192.168.1.50:11434").await.unwrap_err();
        assert!(err.contains("non-loopback"));
    }
}
