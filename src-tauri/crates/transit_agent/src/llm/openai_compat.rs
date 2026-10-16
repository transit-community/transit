//! Generic OpenAI-compatible `/v1/chat/completions` impl of
//! [`crate::llm::LlmClient`] — BYOM custom endpoints
//! (the byom local models design notes (not included in this repository), phase A3).
//!
//! Covers remote Ollama's `/v1`, vLLM, LM Studio, llama.cpp
//! `llama-server`, and LiteLLM. Deliberately a NEW translator/parser
//! pair: the existing `build_openai_body`/`parse_openai_stream` are
//! Responses-API-shaped (`instructions`, `output_item.*` events) and
//! do not speak chat-completions.
//!
//! Transport (T35): rules live in [`super::transport`] — plain http
//! only to loopback; anything else https, verified against the OS
//! trust store (enterprise-internal CAs honored). Same
//! no-proxy/no-redirect/connect-timeout hardening as `ollama.rs`.
//!
//! The optional bearer token is passed IN by transit_app at
//! construction (the same by-value pattern as the direct clients) — this crate still
//! never touches the keychain, and the token is only ever emitted as
//! an `Authorization` header to the endpoint the user configured.
//!
//! Context budgeting (T34): chat-completions has no `num_ctx` knob and
//! most servers truncate or error opaquely on overflow, so the
//! PRE-SEND estimate against the endpoint's user-declared context
//! length is the only guard on this path; server 4xx (vLLM errors on
//! overflow) is surfaced verbatim as a `LocalProvider` error.

use std::collections::{BTreeMap, VecDeque};

use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures::stream::{self, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::ollama::{estimate_request_tokens, wire_model_name};
use super::transport;
use crate::llm::{
    LlmClient, LlmError, LlmMessage, LlmRequest, LlmResult, LlmStream, LlmStreamEvent,
};
use crate::usage::TokenUsage;

/// Plain-data config for [`OpenAiCompatClient`]. transit_app resolves
/// the endpoint entry from `[[local_models.endpoints]]`, reads the
/// bearer from the keychain (transit_app is a deny.toml keyring
/// wrapper; this crate is not), and passes both in.
pub struct OpenAiCompatConfig {
    /// Endpoint base INCLUDING the `/v1` segment where the server uses
    /// one (e.g. `http://127.0.0.1:1234/v1`, `https://vllm.lab:8000/v1`)
    /// — `/chat/completions` is appended here.
    pub base_url: String,
    /// Optional `Authorization: Bearer …` credential for the endpoint
    /// (vLLM `--api-key`, LiteLLM keys, reverse-proxy tokens).
    pub bearer: Option<SecretString>,
    /// User-declared context window for the pre-send budget (T34).
    /// There is no wire-level knob to set or discover it generically.
    pub declared_context_length: u32,
}

pub struct OpenAiCompatClient {
    http: reqwest::Client,
    cfg: OpenAiCompatConfig,
}

impl OpenAiCompatClient {
    /// `http` comes from `transport::endpoint_http_client` so https
    /// endpoints carry the OS-store trust config. The caller has
    /// already enforced the transport rules on `cfg.base_url`
    /// (re-checked per request here — defense in depth).
    pub fn new(http: reqwest::Client, cfg: OpenAiCompatConfig) -> Self {
        Self { http, cfg }
    }
}

#[async_trait]
impl LlmClient for OpenAiCompatClient {
    async fn messages(&self, req: LlmRequest) -> LlmResult<LlmStream> {
        if let Some(reason) = transport::transport_violation(&self.cfg.base_url) {
            return Err(LlmError::LocalProvider(reason));
        }
        // T34 pre-send guard — the only truncation defense on this
        // path (no num_ctx knob, no reliable prompt_eval signal).
        let estimated_tokens = estimate_request_tokens(&req);
        let max_out = max_output_tokens(&req, self.cfg.declared_context_length);
        let budget =
            (self.cfg.declared_context_length as usize * 9 / 10).saturating_sub(max_out as usize);
        if estimated_tokens > budget {
            return Err(LlmError::ContextOverflow {
                estimated_tokens,
                limit: self.cfg.declared_context_length,
            });
        }

        let body = build_openai_compat_body(&req, max_out);
        let url = format!(
            "{}/chat/completions",
            self.cfg.base_url.trim_end_matches('/')
        );
        let mut request = self.http.post(&url).json(&body);
        if let Some(bearer) = &self.cfg.bearer {
            request = request.bearer_auth(bearer.expose_secret());
        }
        let response = request.send().await.map_err(|e| {
            if e.is_connect() {
                LlmError::LocalProvider(format!(
                    "cannot reach the endpoint at {} — is the server running?",
                    self.cfg.base_url
                ))
            } else {
                LlmError::LocalProvider(format!("request to the endpoint failed: {e}"))
            }
        })?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(LlmError::LocalProvider(format!(
                "endpoint returned HTTP {}: {body_text}",
                status.as_u16()
            )));
        }
        let events = response.bytes_stream().eventsource();
        Ok(parse_openai_compat_stream(events).boxed())
    }
}

/// Assistant-output cap. Clamped to half the declared window so the
/// prompt keeps room (mirrors `ollama::num_predict_for`).
fn max_output_tokens(req: &LlmRequest, declared_context_length: u32) -> u32 {
    req.max_tokens
        .unwrap_or(4096)
        .min(declared_context_length / 2)
        .max(1)
}

/// Translate an [`LlmRequest`] into a chat-completions body. Notable
/// wire differences from the native Ollama shape: tool-call
/// `arguments` are a JSON **string**, and tool results reference
/// `tool_call_id` only.
pub(crate) fn build_openai_compat_body(req: &LlmRequest, max_out: u32) -> serde_json::Value {
    let model = wire_model_name(&req.model);

    let mut messages: Vec<serde_json::Value> = Vec::with_capacity(req.messages.len() + 1);
    if let Some(s) = &req.system {
        messages.push(json!({"role": "system", "content": s.as_plain_text()}));
    }
    for m in &req.messages {
        match m {
            LlmMessage::User(t) => messages.push(json!({"role": "user", "content": t})),
            LlmMessage::Assistant(t) => messages.push(json!({"role": "assistant", "content": t})),
            LlmMessage::AssistantWithTools { text, tool_uses } => {
                let calls: Vec<serde_json::Value> = tool_uses
                    .iter()
                    .map(|tu| {
                        json!({
                            "id": tu.id,
                            "type": "function",
                            "function": {
                                "name": tu.name,
                                // Chat-completions carries arguments as a
                                // JSON STRING, not an object.
                                "arguments": serde_json::to_string(&tu.input)
                                    .unwrap_or_else(|_| "{}".to_string()),
                            },
                        })
                    })
                    .collect();
                messages.push(json!({
                    "role": "assistant",
                    "content": text.clone().unwrap_or_default(),
                    "tool_calls": calls,
                }));
            }
            // `is_error` has no wire equivalent (same posture as the
            // Responses translator) — the dispatcher's error text is
            // already in `content`.
            LlmMessage::ToolResult {
                tool_use_id,
                content,
                is_error: _,
            } => {
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id,
                    "content": content,
                }));
            }
        }
    }

    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(model));
    body.insert("messages".into(), json!(messages));
    body.insert("stream".into(), json!(true));
    // Token counts arrive in the final stream chunk only when asked.
    body.insert("stream_options".into(), json!({"include_usage": true}));
    body.insert("max_tokens".into(), json!(max_out));
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

/// Tool call under assembly. Chat-completions streams `arguments` as
/// string FRAGMENTS keyed by `index` (unlike native Ollama's complete
/// units) — the `anthropic.rs` `PendingToolUse` pattern, keyed in a
/// BTreeMap so finalization order is deterministic.
struct PendingCompatCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

/// Convert a chat-completions SSE stream into trait-level
/// [`LlmStreamEvent`]s. Generic over the byte-stream error type so
/// tests feed synthetic events (mirrors `parse_anthropic_stream`).
pub(crate) fn parse_openai_compat_stream<S, E>(
    events: S,
) -> impl futures::Stream<Item = LlmResult<LlmStreamEvent>> + Send + 'static
where
    S: futures::Stream<
            Item = Result<eventsource_stream::Event, eventsource_stream::EventStreamError<E>>,
        > + Send
        + Unpin
        + 'static,
    E: std::fmt::Display + Send + 'static,
{
    struct State<S> {
        events: S,
        queue: VecDeque<LlmResult<LlmStreamEvent>>,
        pending: BTreeMap<u32, PendingCompatCall>,
        usage: TokenUsage,
        done: bool,
        completed_emitted: bool,
    }
    let init = State {
        events,
        queue: VecDeque::new(),
        pending: BTreeMap::new(),
        usage: TokenUsage::default(),
        done: false,
        completed_emitted: false,
    };
    stream::unfold(init, |mut state| async move {
        loop {
            if let Some(item) = state.queue.pop_front() {
                match &item {
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
            match state.events.next().await {
                None => {
                    state.done = true;
                    if state.completed_emitted {
                        return None;
                    }
                    return Some((Err(LlmError::EarlyEnd), state));
                }
                Some(Err(e)) => {
                    state.done = true;
                    return Some((
                        Err(LlmError::Malformed(format!("event-stream error: {e}"))),
                        state,
                    ));
                }
                Some(Ok(event)) => handle_compat_event(
                    &event.data,
                    &mut state.pending,
                    &mut state.usage,
                    &mut state.queue,
                ),
            }
        }
    })
}

fn handle_compat_event(
    data: &str,
    pending: &mut BTreeMap<u32, PendingCompatCall>,
    usage: &mut TokenUsage,
    queue: &mut VecDeque<LlmResult<LlmStreamEvent>>,
) {
    let data = data.trim();
    if data.is_empty() {
        return;
    }
    if data == "[DONE]" {
        // Defensive: llama.cpp-era servers have shipped tool deltas
        // with no finish_reason chunk — finalize whatever is pending
        // before closing out.
        finalize_pending(pending, queue);
        if !queue.iter().any(|e| e.is_err()) {
            queue.push_back(Ok(LlmStreamEvent::Completed(*usage)));
        }
        return;
    }
    let chunk: CompatChunk = match serde_json::from_str(data) {
        Ok(c) => c,
        Err(e) => {
            queue.push_back(Err(LlmError::Malformed(format!(
                "chat-completions chunk: {e}"
            ))));
            return;
        }
    };
    if let Some(err) = chunk.error {
        queue.push_back(Err(LlmError::LocalProvider(format!(
            "endpoint error: {err}"
        ))));
        return;
    }
    if let Some(u) = chunk.usage {
        let cached = u
            .prompt_tokens_details
            .as_ref()
            .map_or(0, |d| d.cached_tokens);
        *usage = TokenUsage {
            input_uncached: u.prompt_tokens.saturating_sub(cached),
            input_cache_write: 0,
            input_cache_read: cached,
            output: u.completion_tokens,
        };
    }
    for choice in chunk.choices {
        if let Some(content) = choice.delta.content {
            if !content.is_empty() {
                queue.push_back(Ok(LlmStreamEvent::TextDelta(content)));
            }
        }
        for tc in choice.delta.tool_calls.unwrap_or_default() {
            let entry = tc.index;
            let slot = pending.entry(entry).or_insert(PendingCompatCall {
                id: None,
                name: None,
                arguments: String::new(),
            });
            if let Some(id) = tc.id.filter(|s| !s.is_empty()) {
                slot.id = Some(id);
            }
            if let Some(f) = tc.function {
                if let Some(name) = f.name.filter(|s| !s.is_empty()) {
                    slot.name = Some(name);
                }
                if let Some(frag) = f.arguments {
                    slot.arguments.push_str(&frag);
                }
            }
        }
        if choice.finish_reason.is_some() {
            finalize_pending(pending, queue);
        }
    }
}

/// Drain pending tool calls (index order) into `ToolUseComplete`
/// events. A slot whose buffered arguments don't parse as a JSON
/// object yields `Malformed` and stops finalization — the turn
/// terminates rather than dispatching a half-parsed call.
fn finalize_pending(
    pending: &mut BTreeMap<u32, PendingCompatCall>,
    queue: &mut VecDeque<LlmResult<LlmStreamEvent>>,
) {
    let drained = std::mem::take(pending);
    for (_, call) in drained {
        let Some(name) = call.name else {
            queue.push_back(Err(LlmError::Malformed(
                "tool_call stream ended without a function name".into(),
            )));
            return;
        };
        let raw = if call.arguments.trim().is_empty() {
            "{}".to_string()
        } else {
            call.arguments
        };
        let input: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v @ serde_json::Value::Object(_)) => v,
            Ok(_) | Err(_) => {
                queue.push_back(Err(LlmError::Malformed(format!(
                    "tool_call arguments for {name}: not a JSON object"
                ))));
                return;
            }
        };
        let id = call
            .id
            .unwrap_or_else(|| format!("compat_{}", uuid::Uuid::new_v4()));
        queue.push_back(Ok(LlmStreamEvent::ToolUseComplete { id, name, input }));
    }
}

/// List model ids from `{base}/models` (OpenAI-compat discovery).
/// This wire carries NO capability metadata — callers must present
/// these as "tool support unverified" (unlike `ollama::probe`, which
/// reads `/api/show` capabilities). Errors are user-shaped strings
/// for the IPC status surface. Nothing returned is a credential.
pub async fn list_models(
    http: &reqwest::Client,
    base_url: &str,
    bearer: Option<&SecretString>,
) -> Result<Vec<String>, String> {
    #[derive(Deserialize)]
    struct ModelsResp {
        #[serde(default)]
        data: Vec<ModelRow>,
    }
    #[derive(Deserialize)]
    struct ModelRow {
        id: String,
    }
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    let mut request = http.get(&url);
    if let Some(b) = bearer {
        request = request.bearer_auth(b.expose_secret());
    }
    let resp = request.send().await.map_err(|e| {
        if e.is_connect() {
            format!("cannot reach the endpoint at {base_url} — is the server running?")
        } else {
            format!("request to the endpoint failed: {e}")
        }
    })?;
    if !resp.status().is_success() {
        return Err(format!("endpoint returned HTTP {}", resp.status().as_u16()));
    }
    resp.json::<ModelsResp>()
        .await
        .map(|r| r.data.into_iter().map(|m| m.id).collect())
        .map_err(|e| format!("unexpected /models response shape: {e}"))
}

#[derive(Deserialize)]
struct CompatChunk {
    #[serde(default)]
    choices: Vec<CompatChoice>,
    #[serde(default)]
    usage: Option<CompatUsage>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}
#[derive(Deserialize)]
struct CompatChoice {
    #[serde(default)]
    delta: CompatDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}
#[derive(Deserialize, Default)]
struct CompatDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<CompatToolCallDelta>>,
}
#[derive(Deserialize)]
struct CompatToolCallDelta {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<CompatFnDelta>,
}
#[derive(Deserialize, Default)]
struct CompatFnDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}
#[derive(Deserialize)]
struct CompatUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<CompatPromptDetails>,
}
#[derive(Deserialize, Default)]
struct CompatPromptDetails {
    #[serde(default)]
    cached_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{SystemPromptInput, ToolSchema, ToolUseBlock};
    use eventsource_stream::Event;
    use futures::StreamExt;
    use std::convert::Infallible;

    fn ev(data: &str) -> Result<Event, eventsource_stream::EventStreamError<Infallible>> {
        Ok(Event {
            event: "message".to_string(),
            data: data.to_string(),
            id: String::new(),
            retry: None,
        })
    }

    fn tool_schema(name: &str) -> ToolSchema {
        ToolSchema {
            name: name.into(),
            description: format!("desc for {name}"),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    fn req_with(messages: Vec<LlmMessage>) -> LlmRequest {
        LlmRequest {
            model: "endpoint:lab-vllm/qwen3:8b".into(),
            system: None,
            messages,
            max_tokens: None,
            tools: None,
        }
    }

    async fn collect(events: Vec<&str>) -> Vec<LlmResult<LlmStreamEvent>> {
        let evs: Vec<_> = events.into_iter().map(ev).collect();
        parse_openai_compat_stream(futures::stream::iter(evs))
            .collect()
            .await
    }

    // ----- body builder -------------------------------------------------

    #[test]
    fn build_body_strips_endpoint_namespace_and_streams_with_usage() {
        let mut req = req_with(vec![LlmMessage::User("hi".into())]);
        req.system = Some(SystemPromptInput::Plain("investigate only".into()));
        let body = build_openai_compat_body(&req, 4096);
        assert_eq!(body.get("model").unwrap(), "qwen3:8b");
        assert_eq!(body.get("stream").unwrap(), &json!(true));
        assert_eq!(
            body.get("stream_options").unwrap(),
            &json!({"include_usage": true})
        );
        assert_eq!(body.get("max_tokens").unwrap(), &json!(4096));
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs[0].get("role").unwrap(), "system");
        assert_eq!(msgs[1].get("role").unwrap(), "user");
    }

    #[test]
    fn build_body_tool_history_uses_stringified_arguments() {
        let req = req_with(vec![
            LlmMessage::AssistantWithTools {
                text: None,
                tool_uses: vec![ToolUseBlock {
                    id: "call_1".into(),
                    name: "read_scrollback".into(),
                    input: json!({"session_id": "s1"}),
                }],
            },
            LlmMessage::ToolResult {
                tool_use_id: "call_1".into(),
                content: "[REDACTED:pem#1]".into(),
                is_error: false,
            },
        ]);
        let body = build_openai_compat_body(&req, 1024);
        let msgs = body.get("messages").unwrap().as_array().unwrap();

        let calls = msgs[0].get("tool_calls").unwrap().as_array().unwrap();
        assert_eq!(calls[0].get("type").unwrap(), "function");
        let args = calls[0].get("function").unwrap().get("arguments").unwrap();
        assert!(
            args.is_string(),
            "chat-completions arguments must be a JSON string, got {args:?}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(args.as_str().unwrap()).unwrap(),
            json!({"session_id": "s1"})
        );

        assert_eq!(msgs[1].get("role").unwrap(), "tool");
        assert_eq!(msgs[1].get("tool_call_id").unwrap(), "call_1");
        assert!(
            msgs[1].get("tool_name").is_none(),
            "compat shape omits tool_name"
        );
    }

    #[test]
    fn build_body_wraps_tools_and_omits_when_none() {
        let mut req = req_with(vec![LlmMessage::User("hi".into())]);
        assert!(build_openai_compat_body(&req, 64).get("tools").is_none());
        req.tools = Some(vec![tool_schema("read_scrollback")]);
        let body = build_openai_compat_body(&req, 64);
        let tools = body.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools[0].get("type").unwrap(), "function");
        assert!(tools[0]
            .get("function")
            .unwrap()
            .get("parameters")
            .is_some());
    }

    #[test]
    fn max_output_tokens_clamps_to_half_the_declared_window() {
        let req = req_with(vec![LlmMessage::User("hi".into())]);
        assert_eq!(max_output_tokens(&req, 16_384), 4096);
        assert_eq!(max_output_tokens(&req, 4096), 2048);
    }

    // ----- stream parser --------------------------------------------------

    #[tokio::test]
    async fn parses_text_deltas_and_usage_from_final_chunk() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{"content":" world"},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":40,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":30}}}"#,
            "[DONE]",
        ])
        .await;
        let mut text = String::new();
        let mut usage = None;
        for e in events {
            match e.unwrap() {
                LlmStreamEvent::TextDelta(t) => text.push_str(&t),
                LlmStreamEvent::Completed(u) => usage = Some(u),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(text, "Hello world");
        let u = usage.expect("Completed");
        assert_eq!(u.input_uncached, 10);
        assert_eq!(u.input_cache_read, 30);
        assert_eq!(u.output, 9);
    }

    #[tokio::test]
    async fn fragmented_tool_arguments_reassemble_on_finish_reason() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"read_scrollback","arguments":""}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"session"}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"_id\":\"s1\"}"}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ])
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
        assert_eq!(id, "call_9");
        assert_eq!(name, "read_scrollback");
        assert_eq!(input.get("session_id").unwrap(), "s1");
        assert!(completed);
    }

    #[tokio::test]
    async fn parallel_tool_calls_interleaved_by_index_finalize_in_order() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"read_scrollback","arguments":"{\"session_id\":"}},{"index":1,"id":"b","function":{"name":"list_open_sessions","arguments":""}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"s1\"}"}}]},"finish_reason":null}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ])
        .await;
        let names: Vec<String> = events
            .into_iter()
            .filter_map(|e| match e.unwrap() {
                LlmStreamEvent::ToolUseComplete { name, .. } => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["read_scrollback", "list_open_sessions"]);
    }

    #[tokio::test]
    async fn missing_tool_call_id_gets_synthesized() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"list_open_sessions","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ])
        .await;
        let id = events
            .into_iter()
            .find_map(|e| match e.unwrap() {
                LlmStreamEvent::ToolUseComplete { id, .. } => Some(id),
                _ => None,
            })
            .expect("ToolUseComplete");
        assert!(id.starts_with("compat_"), "{id}");
    }

    #[tokio::test]
    async fn done_without_usage_completes_with_zero_usage() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}"#,
            "[DONE]",
        ])
        .await;
        match events.last().unwrap() {
            Ok(LlmStreamEvent::Completed(u)) => assert_eq!(*u, TokenUsage::default()),
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn done_with_pending_but_no_finish_reason_still_finalizes() {
        // llama.cpp-era defensive path: tool deltas then straight to
        // [DONE] with no finish_reason chunk.
        let events = collect(vec![
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"list_open_sessions","arguments":"{}"}}]},"finish_reason":null}]}"#,
            "[DONE]",
        ])
        .await;
        let kinds: Vec<&'static str> = events
            .iter()
            .map(|e| match e {
                Ok(LlmStreamEvent::ToolUseComplete { .. }) => "tool",
                Ok(LlmStreamEvent::Completed(_)) => "completed",
                Ok(LlmStreamEvent::TextDelta(_)) => "text",
                Err(_) => "err",
            })
            .collect();
        assert_eq!(kinds, vec!["tool", "completed"]);
    }

    #[tokio::test]
    async fn unparseable_tool_arguments_are_malformed_and_stop_the_stream() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"x","function":{"name":"read_scrollback","arguments":"{not-json"}}]},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ])
        .await;
        match events.last().unwrap() {
            Err(LlmError::Malformed(m)) => assert!(m.contains("read_scrollback")),
            other => panic!("expected Malformed, got {other:?}"),
        }
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Ok(LlmStreamEvent::Completed(_)))),
            "no Completed after malformed tool args"
        );
    }

    #[tokio::test]
    async fn error_chunk_surfaces_as_local_provider() {
        let events = collect(vec![
            r#"{"error":{"message":"model not found","type":"invalid_request_error"}}"#,
        ])
        .await;
        match events.last().unwrap() {
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("model not found")),
            other => panic!("expected LocalProvider, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_end_without_done_is_early_end() {
        let events = collect(vec![
            r#"{"choices":[{"delta":{"content":"abrupt"},"finish_reason":null}]}"#,
        ])
        .await;
        assert!(matches!(events.last().unwrap(), Err(LlmError::EarlyEnd)));
    }

    // ----- transport + guard ----------------------------------------------

    #[tokio::test]
    async fn messages_refuses_plain_http_off_loopback() {
        let client = OpenAiCompatClient::new(
            transport::endpoint_http_client("http://192.168.1.9:8000/v1", None),
            OpenAiCompatConfig {
                base_url: "http://192.168.1.9:8000/v1".into(),
                bearer: None,
                declared_context_length: 8192,
            },
        );
        match client
            .messages(req_with(vec![LlmMessage::User("hi".into())]))
            .await
        {
            Err(LlmError::LocalProvider(m)) => assert!(m.contains("unencrypted"), "{m}"),
            Err(other) => panic!("expected LocalProvider, got {other:?}"),
            Ok(_) => panic!("expected LocalProvider, got a stream"),
        }
    }

    #[tokio::test]
    async fn messages_refuses_oversized_request_before_any_http() {
        let client = OpenAiCompatClient::new(
            transport::endpoint_http_client("http://127.0.0.1:1/v1", None),
            OpenAiCompatConfig {
                base_url: "http://127.0.0.1:1/v1".into(),
                bearer: None,
                declared_context_length: 4096,
            },
        );
        let req = req_with(vec![LlmMessage::User("z".repeat(64 * 1024))]);
        match client.messages(req).await {
            Err(LlmError::ContextOverflow { limit, .. }) => assert_eq!(limit, 4096),
            Err(other) => panic!("expected ContextOverflow, got {other:?}"),
            Ok(_) => panic!("expected ContextOverflow, got a stream"),
        }
    }

    // ----- wiremock end-to-end ---------------------------------------------

    #[tokio::test]
    async fn messages_end_to_end_sends_bearer_and_parses_sse() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"42\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n",
        );
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-test-endpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
            .mount(&server)
            .await;

        let base = format!("{}/v1", server.uri());
        let client = OpenAiCompatClient::new(
            transport::endpoint_http_client(&base, None),
            OpenAiCompatConfig {
                base_url: base,
                bearer: Some(SecretString::new("sk-test-endpoint".to_string().into())),
                declared_context_length: 8192,
            },
        );
        let mut stream = client
            .messages(req_with(vec![LlmMessage::User("meaning?".into())]))
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
        assert_eq!(usage.unwrap().output, 2);
    }

    #[tokio::test]
    async fn list_models_returns_ids_with_bearer() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer sk-x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "data": [{"id": "qwen3-8b", "object": "model"}, {"id": "gemma4", "object": "model"}]
            })))
            .mount(&server)
            .await;

        let base = format!("{}/v1", server.uri());
        let http = transport::endpoint_http_client(&base, None);
        let bearer = SecretString::new("sk-x".to_string().into());
        let ids = list_models(&http, &base, Some(&bearer)).await.unwrap();
        assert_eq!(ids, vec!["qwen3-8b", "gemma4"]);
    }

    #[tokio::test]
    async fn non_2xx_maps_to_local_provider() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"error":{"message":"maximum context length exceeded"}}"#),
            )
            .mount(&server)
            .await;

        let base = format!("{}/v1", server.uri());
        let client = OpenAiCompatClient::new(
            transport::endpoint_http_client(&base, None),
            OpenAiCompatConfig {
                base_url: base,
                bearer: None,
                declared_context_length: 8192,
            },
        );
        match client
            .messages(req_with(vec![LlmMessage::User("hi".into())]))
            .await
        {
            Err(LlmError::LocalProvider(m)) => {
                assert!(m.contains("400"));
                assert!(m.contains("maximum context length"));
            }
            Err(other) => panic!("expected LocalProvider, got {other:?}"),
            Ok(_) => panic!("expected LocalProvider, got a stream"),
        }
    }
}
