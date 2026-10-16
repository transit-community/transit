//! Anthropic Messages-API request/stream translation. The
//! [`crate::llm::LlmClient`] impl that owns the HTTP call lives in
//! `direct.rs` (`DirectAnthropic`); this module is the pure half.
//!
//! Translates [`crate::llm::LlmRequest`] into Anthropic's request
//! shape, decodes the SSE response into [`crate::llm::LlmStreamEvent`]
//! values, and accumulates per-turn token usage as the stream
//! progresses.

use futures::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::llm::{
    LlmError, LlmMessage, LlmRequest, LlmResult, LlmStreamEvent, SystemPromptInput, ToolSchema,
};
#[cfg(test)]
use crate::llm::{SystemSection, ToolUseBlock};
use crate::usage::TokenUsage;
use std::collections::HashMap;

pub(crate) fn build_anthropic_body(req: &LlmRequest) -> serde_json::Value {
    let mut messages = anthropic_messages(&req.messages);

    // Agent-loop cascading message-history cache (CLAUDE.md §18's
    // 4th breakpoint, held in reserve before Phase 8d). Mark the
    // last content block of the latest user-role message with
    // cache_control: ephemeral. Iteration N reads the prior
    // (user + assistant + tool_result)* chain from cache and only
    // pays write fee on the new pair appended this turn.
    //
    // Gated on `tools.is_some()` so the non-agentic chat path stays
    // byte-stable (single-shot User messages don't benefit from a
    // write fee they'll never amortize).
    if req.tools.is_some() {
        mark_last_user_block_cacheable(&mut messages);
    }

    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(req.model));
    body.insert("messages".into(), json!(messages));
    body.insert("stream".into(), json!(true));
    // Anthropic requires `max_tokens`; default to a generous turn cap
    // when the caller doesn't set one. 4096 matches v1's assistant
    // budget — revise per-tier as the chat panel matures.
    body.insert("max_tokens".into(), json!(req.max_tokens.unwrap_or(4096)));
    if let Some(s) = &req.system {
        body.insert("system".into(), anthropic_system_field(s));
    }
    if let Some(tools) = &req.tools {
        body.insert("tools".into(), json!(anthropic_tools(tools)));
    }
    serde_json::Value::Object(body)
}

/// Translate `LlmMessage` history into Anthropic's strict
/// alternating-roles message list. Adjacent `User` + `ToolResult`
/// messages collapse into a single user-role turn with a content
/// array — Anthropic rejects two consecutive user-role messages
/// with a `messages.<i>: each turn must have a different role`
/// error, so the fold is mandatory whenever a tool round happens.
///
/// Plain `User(text)` and `Assistant(text)` with no tool blocks
/// stay as string-content messages (Anthropic accepts both string
/// and `[{type:text,...}]` shapes; the simpler form keeps the
/// non-agentic chat traffic bytewise unchanged from 5d).
fn anthropic_messages(history: &[LlmMessage]) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::with_capacity(history.len());
    let mut user_blocks: Vec<serde_json::Value> = Vec::new();

    fn flush_user(out: &mut Vec<serde_json::Value>, user_blocks: &mut Vec<serde_json::Value>) {
        if user_blocks.is_empty() {
            return;
        }
        if user_blocks.len() == 1 {
            // Single text block — emit as string content for byte
            // stability with the pre-Phase-6 wire format.
            if let Some(block) = user_blocks.first() {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        out.push(json!({"role": "user", "content": text}));
                        user_blocks.clear();
                        return;
                    }
                }
            }
        }
        out.push(json!({"role": "user", "content": user_blocks.clone()}));
        user_blocks.clear();
    }

    for m in history {
        match m {
            LlmMessage::User(text) => {
                user_blocks.push(json!({"type": "text", "text": text}));
            }
            LlmMessage::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                user_blocks.push(json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": content,
                    "is_error": is_error,
                }));
            }
            LlmMessage::Assistant(text) => {
                flush_user(&mut out, &mut user_blocks);
                out.push(json!({"role": "assistant", "content": text}));
            }
            LlmMessage::AssistantWithTools { text, tool_uses } => {
                flush_user(&mut out, &mut user_blocks);
                let mut blocks: Vec<serde_json::Value> = Vec::new();
                if let Some(t) = text {
                    if !t.is_empty() {
                        blocks.push(json!({"type": "text", "text": t}));
                    }
                }
                for tu in tool_uses {
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": tu.id,
                        "name": tu.name,
                        "input": tu.input,
                    }));
                }
                out.push(json!({"role": "assistant", "content": blocks}));
            }
        }
    }
    flush_user(&mut out, &mut user_blocks);
    out
}

/// Stamp `cache_control: { type: "ephemeral" }` on the LAST content
/// block of the LAST user-role message in `messages`. Used only when
/// the request advertises tools (agent-loop case) — see CLAUDE.md
/// §18 and the gate in `build_anthropic_body`.
///
/// Promotes a string-content message to a single-block content array
/// in passing, since Anthropic's wire shape only lets `cache_control`
/// ride on content blocks, not on the string form.
fn mark_last_user_block_cacheable(messages: &mut [serde_json::Value]) {
    let Some(last_user_idx) = messages.iter().rposition(|m| {
        m.get("role")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| r == "user")
    }) else {
        return;
    };
    let msg = &mut messages[last_user_idx];
    let Some(content) = msg.get_mut("content") else {
        return;
    };
    if let Some(text) = content.as_str().map(|s| s.to_string()) {
        *content = json!([{"type": "text", "text": text}]);
    }
    if let Some(arr) = content.as_array_mut() {
        if let Some(last_block) = arr.last_mut() {
            if let Some(obj) = last_block.as_object_mut() {
                obj.insert("cache_control".into(), json!({"type": "ephemeral"}));
            }
        }
    }
}

/// Translate [`SystemPromptInput`] into Anthropic's `system` field
/// wire shape. `Plain` becomes a bare JSON string (the pre-Phase-8d
/// wire); `Sections` becomes an array of `{type:"text",text:..,...}`
/// blocks, with `cache_control: { type: "ephemeral" }` attached to
/// every section whose `cache_after` is `true`.
///
/// Up to four `cache_control` markers may appear across the whole
/// request (system + tools + messages combined); the canonical
/// system-prompt layout (CLAUDE.md §18) emits three of them here.
fn anthropic_system_field(s: &SystemPromptInput) -> serde_json::Value {
    match s {
        SystemPromptInput::Plain(text) => json!(text),
        SystemPromptInput::Sections(secs) => {
            // Anthropic rejects an EMPTY text content block ("system: text
            // content blocks must be non-empty", HTTP 400). A section can
            // legitimately render empty — e.g. `KnownEndpoints` with no API
            // controller open — so drop empty sections before they become
            // blocks. (The OpenAI client concatenates sections into a single
            // string, where an empty one is harmless; this per-section block
            // shape is Anthropic-only, so this is where the constraint lives.)
            // An empty section carries no cacheable content, so filtering it
            // never drops a meaningful cache breakpoint.
            let blocks: Vec<serde_json::Value> = secs
                .iter()
                .filter(|sec| !sec.text.is_empty())
                .map(|sec| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("type".into(), json!("text"));
                    obj.insert("text".into(), json!(sec.text));
                    if sec.cache_after {
                        obj.insert("cache_control".into(), json!({"type": "ephemeral"}));
                    }
                    serde_json::Value::Object(obj)
                })
                .collect();
            serde_json::Value::Array(blocks)
        }
    }
}

/// Translate the trait-level `ToolSchema` list into Anthropic's
/// `tools` array shape. The schema fields map 1:1 — Anthropic's
/// shape is what we picked as the canonical form.
fn anthropic_tools(tools: &[ToolSchema]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            })
        })
        .collect()
}

struct PendingToolUse {
    id: String,
    name: String,
    partial_json: String,
}

/// Convert an Anthropic event stream into the trait-level
/// [`LlmStreamEvent`]. Generic over the underlying byte-stream error
/// type so this function is reusable from tests with synthetic
/// streams.
pub(crate) fn parse_anthropic_stream<S, E>(
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
        usage: TokenUsage,
        done: bool,
        completed_emitted: bool,
        /// Per-`index` tool_use blocks under assembly. Anthropic
        /// emits `content_block_start { index, type:tool_use, id,
        /// name }` then zero-or-more
        /// `content_block_delta { index, delta:{ type:input_json_delta,
        /// partial_json } }`, and finalizes on `content_block_stop`.
        /// The empty-input case (e.g. `list_open_sessions`) sends
        /// no delta events; the entry's `partial_json` stays empty
        /// and we treat that as `{}` at finalization.
        pending_tools: HashMap<u32, PendingToolUse>,
    }
    let init = State {
        events,
        usage: TokenUsage::default(),
        done: false,
        completed_emitted: false,
        pending_tools: HashMap::new(),
    };
    stream::unfold(init, |mut state| async move {
        if state.done {
            return None;
        }
        loop {
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
                Some(Ok(event)) => {
                    match handle_anthropic_event(&event, &mut state.usage, &mut state.pending_tools)
                    {
                        Ok(Some(out)) => {
                            if matches!(out, LlmStreamEvent::Completed(_)) {
                                state.completed_emitted = true;
                            }
                            return Some((Ok(out), state));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            state.done = true;
                            return Some((Err(e), state));
                        }
                    }
                }
            }
        }
    })
}

fn handle_anthropic_event(
    event: &eventsource_stream::Event,
    usage: &mut TokenUsage,
    pending_tools: &mut HashMap<u32, PendingToolUse>,
) -> LlmResult<Option<LlmStreamEvent>> {
    match event.event.as_str() {
        "message_start" => {
            let parsed: AnthropicMessageStart = serde_json::from_str(&event.data)
                .map_err(|e| LlmError::Malformed(format!("message_start: {e}")))?;
            usage.input_uncached = parsed.message.usage.input_tokens.unwrap_or(0);
            usage.input_cache_write = parsed
                .message
                .usage
                .cache_creation_input_tokens
                .unwrap_or(0);
            usage.input_cache_read = parsed.message.usage.cache_read_input_tokens.unwrap_or(0);
            // `output_tokens` from message_start is typically 0; the
            // final cumulative count arrives via message_delta.
            usage.output = parsed.message.usage.output_tokens.unwrap_or(0);
            Ok(None)
        }
        "content_block_start" => {
            let parsed: AnthropicContentBlockStart = serde_json::from_str(&event.data)
                .map_err(|e| LlmError::Malformed(format!("content_block_start: {e}")))?;
            if parsed.content_block.block_type == "tool_use" {
                let id = parsed
                    .content_block
                    .id
                    .ok_or_else(|| LlmError::Malformed("tool_use start missing id".into()))?;
                let name = parsed
                    .content_block
                    .name
                    .ok_or_else(|| LlmError::Malformed("tool_use start missing name".into()))?;
                pending_tools.insert(
                    parsed.index,
                    PendingToolUse {
                        id,
                        name,
                        partial_json: String::new(),
                    },
                );
            }
            Ok(None)
        }
        "content_block_delta" => {
            let parsed: AnthropicContentBlockDelta = serde_json::from_str(&event.data)
                .map_err(|e| LlmError::Malformed(format!("content_block_delta: {e}")))?;
            match parsed.delta.delta_type.as_str() {
                "text_delta" => {
                    if let Some(text) = parsed.delta.text {
                        return Ok(Some(LlmStreamEvent::TextDelta(text)));
                    }
                    Ok(None)
                }
                "input_json_delta" => {
                    if let (Some(pending), Some(chunk)) = (
                        pending_tools.get_mut(&parsed.index),
                        parsed.delta.partial_json,
                    ) {
                        pending.partial_json.push_str(&chunk);
                    }
                    Ok(None)
                }
                // thinking_delta and any future delta types are
                // informational; the agent loop never sees them.
                _ => Ok(None),
            }
        }
        "content_block_stop" => {
            let parsed: AnthropicContentBlockStop = serde_json::from_str(&event.data)
                .map_err(|e| LlmError::Malformed(format!("content_block_stop: {e}")))?;
            if let Some(pending) = pending_tools.remove(&parsed.index) {
                // Empty-input tools (e.g. list_open_sessions) send no
                // input_json_delta events; treat the empty buffer
                // as the JSON object `{}`.
                let raw = if pending.partial_json.is_empty() {
                    "{}".to_string()
                } else {
                    pending.partial_json
                };
                let input: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                    LlmError::Malformed(format!(
                        "tool_use input JSON for {}: {e}: {raw}",
                        pending.name
                    ))
                })?;
                return Ok(Some(LlmStreamEvent::ToolUseComplete {
                    id: pending.id,
                    name: pending.name,
                    input,
                }));
            }
            Ok(None)
        }
        "message_delta" => {
            let parsed: AnthropicMessageDelta = serde_json::from_str(&event.data)
                .map_err(|e| LlmError::Malformed(format!("message_delta: {e}")))?;
            // message_delta.usage.output_tokens is the cumulative
            // final output count — overwrite, don't add.
            if let Some(out) = parsed.usage.and_then(|u| u.output_tokens) {
                usage.output = out;
            }
            Ok(None)
        }
        "message_stop" => Ok(Some(LlmStreamEvent::Completed(*usage))),
        "error" => Err(LlmError::Malformed(format!(
            "provider error: {}",
            event.data
        ))),
        // ping is informational; empty event types are stream-level
        // keepalives that eventsource_stream surfaces as ev.event="".
        other => {
            if other != "ping" && !other.is_empty() {
                warn!(event = %other, "unhandled Anthropic event type");
            }
            Ok(None)
        }
    }
}

#[derive(Deserialize)]
struct AnthropicMessageStart {
    message: AnthropicMessage,
}
#[derive(Deserialize)]
struct AnthropicMessage {
    #[serde(default)]
    usage: AnthropicUsage,
}
#[derive(Deserialize, Default)]
struct AnthropicUsage {
    input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}
#[derive(Deserialize)]
struct AnthropicContentBlockStart {
    index: u32,
    content_block: AnthropicContentBlockHead,
}
#[derive(Deserialize)]
struct AnthropicContentBlockHead {
    #[serde(rename = "type")]
    block_type: String,
    id: Option<String>,
    name: Option<String>,
}
#[derive(Deserialize)]
struct AnthropicContentBlockDelta {
    index: u32,
    delta: AnthropicDelta,
}
#[derive(Deserialize)]
struct AnthropicDelta {
    #[serde(rename = "type")]
    delta_type: String,
    text: Option<String>,
    partial_json: Option<String>,
}
#[derive(Deserialize)]
struct AnthropicContentBlockStop {
    index: u32,
}
#[derive(Deserialize)]
struct AnthropicMessageDelta {
    usage: Option<AnthropicUsage>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use eventsource_stream::Event;
    use futures::StreamExt;
    use std::convert::Infallible;

    fn ev(
        event_type: &str,
        data: &str,
    ) -> Result<Event, eventsource_stream::EventStreamError<Infallible>> {
        Ok(Event {
            event: event_type.to_string(),
            data: data.to_string(),
            id: String::new(),
            retry: None,
        })
    }

    #[test]
    fn build_body_translates_messages_and_system() {
        let req = LlmRequest {
            model: "claude-opus-4-7".into(),
            system: Some("you are a helpful assistant".into()),
            messages: vec![
                LlmMessage::User("hello".into()),
                LlmMessage::Assistant("hi".into()),
            ],
            max_tokens: Some(2000),
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let obj = body.as_object().unwrap();
        assert_eq!(obj.get("model").unwrap(), "claude-opus-4-7");
        assert_eq!(obj.get("stream").unwrap(), &json!(true));
        assert_eq!(obj.get("max_tokens").unwrap(), &json!(2000));
        assert_eq!(obj.get("system").unwrap(), "you are a helpful assistant");
        let msgs = obj.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].get("role").unwrap(), "user");
        assert_eq!(msgs[1].get("role").unwrap(), "assistant");
    }

    #[test]
    fn build_body_plain_system_stays_a_bare_string() {
        // Byte stability for the non-agentic chat path: a Plain
        // system prompt must still serialize as `"system": "<text>"`
        // (not as a single-block array). Pre-Phase-8d clients depend
        // on this wire shape.
        let req = LlmRequest {
            model: "x".into(),
            system: Some(SystemPromptInput::Plain("hello".into())),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        assert_eq!(body.get("system").unwrap(), &json!("hello"));
    }

    #[test]
    fn build_body_sections_become_text_blocks_with_cache_control() {
        let req = LlmRequest {
            model: "x".into(),
            system: Some(SystemPromptInput::Sections(vec![
                SystemSection {
                    text: "A".into(),
                    cache_after: true,
                },
                SystemSection {
                    text: "B".into(),
                    cache_after: false,
                },
                SystemSection {
                    text: "C".into(),
                    cache_after: true,
                },
            ])),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let blocks = body.get("system").unwrap().as_array().unwrap();
        assert_eq!(blocks.len(), 3);

        // Block 0: text "A" with cache_control.
        assert_eq!(blocks[0].get("type").unwrap(), "text");
        assert_eq!(blocks[0].get("text").unwrap(), "A");
        assert_eq!(
            blocks[0].get("cache_control").unwrap(),
            &json!({"type": "ephemeral"})
        );
        // Block 1: text "B", NO cache_control key.
        assert_eq!(blocks[1].get("text").unwrap(), "B");
        assert!(blocks[1].get("cache_control").is_none());
        // Block 2: text "C" with cache_control.
        assert_eq!(blocks[2].get("text").unwrap(), "C");
        assert_eq!(
            blocks[2].get("cache_control").unwrap(),
            &json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn build_body_drops_empty_system_sections() {
        // Regression (v4.2.0): an empty section — e.g. `KnownEndpoints` with no
        // API controller open — must NOT become an empty text block. Anthropic
        // rejects those with 400 "system: text content blocks must be
        // non-empty", which broke every SSH-only agent chat on Anthropic models
        // (GPT was fine — its client concatenates sections into one string).
        let req = LlmRequest {
            model: "x".into(),
            system: Some(SystemPromptInput::Sections(vec![
                SystemSection {
                    text: "A".into(),
                    cache_after: true,
                },
                SystemSection {
                    text: String::new(), // empty — must be dropped
                    cache_after: false,
                },
                SystemSection {
                    text: "C".into(),
                    cache_after: false,
                },
            ])),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let blocks = body.get("system").unwrap().as_array().unwrap();
        assert_eq!(blocks.len(), 2, "the empty section must be filtered out");
        assert_eq!(blocks[0].get("text").unwrap(), "A");
        assert_eq!(blocks[1].get("text").unwrap(), "C");
        for b in blocks {
            assert!(
                !b.get("text").unwrap().as_str().unwrap().is_empty(),
                "no empty text block may reach Anthropic"
            );
        }
    }

    #[test]
    fn build_body_with_tools_marks_last_user_block_cacheable() {
        // P0.5 — 4th cache breakpoint. With tools advertised
        // (agent-loop path), the latest user-role message's last
        // content block carries cache_control: ephemeral.
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: Some(vec![tool_schema("list_open_sessions")]),
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        // String content was promoted to a single-block array so
        // cache_control could attach.
        let content = msgs[0].get("content").unwrap().as_array().unwrap();
        assert_eq!(content[0].get("type").unwrap(), "text");
        assert_eq!(content[0].get("text").unwrap(), "hi");
        assert_eq!(
            content[0].get("cache_control").unwrap(),
            &json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn build_body_with_tools_marks_last_tool_result_cacheable() {
        // The cascading-cache shape: a turn that's appending the
        // latest tool_result marks THAT tool_result with
        // cache_control, so the next iteration's prefix (everything
        // up through this tool_result) hits the cache.
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![
                LlmMessage::User("read vEX1 scrollback".into()),
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
                    content: "[REDACTED:pem#1]".into(),
                    is_error: false,
                },
            ],
            max_tokens: None,
            tools: Some(vec![tool_schema("read_scrollback")]),
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        // Last message: folded user-role containing the tool_result.
        let last = msgs.last().unwrap();
        assert_eq!(last.get("role").unwrap(), "user");
        let content = last.get("content").unwrap().as_array().unwrap();
        let last_block = content.last().unwrap();
        assert_eq!(last_block.get("type").unwrap(), "tool_result");
        assert_eq!(last_block.get("tool_use_id").unwrap(), "tu_1");
        assert_eq!(
            last_block.get("cache_control").unwrap(),
            &json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn build_body_without_tools_does_not_mark_messages_for_caching() {
        // Byte-stability pin for the non-agentic chat path. tools=None
        // skips the message-history breakpoint so a single User("hi")
        // still serializes as `{"role":"user","content":"hi"}` — no
        // promotion to content-array, no cache_control.
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs[0].get("content").unwrap(), &json!("hi"));
    }

    #[test]
    fn build_body_total_cache_breakpoints_stay_under_anthropic_limit_of_four() {
        // Anthropic caps cache_control markers at 4 per request.
        // Canonical layout: 3 in system + 1 in messages = 4. Anything
        // higher fails at the provider — this test pins the count.
        use crate::system_prompt;
        use transit_core::inventory::Vendor;
        use transit_policy::{PolicyMode, PolicySummary, Precedence};

        let prompt = system_prompt::build(
            &[],
            &[(
                Vendor::Junos,
                PolicySummary {
                    mode: PolicyMode::Gated,
                    precedence: Precedence::BlockWins,
                    allowed: vec!["^show".into()],
                    blocked: vec!["^reload".into()],
                    pipe_allowed: vec![],
                    pipe_blocked: vec![],
                    phrasebook: vec![],
                },
            )],
        );
        let req = LlmRequest {
            model: "x".into(),
            system: Some(prompt.to_llm_input()),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: Some(vec![tool_schema("read_scrollback")]),
        };
        let body = build_anthropic_body(&req);

        let mut total = 0;
        let system_blocks = body.get("system").unwrap().as_array().unwrap();
        for b in system_blocks {
            if b.get("cache_control").is_some() {
                total += 1;
            }
        }
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        for m in msgs {
            if let Some(arr) = m.get("content").and_then(|c| c.as_array()) {
                for block in arr {
                    if block.get("cache_control").is_some() {
                        total += 1;
                    }
                }
            }
        }
        assert_eq!(total, 4, "expected exactly 4 cache breakpoints");
    }

    #[test]
    fn build_body_canonical_layout_emits_exactly_three_cache_breakpoints() {
        // Pin the canonical layout's breakpoint count (CLAUDE.md §18)
        // at the wire format. The 4th slot is reserved for the
        // message-history breakpoint added by P0.5.
        use crate::system_prompt;
        use transit_core::inventory::Vendor;
        use transit_policy::{PolicyMode, PolicySummary, Precedence};

        let prompt = system_prompt::build(
            &[],
            &[(
                Vendor::Junos,
                PolicySummary {
                    mode: PolicyMode::Gated,
                    precedence: Precedence::BlockWins,
                    allowed: vec!["^show( |$)".into()],
                    blocked: vec!["^reload".into()],
                    pipe_allowed: vec![],
                    pipe_blocked: vec![],
                    phrasebook: vec![],
                },
            )],
        );
        let req = LlmRequest {
            model: "x".into(),
            system: Some(prompt.to_llm_input()),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let blocks = body.get("system").unwrap().as_array().unwrap();
        let cache_count = blocks
            .iter()
            .filter(|b| b.get("cache_control").is_some())
            .count();
        assert_eq!(
            cache_count, 3,
            "canonical system layout must emit exactly 3 cache_control breakpoints"
        );
    }

    #[test]
    fn build_body_max_tokens_defaults_to_4096() {
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        assert_eq!(body.get("max_tokens").unwrap(), &json!(4096));
    }

    #[tokio::test]
    async fn parses_text_deltas_and_emits_completed() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":12,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"text_delta","text":" world"}}"#,
            ),
            ev(
                "message_delta",
                r#"{"delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut texts = Vec::new();
        let mut final_usage = None;
        while let Some(item) = s.next().await {
            match item.unwrap() {
                LlmStreamEvent::TextDelta(t) => texts.push(t),
                LlmStreamEvent::Completed(u) => final_usage = Some(u),
                LlmStreamEvent::ToolUseComplete { .. } => {
                    panic!("did not expect a ToolUseComplete in this test")
                }
            }
        }
        assert_eq!(texts.join(""), "Hello world");
        let u = final_usage.expect("Completed event");
        assert_eq!(u.input_uncached, 12);
        assert_eq!(u.output, 4);
    }

    #[tokio::test]
    async fn cache_read_and_write_carry_through_to_completed() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":3,"cache_creation_input_tokens":100,"cache_read_input_tokens":2000,"output_tokens":0}}}"#,
            ),
            ev(
                "message_delta",
                r#"{"delta":{},"usage":{"output_tokens":15}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut final_usage = None;
        while let Some(item) = s.next().await {
            if let LlmStreamEvent::Completed(u) = item.unwrap() {
                final_usage = Some(u);
            }
        }
        let u = final_usage.unwrap();
        assert_eq!(u.input_uncached, 3);
        assert_eq!(u.input_cache_write, 100);
        assert_eq!(u.input_cache_read, 2000);
        assert_eq!(u.output, 15);
    }

    #[tokio::test]
    async fn ignores_thinking_delta_chunks() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":1,"delta":{"type":"text_delta","text":"answer"}}"#,
            ),
            ev(
                "message_delta",
                r#"{"delta":{},"usage":{"output_tokens":1}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut texts = Vec::new();
        while let Some(item) = s.next().await {
            if let LlmStreamEvent::TextDelta(t) = item.unwrap() {
                texts.push(t);
            }
        }
        assert_eq!(texts, vec!["answer"]);
    }

    #[tokio::test]
    async fn early_end_when_stream_closes_without_message_stop() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"text_delta","text":"abrupt"}}"#,
            ),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut last = None;
        while let Some(item) = s.next().await {
            last = Some(item);
        }
        match last.unwrap() {
            Err(LlmError::EarlyEnd) => {}
            other => panic!("expected EarlyEnd, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn provider_error_event_is_surfaced_as_malformed() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "error",
                r#"{"type":"overloaded_error","message":"slow down"}"#,
            ),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut got_err = false;
        while let Some(item) = s.next().await {
            if let Err(LlmError::Malformed(m)) = item {
                assert!(m.contains("overloaded_error"));
                got_err = true;
            }
        }
        assert!(got_err);
    }

    // ----- Tool use (Phase 6 C2) ---------------------------------------

    fn tool_schema(name: &str) -> ToolSchema {
        ToolSchema {
            name: name.into(),
            description: format!("desc for {name}"),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    #[test]
    fn build_body_serializes_tools_field_when_present() {
        let req = LlmRequest {
            model: "claude-opus-4-7".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: Some(vec![
                tool_schema("list_open_sessions"),
                tool_schema("read_scrollback"),
            ]),
        };
        let body = build_anthropic_body(&req);
        let tools = body.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].get("name").unwrap(), "list_open_sessions");
        assert_eq!(
            tools[0].get("description").unwrap(),
            "desc for list_open_sessions"
        );
        assert!(tools[0].get("input_schema").is_some());
    }

    #[test]
    fn build_body_omits_tools_field_when_none() {
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn build_body_translates_assistant_with_tools_to_content_array() {
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![
                LlmMessage::User("read vEX1 scrollback".into()),
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
            ],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].get("role").unwrap(), "user");
        // Assistant turn has content array with text + tool_use blocks.
        assert_eq!(msgs[1].get("role").unwrap(), "assistant");
        let assistant_content = msgs[1].get("content").unwrap().as_array().unwrap();
        assert_eq!(assistant_content[0].get("type").unwrap(), "text");
        assert_eq!(assistant_content[0].get("text").unwrap(), "Reading…");
        assert_eq!(assistant_content[1].get("type").unwrap(), "tool_use");
        assert_eq!(assistant_content[1].get("id").unwrap(), "tu_1");
        assert_eq!(assistant_content[1].get("name").unwrap(), "read_scrollback");
        // ToolResult goes into a user-role content array.
        assert_eq!(msgs[2].get("role").unwrap(), "user");
        let user_content = msgs[2].get("content").unwrap().as_array().unwrap();
        assert_eq!(user_content[0].get("type").unwrap(), "tool_result");
        assert_eq!(user_content[0].get("tool_use_id").unwrap(), "tu_1");
        assert_eq!(user_content[0].get("content").unwrap(), "[REDACTED:pem#1]");
        assert_eq!(user_content[0].get("is_error").unwrap(), &json!(false));
    }

    #[test]
    fn build_body_folds_consecutive_user_and_tool_results_into_one_turn() {
        // Anthropic rejects two consecutive user-role messages — the
        // assistant turn must alternate. Adjacent User + ToolResult
        // entries fold into a single user-role with a content array.
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![
                LlmMessage::AssistantWithTools {
                    text: None,
                    tool_uses: vec![
                        ToolUseBlock {
                            id: "tu_a".into(),
                            name: "read_scrollback".into(),
                            input: json!({"session_id": "s1"}),
                        },
                        ToolUseBlock {
                            id: "tu_b".into(),
                            name: "read_scrollback".into(),
                            input: json!({"session_id": "s2"}),
                        },
                    ],
                },
                LlmMessage::ToolResult {
                    tool_use_id: "tu_a".into(),
                    content: "out a".into(),
                    is_error: false,
                },
                LlmMessage::ToolResult {
                    tool_use_id: "tu_b".into(),
                    content: "out b".into(),
                    is_error: false,
                },
            ],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        // assistant + folded user — exactly two messages.
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].get("role").unwrap(), "assistant");
        assert_eq!(msgs[1].get("role").unwrap(), "user");
        let user_blocks = msgs[1].get("content").unwrap().as_array().unwrap();
        assert_eq!(user_blocks.len(), 2);
        assert_eq!(user_blocks[0].get("tool_use_id").unwrap(), "tu_a");
        assert_eq!(user_blocks[1].get("tool_use_id").unwrap(), "tu_b");
    }

    #[test]
    fn build_body_keeps_plain_user_text_as_string_content() {
        // Pin: the non-agentic chat path's wire bytes are unchanged
        // by Phase 6's type extensions. A single User(text) still
        // serializes as `{"role":"user","content":"<text>"}`.
        let req = LlmRequest {
            model: "x".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_anthropic_body(&req);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs[0].get("content").unwrap(), "hi");
    }

    #[tokio::test]
    async fn parses_tool_use_block_and_emits_tool_use_complete() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"tool_use","id":"tu_x","name":"read_scrollback","input":{}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"session_id\""}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":":\"s1\"}"}}"#,
            ),
            ev("content_block_stop", r#"{"index":0}"#),
            ev(
                "message_delta",
                r#"{"delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut tool_use = None;
        let mut completed = false;
        while let Some(item) = s.next().await {
            match item.unwrap() {
                LlmStreamEvent::ToolUseComplete { id, name, input } => {
                    tool_use = Some((id, name, input));
                }
                LlmStreamEvent::Completed(_) => completed = true,
                LlmStreamEvent::TextDelta(_) => {}
            }
        }
        let (id, name, input) = tool_use.expect("ToolUseComplete event");
        assert_eq!(id, "tu_x");
        assert_eq!(name, "read_scrollback");
        assert_eq!(input.get("session_id").unwrap(), "s1");
        assert!(completed);
    }

    #[tokio::test]
    async fn parses_tool_use_with_empty_input_block() {
        // list_open_sessions has no inputs; Anthropic sends no
        // input_json_delta events between block_start and block_stop.
        // The parser must still emit ToolUseComplete with `input={}`.
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"tool_use","id":"tu_e","name":"list_open_sessions","input":{}}}"#,
            ),
            ev("content_block_stop", r#"{"index":0}"#),
            ev(
                "message_delta",
                r#"{"delta":{},"usage":{"output_tokens":2}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut got = None;
        while let Some(item) = s.next().await {
            if let LlmStreamEvent::ToolUseComplete { name, input, .. } = item.unwrap() {
                got = Some((name, input));
            }
        }
        let (name, input) = got.unwrap();
        assert_eq!(name, "list_open_sessions");
        assert_eq!(input, json!({}));
    }

    #[tokio::test]
    async fn tool_use_with_interleaved_text_delta_emits_both() {
        // Index 0 is a text block with two deltas; index 1 is a
        // tool_use block. The parser must surface the text deltas
        // verbatim and the tool_use_complete after content_block_stop
        // for index 1.
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":3,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"text_delta","text":"checking "}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"text_delta","text":"vEX1"}}"#,
            ),
            ev("content_block_stop", r#"{"index":0}"#),
            ev(
                "content_block_start",
                r#"{"index":1,"content_block":{"type":"tool_use","id":"tu_y","name":"read_scrollback","input":{}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":1,"delta":{"type":"input_json_delta","partial_json":"{\"session_id\":\"s1\"}"}}"#,
            ),
            ev("content_block_stop", r#"{"index":1}"#),
            ev(
                "message_delta",
                r#"{"delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":11}}"#,
            ),
            ev("message_stop", r#"{}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut text = String::new();
        let mut tool_use = None;
        while let Some(item) = s.next().await {
            match item.unwrap() {
                LlmStreamEvent::TextDelta(t) => text.push_str(&t),
                LlmStreamEvent::ToolUseComplete { id, .. } => tool_use = Some(id),
                LlmStreamEvent::Completed(_) => {}
            }
        }
        assert_eq!(text, "checking vEX1");
        assert_eq!(tool_use, Some("tu_y".to_string()));
    }

    #[tokio::test]
    async fn invalid_partial_json_at_stop_emits_malformed() {
        let events = futures::stream::iter(vec![
            ev(
                "message_start",
                r#"{"message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}"#,
            ),
            ev(
                "content_block_start",
                r#"{"index":0,"content_block":{"type":"tool_use","id":"tu_z","name":"read_scrollback","input":{}}}"#,
            ),
            ev(
                "content_block_delta",
                r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{not-json"}}"#,
            ),
            ev("content_block_stop", r#"{"index":0}"#),
        ]);
        let mut s = parse_anthropic_stream(events).boxed();
        let mut got_malformed = false;
        while let Some(item) = s.next().await {
            if let Err(LlmError::Malformed(m)) = item {
                assert!(m.contains("read_scrollback"));
                got_malformed = true;
            }
        }
        assert!(got_malformed);
    }
}
