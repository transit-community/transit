//! OpenAI **Responses API** request/stream translation. The
//! [`crate::llm::LlmClient`] impl that owns the HTTP call lives in
//! `direct.rs` (`DirectOpenAI`); this module is the pure half.
//!
//! GPT-5.6 (Sol/Terra) are reasoning-first models; OpenAI's Chat
//! Completions API forbids function tools + reasoning together, which
//! forced `reasoning_effort: "none"` and made the agent loop fail to
//! converge (it re-ran the same tool plan without observing results).
//! The Responses API is the only endpoint that allows tools +
//! reasoning at once, so this client speaks it natively: it translates
//! [`crate::llm::LlmRequest`] into the Responses request shape
//! (`input` items, top-level `instructions`, flattened `tools`,
//! `reasoning.effort`), and decodes the `response.*` server-sent
//! events into [`crate::llm::LlmStreamEvent`], reading per-turn usage
//! off the terminal `response.completed` event. The trait surface
//! (mod.rs), the agent loop, and `Conversation` are unchanged — a
//! Responses `call_id` maps straight onto our provider-agnostic
//! tool-use `id`.

use futures::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::json;

#[cfg(test)]
use crate::llm::ToolUseBlock;
use crate::llm::{LlmError, LlmMessage, LlmRequest, LlmResult, LlmStreamEvent, ToolSchema};
use crate::usage::TokenUsage;
use std::collections::HashMap;

/// Reasoning effort for GPT-5.6 agent turns. Reasoning tokens bill at
/// the OUTPUT rate (e.g. $30/MTok on Sol), so effort is a direct cost
/// knob — `"low"` is the cheapest setting that restores agentic
/// convergence (reasoning at all is what stops the read-scrollback
/// loop). The rounds/cost checkpoint + tier budget bound runaway;
/// bump to `"medium"` only if smoke shows `"low"` under-reasons.
const REASONING_EFFORT: &str = "low";

/// `plan` = the request rides a ChatGPT plan token (Sign in with ChatGPT)
/// rather than an API key. The plan path rejects a documented set of
/// fields — `max_output_tokens` is the one this body otherwise sets — so
/// those are omitted in plan mode. `store:false` + `stream:true` are
/// required there and already always sent.
pub(crate) fn build_openai_body(req: &LlmRequest, plan: bool) -> serde_json::Value {
    // Responses API takes an `input` array of items. Plain turns are
    // `{role, content}` messages; a tool CALL is a `function_call`
    // item and a tool RESULT is a `function_call_output` item, both
    // correlated to the call by `call_id` (which is our provider-
    // agnostic tool-use `id`). The system prompt is NOT an input item
    // here — it goes in the top-level `instructions` field below.
    let mut input = Vec::with_capacity(req.messages.len());
    for m in &req.messages {
        match m {
            LlmMessage::User(t) => input.push(json!({"role": "user", "content": t})),
            LlmMessage::Assistant(t) => input.push(json!({"role": "assistant", "content": t})),
            LlmMessage::AssistantWithTools { text, tool_uses } => {
                // Optional assistant prose precedes its tool calls;
                // omit the message item entirely on a pure tool-call
                // turn (Responses has no `content: null` convention).
                if let Some(t) = text.as_deref() {
                    if !t.is_empty() {
                        input.push(json!({"role": "assistant", "content": t}));
                    }
                }
                for tu in tool_uses {
                    input.push(json!({
                        "type": "function_call",
                        "call_id": tu.id,
                        "name": tu.name,
                        // Responses wants `arguments` as a JSON STRING.
                        "arguments": tu.input.to_string(),
                    }));
                }
            }
            LlmMessage::ToolResult {
                tool_use_id,
                content,
                is_error: _,
            } => {
                // Responses' function_call_output has no is_error flag;
                // the model reads failure from the content string (the
                // dispatcher writes a clear error prefix, e.g. "policy
                // gate denied: …"), same as the old chat path.
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": tool_use_id,
                    "output": content,
                }));
            }
        }
    }

    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(req.model));
    body.insert("input".into(), json!(input));
    body.insert("stream".into(), json!(true));
    // Stateless: we replay the full `input` each turn, so we don't want
    // OpenAI retaining prior responses (no `previous_response_id`).
    body.insert("store".into(), json!(false));
    // Tools + reasoning together — the whole reason for the Responses
    // path. Effort is a cost knob (see REASONING_EFFORT).
    body.insert("reasoning".into(), json!({ "effort": REASONING_EFFORT }));
    if let Some(sys) = &req.system {
        // System prompt → top-level `instructions`. Bytes match
        // SystemPrompt::render()/as_plain_text(), preserving the
        // auto-cache prefix OpenAI detects on repeated instructions.
        body.insert("instructions".into(), json!(sys.as_plain_text()));
    }
    if let Some(mt) = req.max_tokens {
        // Chat Completions' `max_tokens` is `max_output_tokens` here. The
        // ChatGPT-plan path rejects the field (preview limitation), so it
        // is omitted there; the loop's own round/token accounting still
        // bounds the turn.
        if !plan {
            body.insert("max_output_tokens".into(), json!(mt));
        }
    }
    if let Some(tools) = &req.tools {
        body.insert("tools".into(), json!(openai_tools(tools)));
    }
    serde_json::Value::Object(body)
}

/// Translate the trait-level `ToolSchema` list into the Responses
/// tool shape — FLATTENED `{type:"function", name, description,
/// parameters}` (Chat Completions nested these under `function:{}`).
/// `ToolSchema.input_schema` maps to `parameters` directly.
fn openai_tools(tools: &[ToolSchema]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "name": t.name,
                "description": t.description,
                "parameters": t.input_schema,
            })
        })
        .collect()
}

/// A function call under assembly, keyed by the Responses output-item
/// `id`. `call_id` is the stable identifier we emit as the tool-use
/// `id` (it correlates the later `function_call_output`); `name` +
/// `arguments` are seeded from `response.output_item.added` and the
/// `arguments` string is appended by `function_call_arguments.delta`.
struct PendingToolCall {
    call_id: String,
    name: String,
    arguments: String,
}

/// Convert an OpenAI event stream into the trait-level
/// [`LlmStreamEvent`]. Generic over the underlying byte-stream error
/// type so this function is reusable from tests with synthetic
/// streams.
pub(crate) fn parse_openai_stream<S, E>(
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
        /// Function calls under assembly, keyed by Responses output-item
        /// `id`. `response.output_item.added` seeds {call_id, name};
        /// `response.function_call_arguments.delta` appends args;
        /// `response.output_item.done` finalizes one into the queue.
        pending_tools: HashMap<String, PendingToolCall>,
        /// Tool-use events queued for emission. `output_item.done`
        /// fires once per completed function call, and we can't return
        /// more than one event per `unfold` step, so finalization
        /// stages the queue and the loop drains it one per yield.
        emit_queue: std::collections::VecDeque<LlmStreamEvent>,
    }
    let init = State {
        events,
        usage: TokenUsage::default(),
        done: false,
        completed_emitted: false,
        pending_tools: HashMap::new(),
        emit_queue: std::collections::VecDeque::new(),
    };
    stream::unfold(init, |mut state| async move {
        if state.done {
            return None;
        }
        loop {
            // Drain any queued tool-use events first — the previous
            // chunk may have finalized multiple tools at once.
            if let Some(out) = state.emit_queue.pop_front() {
                return Some((Ok(out), state));
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
                Some(Ok(ev)) => {
                    // Responses ends by simply closing the stream after
                    // `response.completed`; some gateways also emit a
                    // `[DONE]` sentinel. Treat it as end-of-stream: fine
                    // if we already saw `response.completed`, else a
                    // regression worth surfacing rather than zeroing.
                    if ev.data == "[DONE]" {
                        state.done = true;
                        if state.completed_emitted {
                            return None;
                        }
                        return Some((Err(LlmError::EarlyEnd), state));
                    }
                    match handle_openai_chunk(
                        &ev.data,
                        &mut state.usage,
                        &mut state.pending_tools,
                        &mut state.emit_queue,
                    ) {
                        Ok(OpenAiOutcome::Text(t)) => {
                            return Some((Ok(LlmStreamEvent::TextDelta(t)), state));
                        }
                        Ok(OpenAiOutcome::UsageFinal) => {
                            state.completed_emitted = true;
                            return Some((Ok(LlmStreamEvent::Completed(state.usage)), state));
                        }
                        Ok(OpenAiOutcome::None) => continue,
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

#[derive(Debug)]
enum OpenAiOutcome {
    Text(String),
    UsageFinal,
    None,
}

fn handle_openai_chunk(
    data: &str,
    usage: &mut TokenUsage,
    pending_tools: &mut HashMap<String, PendingToolCall>,
    emit_queue: &mut std::collections::VecDeque<LlmStreamEvent>,
) -> LlmResult<OpenAiOutcome> {
    let ev: RespEvent = serde_json::from_str(data)
        .map_err(|e| LlmError::Malformed(format!("responses event: {e}: {data}")))?;
    match ev.kind.as_str() {
        // Assistant prose token.
        "response.output_text.delta" => {
            if let Some(delta) = ev.delta {
                return Ok(OpenAiOutcome::Text(delta));
            }
            Ok(OpenAiOutcome::None)
        }
        // A new output item begins. Seed a PendingToolCall for
        // function_call items (carries call_id + name; arguments
        // usually stream in via the deltas below, but seed any that
        // arrived here for zero-arg calls).
        "response.output_item.added" => {
            if let Some(item) = ev.item {
                if item.kind.as_deref() == Some("function_call") {
                    if let (Some(id), Some(call_id), Some(name)) =
                        (item.id, item.call_id, item.name)
                    {
                        pending_tools.insert(
                            id,
                            PendingToolCall {
                                call_id,
                                name,
                                arguments: item.arguments.unwrap_or_default(),
                            },
                        );
                    }
                }
            }
            Ok(OpenAiOutcome::None)
        }
        // Streamed function-call arguments, keyed by the item id.
        "response.function_call_arguments.delta" => {
            if let (Some(item_id), Some(delta)) = (ev.item_id, ev.delta) {
                if let Some(p) = pending_tools.get_mut(&item_id) {
                    p.arguments.push_str(&delta);
                }
            }
            Ok(OpenAiOutcome::None)
        }
        // An output item finished. For a function_call, finalize it:
        // resolve name/args (prefer the streamed accumulator, fall
        // back to the item's own fields), parse args, queue a
        // ToolUseComplete keyed by call_id (our tool-use id).
        "response.output_item.done" => {
            let Some(item) = ev.item else {
                return Ok(OpenAiOutcome::None);
            };
            if item.kind.as_deref() != Some("function_call") {
                return Ok(OpenAiOutcome::None);
            }
            let pending = item.id.as_ref().and_then(|id| pending_tools.remove(id));
            let call_id = pending
                .as_ref()
                .map(|p| p.call_id.clone())
                .or(item.call_id)
                .ok_or_else(|| {
                    LlmError::Malformed("responses function_call missing call_id".into())
                })?;
            let name = pending
                .as_ref()
                .map(|p| p.name.clone())
                .or(item.name)
                .ok_or_else(|| {
                    LlmError::Malformed("responses function_call missing name".into())
                })?;
            // Prefer streamed args; else the item's own; else empty → {}.
            let raw = pending
                .map(|p| p.arguments)
                .filter(|a| !a.is_empty())
                .or(item.arguments)
                .filter(|a| !a.is_empty())
                .unwrap_or_else(|| "{}".to_string());
            let input: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                LlmError::Malformed(format!(
                    "responses function_call arguments ({name}): {e}: {raw}"
                ))
            })?;
            emit_queue.push_back(LlmStreamEvent::ToolUseComplete {
                id: call_id,
                name,
                input,
            });
            Ok(OpenAiOutcome::None)
        }
        // Terminal events — usage lives at `response.usage`.
        //
        // `response.incomplete` (v6.1.1) is the Responses API's "hit
        // max_output_tokens" terminal: with the per-turn token ceiling
        // now always sent (and reasoning tokens sharing that budget), a
        // long turn can end incomplete. Treat it as a normal completion
        // of whatever text/tool-calls already streamed — dropping it to
        // the `_` arm would leave the stream Completed-less and surface
        // the WHOLE turn as a provider error (`EarlyEnd`), losing output
        // the user already paid for.
        "response.completed" | "response.incomplete" => {
            if let Some(u) = ev.response.and_then(|r| r.usage) {
                let input_total = u.input_tokens.unwrap_or(0);
                let cached = u
                    .input_tokens_details
                    .as_ref()
                    .and_then(|d| d.cached_tokens)
                    .unwrap_or(0);
                usage.input_cache_read = cached;
                // Responses reports no cache-WRITE count; those tokens
                // fall into `input_uncached` (1× not 1.25× — small,
                // safe under-count). Cost is internal-only anyway.
                usage.input_cache_write = 0;
                usage.input_uncached = input_total.saturating_sub(cached);
                // `output_tokens` INCLUDES reasoning tokens as a subset
                // — billing on `output` captures reasoning; do NOT add
                // output_tokens_details.reasoning_tokens on top.
                usage.output = u.output_tokens.unwrap_or(0);
            }
            Ok(OpenAiOutcome::UsageFinal)
        }
        // A terminal failure. The ChatGPT-plan path reports its cap /
        // eligibility / auth outcomes here with a stable `error.code`;
        // map those to typed errors so the shell can route UX. Anything
        // else surfaces as a provider error with the message.
        "response.failed" | "error" => {
            let (code, message) = ev
                .response
                .and_then(|r| r.error)
                .or(ev.error)
                .map(|e| (e.code.unwrap_or_default(), e.message.unwrap_or_default()))
                .unwrap_or_default();
            Err(plan_error_for_code(&code, &message).unwrap_or_else(|| {
                LlmError::Malformed(format!("response failed: {code} {message}"))
            }))
        }
        // response.created / .in_progress / content_part.* / other —
        // nothing we surface.
        _ => Ok(OpenAiOutcome::None),
    }
}

/// A generic Responses server-sent event. Every event carries a
/// `type`; the other fields are populated per-type (serde leaves the
/// rest `None`). This one struct covers the handful of event kinds we
/// act on — text deltas, function-call lifecycle, and the terminal
/// usage — and ignores the many we don't.
#[derive(Deserialize)]
struct RespEvent {
    #[serde(rename = "type")]
    kind: String,
    /// `output_text.delta` text, or `function_call_arguments.delta` args.
    delta: Option<String>,
    /// `function_call_arguments.delta` output-item id.
    item_id: Option<String>,
    /// `output_item.added` / `output_item.done` item.
    item: Option<RespItem>,
    /// `response.completed` payload (holds usage), or the
    /// `response.failed` payload (holds `error`).
    response: Option<RespCompleted>,
    /// Top-level `error` event payload.
    error: Option<RespError>,
}

#[derive(Deserialize, Default)]
struct RespError {
    code: Option<String>,
    message: Option<String>,
}

/// Map a Sign-in-with-ChatGPT error code (status body or stream event)
/// to its typed error; `None` for any other code.
pub(crate) fn plan_error_for_code(code: &str, message: &str) -> Option<LlmError> {
    match code {
        "subscription_sharing_usage_limit_exceeded" => Some(LlmError::PlanCapReached),
        "subscription_sharing_user_not_eligible" => Some(LlmError::PlanNotEligible),
        "subscription_sharing_invalid_user"
        | "chatpass_v2_scope_not_authorized"
        | "chatpass_v2_invalid_authorization_context" => Some(LlmError::PlanReauthRequired),
        "subscription_sharing_unsupported_capability"
        | "subscription_sharing_route_not_supported" => Some(LlmError::PlanUnsupported {
            message: message.to_string(),
        }),
        _ => None,
    }
}
#[derive(Deserialize)]
struct RespItem {
    #[serde(rename = "type")]
    kind: Option<String>,
    id: Option<String>,
    call_id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
}
#[derive(Deserialize)]
struct RespCompleted {
    usage: Option<RespUsage>,
    error: Option<RespError>,
}
#[derive(Deserialize)]
struct RespUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    input_tokens_details: Option<RespInputTokensDetails>,
}
#[derive(Deserialize)]
struct RespInputTokensDetails {
    cached_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use eventsource_stream::Event;
    use futures::StreamExt;
    use std::convert::Infallible;

    fn ev(data: &str) -> Result<Event, eventsource_stream::EventStreamError<Infallible>> {
        Ok(Event {
            event: String::new(),
            data: data.to_string(),
            id: String::new(),
            retry: None,
        })
    }

    #[test]
    fn build_body_puts_system_in_instructions_not_input() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: Some("you are concise".into()),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: Some(100),
            tools: None,
        };
        let body = build_openai_body(&req, false);
        // System → top-level instructions (Responses shape), NOT an input item.
        assert_eq!(body.get("instructions").unwrap(), "you are concise");
        let input = body.get("input").unwrap().as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].get("role").unwrap(), "user");
        // max_tokens → max_output_tokens.
        assert_eq!(body.get("max_output_tokens").unwrap(), &json!(100));
    }

    #[test]
    fn build_body_sets_stream_store_and_reasoning() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_openai_body(&req, false);
        assert_eq!(body.get("stream").unwrap(), &json!(true));
        // Stateless — no server-side retention.
        assert_eq!(body.get("store").unwrap(), &json!(false));
        // Tools + reasoning together is the whole point of this path.
        assert_eq!(body.get("reasoning").unwrap().get("effort").unwrap(), "low");
        // No Chat-Completions leftovers.
        assert!(body.get("stream_options").is_none());
        assert!(body.get("messages").is_none());
    }

    #[test]
    fn build_body_omits_max_output_tokens_if_unset() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: None,
        };
        let body = build_openai_body(&req, false);
        assert!(body.get("max_output_tokens").is_none());
    }

    /// The ChatGPT-plan path (preview) rejects `max_output_tokens` and
    /// requires `store:false` + `stream:true`; pin the body shape so a
    /// future edit can't reintroduce a forbidden field there.
    #[test]
    fn plan_mode_omits_forbidden_fields_and_keeps_required_ones() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: Some("sys".into()),
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: Some(2048),
            tools: None,
        };
        let plan = build_openai_body(&req, true);
        assert!(plan.get("max_output_tokens").is_none());
        for forbidden in [
            "temperature",
            "top_p",
            "truncation",
            "user",
            "metadata",
            "prompt_cache_retention",
            "background",
            "conversation",
        ] {
            assert!(plan.get(forbidden).is_none(), "{forbidden} must be absent");
        }
        assert_eq!(plan.get("store").unwrap(), &json!(false));
        assert_eq!(plan.get("stream").unwrap(), &json!(true));
        assert!(plan.get("input").unwrap().is_array());
        assert_eq!(plan.get("instructions").unwrap(), "sys");
        // API-key mode still sends the ceiling.
        let key = build_openai_body(&req, false);
        assert_eq!(key.get("max_output_tokens").unwrap(), &json!(2048));
    }

    #[test]
    fn response_failed_event_maps_plan_codes() {
        let mut usage = TokenUsage::default();
        let mut pending = HashMap::new();
        let mut q = std::collections::VecDeque::new();
        let cap = r#"{"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"cap"}}}"#;
        let err = handle_openai_chunk(cap, &mut usage, &mut pending, &mut q).unwrap_err();
        assert!(matches!(err, LlmError::PlanCapReached), "{err}");
        let reauth = r#"{"type":"error","error":{"code":"subscription_sharing_invalid_user","message":"x"}}"#;
        let err = handle_openai_chunk(reauth, &mut usage, &mut pending, &mut q).unwrap_err();
        assert!(matches!(err, LlmError::PlanReauthRequired), "{err}");
        let other = r#"{"type":"response.failed","response":{"error":{"code":"server_error","message":"boom"}}}"#;
        let err = handle_openai_chunk(other, &mut usage, &mut pending, &mut q).unwrap_err();
        assert!(
            matches!(err, LlmError::Malformed(ref m) if m.contains("boom")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn parses_text_deltas_and_usage() {
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.created","response":{"id":"r1"}}"#),
            ev(r#"{"type":"response.output_text.delta","delta":"Hello"}"#),
            ev(r#"{"type":"response.output_text.delta","delta":" world"}"#),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":12,"output_tokens":4,"input_tokens_details":{"cached_tokens":8}}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
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
        // input_tokens 12, cached 8 → 4 uncached.
        assert_eq!(u.input_uncached, 4);
        assert_eq!(u.input_cache_read, 8);
        assert_eq!(u.input_cache_write, 0);
        assert_eq!(u.output, 4);
    }

    #[tokio::test]
    async fn reasoning_tokens_are_billed_within_output_not_added() {
        // Responses `output_tokens` INCLUDES reasoning tokens as a
        // subset (here 30 of 50). We bill on `output` = 50; we must NOT
        // add reasoning on top (which would over-count to 80).
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.output_text.delta","delta":"hi"}"#),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":20,"output_tokens":50,"input_tokens_details":{"cached_tokens":8},"output_tokens_details":{"reasoning_tokens":30}}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut final_usage = None;
        while let Some(item) = s.next().await {
            if let Ok(LlmStreamEvent::Completed(u)) = item {
                final_usage = Some(u);
            }
        }
        let u = final_usage.expect("Completed event");
        assert_eq!(u.output, 50); // includes reasoning, not 80
        assert_eq!(u.input_uncached, 12); // 20 - 8 cached
        assert_eq!(u.input_cache_read, 8);
        assert_eq!(u.input_cache_write, 0); // Responses has no write count
    }

    #[tokio::test]
    async fn response_incomplete_is_a_truncated_but_usable_turn() {
        // v6.1.1 — with the per-turn token ceiling always sent (and
        // reasoning tokens sharing max_output_tokens), a long turn can
        // terminate with `response.incomplete`. That must complete the
        // stream with the text that already arrived — NOT fall through
        // to the `_` arm and surface the whole turn as EarlyEnd.
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.output_text.delta","delta":"partial answ"}"#),
            ev(
                r#"{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":10,"output_tokens":4096}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut texts = Vec::new();
        let mut final_usage = None;
        while let Some(item) = s.next().await {
            match item.unwrap() {
                LlmStreamEvent::TextDelta(t) => texts.push(t),
                LlmStreamEvent::Completed(u) => final_usage = Some(u),
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert_eq!(texts.join(""), "partial answ");
        let u = final_usage.expect("incomplete must still complete the stream");
        assert_eq!(u.output, 4096);
    }

    #[tokio::test]
    async fn stream_end_before_completed_is_early_end() {
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.output_text.delta","delta":"part"}"#),
            // stream just ends — no response.completed
        ]);
        let mut s = parse_openai_stream(events).boxed();
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
    async fn malformed_event_data_surfaces_as_error() {
        let events = futures::stream::iter(vec![ev(r#"{not-json"#)]);
        let mut s = parse_openai_stream(events).boxed();
        match s.next().await.unwrap() {
            Err(LlmError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_cached_tokens_treats_all_input_as_uncached() {
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.output_text.delta","delta":"a"}"#),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":10,"output_tokens":3}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut final_usage = None;
        while let Some(item) = s.next().await {
            if let Ok(LlmStreamEvent::Completed(u)) = item {
                final_usage = Some(u);
            }
        }
        let u = final_usage.unwrap();
        assert_eq!(u.input_uncached, 10);
        assert_eq!(u.input_cache_read, 0);
        assert_eq!(u.output, 3);
    }

    // ----- Tool use (Phase 6 C3, Responses shape) ----------------------

    fn tool_schema(name: &str) -> ToolSchema {
        ToolSchema {
            name: name.into(),
            description: format!("desc for {name}"),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    #[test]
    fn build_body_serializes_tools_flattened() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: None,
            messages: vec![LlmMessage::User("hi".into())],
            max_tokens: None,
            tools: Some(vec![tool_schema("read_scrollback")]),
        };
        let body = build_openai_body(&req, false);
        let tools = body.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 1);
        // Responses flattens: name/description/parameters are top-level
        // on the tool, NOT nested under `function`.
        assert_eq!(tools[0].get("type").unwrap(), "function");
        assert_eq!(tools[0].get("name").unwrap(), "read_scrollback");
        assert_eq!(
            tools[0].get("description").unwrap(),
            "desc for read_scrollback"
        );
        assert!(tools[0].get("parameters").is_some());
        assert!(tools[0].get("function").is_none());
    }

    #[test]
    fn build_body_translates_tools_to_responses_items() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: None,
            messages: vec![
                LlmMessage::User("look up sessions".into()),
                LlmMessage::AssistantWithTools {
                    text: None,
                    tool_uses: vec![ToolUseBlock {
                        id: "call_1".into(),
                        name: "list_open_sessions".into(),
                        input: json!({}),
                    }],
                },
                LlmMessage::ToolResult {
                    tool_use_id: "call_1".into(),
                    content: "[{\"id\":\"s1\"}]".into(),
                    is_error: false,
                },
            ],
            max_tokens: None,
            tools: None,
        };
        let body = build_openai_body(&req, false);
        let input = body.get("input").unwrap().as_array().unwrap();
        // user message + function_call item + function_call_output item.
        // The pure tool-call assistant turn adds NO message item.
        assert_eq!(input.len(), 3);
        assert_eq!(input[0].get("role").unwrap(), "user");
        // The tool call → function_call item keyed by call_id.
        assert_eq!(input[1].get("type").unwrap(), "function_call");
        assert_eq!(input[1].get("call_id").unwrap(), "call_1");
        assert_eq!(input[1].get("name").unwrap(), "list_open_sessions");
        // arguments is a JSON STRING (Responses shape).
        assert_eq!(input[1].get("arguments").unwrap(), "{}");
        // The tool result → function_call_output item, same call_id.
        assert_eq!(input[2].get("type").unwrap(), "function_call_output");
        assert_eq!(input[2].get("call_id").unwrap(), "call_1");
        assert_eq!(input[2].get("output").unwrap(), "[{\"id\":\"s1\"}]");
    }

    #[test]
    fn build_body_keeps_assistant_prose_before_tool_calls() {
        let req = LlmRequest {
            model: "gpt-5.6-sol".into(),
            system: None,
            messages: vec![LlmMessage::AssistantWithTools {
                text: Some("let me check".into()),
                tool_uses: vec![ToolUseBlock {
                    id: "c1".into(),
                    name: "list_open_sessions".into(),
                    input: json!({}),
                }],
            }],
            max_tokens: None,
            tools: None,
        };
        let body = build_openai_body(&req, false);
        let input = body.get("input").unwrap().as_array().unwrap();
        // assistant prose message + the function_call item.
        assert_eq!(input.len(), 2);
        assert_eq!(input[0].get("role").unwrap(), "assistant");
        assert_eq!(input[0].get("content").unwrap(), "let me check");
        assert_eq!(input[1].get("type").unwrap(), "function_call");
    }

    #[tokio::test]
    async fn parses_streamed_tool_call_and_emits_tool_use_complete() {
        // output_item.added seeds call_id+name; arguments stream in via
        // deltas keyed by the item id; output_item.done finalizes.
        let events = futures::stream::iter(vec![
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc_1","type":"function_call","call_id":"call_x","name":"read_scrollback","arguments":""}}"#,
            ),
            ev(
                r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"session_id\""}"#,
            ),
            ev(
                r#"{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":":\"s1\"}"}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc_1","type":"function_call","call_id":"call_x","name":"read_scrollback"}}"#,
            ),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":10,"output_tokens":4}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
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
        // The emitted id is the call_id (correlates the tool result).
        assert_eq!(id, "call_x");
        assert_eq!(name, "read_scrollback");
        assert_eq!(input.get("session_id").unwrap(), "s1");
        assert!(completed);
    }

    #[tokio::test]
    async fn parses_two_tool_calls_in_call_order() {
        let events = futures::stream::iter(vec![
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc0","type":"function_call","call_id":"c0","name":"read_scrollback","arguments":"{\"session_id\":\"s1\"}"}}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc0","type":"function_call","call_id":"c0","name":"read_scrollback","arguments":"{\"session_id\":\"s1\"}"}}"#,
            ),
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc1","type":"function_call","call_id":"c1","name":"read_scrollback","arguments":"{\"session_id\":\"s2\"}"}}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc1","type":"function_call","call_id":"c1","name":"read_scrollback","arguments":"{\"session_id\":\"s2\"}"}}"#,
            ),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":2,"output_tokens":1}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut ids = Vec::new();
        while let Some(item) = s.next().await {
            if let LlmStreamEvent::ToolUseComplete { id, .. } = item.unwrap() {
                ids.push(id);
            }
        }
        assert_eq!(ids, vec!["c0".to_string(), "c1".to_string()]);
    }

    #[tokio::test]
    async fn empty_args_function_call_finalizes_as_empty_object() {
        // A no-argument tool: no delta events, output_item carries "".
        let events = futures::stream::iter(vec![
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc","type":"function_call","call_id":"c","name":"list_open_sessions","arguments":""}}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc","type":"function_call","call_id":"c","name":"list_open_sessions","arguments":""}}"#,
            ),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut input = None;
        while let Some(item) = s.next().await {
            if let LlmStreamEvent::ToolUseComplete { input: i, .. } = item.unwrap() {
                input = Some(i);
            }
        }
        assert_eq!(input.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn parses_text_then_tool_call_in_same_turn() {
        let events = futures::stream::iter(vec![
            ev(r#"{"type":"response.output_text.delta","delta":"checking…"}"#),
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc","type":"function_call","call_id":"c","name":"list_open_sessions","arguments":"{}"}}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc","type":"function_call","call_id":"c","name":"list_open_sessions","arguments":"{}"}}"#,
            ),
            ev(
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":2}}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
        let mut text = String::new();
        let mut got_tool = false;
        while let Some(item) = s.next().await {
            match item.unwrap() {
                LlmStreamEvent::TextDelta(t) => text.push_str(&t),
                LlmStreamEvent::ToolUseComplete { name, .. } => {
                    assert_eq!(name, "list_open_sessions");
                    got_tool = true;
                }
                LlmStreamEvent::Completed(_) => {}
            }
        }
        assert_eq!(text, "checking…");
        assert!(got_tool);
    }

    #[tokio::test]
    async fn malformed_tool_call_arguments_surfaces_as_error() {
        let events = futures::stream::iter(vec![
            ev(
                r#"{"type":"response.output_item.added","item":{"id":"fc","type":"function_call","call_id":"c","name":"read_scrollback","arguments":""}}"#,
            ),
            ev(
                r#"{"type":"response.function_call_arguments.delta","item_id":"fc","delta":"{not-json"}"#,
            ),
            ev(
                r#"{"type":"response.output_item.done","item":{"id":"fc","type":"function_call","call_id":"c","name":"read_scrollback"}}"#,
            ),
        ]);
        let mut s = parse_openai_stream(events).boxed();
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
