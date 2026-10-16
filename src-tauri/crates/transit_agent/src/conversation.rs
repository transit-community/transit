//! Chat-history container — the dynamic state that Phase 6's loop
//! drives turn by turn.
//!
//! `Conversation` is intentionally narrow: it owns the message log,
//! the scrollback source, the dispatcher, the per-Conversation
//! redactor (`Arc<Mutex<>>` shared with the dispatcher), the policy
//! summaries that feed the system prompt, and the cumulative
//! `TokenUsage`. It exposes:
//!
//! - `record_user(text)` / `record_assistant_text(text)` — append
//!   chat messages.
//! - `dispatch_tool(call) -> Result<ToolResult, AgentError>` — runs
//!   a tool through the dispatcher, recording the call and its
//!   result (success or stringified error) as messages.
//! - `system_prompt() -> SystemPrompt` — builds the cache-aware
//!   prompt structure from the live ScrollbackSource state.
//! - `messages() -> &[Message]` — read-only chronological view.
//! - `usage` — cumulative `TokenUsage`, public for Phase 6 to
//!   accumulate per-turn deltas.
//!
//! There is **no** `LlmClient` here. Phase 5d defines the trait when
//! there's a real cloud client to plug in; until then, tests drive
//! turns directly via `record_*` and `dispatch_tool`.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use transit_core::inventory::Vendor;
use transit_policy::PolicySummary;

use crate::capture::CaptureSource;
use crate::dispatcher::ToolDispatcher;
use crate::error::AgentError;
use crate::llm::{LlmMessage, ToolUseBlock};
use crate::redaction::ConversationRedactor;
use crate::scrollback::ScrollbackSource;
use crate::system_prompt::{self, SystemPrompt};
use crate::tools::{ToolCall, ToolResult};
use crate::usage::TokenUsage;

#[derive(Debug, Clone)]
pub enum Message {
    User {
        text: String,
        at: SystemTime,
    },
    Assistant {
        text: String,
        at: SystemTime,
    },
    /// Phase 5b path: `Conversation::dispatch_tool` records this when
    /// a ToolCall is dispatched directly (no surrounding LlmClient
    /// turn). `to_llm_messages()` skips this variant — only the
    /// AgentLoop-recorded `AssistantWithTools` + id-tagged
    /// `ToolResult` pairs cross the LlmClient boundary.
    ToolCall {
        call: ToolCall,
        at: SystemTime,
    },
    /// Phase 6 path: `AgentLoop` records this when the model's
    /// assistant turn included one or more `tool_use` blocks. The
    /// `tool_uses` carry the model-supplied ids that subsequent
    /// `ToolResult` messages match against. `text` is any prose the
    /// model emitted alongside the tools (often empty).
    AssistantWithTools {
        text: Option<String>,
        tool_uses: Vec<ToolUseBlock>,
        at: SystemTime,
    },
    /// `Result<ToolResult, String>` — the error case is stringified
    /// because `AgentError` doesn't impl `Clone` and we want
    /// `Conversation` snapshots to be cheap to clone.
    ///
    /// Phase 6: `tool_use_id` matches a `ToolUseBlock.id` from the
    /// preceding `AssistantWithTools` turn. `is_error` is set when
    /// the dispatcher returned an `AgentError` so the LLM-side
    /// translation can flip the right flag (Anthropic carries
    /// `is_error` on the tool_result block; OpenAI inlines into
    /// content).
    ///
    /// Phase 5b path leaves `tool_use_id: None` and `is_error`
    /// inferred from `result` — the loop translator skips those
    /// records when building the LlmMessage list.
    ToolResult {
        tool_use_id: Option<String>,
        result: Result<ToolResult, String>,
        is_error: bool,
        at: SystemTime,
    },
}

/// Tool-result messages newer than this many (counting only bulky
/// `ReadScrollback`/`ProposeCommand` device-output results) stay
/// verbatim in [`Conversation::to_llm_messages`]; older ones are
/// pruning candidates.
const RECENT_TOOL_RESULTS_VERBATIM: usize = 6;

/// A pruning candidate is only collapsed if its serialized content
/// exceeds this — small old results aren't worth a breadcrumb.
const PRUNE_MIN_BYTES: usize = 2 * 1024;

/// Build a mechanical, device-byte-free breadcrumb for a pruned bulky
/// tool result. `orig_bytes` is the serialized length we collapsed.
/// The model is told it can re-read — the device still holds the
/// scrollback, so nothing is truly lost.
///
/// v6.1.x — the breadcrumb carries the BINDING (session, device, and the
/// command/path that produced the output) inline. Everything echoed here
/// is either Transit-authored (device name from inventory) or the
/// model's OWN prior tool input, which survives pruning in the adjacent
/// `tool_use` block anyway — this is a locality fix (models don't
/// reliably join breadcrumb→tool_use pairs across a long thread), not a
/// new information channel. No device bytes: §9 unaffected.
fn prune_breadcrumb(
    result: &Result<ToolResult, String>,
    orig_bytes: usize,
    binding: &str,
) -> String {
    match result {
        Ok(ToolResult::ReadScrollback(o)) => format!(
            "[Transit pruned an earlier read_scrollback result{binding}: {orig_bytes} bytes \
             elided to save context (truncated={}). Re-run read_scrollback on this session to \
             see it again.]",
            o.truncated
        ),
        Ok(ToolResult::ProposeCommand(o)) => format!(
            "[Transit pruned an earlier command output{binding}: {orig_bytes} bytes elided to \
             save context (executed={}). The full output is in the device scrollback — re-run \
             read_scrollback on this session to recover it.]",
            o.executed
        ),
        Ok(ToolResult::ProposeApiCall(o)) => format!(
            "[Transit pruned an earlier API response{binding}: {orig_bytes} bytes elided to save \
             context (executed={}). Re-run read_scrollback on this API session to see it again.]",
            o.executed
        ),
        // A capture answer is cheap to reproduce — the index is still
        // open and the query is deterministic — so the breadcrumb says
        // so rather than implying the information is gone.
        Ok(ToolResult::QueryCapture(o)) => format!(
            "[Transit pruned an earlier query_capture result: {orig_bytes} bytes elided to save \
             context (truncated={}). Re-run the same query_capture call to see it again.]",
            o.truncated
        ),
        // Only ReadScrollback/ProposeCommand/ProposeApiCall are pruning
        // candidates; other kinds never reach here.
        _ => format!("[Transit pruned an earlier tool result: {orig_bytes} bytes elided.]"),
    }
}

/// The `" on s3 (R4), command `show route`"` clause for a pruned
/// result's breadcrumb, derived from the model's own paired tool INPUT
/// plus the roster's device name. Empty when the input isn't available
/// (Phase 5b-style results with no recorded pairing).
fn breadcrumb_binding(
    input: Option<&serde_json::Value>,
    alias_device: &std::collections::HashMap<String, String>,
    raw_device: &std::collections::HashMap<String, String>,
) -> String {
    let Some(input) = input else {
        return String::new();
    };
    let Some(sess) = input.get("session_id").and_then(|v| v.as_str()) else {
        return String::new();
    };
    // Every echoed value is model-controlled (the session_id and
    // command/path came off the model's own tool call). This is a
    // Transit-VOICED line the injection guard tells the model to trust,
    // so each field is clamped AND stripped of characters that could
    // forge a second `[Transit …]` breadcrumb or blow past PRUNE_MIN
    // (an unbounded id would grow the transcript pruning exists to
    // shrink). Same defense class as `envelope_attr_safe`.
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_control() && !matches!(c, '[' | ']' | '`'))
            .take(48)
            .collect()
    };
    let mut out = format!(" on {}", clean(sess));
    // Resolve device alias-map FIRST, raw id SECOND (mirrors the
    // dispatcher's resolution precedence — a flattened last-write-wins
    // map could name a different session's device when a later raw id
    // collides with an earlier allocated alias).
    if let Some(device) = alias_device.get(sess).or_else(|| raw_device.get(sess)) {
        out.push_str(&format!(" ({})", clean(device)));
    }
    if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
        out.push_str(&format!(", command `{}`", clean(cmd)));
    } else if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
        out.push_str(&format!(", GET {}", clean(path)));
    }
    out
}

pub struct Conversation {
    messages: Vec<Message>,
    pub(crate) dispatcher: Arc<dyn ToolDispatcher>,
    sessions: Arc<dyn ScrollbackSource>,
    /// Per-vendor policy summaries fed to the system-prompt builder.
    /// Sorted alphabetically by vendor at construction so the cached
    /// prefix is byte-stable.
    policies: Vec<(Vendor, PolicySummary)>,
    /// Shared with the `DefaultDispatcher` (or any dispatcher that
    /// honors per-Conversation ordinals). The `Arc<Mutex<>>` lets the
    /// dispatcher hold a clone without us giving up the ability to
    /// inspect `distinct_secrets()` from the Conversation.
    #[allow(dead_code)] // Phase 6 will introspect for prompt sidebar
    redactor: Arc<Mutex<ConversationRedactor>>,
    /// The open packet captures, when a capture engine is wired
    /// (v6.0.1 — the same `Arc` the `DefaultDispatcher` serves
    /// `query_capture` from, so the prompt's "Open packet captures"
    /// roster and the tool answer from one view). `None` in tests and
    /// deployments that predate/disable the PCaps surface; the prompt
    /// then simply omits the section. The production impl returns an
    /// empty list when `[pcap] agent_access = false`, so a severed
    /// agent view names no captures here either.
    captures: Option<Arc<dyn CaptureSource>>,
    /// Cumulative input/output token counts across all turns. Phase
    /// 6's loop calls `usage.add(&turn_usage)` after every LLM call.
    pub usage: TokenUsage,
}

impl Conversation {
    /// Construct from a dispatcher and scrollback source. The caller
    /// supplies the policy summaries (typically derived from the
    /// production `PolicyEngine`); they're cloned + sorted internally.
    /// The shared `ConversationRedactor` must be the same instance
    /// the dispatcher was constructed with — otherwise ordinals
    /// would diverge between what the dispatcher emits and what the
    /// prompt's ordinal-explanation refers to.
    pub fn new(
        dispatcher: Arc<dyn ToolDispatcher>,
        sessions: Arc<dyn ScrollbackSource>,
        redactor: Arc<Mutex<ConversationRedactor>>,
        policies: Vec<(Vendor, PolicySummary)>,
    ) -> Self {
        let mut policies = policies;
        // sort_by (not sort_by_key): `Vendor::as_str` borrows `self`
        // post-Custom, so a by-key closure returning the borrow can't
        // satisfy sort_by_key's owned-key bound.
        policies.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
        Self {
            messages: Vec::new(),
            dispatcher,
            sessions,
            policies,
            redactor,
            captures: None,
            usage: TokenUsage::default(),
        }
    }

    /// Attach a capture source so the system prompt's "Open packet
    /// captures" section renders from live state (v6.0.1 — fixes the
    /// gap where `query_capture` shipped but production always built
    /// the prompt with an empty capture list). Pass the SAME `Arc` the
    /// dispatcher was built with, for the same reason the redactor is
    /// shared: the prompt must describe the world the tools will
    /// actually answer from.
    pub fn with_captures(mut self, captures: Arc<dyn CaptureSource>) -> Self {
        self.captures = Some(captures);
        self
    }

    pub fn record_user(&mut self, text: impl Into<String>) {
        self.messages.push(Message::User {
            text: text.into(),
            at: SystemTime::now(),
        });
    }

    pub fn record_assistant_text(&mut self, text: impl Into<String>) {
        self.messages.push(Message::Assistant {
            text: text.into(),
            at: SystemTime::now(),
        });
    }

    /// Run a tool through the dispatcher and record both the call and
    /// the result. Returns the result so the caller (Phase 6's loop,
    /// or a test) can feed it back into the LLM. Failures are
    /// recorded as `Message::ToolResult { result: Err(...) }` AND
    /// returned as the original `AgentError` — recording the error
    /// is what lets the LLM see "you tried X, it failed because Y."
    pub async fn dispatch_tool(&mut self, call: ToolCall) -> Result<ToolResult, AgentError> {
        let now = SystemTime::now();
        self.messages.push(Message::ToolCall {
            call: call.clone(),
            at: now,
        });
        let outcome = self.dispatcher.dispatch(call).await;
        let recorded = match &outcome {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(e.to_string()),
        };
        let is_error = recorded.is_err();
        self.messages.push(Message::ToolResult {
            tool_use_id: None,
            result: recorded,
            is_error,
            at: SystemTime::now(),
        });
        outcome
    }

    /// Phase 6: record an assistant turn that contained tool_use
    /// blocks. The AgentLoop calls this after the model's stream
    /// closes and before dispatching individual tool calls.
    pub fn record_assistant_with_tools(
        &mut self,
        text: Option<String>,
        tool_uses: Vec<ToolUseBlock>,
    ) {
        self.messages.push(Message::AssistantWithTools {
            text,
            tool_uses,
            at: SystemTime::now(),
        });
    }

    /// Phase 6: record a tool result with its matching `tool_use_id`.
    /// The AgentLoop calls this after dispatching each `ToolUseBlock`
    /// from the preceding `AssistantWithTools` turn. `is_error` is
    /// also stored on the message so the LLM-side translation can
    /// emit `is_error: true` on the Anthropic `tool_result` block.
    pub fn record_tool_result(
        &mut self,
        tool_use_id: impl Into<String>,
        result: Result<ToolResult, String>,
    ) {
        let is_error = result.is_err();
        self.messages.push(Message::ToolResult {
            tool_use_id: Some(tool_use_id.into()),
            result,
            is_error,
            at: SystemTime::now(),
        });
    }

    /// Translate the message log into the `Vec<LlmMessage>` shape the
    /// AgentLoop hands to `LlmClient::messages`. Phase 5b's
    /// `dispatch_tool`-recorded `ToolCall` + un-tagged `ToolResult`
    /// messages are SKIPPED — they predate the loop's id-tracking
    /// model and can't be safely translated to Anthropic's
    /// strict-alternation message list.
    ///
    /// In practice an AgentLoop-driven Conversation never contains
    /// the Phase 5b variants (the loop never calls `dispatch_tool`),
    /// so the skip is a no-op for production traffic. The skip exists
    /// so a Phase 5b test that builds a Conversation, calls
    /// `dispatch_tool`, then hands it to a hypothetical AgentLoop
    /// doesn't generate malformed Anthropic requests.
    pub fn to_llm_messages(&self) -> Vec<LlmMessage> {
        // First pass: index the bulky device-output tool results
        // (read_scrollback / propose_command). The most recent
        // RECENT_TOOL_RESULTS_VERBATIM of these stay verbatim; older
        // ones over PRUNE_MIN_BYTES collapse to a re-readable
        // breadcrumb so a long log-parsing session doesn't re-send
        // every blob each turn. This is MECHANICAL (no model summary)
        // and RECOVERABLE — the device still holds the scrollback, so
        // the model can re-read. Errors and small/tiny kinds are never
        // pruned. Pruning operates on already-redacted content (the
        // dispatcher redacts at the source) and the breadcrumb carries
        // no device bytes, so it can never reintroduce a secret.
        let bulky_indices: Vec<usize> = self
            .messages
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                matches!(
                    m,
                    Message::ToolResult {
                        tool_use_id: Some(_),
                        result: Ok(ToolResult::ReadScrollback(_)
                            | ToolResult::ProposeCommand(_)
                            | ToolResult::ProposeApiCall(_)
                            // A capture answer is exactly the shape this
                            // machinery exists for: bulky, and cheaply
                            // reproducible by re-running the query.
                            | ToolResult::QueryCapture(_)),
                        ..
                    }
                )
            })
            .map(|(i, _)| i)
            .collect();
        let prune_before = bulky_indices
            .len()
            .saturating_sub(RECENT_TOOL_RESULTS_VERBATIM);
        let prune_candidates: std::collections::HashSet<usize> =
            bulky_indices.into_iter().take(prune_before).collect();

        // v6.1.x — breadcrumb bindings: the paired tool INPUT by
        // tool_use_id (the model's own arguments), and alias/raw-id →
        // device from ONE roster listing, so a breadcrumb can say what
        // ran where without a per-breadcrumb list() walk.
        let input_by_id: std::collections::HashMap<&str, &serde_json::Value> = self
            .messages
            .iter()
            .filter_map(|m| match m {
                Message::AssistantWithTools { tool_uses, .. } => Some(tool_uses.iter()),
                _ => None,
            })
            .flatten()
            .map(|tu| (tu.id.as_str(), &tu.input))
            .collect();
        // Two SEPARATE maps, not one flattened one: an alias and a raw
        // id can collide (a later session's registry id equal to an
        // earlier session's allocated alias), and a flattened
        // last-write-wins map would then bind the breadcrumb to the
        // wrong device. Resolution consults alias first (see
        // breadcrumb_binding), matching the dispatcher's precedence.
        let listed = self.sessions.list();
        let alias_device: std::collections::HashMap<String, String> = listed
            .iter()
            .filter_map(|m| m.alias.clone().map(|a| (a, m.device_id.clone())))
            .collect();
        let raw_device: std::collections::HashMap<String, String> = listed
            .iter()
            .map(|m| (m.session_id.clone(), m.device_id.clone()))
            .collect();

        let mut out = Vec::with_capacity(self.messages.len());
        for (i, m) in self.messages.iter().enumerate() {
            match m {
                Message::User { text, .. } => out.push(LlmMessage::User(text.clone())),
                Message::Assistant { text, .. } => out.push(LlmMessage::Assistant(text.clone())),
                Message::AssistantWithTools {
                    text, tool_uses, ..
                } => out.push(LlmMessage::AssistantWithTools {
                    text: text.clone(),
                    tool_uses: tool_uses.clone(),
                }),
                Message::ToolResult {
                    tool_use_id: Some(id),
                    result,
                    is_error,
                    ..
                } => {
                    let verbatim = match result {
                        Ok(r) => serde_json::to_string(r).unwrap_or_else(|e| {
                            format!("(internal: failed to serialize tool result: {e})")
                        }),
                        Err(s) => s.clone(),
                    };
                    // Collapse OLD bulky blobs to a breadcrumb. We
                    // keep `tool_use_id` so the Anthropic
                    // tool_use↔tool_result pairing still holds —
                    // dropping the message would orphan the prior
                    // tool_use and the provider would reject the turn.
                    let content =
                        if prune_candidates.contains(&i) && verbatim.len() > PRUNE_MIN_BYTES {
                            let binding = breadcrumb_binding(
                                input_by_id.get(id.as_str()).copied(),
                                &alias_device,
                                &raw_device,
                            );
                            prune_breadcrumb(result, verbatim.len(), &binding)
                        } else {
                            verbatim
                        };
                    out.push(LlmMessage::ToolResult {
                        tool_use_id: id.clone(),
                        content,
                        is_error: *is_error,
                    });
                }
                // Phase 5b artifacts — see the doc comment above.
                Message::ToolCall { .. }
                | Message::ToolResult {
                    tool_use_id: None, ..
                } => {}
            }
        }
        out
    }

    /// Build the system prompt from current open-session state. The
    /// `policies` slice is the construction-time snapshot (stable
    /// across turns); `open_sessions` and the open captures are
    /// fetched live so opening or closing either reflects on the
    /// next turn (both land in the volatile `OpenSessions` section —
    /// no cached-prefix cost).
    pub fn system_prompt(&self) -> SystemPrompt {
        let open = self.sessions.list();
        let captures = self.captures.as_ref().map(|c| c.list()).unwrap_or_default();
        system_prompt::build_with_captures(&open, &self.policies, &captures)
    }

    /// Read-only view of the message log in chronological order.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }
}

impl ToolResult {
    // Helper — `ToolResult` doesn't impl Clone in tools.rs by default
    // because the variants don't all need it. Conversation needs it
    // for the message log.
}

// `ToolResult` derives Clone in tools.rs (Serialize derive
// requires it). Sanity check at compile time.
const _: fn() = || {
    fn assert_clone<T: Clone>() {}
    assert_clone::<ToolResult>();
    assert_clone::<ToolCall>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MockDispatcher, MockScrollbackSource};
    use crate::tools::{
        AskUserInput, ListOpenSessionsInput, ListOpenSessionsOutput, ProposeCommandInput,
        ProposeCommandOutput, ReadScrollbackInput, ReadScrollbackOutput, SessionSummary,
    };
    use crate::{SessionKind, SessionMeta};

    fn meta(id: &str, device: &str) -> SessionMeta {
        SessionMeta {
            session_id: id.to_string(),
            device_id: device.to_string(),
            vendor: Vendor::Junos,
            kind: SessionKind::Ssh,
            opened_at: "2026-05-09T00:00:00Z".to_string(),
            api_endpoints: Vec::new(),
            alias: None,
            commands_run: None,
            scrollback_bytes: None,
        }
    }

    fn fresh() -> Conversation {
        let dispatcher = Arc::new(
            MockDispatcher::new()
                .with_list(|| {
                    Ok(ListOpenSessionsOutput {
                        sessions: vec![SessionSummary {
                            session_id: "s1".into(),
                            device_id: "vEX1".into(),
                            vendor: "junos".into(),
                            kind: "ssh".into(),
                            opened_at: "2026-05-09T00:00:00Z".into(),
                        }],
                    })
                })
                .with_read(|sid, _| {
                    Ok(ReadScrollbackOutput {
                        text: format!("scrollback for {sid}"),
                        truncated: false,
                        total_matched: None,
                    })
                }),
        );
        let sessions = Arc::new(
            MockScrollbackSource::new().with_session(meta("s1", "vEX1"), "scrollback for s1"),
        );
        let redactor = Arc::new(Mutex::new(ConversationRedactor::new()));
        Conversation::new(dispatcher, sessions, redactor, Vec::new())
    }

    #[tokio::test]
    async fn records_user_assistant_in_order() {
        let mut c = fresh();
        c.record_user("hello");
        c.record_assistant_text("hi");
        c.record_user("again");
        let m = c.messages();
        assert!(matches!(m[0], Message::User { ref text, .. } if text == "hello"));
        assert!(matches!(m[1], Message::Assistant { ref text, .. } if text == "hi"));
        assert!(matches!(m[2], Message::User { ref text, .. } if text == "again"));
    }

    #[tokio::test]
    async fn dispatch_tool_records_call_then_result() {
        let mut c = fresh();
        let res = c
            .dispatch_tool(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
            .await
            .unwrap();
        let _ = res;
        let m = c.messages();
        assert_eq!(m.len(), 2);
        assert!(matches!(m[0], Message::ToolCall { .. }));
        assert!(matches!(
            m[1],
            Message::ToolResult {
                tool_use_id: None,
                result: Ok(_),
                is_error: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dispatch_tool_records_error_as_stringified_result() {
        let mut c = fresh();
        // ProposeCommand isn't wired in MockDispatcher (defaults to
        // NotImplemented), so this exercises the error-recording path.
        let err = c
            .dispatch_tool(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".to_string(),
                command: "show version".to_string(),
            }))
            .await
            .unwrap_err();
        match err {
            AgentError::NotImplemented { .. } => {}
            _ => panic!("expected NotImplemented"),
        }
        let m = c.messages();
        assert_eq!(m.len(), 2);
        let result_msg = match &m[1] {
            Message::ToolResult { result, .. } => result.clone(),
            _ => panic!("expected ToolResult message"),
        };
        match result_msg {
            Err(s) => assert!(
                s.contains("propose_command"),
                "expected error string mentions tool: {s}"
            ),
            Ok(_) => panic!("expected error result"),
        }
    }

    #[tokio::test]
    async fn dispatch_tool_returns_outcome_to_caller() {
        // The recording is a side-effect; the call site must still
        // receive the outcome so Phase 6's loop can feed it back to
        // the LLM.
        let mut c = fresh();
        let res = c
            .dispatch_tool(ToolCall::ReadScrollback(ReadScrollbackInput {
                session_id: "s1".to_string(),
                max_bytes: 4096,
                match_: None,
                context_lines: 2,
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ReadScrollback(o) => assert!(o.text.contains("scrollback for s1")),
            _ => panic!(),
        }
    }

    #[test]
    fn system_prompt_includes_open_sessions_from_source() {
        let c = fresh();
        let p = c.system_prompt();
        let r = p.render();
        assert!(r.contains("session_id: s1"));
        assert!(r.contains("device: vEX1"));
    }

    #[test]
    fn system_prompt_lists_open_captures_when_source_attached() {
        // v6.0.1 — the production gap this pins: `query_capture` shipped
        // in v6.0.0 but the Conversation always built the prompt with an
        // empty capture slice, so the "Open packet captures" section
        // never rendered and the model was told about captures nowhere.
        let c = fresh().with_captures(Arc::new(
            crate::testing::MockCaptureSource::new().with_capture("c1", "lab.pcapng"),
        ));
        let r = c.system_prompt().render();
        assert!(r.contains("## Open packet captures"));
        assert!(r.contains("capture_id: c1"));
        assert!(r.contains("lab.pcapng"));
    }

    #[test]
    fn system_prompt_omits_capture_section_without_source_or_captures() {
        // No source attached (pre-PCaps callers) → no section. Source
        // attached but nothing open → no section either (no noise).
        let none = fresh();
        assert!(!none
            .system_prompt()
            .render()
            .contains("## Open packet captures"));

        let empty = fresh().with_captures(Arc::new(crate::testing::MockCaptureSource::new()));
        assert!(!empty
            .system_prompt()
            .render()
            .contains("## Open packet captures"));
    }

    #[test]
    fn usage_starts_at_zero() {
        let c = fresh();
        assert_eq!(c.usage, TokenUsage::default());
    }

    #[tokio::test]
    async fn ask_user_records_call_and_not_implemented_error() {
        let mut c = fresh();
        let _ = c
            .dispatch_tool(ToolCall::AskUser(AskUserInput {
                question: "Which device?".to_string(),
            }))
            .await
            .unwrap_err();
        let m = c.messages();
        assert!(matches!(m[0], Message::ToolCall { .. }));
        assert!(matches!(
            m[1],
            Message::ToolResult {
                tool_use_id: None,
                result: Err(_),
                is_error: true,
                ..
            }
        ));
    }

    #[test]
    fn record_assistant_with_tools_appends_message() {
        let mut c = fresh();
        c.record_assistant_with_tools(
            Some("checking".into()),
            vec![ToolUseBlock {
                id: "tu1".into(),
                name: "list_open_sessions".into(),
                input: serde_json::json!({}),
            }],
        );
        let m = c.messages();
        assert_eq!(m.len(), 1);
        match &m[0] {
            Message::AssistantWithTools {
                text, tool_uses, ..
            } => {
                assert_eq!(text.as_deref(), Some("checking"));
                assert_eq!(tool_uses.len(), 1);
                assert_eq!(tool_uses[0].id, "tu1");
            }
            _ => panic!("expected AssistantWithTools"),
        }
    }

    #[test]
    fn record_tool_result_carries_tool_use_id_and_is_error_flag() {
        let mut c = fresh();
        c.record_tool_result(
            "tu1",
            Ok(ToolResult::ListOpenSessions(ListOpenSessionsOutput {
                sessions: vec![],
            })),
        );
        c.record_tool_result("tu2", Err("policy denied: foo".into()));
        let m = c.messages();
        assert_eq!(m.len(), 2);
        assert!(matches!(
            &m[0],
            Message::ToolResult {
                tool_use_id: Some(id),
                is_error: false,
                ..
            } if id == "tu1"
        ));
        assert!(matches!(
            &m[1],
            Message::ToolResult {
                tool_use_id: Some(id),
                is_error: true,
                ..
            } if id == "tu2"
        ));
    }

    #[test]
    fn to_llm_messages_translates_loop_recorded_messages() {
        let mut c = fresh();
        c.record_user("why is BGP down?");
        c.record_assistant_with_tools(
            Some("checking".into()),
            vec![ToolUseBlock {
                id: "tu1".into(),
                name: "list_open_sessions".into(),
                input: serde_json::json!({}),
            }],
        );
        c.record_tool_result(
            "tu1",
            Ok(ToolResult::ListOpenSessions(ListOpenSessionsOutput {
                sessions: vec![],
            })),
        );
        c.record_assistant_text("Looks ok.");

        let llm = c.to_llm_messages();
        assert_eq!(llm.len(), 4);
        assert!(matches!(&llm[0], LlmMessage::User(t) if t == "why is BGP down?"));
        assert!(matches!(
            &llm[1],
            LlmMessage::AssistantWithTools { text, tool_uses }
                if text.as_deref() == Some("checking") && tool_uses.len() == 1
        ));
        assert!(matches!(
            &llm[2],
            LlmMessage::ToolResult {
                tool_use_id,
                is_error: false,
                ..
            } if tool_use_id == "tu1"
        ));
        assert!(matches!(&llm[3], LlmMessage::Assistant(t) if t == "Looks ok."));
    }

    #[tokio::test]
    async fn to_llm_messages_skips_phase_5b_dispatch_tool_records() {
        // Phase 5b's `dispatch_tool` records `Message::ToolCall` and
        // `Message::ToolResult { tool_use_id: None }`. Translating
        // those into LlmMessages would generate Anthropic-rejected
        // shapes (no id on the tool_result block), so the
        // translator drops them. The doc comment on `to_llm_messages`
        // covers why.
        let mut c = fresh();
        c.record_user("hi");
        let _ = c
            .dispatch_tool(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
            .await;
        c.record_assistant_text("done");
        let llm = c.to_llm_messages();
        // User + Assistant, no tool entries.
        assert_eq!(llm.len(), 2);
        assert!(matches!(&llm[0], LlmMessage::User(_)));
        assert!(matches!(&llm[1], LlmMessage::Assistant(_)));
    }

    // ----- Mechanical context pruning -----------------------------

    fn big_read(n: usize) -> Result<ToolResult, String> {
        Ok(ToolResult::ReadScrollback(ReadScrollbackOutput {
            text: "X".repeat(n),
            truncated: false,
            total_matched: None,
        }))
    }

    /// (tool_use_id, content) pairs for every id-tagged ToolResult the
    /// LLM would see, in order.
    fn tool_result_contents(c: &Conversation) -> Vec<(String, String)> {
        c.to_llm_messages()
            .into_iter()
            .filter_map(|m| match m {
                LlmMessage::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => Some((tool_use_id, content)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn to_llm_messages_keeps_recent_bulky_results_verbatim_and_prunes_old() {
        let mut c = fresh();
        for i in 0..8 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let results = tool_result_contents(&c);
        assert_eq!(results.len(), 8);
        // The 2 oldest collapse to breadcrumbs; the last 6 stay
        // verbatim (RECENT_TOOL_RESULTS_VERBATIM = 6).
        for (id, content) in &results[..2] {
            assert!(
                content.contains("Transit pruned") && content.contains("bytes elided"),
                "{id} should be a breadcrumb, got: {content}"
            );
            assert!(
                !content.contains("XXXX"),
                "{id} breadcrumb must not contain device bytes"
            );
        }
        for (id, content) in &results[2..] {
            assert!(
                content.contains("XXXX"),
                "{id} should be verbatim (recent), got a breadcrumb"
            );
        }
    }

    #[test]
    fn to_llm_messages_preserves_tool_use_id_on_pruned_results() {
        let mut c = fresh();
        for i in 0..8 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let results = tool_result_contents(&c);
        // Pruned (oldest) results keep their tool_use_id so the
        // Anthropic tool_use↔tool_result pairing still holds.
        assert_eq!(results[0].0, "tu_0");
        assert_eq!(results[1].0, "tu_1");
    }

    #[test]
    fn to_llm_messages_does_not_prune_small_old_results() {
        let mut c = fresh();
        // 8 SMALL results (well under PRUNE_MIN_BYTES): even the 2
        // oldest, outside the recent window, stay verbatim.
        for i in 0..8 {
            c.record_tool_result(format!("tu_{i}"), big_read(16));
        }
        for (id, content) in tool_result_contents(&c) {
            assert!(
                !content.contains("Transit pruned"),
                "{id} small result must not be pruned"
            );
        }
    }

    #[test]
    fn to_llm_messages_does_not_prune_errors_or_small_kinds() {
        let mut c = fresh();
        c.record_tool_result("err", Err("X".repeat(4096))); // big, but an error
        c.record_tool_result(
            "los",
            Ok(ToolResult::ListOpenSessions(ListOpenSessionsOutput {
                sessions: vec![],
            })),
        );
        for i in 0..8 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let results = tool_result_contents(&c);
        let err = results.iter().find(|(id, _)| id == "err").unwrap();
        assert!(err.1.contains("XXXX"), "big errors are never pruned");
        let los = results.iter().find(|(id, _)| id == "los").unwrap();
        assert!(
            !los.1.contains("Transit pruned"),
            "small kinds are never pruned"
        );
        let pruned = results
            .iter()
            .filter(|(_, content)| content.contains("Transit pruned"))
            .count();
        assert_eq!(pruned, 2, "exactly the 2 oldest reads should be pruned");
    }

    #[test]
    fn to_llm_messages_pruning_is_non_mutating() {
        let mut c = fresh();
        for i in 0..8 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let before = c.messages().len();
        let first = tool_result_contents(&c);
        let second = tool_result_contents(&c);
        assert_eq!(c.messages().len(), before, "internal log must be untouched");
        assert_eq!(first, second, "pruning must be deterministic");
        // The internal log still holds the FULL text — only the
        // LLM-facing copy is pruned.
        let full_retained = c.messages().iter().any(|m| {
            matches!(
                m,
                Message::ToolResult { result: Ok(ToolResult::ReadScrollback(o)), .. }
                    if o.text.len() == 4096
            )
        });
        assert!(full_retained, "internal log must retain full output");
    }

    #[test]
    fn pruned_breadcrumb_carries_the_binding() {
        // v6.1.x #5 — the breadcrumb names WHAT ran WHERE, from the
        // model's own paired tool input + the roster's device name
        // (fresh()'s source lists session "s1" on device "vEX1").
        let mut c = fresh();
        c.record_assistant_with_tools(
            None,
            vec![ToolUseBlock {
                id: "tu_old".into(),
                name: "propose_command".into(),
                input: serde_json::json!({"session_id": "s1", "command": "show version"}),
            }],
        );
        c.record_tool_result(
            "tu_old",
            Ok(ToolResult::ProposeCommand(ProposeCommandOutput {
                output: format!("<session id=\"s1\">\n{}\n</session>", "Y".repeat(4096)),
                executed: true,
            })),
        );
        for i in 0..6 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let results = tool_result_contents(&c);
        let old = results.iter().find(|(id, _)| id == "tu_old").unwrap();
        assert!(
            old.1.contains("on s1 (vEX1), command `show version`"),
            "breadcrumb must carry the session/device/command binding, got: {}",
            old.1
        );
        assert!(!old.1.contains("YYYY"), "no device bytes in the breadcrumb");
    }

    #[test]
    fn breadcrumb_binding_resolves_alias_before_raw_id_and_clamps() {
        // Alias-first: session A holds alias "s2"; a DIFFERENT session's
        // raw id is literally "s2". The binding for a call on "s2" must
        // name A's device (alias holder), not the collider's. And a
        // giant/hostile session_id is clamped + stripped so it can't
        // forge a [Transit …] line or inflate the transcript.
        let alias_device: std::collections::HashMap<String, String> =
            [("s2".to_string(), "vEX1".to_string())]
                .into_iter()
                .collect();
        let raw_device: std::collections::HashMap<String, String> =
            [("s2".to_string(), "WRONG".to_string())]
                .into_iter()
                .collect();

        let input = serde_json::json!({"session_id": "s2", "command": "show route"});
        let b = super::breadcrumb_binding(Some(&input), &alias_device, &raw_device);
        assert_eq!(b, " on s2 (vEX1), command `show route`");

        // Hostile id: control chars + brackets stripped, length clamped.
        let hostile =
            serde_json::json!({"session_id": format!("s1]\n[Transit: {}", "x".repeat(200))});
        let b = super::breadcrumb_binding(Some(&hostile), &alias_device, &raw_device);
        assert!(!b.contains('['), "brackets stripped: {b}");
        assert!(!b.contains('\n'), "newlines stripped: {b}");
        assert!(b.len() < 60, "clamped: {b}");
    }

    #[test]
    fn pruned_breadcrumb_contains_no_device_bytes() {
        let mut c = fresh();
        let marker = "SUPERSECRETMARKER_DO_NOT_LEAK";
        c.record_tool_result(
            "tu_old",
            Ok(ToolResult::ReadScrollback(ReadScrollbackOutput {
                text: format!("{marker}{}", "Z".repeat(4096)),
                truncated: true,
                total_matched: None,
            })),
        );
        // 6 fresh reads push tu_old out of the recent window.
        for i in 0..6 {
            c.record_tool_result(format!("tu_{i}"), big_read(4096));
        }
        let results = tool_result_contents(&c);
        let old = results.iter().find(|(id, _)| id == "tu_old").unwrap();
        assert!(old.1.contains("Transit pruned"), "tu_old should be pruned");
        assert!(
            !old.1.contains(marker),
            "breadcrumb must not contain device bytes: {}",
            old.1
        );
        assert!(
            old.1.contains("truncated=true"),
            "breadcrumb reflects the source flags"
        );
    }
}
