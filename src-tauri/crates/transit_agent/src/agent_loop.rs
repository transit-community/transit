//! `AgentLoop` — Phase 6's iteration orchestrator.
//!
//! Drives the plan/execute/observe loop:
//!
//! ```text
//! ┌─ user message
//! │
//! ▼
//! [build LlmRequest from Conversation] ◀─┐
//! │                                       │
//! ▼                                       │
//! [client.messages(req)] → stream         │
//! │                                       │
//! ▼                                       │
//! [drain stream]                          │
//!   ├─ TextDelta  → forward + buffer      │
//!   ├─ ToolUseCpl → buffer block          │
//!   └─ Completed  → record usage          │
//! │                                       │
//! ▼                                       │
//! tool_uses empty? ─Yes─→ [Assistant text]│
//! │                       [Completed:End] │
//! No                                      │
//! ▼                                       │
//! [AssistantWithTools]                    │
//! │                                       │
//! ▼                                       │
//! for each tool_use:                      │
//!   ToolUseBegin → dispatch → ToolUseEnd  │
//!   record_tool_result(id, result)        │
//! │                                       │
//! ▼                                       │
//! [bounds check] ─over?─→ [Completed:Cap] │
//! │                                       │
//! └────────────────────────────────────── ┘
//! ```
//!
//! Cancellation: every await point selects on `Arc<Notify>`. A
//! notify before a tool dispatch drops the in-flight LLM stream and
//! exits cleanly with `Completed { stop_reason: UserAborted }` —
//! the Conversation log is left in a consistent state (no
//! `AssistantWithTools` without matching `ToolResult`s).
//!
//! Bounds — a one-click checkpoint model (no silent kills):
//! - `checkpoint_rounds` (default 50) — pause after this many
//!   tool-rounds since the last user message. The chat UI renders a
//!   one-click Continue; an unattended runaway pauses here and won't
//!   proceed without a human.
//! - `checkpoint_cost_microdollars` (default $5) — pause after this
//!   much *internal* spend (computed via `usage::pricing_for_model`,
//!   NEVER surfaced to the UI). Bounds runaway cost.
//! - `stream_timeout` (default 90s, per turn) — a single round's
//!   stream that hangs longer than this terminates with
//!   `StreamTimeout`. Safety guard against an infinite/compromised
//!   stream; reset every round so a long user-paced investigation
//!   never accumulates toward it.
//!
//! On a `Checkpoint` the loop records NO synthetic message (the chat
//! UI owns the Continue affordance); other terminal reasons append a
//! short `Assistant("…")` note. The loop always emits exactly one
//! `Completed { stop_reason }`.

use std::sync::Arc;
use std::time::Duration;

use futures::stream::BoxStream;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::warn;

use crate::conversation::Conversation;
use crate::llm::{LlmClient, LlmError, LlmRequest, LlmStreamEvent, ToolSchema, ToolUseBlock};
use crate::tools::{ToolCall, ToolResult};
use crate::usage::{pricing_for_model, TokenUsage};

/// Checkpoint/timeout bounds enforced by [`AgentLoop::run`].
///
/// The loop auto-continues through a normal investigation (each
/// `propose_command` already blocks on the approval modal, so the
/// loop is user-paced). It pauses for a one-click Continue only after
/// a high autonomous burst, and a per-turn timeout guards a hung
/// stream. There is no silent kill.
#[derive(Debug, Clone)]
pub struct LoopBounds {
    /// Pause after this many tool-rounds since the last user message
    /// (one round = one LLM round-trip plus its tool dispatches). The
    /// chat UI renders a one-click Continue; an unattended runaway
    /// pauses here and won't proceed without a human click.
    pub checkpoint_rounds: u32,
    /// Pause after this much cumulative spend this run, in
    /// microdollars, computed against [`pricing_for_model`]. This
    /// figure is INTERNAL — it decides *when* to pause and is never
    /// surfaced to the UI.
    pub checkpoint_cost_microdollars: u64,
    /// Per-turn cap on a single round's stream. Reset every round, so
    /// a long multi-round investigation never accumulates toward it;
    /// only a single hung/compromised stream trips it.
    pub stream_timeout: Duration,
}

impl Default for LoopBounds {
    fn default() -> Self {
        Self {
            checkpoint_rounds: 50,
            checkpoint_cost_microdollars: 5_000_000, // $5
            stream_timeout: Duration::from_secs(90),
        }
    }
}

impl LoopBounds {
    /// Stream budget for local (BYOM) models. Local rounds
    /// legitimately run long — cold model load (~10s), full-window
    /// prompt eval on modest hardware, and Ollama's default
    /// single-slot queueing (a second chat waits behind the first)
    /// all bill against the same per-round clock — so the cloud
    /// default of 90s would kill healthy streams. Still a per-round
    /// TOTAL, not an inactivity timeout: a >600s stream pauses at the
    /// recoverable StreamTimeout/Continue card.
    pub const LOCAL_STREAM_TIMEOUT: Duration = Duration::from_secs(600);

    /// Provider-aware defaults. Local (BYOM) models get the longer
    /// stream budget; everything else keeps [`Default`]. Keyed on the
    /// same `llm::is_local_model` predicate as factory routing and
    /// [`pricing_for_model`] so the three can never diverge.
    pub fn for_model(model: &str) -> Self {
        if crate::llm::is_local_model(model) {
            Self {
                stream_timeout: Self::LOCAL_STREAM_TIMEOUT,
                ..Self::default()
            }
        } else {
            Self::default()
        }
    }
}

/// Why the loop terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Model emitted a final answer with no tool_uses — normal end
    /// of investigation.
    EndTurn,
    /// Reached a one-click checkpoint (`checkpoint_rounds` or
    /// `checkpoint_cost_microdollars`). NOT an error — the chat UI
    /// renders a Continue affordance. `cost_microdollars` is internal
    /// (never surfaced); the UI uses `rounds` (and token totals).
    Checkpoint { rounds: u32, cost_microdollars: u64 },
    /// A single round's stream hung past `bounds.stream_timeout`.
    /// Recoverable — the UI offers Continue/retry.
    StreamTimeout,
    /// `cancel.notify_one()` fired (Stop button).
    UserAborted,
    /// `LlmClient::messages` returned an error or the stream
    /// reported one.
    ProviderError(String),
}

/// One frame of the loop's outward-facing event stream. The
/// `transit_app::chat` adapter (C9) maps these onto Tauri events.
#[derive(Debug, Clone)]
pub enum AgentLoopEvent {
    /// Streamed assistant prose. Chunks aren't always delimited at
    /// word boundaries — the consumer concatenates verbatim.
    TextDelta(String),
    /// A tool call has been parsed and is about to be dispatched.
    ToolUseBegin {
        iteration: u32,
        id: String,
        call: ToolCall,
    },
    /// The dispatcher returned. `result` mirrors the Conversation's
    /// stored shape (`Result<ToolResult, String>` so the error case
    /// is `Clone`).
    ToolUseEnd {
        iteration: u32,
        id: String,
        result: Result<ToolResult, String>,
    },
    /// One iteration of the loop completed (assistant turn + any
    /// tool dispatches). Emitted before the checkpoint check; the
    /// chat UI uses it to drive the live activity readout (rounds run
    /// + tokens consumed — never a dollar figure).
    IterationComplete {
        iteration: u32,
        cumulative_usage: TokenUsage,
    },
    /// Terminal event. Always the last frame on the stream.
    Completed {
        final_usage: TokenUsage,
        stop_reason: StopReason,
    },
}

/// One run through the iteration loop.
///
/// Owns the `Conversation` (mutated in place as each iteration
/// records assistant + tool messages), the `LlmClient` (consumed
/// once `run` is called — the loop is single-shot), and the cancel
/// token.
pub struct AgentLoop {
    pub conversation: Conversation,
    pub client: Box<dyn LlmClient>,
    pub bounds: LoopBounds,
    pub tools: Vec<ToolSchema>,
    pub model: String,
    /// Per-turn cap on assistant-emitted tokens. Anthropic requires
    /// this; OpenAI treats it as optional. None means the impls
    /// pick a default (4096 for Anthropic).
    pub max_tokens_per_turn: Option<u32>,
    /// Shared cancel signal. Notify it once to terminate the loop
    /// at the next await boundary.
    pub cancel: Arc<Notify>,
}

impl AgentLoop {
    /// Drive the loop. Returns a stream of [`AgentLoopEvent`]s ending
    /// with exactly one [`AgentLoopEvent::Completed`].
    ///
    /// The consumer MUST drain the stream — backpressure on the
    /// receiver stalls the loop. The chat-side adapter forwards every
    /// event onto a Tauri-event topic so the consumer is just the
    /// runtime's own scheduler.
    pub fn run(self) -> BoxStream<'static, AgentLoopEvent> {
        let (tx, rx) = mpsc::unbounded_channel::<AgentLoopEvent>();
        tokio::spawn(async move {
            let final_event = self.drive(tx.clone()).await;
            // `drive` always returns a Completed-shaped value; even
            // panics in the loop body are caught by tokio::spawn and
            // turned into "task panicked" — but in that case the tx
            // is dropped without a send. The receiver-side stream
            // ends naturally; downstream consumers see no terminal
            // Completed event and treat that as "loop crashed".
            let _ = tx.send(final_event);
        });
        UnboundedReceiverStream::new(rx).boxed()
    }

    async fn drive(mut self, tx: mpsc::UnboundedSender<AgentLoopEvent>) -> AgentLoopEvent {
        let mut iteration: u32 = 0;

        loop {
            // Top-of-iteration cancel check.
            if self.is_cancelled() {
                return self.terminate(StopReason::UserAborted);
            }

            // Checkpoint: pause a long autonomous burst BEFORE issuing
            // the next LLM round-trip, so an unattended runaway can't
            // make another call without a human click. Whichever
            // threshold trips first wins. `iteration` is the round
            // count since the last user message (a fresh Conversation
            // + loop is built per user message), and the cost is the
            // INTERNAL spend ceiling — never surfaced to the UI.
            let cost = self.current_cost_microdollars();
            if iteration >= self.bounds.checkpoint_rounds
                || cost >= self.bounds.checkpoint_cost_microdollars
            {
                return self.terminate(StopReason::Checkpoint {
                    rounds: iteration,
                    cost_microdollars: cost,
                });
            }

            iteration += 1;

            // ---- Build request --------------------------------
            let req = self.build_request();

            // ---- Open stream ---------------------------------
            let mut stream = match self.open_stream(req).await {
                Ok(s) => s,
                Err(e) => return self.terminate(StopReason::ProviderError(e.to_string())),
            };

            // ---- Drain stream ---------------------------------
            let mut text_buf = String::new();
            let mut tool_uses: Vec<ToolUseBlock> = Vec::new();
            let mut turn_usage = TokenUsage::default();
            let mut stream_error: Option<String> = None;

            // Per-turn stream-timeout guard, created fresh each round
            // so a long user-paced investigation never accumulates
            // toward it. Fires only if THIS round's stream hangs — the
            // safety replacement for the old total wall-clock, and a
            // fix for the genuine no-timeout hang.
            let stream_deadline = tokio::time::sleep(self.bounds.stream_timeout);
            tokio::pin!(stream_deadline);

            loop {
                if self.is_cancelled() {
                    drop(stream);
                    return self.terminate(StopReason::UserAborted);
                }
                let next = tokio::select! {
                    biased;
                    _ = self.cancel.notified() => {
                        drop(stream);
                        return self.terminate(StopReason::UserAborted);
                    }
                    _ = &mut stream_deadline => {
                        drop(stream);
                        return self.terminate(StopReason::StreamTimeout);
                    }
                    n = stream.next() => n,
                };
                match next {
                    None => break,
                    Some(Err(LlmError::EarlyEnd)) => {
                        stream_error = Some("provider stream closed without Completed".into());
                        break;
                    }
                    Some(Err(e)) => {
                        stream_error = Some(e.to_string());
                        break;
                    }
                    Some(Ok(LlmStreamEvent::TextDelta(t))) => {
                        text_buf.push_str(&t);
                        let _ = tx.send(AgentLoopEvent::TextDelta(t));
                    }
                    Some(Ok(LlmStreamEvent::ToolUseComplete { id, name, input })) => {
                        tool_uses.push(ToolUseBlock { id, name, input });
                    }
                    Some(Ok(LlmStreamEvent::Completed(u))) => {
                        turn_usage = u;
                    }
                }
            }

            self.conversation.usage.add(&turn_usage);

            if let Some(reason) = stream_error {
                return self.terminate(StopReason::ProviderError(reason));
            }

            // ---- Decide: end-turn or dispatch tools? ---------
            if tool_uses.is_empty() {
                // No tools — the model gave a final answer.
                if !text_buf.is_empty() {
                    self.conversation.record_assistant_text(text_buf);
                }
                return self.terminate(StopReason::EndTurn);
            }

            // Record the assistant turn (text + tool_uses) BEFORE
            // dispatching. If the loop is cancelled mid-dispatch
            // below, the message log still holds a coherent
            // AssistantWithTools — the missing ToolResult is the
            // only inconsistency, and the next turn would naturally
            // overwrite it.
            self.conversation.record_assistant_with_tools(
                if text_buf.is_empty() {
                    None
                } else {
                    Some(text_buf)
                },
                tool_uses.clone(),
            );

            // ---- Dispatch each tool ---------------------------
            for tu in tool_uses {
                if self.is_cancelled() {
                    return self.terminate(StopReason::UserAborted);
                }

                let call = match parse_tool_call(&tu) {
                    Ok(c) => c,
                    Err(e) => {
                        // The model emitted a tool_use whose name or
                        // input shape doesn't match any ToolCall
                        // variant (six as of v6.0.0 — the count lives
                        // in tools.rs's const_assert, not here).
                        // Record as an error so the model can correct
                        // itself next turn.
                        let err = format!("tool_call parse failed: {e}");
                        self.conversation
                            .record_tool_result(&tu.id, Err(err.clone()));
                        let _ = tx.send(AgentLoopEvent::ToolUseEnd {
                            iteration,
                            id: tu.id.clone(),
                            result: Err(err),
                        });
                        continue;
                    }
                };

                let _ = tx.send(AgentLoopEvent::ToolUseBegin {
                    iteration,
                    id: tu.id.clone(),
                    call: call.clone(),
                });

                let dispatcher = self.conversation.dispatcher_arc();
                let outcome: Result<ToolResult, String> = tokio::select! {
                    biased;
                    _ = self.cancel.notified() => {
                        return self.terminate(StopReason::UserAborted);
                    }
                    r = dispatcher.dispatch(call) => r.map_err(|e| e.to_string()),
                };
                self.conversation
                    .record_tool_result(&tu.id, outcome.clone());
                let _ = tx.send(AgentLoopEvent::ToolUseEnd {
                    iteration,
                    id: tu.id,
                    result: outcome,
                });
            }

            let _ = tx.send(AgentLoopEvent::IterationComplete {
                iteration,
                cumulative_usage: self.conversation.usage,
            });
            // Loop back; bounds check at top will re-evaluate.
        }
    }

    fn is_cancelled(&self) -> bool {
        // Best-effort poll: Notify doesn't expose a `is_notified()`,
        // so we use an immediate `try` via select with a zero-delay
        // future. The `biased` select in the main drive loop covers
        // the await-point case; this helper covers the synchronous
        // boundary checks at the top of each iteration.
        // Zero-delay yields once; on the first poll the Notify
        // returns Pending (not yet notified) — but the await has
        // already completed when notify_one was called before.
        // Simpler: try_notified would be ideal; since it doesn't
        // exist publicly, we just rely on the await-point selects.
        // This helper returns false; callers MUST also `select!` on
        // `cancel.notified()` at every async boundary.
        false
    }

    /// Internal spend so far this run, in microdollars, for the
    /// checkpoint trip. Computed against [`pricing_for_model`] (a
    /// conservative upper bound for unknown models). NEVER surfaced
    /// to the UI — only `drive()` reads it to decide when to pause.
    fn current_cost_microdollars(&self) -> u64 {
        self.conversation
            .usage
            .cost_microdollars(&pricing_for_model(&self.model))
    }

    fn build_request(&self) -> LlmRequest {
        LlmRequest {
            model: self.model.clone(),
            // Pass the SystemPrompt structurally so the Anthropic
            // client can emit cache_control markers at each
            // cache_after section (CLAUDE.md §18). OpenAI flattens
            // back to the rendered string at body-build time.
            system: Some(self.conversation.system_prompt().to_llm_input()),
            messages: self.conversation.to_llm_messages(),
            max_tokens: self.max_tokens_per_turn,
            tools: Some(self.tools.clone()),
        }
    }

    async fn open_stream(&self, req: LlmRequest) -> Result<crate::llm::LlmStream, LlmError> {
        self.client.messages(req).await
    }

    fn terminate(mut self, stop_reason: StopReason) -> AgentLoopEvent {
        // Synthetic assistant message so the chat thread surfaces
        // *why* the loop ended. Skipped for EndTurn (the model's
        // final answer is already the last assistant message).
        let synthetic = match &stop_reason {
            // The model's final answer is already the last message.
            StopReason::EndTurn => None,
            // Checkpoint is NOT an error — the chat UI renders a
            // one-click Continue affordance from the stop_reason, so
            // we add NO message and keep the thread clean.
            StopReason::Checkpoint { .. } => None,
            StopReason::StreamTimeout => Some(
                "The model's response stalled. Continue to retry from where it left off."
                    .to_string(),
            ),
            StopReason::UserAborted => Some("Loop stopped at user request.".to_string()),
            StopReason::ProviderError(e) => Some(format!("Loop terminated: provider error: {e}")),
        };
        if let Some(text) = synthetic {
            self.conversation.record_assistant_text(text);
        }
        AgentLoopEvent::Completed {
            final_usage: self.conversation.usage,
            stop_reason,
        }
    }
}

/// Translate a [`ToolUseBlock`] (model-supplied name + input JSON)
/// into a typed [`ToolCall`]. Folds the name onto the input as the
/// `serde(tag = "tool")` discriminator.
fn parse_tool_call(tu: &ToolUseBlock) -> Result<ToolCall, String> {
    let mut payload = match tu.input.clone() {
        Value::Object(map) => map,
        Value::Null => serde_json::Map::new(),
        other => {
            return Err(format!(
                "tool input must be a JSON object, got {}",
                other_kind(&other)
            ));
        }
    };
    if payload.contains_key("tool") {
        // Defensive: shouldn't happen — `tool` is our internal
        // discriminator, not part of the public schema. If the
        // model hallucinates a `tool` field in inputs, drop it
        // and keep going.
        warn!(
            tool_name = %tu.name,
            "tool_use input contained a `tool` field — overriding with the canonical name"
        );
        payload.remove("tool");
    }
    payload.insert("tool".to_string(), Value::String(tu.name.clone()));
    serde_json::from_value(Value::Object(payload)).map_err(|e| e.to_string())
}

fn other_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// Bridge: AgentLoop needs to share the Conversation's dispatcher
// across iterations without consuming it. Conversation already
// holds an `Arc<dyn ToolDispatcher>`; expose a clone-helper here so
// the loop doesn't reach into private fields.
impl Conversation {
    /// Loop-internal: clone the dispatcher Arc for direct dispatch.
    /// Used by `AgentLoop::drive` to issue tool calls without going
    /// through `dispatch_tool` (which records its own message-pair
    /// shape — the loop records messages with model-supplied ids).
    pub(crate) fn dispatcher_arc(&self) -> Arc<dyn crate::dispatcher::ToolDispatcher> {
        Arc::clone(&self.dispatcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::ConversationRedactor;
    use crate::testing::{MockDispatcher, MockScrollbackSource};
    use crate::tools::{ListOpenSessionsOutput, ReadScrollbackOutput, SessionSummary};
    use async_trait::async_trait;
    use futures::stream;
    use serde_json::json;
    use std::sync::Mutex as StdMutex;

    use crate::llm::{LlmClient, LlmResult, LlmStream};

    /// Stub LlmClient that replays a queue of canned per-call event
    /// sequences. Each call to `messages` returns the next entry
    /// (or panics if the queue is empty — a test that exercises
    /// more turns than scripted is a test bug).
    struct StubLlmClient {
        queue: StdMutex<Vec<Vec<LlmResult<LlmStreamEvent>>>>,
    }

    impl StubLlmClient {
        fn new(turns: Vec<Vec<LlmResult<LlmStreamEvent>>>) -> Self {
            Self {
                queue: StdMutex::new(turns),
            }
        }
    }

    #[async_trait]
    impl LlmClient for StubLlmClient {
        async fn messages(&self, _req: LlmRequest) -> LlmResult<LlmStream> {
            let mut q = self.queue.lock().unwrap();
            assert!(
                !q.is_empty(),
                "StubLlmClient ran out of canned responses — test asked for more turns than scripted"
            );
            let events = q.remove(0);
            Ok(stream::iter(events).boxed())
        }
    }

    fn delta(s: &str) -> LlmResult<LlmStreamEvent> {
        Ok(LlmStreamEvent::TextDelta(s.to_string()))
    }
    fn tool(id: &str, name: &str, input: Value) -> LlmResult<LlmStreamEvent> {
        Ok(LlmStreamEvent::ToolUseComplete {
            id: id.into(),
            name: name.into(),
            input,
        })
    }
    fn done(input_uncached: u64, output: u64) -> LlmResult<LlmStreamEvent> {
        Ok(LlmStreamEvent::Completed(TokenUsage {
            input_uncached,
            input_cache_write: 0,
            input_cache_read: 0,
            output,
        }))
    }

    fn fresh_conversation() -> Conversation {
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
                        text: format!("scrollback-{sid}"),
                        truncated: false,
                        total_matched: None,
                    })
                }),
        );
        let sessions = Arc::new(MockScrollbackSource::new());
        let redactor = Arc::new(StdMutex::new(ConversationRedactor::new()));
        Conversation::new(dispatcher, sessions, redactor, Vec::new())
    }

    fn make_loop(client: Box<dyn LlmClient>, mut conv: Conversation) -> AgentLoop {
        conv.record_user("test");
        AgentLoop {
            conversation: conv,
            client,
            bounds: LoopBounds::default(),
            tools: vec![],
            model: "claude-opus-4-7".into(),
            max_tokens_per_turn: None,
            cancel: Arc::new(Notify::new()),
        }
    }

    async fn drain(stream: BoxStream<'static, AgentLoopEvent>) -> Vec<AgentLoopEvent> {
        stream.collect::<Vec<_>>().await
    }

    #[tokio::test]
    async fn single_turn_no_tools_emits_text_then_completed_endturn() {
        let client = Box::new(StubLlmClient::new(vec![vec![
            delta("Hello"),
            delta(", world"),
            done(10, 5),
        ]]));
        let l = make_loop(client, fresh_conversation());
        let events = drain(l.run()).await;
        // Expect: TextDelta x2, Completed(EndTurn).
        let texts: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AgentLoopEvent::TextDelta(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts.join(""), "Hello, world");
        let last = events.last().unwrap();
        assert!(matches!(
            last,
            AgentLoopEvent::Completed {
                stop_reason: StopReason::EndTurn,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tool_use_dispatched_then_followup_text_terminates_endturn() {
        let client = Box::new(StubLlmClient::new(vec![
            // Turn 1: emit tool_use
            vec![
                delta("Looking…"),
                tool("tu_1", "list_open_sessions", json!({})),
                done(10, 4),
            ],
            // Turn 2: emit final text after tool result
            vec![delta("Found vEX1"), done(20, 8)],
        ]));
        let l = make_loop(client, fresh_conversation());
        let events = drain(l.run()).await;

        let begins: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, AgentLoopEvent::ToolUseBegin { .. }))
            .collect();
        assert_eq!(begins.len(), 1);
        let ends: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, AgentLoopEvent::ToolUseEnd { .. }))
            .collect();
        assert_eq!(ends.len(), 1);

        // Ends with EndTurn (the second turn had no tool_uses).
        let last = events.last().unwrap();
        assert!(matches!(
            last,
            AgentLoopEvent::Completed {
                stop_reason: StopReason::EndTurn,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn checkpoint_rounds_pauses_runaway_tool_loop() {
        // Every turn emits a tool_use → loop should pause at the round
        // checkpoint rather than spinning forever.
        let mut turns: Vec<Vec<LlmResult<LlmStreamEvent>>> = Vec::new();
        for _ in 0..5 {
            turns.push(vec![
                tool("tu", "list_open_sessions", json!({})),
                done(1, 1),
            ]);
        }
        let client = Box::new(StubLlmClient::new(turns));
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.checkpoint_rounds = 3;
        l.bounds.checkpoint_cost_microdollars = u64::MAX; // pin rounds
        let events = drain(l.run()).await;
        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::Checkpoint { rounds: 3, .. },
                    ..
                }
            ),
            "expected Checkpoint{{rounds:3}}, got {last:?}"
        );
    }

    #[tokio::test]
    async fn checkpoint_cost_pauses_loop() {
        let client = Box::new(StubLlmClient::new(vec![
            // One turn whose cost crosses the threshold (~69_975 µ$
            // at Opus rates — $5/$25 — for 9_000 input + 999 output).
            vec![
                tool("tu", "list_open_sessions", json!({})),
                done(9_000, 999),
            ],
            // Reached only if the checkpoint didn't fire — the check
            // runs at the TOP of the next iteration.
            vec![delta("never seen"), done(1, 1)],
        ]));
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.checkpoint_cost_microdollars = 50_000; // $0.05
        l.bounds.checkpoint_rounds = u32::MAX; // pin cost
        let events = drain(l.run()).await;
        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::Checkpoint { .. },
                    ..
                }
            ),
            "expected Checkpoint, got {last:?}"
        );
    }

    #[test]
    fn for_model_gives_local_models_the_long_stream_budget_only() {
        let local = LoopBounds::for_model("ollama:qwen3:8b");
        assert_eq!(local.stream_timeout, LoopBounds::LOCAL_STREAM_TIMEOUT);
        // Only the stream budget changes — the rounds/cost checkpoints
        // keep their defaults (rounds is the effective local bound;
        // cost is zero-priced via usage::pricing_for_model).
        let default = LoopBounds::default();
        assert_eq!(local.checkpoint_rounds, default.checkpoint_rounds);
        assert_eq!(
            local.checkpoint_cost_microdollars,
            default.checkpoint_cost_microdollars
        );

        let cloud = LoopBounds::for_model("claude-opus-4-8");
        assert_eq!(cloud.stream_timeout, default.stream_timeout);
    }

    #[tokio::test]
    async fn local_model_zero_cost_never_trips_cost_checkpoint() {
        // The same token volume that trips checkpoint_cost_pauses_loop
        // at Opus rates — but on a local model id it prices at zero, so
        // the loop must run to EndTurn. (A regression here means
        // pricing_for_model stopped consulting is_local_model.)
        let client = Box::new(StubLlmClient::new(vec![
            vec![
                tool("tu", "list_open_sessions", json!({})),
                done(9_000, 999),
            ],
            vec![delta("all done"), done(9_000, 999)],
        ]));
        let mut l = make_loop(client, fresh_conversation());
        l.model = "ollama:qwen3:8b".into();
        l.bounds.checkpoint_cost_microdollars = 50_000; // $0.05 — trips instantly at Opus rates
        let events = drain(l.run()).await;
        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::EndTurn,
                    ..
                }
            ),
            "zero-priced local usage must not trip the cost checkpoint, got {last:?}"
        );
    }

    /// Producer that returns the SAME tool_use event sequence on
    /// every `messages` call — never runs out, never returns an end-
    /// turn. Models the "jailbroken / compromised model emits tool_use
    /// forever" attack from threat-model T19. Distinct from
    /// `StubLlmClient` which panics when its canned queue empties:
    /// `StubLlmClient`-based bounds tests script max_iter+N turns and
    /// rely on the queue's panic as a safety net. Those tests would
    /// still pass with a broken "iteration only counts non-empty
    /// turns" bug. This client removes the safety net so a bound bug
    /// becomes "test hangs", caught by the `tokio::time::timeout`
    /// wrapper in each call site.
    struct InfiniteToolUseClient {
        /// Per-turn token usage. Tests pick values that make a
        /// specific bound fire predictably.
        input_per_turn: u64,
        output_per_turn: u64,
    }

    #[async_trait]
    impl LlmClient for InfiniteToolUseClient {
        async fn messages(&self, _req: LlmRequest) -> LlmResult<LlmStream> {
            let events = vec![
                tool("tu", "list_open_sessions", json!({})),
                done(self.input_per_turn, self.output_per_turn),
            ];
            Ok(stream::iter(events).boxed())
        }
    }

    #[tokio::test]
    async fn infinite_tool_use_pauses_at_checkpoint_rounds() {
        // T19 headline assertion: a model that emits tool_use forever
        // (no end-turn ever) must hit the round checkpoint and pause.
        // The 5s timeout wrapper turns "loop is unbounded" from "test
        // hangs" into "test fails fast" — the bounded loop completes
        // in milliseconds.
        let client = Box::new(InfiniteToolUseClient {
            input_per_turn: 10,
            output_per_turn: 5,
        });
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.checkpoint_rounds = 4;
        // Pin rounds: make cost + timeout non-firing.
        l.bounds.checkpoint_cost_microdollars = u64::MAX;
        l.bounds.stream_timeout = Duration::from_secs(60);

        let events = tokio::time::timeout(Duration::from_secs(5), drain(l.run()))
            .await
            .expect("loop must terminate within 5s — bounds bug if it hangs");

        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::Checkpoint { rounds: 4, .. },
                    ..
                }
            ),
            "expected Checkpoint{{rounds:4}}, got {last:?}"
        );
        let iter_completes = events
            .iter()
            .filter(|e| matches!(e, AgentLoopEvent::IterationComplete { .. }))
            .count();
        assert_eq!(
            iter_completes, 4,
            "must complete exactly checkpoint_rounds rounds before pausing"
        );
    }

    #[tokio::test]
    async fn infinite_tool_use_pauses_at_checkpoint_cost() {
        // Same producer, cost checkpoint instead. ~5_250 µ$/turn at
        // Opus rates (100 input + 50 output); threshold 10_000 →
        // pauses at the top of the 3rd iteration with Checkpoint.
        let client = Box::new(InfiniteToolUseClient {
            input_per_turn: 100,
            output_per_turn: 50,
        });
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.checkpoint_rounds = 99;
        l.bounds.checkpoint_cost_microdollars = 10_000;
        l.bounds.stream_timeout = Duration::from_secs(60);

        let events = tokio::time::timeout(Duration::from_secs(5), drain(l.run()))
            .await
            .expect("loop must terminate within 5s — bounds bug if it hangs");

        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::Checkpoint { .. },
                    ..
                }
            ),
            "expected Checkpoint, got {last:?}"
        );
    }

    /// Client whose stream never yields and never closes — models a
    /// hung / compromised provider stream. Proves the per-turn stream
    /// timeout fires (regression-pins the real no-timeout hang).
    struct HangingStreamClient;

    #[async_trait]
    impl LlmClient for HangingStreamClient {
        async fn messages(&self, _req: LlmRequest) -> LlmResult<LlmStream> {
            Ok(stream::pending::<LlmResult<LlmStreamEvent>>().boxed())
        }
    }

    #[tokio::test]
    async fn stream_timeout_terminates_hung_stream() {
        // A single round whose stream never yields and never closes
        // must terminate at the per-turn stream timeout. The 5s outer
        // wrapper turns "loop hangs forever" into "test fails fast".
        let client = Box::new(HangingStreamClient);
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.stream_timeout = Duration::from_millis(50);

        let events = tokio::time::timeout(Duration::from_secs(5), drain(l.run()))
            .await
            .expect("stream timeout must fire — hang bug if it doesn't");
        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::StreamTimeout,
                    ..
                }
            ),
            "expected StreamTimeout, got {last:?}"
        );
    }

    /// Client whose stream emits a turn's events after a fixed delay
    /// (a slow-but-not-hung provider). Proves the per-turn stream
    /// timeout RESETS each round.
    struct DelayedStreamClient {
        delay: Duration,
        turns: StdMutex<Vec<Vec<LlmResult<LlmStreamEvent>>>>,
    }

    #[async_trait]
    impl LlmClient for DelayedStreamClient {
        async fn messages(&self, _req: LlmRequest) -> LlmResult<LlmStream> {
            let turn = {
                let mut q = self.turns.lock().unwrap();
                assert!(!q.is_empty(), "DelayedStreamClient ran out of turns");
                q.remove(0)
            };
            let delay = self.delay;
            let s = stream::once(async move {
                tokio::time::sleep(delay).await;
                stream::iter(turn)
            })
            .flatten();
            Ok(s.boxed())
        }
    }

    #[tokio::test]
    async fn stream_timeout_resets_per_turn() {
        // Each round's stream takes ~30ms (< the 200ms per-turn
        // timeout), but 7 rounds total ~210ms (> 200ms). A CUMULATIVE
        // timeout would fire mid-investigation; a correct PER-TURN
        // timeout never does. Assert the loop ends normally.
        let mut turns: Vec<Vec<LlmResult<LlmStreamEvent>>> = Vec::new();
        for _ in 0..6 {
            turns.push(vec![
                tool("tu", "list_open_sessions", json!({})),
                done(1, 1),
            ]);
        }
        turns.push(vec![delta("done"), done(1, 1)]); // 7th: end-turn
        let client = Box::new(DelayedStreamClient {
            delay: Duration::from_millis(30),
            turns: StdMutex::new(turns),
        });
        let mut l = make_loop(client, fresh_conversation());
        l.bounds.stream_timeout = Duration::from_millis(200);
        l.bounds.checkpoint_rounds = 99;
        l.bounds.checkpoint_cost_microdollars = u64::MAX;

        let events = tokio::time::timeout(Duration::from_secs(5), drain(l.run()))
            .await
            .expect("must finish well within 5s");
        let last = events.last().unwrap();
        assert!(
            matches!(
                last,
                AgentLoopEvent::Completed {
                    stop_reason: StopReason::EndTurn,
                    ..
                }
            ),
            "per-turn timeout must reset each round; got {last:?}"
        );
    }

    #[tokio::test]
    async fn cancel_notify_aborts_during_stream() {
        // A turn with a tool_use that hands off; we cancel before
        // letting the loop dispatch.
        let client = Box::new(StubLlmClient::new(vec![vec![
            delta("starting"),
            tool("tu", "list_open_sessions", json!({})),
            done(1, 1),
        ]]));
        let mut l = make_loop(client, fresh_conversation());
        let cancel = Arc::clone(&l.cancel);
        l.bounds.checkpoint_rounds = 5;

        // Pre-fire the cancel notify so the first await-point select
        // wins on the cancel branch.
        cancel.notify_one();
        let events = drain(l.run()).await;
        let last = events.last().unwrap();
        assert!(matches!(
            last,
            AgentLoopEvent::Completed {
                stop_reason: StopReason::UserAborted,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn provider_error_terminates_with_provider_error() {
        let client = Box::new(StubLlmClient::new(vec![vec![
            delta("partial"),
            Err(LlmError::Malformed("garbled".into())),
        ]]));
        let l = make_loop(client, fresh_conversation());
        let events = drain(l.run()).await;
        let last = events.last().unwrap();
        match last {
            AgentLoopEvent::Completed {
                stop_reason: StopReason::ProviderError(e),
                ..
            } => {
                assert!(e.contains("garbled"), "unexpected error message: {e}");
            }
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_dispatch_error_records_then_loop_continues() {
        // First turn: tool_use that the dispatcher rejects (no
        // `with_propose` override → defaults to NotImplemented).
        // Second turn: model recovers with text-only answer.
        let client = Box::new(StubLlmClient::new(vec![
            vec![
                tool(
                    "tu_1",
                    "propose_command",
                    json!({"session_id": "s1", "command": "show version"}),
                ),
                done(10, 2),
            ],
            vec![delta("falling back"), done(20, 5)],
        ]));
        let l = make_loop(client, fresh_conversation());
        let events = drain(l.run()).await;
        let ends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                AgentLoopEvent::ToolUseEnd { result, .. } => Some(result.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ends.len(), 1);
        assert!(ends[0].is_err(), "expected propose_command to error");
        let last = events.last().unwrap();
        assert!(matches!(
            last,
            AgentLoopEvent::Completed {
                stop_reason: StopReason::EndTurn,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn malformed_tool_input_records_error_then_continues() {
        // Model emits a tool_use whose `name` doesn't match any
        // ToolCall variant. Recorded as an error so the model can
        // correct itself; loop continues to next turn.
        let client = Box::new(StubLlmClient::new(vec![
            vec![tool("tu_x", "imaginary_tool", json!({})), done(1, 1)],
            vec![delta("ok"), done(2, 1)],
        ]));
        let l = make_loop(client, fresh_conversation());
        let events = drain(l.run()).await;
        let parse_failures: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                AgentLoopEvent::ToolUseEnd { result: Err(s), .. }
                    if s.contains("parse failed") || s.contains("imaginary_tool") =>
                {
                    Some(s.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(parse_failures.len(), 1);
        let last = events.last().unwrap();
        assert!(matches!(
            last,
            AgentLoopEvent::Completed {
                stop_reason: StopReason::EndTurn,
                ..
            }
        ));
    }
}
