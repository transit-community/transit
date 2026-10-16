//! Test helpers — `MockDispatcher` for downstream-phase tests.
//!
//! Production dispatchers compose `transit_ssh`, `transit_policy`,
//! and Tauri (`transit_app::commands::agent_dispatch` per CLAUDE.md
//! §8). Those live downstream of this crate, so we can't test the
//! agent's loop logic against them from inside `transit_agent`. The
//! mock fills that gap: it implements the trait with canned
//! responses driven by per-tool closures so a test can script
//! "list returns these sessions, scrollback returns this redacted
//! string, propose succeeds, ask returns this answer."
//!
//! Why this lives in the agent crate and not in a test-only crate:
//! Phase 5b's `Conversation` integration tests need a dispatcher to
//! drive the loop; making them depend on a `transit_agent_testing`
//! crate would inflate the workspace. `pub mod testing` keeps the
//! mock accessible while signaling its intended audience.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::dispatcher::ToolDispatcher;
use crate::error::AgentError;
use crate::scrollback::{ScrollbackSource, SessionMeta, Snapshot};
use crate::tools::{
    AskUserOutput, ListOpenSessionsOutput, ProposeApiCallOutput, ProposeCommandOutput,
    ReadScrollbackOutput, ToolCall, ToolResult,
};

/// Closure boxed for sharing across awaits.
type ListFn = Arc<dyn Fn() -> Result<ListOpenSessionsOutput, AgentError> + Send + Sync>;
type ReadFn = Arc<dyn Fn(&str, usize) -> Result<ReadScrollbackOutput, AgentError> + Send + Sync>;
type ProposeFn = Arc<dyn Fn(&str, &str) -> Result<ProposeCommandOutput, AgentError> + Send + Sync>;
type AskFn = Arc<dyn Fn(&str) -> Result<AskUserOutput, AgentError> + Send + Sync>;
type ApiCallFn = Arc<dyn Fn(&str, &str) -> Result<ProposeApiCallOutput, AgentError> + Send + Sync>;

/// Scriptable dispatcher for tests. Each handler defaults to
/// `AgentError::NotImplemented`; tests override only the tools the
/// scenario exercises.
pub struct MockDispatcher {
    list: ListFn,
    read: ReadFn,
    propose: ProposeFn,
    ask: AskFn,
    api_call: ApiCallFn,
    /// Records every call in order. Tests can assert the model
    /// invoked the expected sequence of tools.
    pub calls: Arc<Mutex<Vec<ToolCall>>>,
}

impl MockDispatcher {
    /// All four handlers default to `NotImplemented`. Override
    /// before use via the `with_*` builders.
    pub fn new() -> Self {
        Self {
            list: Arc::new(|| {
                Err(AgentError::NotImplemented {
                    tool: "list_open_sessions",
                })
            }),
            read: Arc::new(|_, _| {
                Err(AgentError::NotImplemented {
                    tool: "read_scrollback",
                })
            }),
            propose: Arc::new(|_, _| {
                Err(AgentError::NotImplemented {
                    tool: "propose_command",
                })
            }),
            ask: Arc::new(|_| Err(AgentError::NotImplemented { tool: "ask_user" })),
            api_call: Arc::new(|_, _| {
                Err(AgentError::NotImplemented {
                    tool: "propose_api_call",
                })
            }),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_list<F>(mut self, f: F) -> Self
    where
        F: Fn() -> Result<ListOpenSessionsOutput, AgentError> + Send + Sync + 'static,
    {
        self.list = Arc::new(f);
        self
    }

    pub fn with_read<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, usize) -> Result<ReadScrollbackOutput, AgentError> + Send + Sync + 'static,
    {
        self.read = Arc::new(f);
        self
    }

    pub fn with_propose<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> Result<ProposeCommandOutput, AgentError> + Send + Sync + 'static,
    {
        self.propose = Arc::new(f);
        self
    }

    pub fn with_ask<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<AskUserOutput, AgentError> + Send + Sync + 'static,
    {
        self.ask = Arc::new(f);
        self
    }

    pub fn with_api_call<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> Result<ProposeApiCallOutput, AgentError> + Send + Sync + 'static,
    {
        self.api_call = Arc::new(f);
        self
    }
}

impl Default for MockDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolDispatcher for MockDispatcher {
    async fn dispatch(&self, call: ToolCall) -> Result<ToolResult, AgentError> {
        self.calls
            .lock()
            .expect("call log mutex poisoned")
            .push(call.clone());
        match call {
            ToolCall::ListOpenSessions(_) => (self.list)().map(ToolResult::ListOpenSessions),
            ToolCall::ReadScrollback(input) => {
                (self.read)(&input.session_id, input.max_bytes).map(ToolResult::ReadScrollback)
            }
            ToolCall::ProposeCommand(input) => {
                (self.propose)(&input.session_id, &input.command).map(ToolResult::ProposeCommand)
            }
            ToolCall::AskUser(input) => (self.ask)(&input.question).map(ToolResult::AskUser),
            ToolCall::QueryCapture(_) => Err(AgentError::NotImplemented {
                tool: "query_capture",
            }),

            ToolCall::ProposeApiCall(input) => {
                (self.api_call)(&input.session_id, &input.path).map(ToolResult::ProposeApiCall)
            }
        }
    }
}

// ---------------------------------------------------------------------
// MockScrollbackSource — canned scrollback for `DefaultDispatcher`
// tests and Phase 5b's Conversation integration tests.
// ---------------------------------------------------------------------

/// In-memory `ScrollbackSource` impl. Sessions are added via
/// `with_session(meta, scrollback)`. `snapshot` returns the FULL
/// stored scrollback — per the trait contract, all sizing (the
/// tool's `max_bytes` tail-keep window + the output cap) happens in
/// the dispatcher, strictly after redaction.
#[derive(Debug, Default, Clone)]
pub struct MockScrollbackSource {
    /// Keyed by session_id. The String is the canned scrollback.
    sessions: HashMap<String, (SessionMeta, String)>,
}

impl MockScrollbackSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_session(mut self, meta: SessionMeta, scrollback: impl Into<String>) -> Self {
        self.sessions
            .insert(meta.session_id.clone(), (meta, scrollback.into()));
        self
    }
}

impl ScrollbackSource for MockScrollbackSource {
    fn snapshot(&self, session_id: &str) -> Option<Snapshot> {
        // Full ring contents, no head-drop: the mock's canned string
        // IS the ring. `truncated: false` because nothing was ever
        // evicted — the dispatcher's own post-redaction trims set
        // the flag when they fire.
        let (_, full) = self.sessions.get(session_id)?;
        Some(Snapshot {
            text: full.clone(),
            truncated: false,
            json: false,
        })
    }

    fn list(&self) -> Vec<SessionMeta> {
        let mut v: Vec<SessionMeta> = self.sessions.values().map(|(m, _)| m.clone()).collect();
        // Stable order for snapshot tests.
        v.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{
        ListOpenSessionsInput, ProposeCommandInput, ReadScrollbackInput, SessionSummary,
    };

    #[tokio::test]
    async fn defaults_to_not_implemented() {
        let mock = MockDispatcher::new();
        let err = mock
            .dispatch(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::NotImplemented { .. }));
    }

    #[tokio::test]
    async fn with_list_drives_canned_response() {
        let mock = MockDispatcher::new().with_list(|| {
            Ok(ListOpenSessionsOutput {
                sessions: vec![SessionSummary {
                    session_id: "s1".into(),
                    device_id: "vEX1".into(),
                    vendor: "junos".into(),
                    kind: "ssh".into(),
                    opened_at: "2026-05-08T00:00:00Z".into(),
                }],
            })
        });
        let res = mock
            .dispatch(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
            .await
            .unwrap();
        match res {
            ToolResult::ListOpenSessions(o) => {
                assert_eq!(o.sessions.len(), 1);
                assert_eq!(o.sessions[0].device_id, "vEX1");
            }
            _ => panic!("expected ListOpenSessions"),
        }
    }

    #[tokio::test]
    async fn calls_are_recorded() {
        let mock = MockDispatcher::new()
            .with_list(|| Ok(ListOpenSessionsOutput { sessions: vec![] }))
            .with_read(|_, _| {
                Ok(ReadScrollbackOutput {
                    text: "hello".into(),
                    truncated: false,
                    total_matched: None,
                })
            });
        mock.dispatch(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
            .await
            .unwrap();
        mock.dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "s1".into(),
            max_bytes: 4096,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
        let log = mock.calls.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert!(matches!(log[0], ToolCall::ListOpenSessions(_)));
        assert!(matches!(log[1], ToolCall::ReadScrollback(_)));
    }

    #[tokio::test]
    async fn with_ask_drives_canned_response() {
        let mock = MockDispatcher::new().with_ask(|q| {
            Ok(AskUserOutput {
                answer: format!("you asked: {q}"),
            })
        });
        let res = mock
            .dispatch(ToolCall::AskUser(crate::tools::AskUserInput {
                question: "Which device?".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::AskUser(o) => assert_eq!(o.answer, "you asked: Which device?"),
            _ => panic!("expected AskUser"),
        }
    }

    #[tokio::test]
    async fn propose_routing_works() {
        let mock = MockDispatcher::new().with_propose(|_, cmd| {
            Ok(ProposeCommandOutput {
                output: format!("ran: {cmd}"),
                executed: true,
            })
        });
        let res = mock
            .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
                session_id: "s1".into(),
                command: "show version".into(),
            }))
            .await
            .unwrap();
        match res {
            ToolResult::ProposeCommand(o) => {
                assert_eq!(o.output, "ran: show version");
                assert!(o.executed);
            }
            _ => panic!("expected ProposeCommand"),
        }
    }
}

// ---------------------------------------------------------------------
// Capture source (v6.0.0 PCaps)
// ---------------------------------------------------------------------

/// In-memory [`CaptureSource`] impl. Answers every query with the same
/// canned text, which is all the dispatcher tests need: what they are
/// checking is the redaction, capping and framing the dispatcher applies
/// *around* an answer, not the engine that produced it.
#[derive(Debug, Default, Clone)]
pub struct MockCaptureSource {
    captures: Vec<crate::capture::CaptureMeta>,
    answer: String,
    total_matched: Option<u64>,
}

impl MockCaptureSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capture(mut self, capture_id: &str, name: &str) -> Self {
        self.captures.push(crate::capture::CaptureMeta {
            capture_id: capture_id.into(),
            name: name.into(),
            packets: 42,
            bytes: 4096,
            duration: "00:00:10.000".into(),
            live: false,
        });
        self
    }

    pub fn answering(mut self, text: impl Into<String>) -> Self {
        self.answer = text.into();
        self
    }

    pub fn with_total_matched(mut self, n: u64) -> Self {
        self.total_matched = Some(n);
        self
    }
}

impl crate::capture::CaptureSource for MockCaptureSource {
    fn list(&self) -> Vec<crate::capture::CaptureMeta> {
        self.captures.clone()
    }

    fn query(
        &self,
        capture_id: Option<&str>,
        _kind: &crate::capture::CaptureQueryKind,
    ) -> Result<crate::capture::CaptureAnswer, crate::capture::CaptureQueryError> {
        // Resolution goes through the shared helper, so the mock cannot
        // drift from the real source on the one behaviour a model will
        // actually trip over.
        crate::capture::resolve_capture_id(capture_id, &self.captures)?;
        Ok(crate::capture::CaptureAnswer {
            text: self.answer.clone(),
            total_matched: self.total_matched,
            returned: None,
            truncated: false,
        })
    }
}
