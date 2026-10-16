//! LLM tool surface, redaction filter, and Conversation state.
//!
//! The agent's tool surface is exactly six tools — `list_open_sessions`,
//! `read_scrollback`, `propose_command`, `ask_user`, `propose_api_call`
//! (the fifth, v4.0.0 — GET-only investigation of API/controller sessions),
//! and `query_capture` (the sixth, v6.0.0 — read-only, metadata-only
//! queries against an open packet capture).
//! Adding another requires explicit user approval and updates to the
//! `transit-agent-firewall-test` skill's expected variant count.
//!
//! This crate is explicitly forbidden from depending on `transit_auth`.
//! That makes the agent firewall a property of the type system: the agent
//! has no path by which it could read a credential, even if a future tool
//! were added.

pub mod agent_loop;
pub mod capture;
mod conversation;
mod dispatcher;
mod dispatcher_impl;
mod error;
pub mod llm;
pub mod redaction;
pub mod scrollback;
pub mod system_prompt;
pub mod testing;
mod text;
mod tool_schemas;
mod tools;
pub mod usage;

pub use agent_loop::{AgentLoop, AgentLoopEvent, LoopBounds, StopReason};
pub use capture::{
    resolve_capture_id, CaptureAnswer, CaptureMeta, CaptureQueryError, CaptureQueryKind,
    CaptureSource,
};
pub use conversation::{Conversation, Message};
pub use dispatcher::ToolDispatcher;
pub use dispatcher_impl::DefaultDispatcher;
pub use error::AgentError;
pub use llm::{
    DirectAnthropic, DirectOpenAI, LlmClient, LlmError, LlmMessage, LlmRequest, LlmResult,
    LlmStream, LlmStreamEvent, ModelLevel, OpenAiAuth, ProviderModel, ToolSchema, ToolUseBlock,
};
pub use redaction::{ConversationRedactor, RedactionFilter};
pub use scrollback::{ScrollbackSource, SessionKind, SessionMeta, Snapshot};
pub use system_prompt::{PromptSection, SectionKind, SystemPrompt};
pub use text::{
    cap_head_tail, cap_json_response, envelope_attr_safe, frame_session, match_filter, tail_keep,
};
pub use tool_schemas::standard_tool_schemas;
pub use tools::{
    AskUserInput, AskUserOutput, CaptureQueryWire, ListOpenSessionsInput, ListOpenSessionsOutput,
    ProposeApiCallInput, ProposeApiCallOutput, ProposeCommandInput, ProposeCommandOutput,
    QueryCaptureInput, QueryCaptureOutput, ReadScrollbackInput, ReadScrollbackOutput,
    SessionSummary, ToolCall, ToolResult,
};
pub use usage::{Pricing, TokenUsage};
