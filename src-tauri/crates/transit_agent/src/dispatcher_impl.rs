//! Production-style `ToolDispatcher` for Phase 5b.
//!
//! `DefaultDispatcher` composes a [`ScrollbackSource`] (the SSH-side
//! seam) with a per-Conversation [`ConversationRedactor`] and:
//!
//! - serves `ListOpenSessions` from `source.list()`
//! - serves `ReadScrollback` by snapshotting the FULL ring →
//!   redacting → tail-keep windowing to the tool's `max_bytes` →
//!   capping → wrapping the result in `<session id="…">…</session>`
//!   framing tags. Every trim runs strictly AFTER `redact()` (the
//!   redact-before-trim contract — a pre-redaction trim can
//!   decapitate a PEM block and blind the multi-line matcher). The
//!   framing lives here (not in `Conversation`) because untrusted
//!   device bytes must be marked at the source — any caller that
//!   bypasses `Conversation` (CLI smoke tools, future UI surfaces)
//!   still gets the injection guard.
//! - returns `NotImplemented` for `ProposeCommand` (Phase 6 owns
//!   Inviolable Rule 3: every propose runs both the policy gate AND
//!   the UI modal — half-implementing it here would defeat the rule)
//! - returns `NotImplemented` for `AskUser` (Phase 5d wires the chat
//!   panel; without a UI to render the prompt, there's no way to
//!   honor the call)

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::capture::{CaptureQueryKind, CaptureSource};
use crate::dispatcher::ToolDispatcher;
use crate::error::AgentError;
use crate::redaction::ConversationRedactor;
use crate::scrollback::ScrollbackSource;
use crate::tools::{
    CaptureQueryWire, ListOpenSessionsOutput, QueryCaptureOutput, ReadScrollbackOutput,
    SessionSummary, ToolCall, ToolResult,
};

pub struct DefaultDispatcher {
    source: Arc<dyn ScrollbackSource>,
    redactor: Arc<Mutex<ConversationRedactor>>,
    /// v6.0.0 PCaps. `None` when no capture engine is wired (every test
    /// that predates the surface, and a deployment with
    /// `[pcap] agent_access = false`), in which case `query_capture`
    /// answers `NotImplemented` rather than pretending there is nothing
    /// to see.
    captures: Option<Arc<dyn CaptureSource>>,
}

impl DefaultDispatcher {
    pub fn new(
        source: Arc<dyn ScrollbackSource>,
        redactor: Arc<Mutex<ConversationRedactor>>,
    ) -> Self {
        Self {
            source,
            redactor,
            captures: None,
        }
    }

    /// Attach a capture source, making `query_capture` answerable.
    ///
    /// Opt-in rather than a constructor argument so the absence of a
    /// capture engine stays the default: a caller that has not thought
    /// about the PCaps surface does not accidentally expose it.
    pub fn with_captures(mut self, captures: Arc<dyn CaptureSource>) -> Self {
        self.captures = Some(captures);
        self
    }
}

/// Translate the wire shape into the engine-facing query.
///
/// A deliberate second enum rather than one shared type: the wire form is
/// part of the model-facing contract (and is what `deny_unknown_fields`
/// polices), while the engine form is free to change. Mapping between
/// them here means a new engine capability cannot become model-reachable
/// by accident — someone has to add an arm.
fn wire_to_query(w: &CaptureQueryWire) -> CaptureQueryKind {
    match w {
        CaptureQueryWire::List {} => CaptureQueryKind::List,
        CaptureQueryWire::Overview {} => CaptureQueryKind::Overview,
        CaptureQueryWire::Packets {
            filter,
            offset,
            limit,
        } => CaptureQueryKind::Packets {
            filter: filter.clone(),
            offset: *offset,
            limit: *limit,
        },
        CaptureQueryWire::Conversations { by, limit } => CaptureQueryKind::Conversations {
            by: by.clone(),
            limit: *limit,
        },
        CaptureQueryWire::Flow { flow_id } => CaptureQueryKind::Flow { flow_id: *flow_id },
        CaptureQueryWire::Packet { number } => CaptureQueryKind::Packet { number: *number },
        CaptureQueryWire::Findings { severity, limit } => CaptureQueryKind::Findings {
            severity: severity.clone(),
            limit: *limit,
        },
        CaptureQueryWire::Timeline { bucket_ms, filter } => CaptureQueryKind::Timeline {
            bucket_ms: *bucket_ms,
            filter: filter.clone(),
        },
    }
}

#[async_trait]
impl ToolDispatcher for DefaultDispatcher {
    async fn dispatch(&self, call: ToolCall) -> Result<ToolResult, AgentError> {
        match call {
            ToolCall::ListOpenSessions(_) => {
                let sessions = self
                    .source
                    .list()
                    .into_iter()
                    .map(|m| SessionSummary {
                        // v6.1.1 — the agent's session id IS the chat's
                        // alias (`s1`) when the scoped view allocated one.
                        // The backend registry key was never load-bearing
                        // for the model, only a stable roster; local
                        // models demonstrably mangle 36-char UUIDs under
                        // multi-session load. Raw ids still appear for
                        // unscoped sources (unit tests) and stay accepted
                        // as tool input either way.
                        session_id: m.agent_facing_id().to_string(),
                        device_id: m.device_id,
                        vendor: m.vendor.as_str().to_string(),
                        kind: m.kind.as_str().to_string(),
                        opened_at: m.opened_at,
                    })
                    .collect();
                Ok(ToolResult::ListOpenSessions(ListOpenSessionsOutput {
                    sessions,
                }))
            }

            ToolCall::ReadScrollback(input) => {
                // The source returns the FULL ring — no byte budget.
                // Sizing happens below, strictly after redaction.
                let snap = self.source.snapshot(&input.session_id).ok_or_else(|| {
                    AgentError::SessionNotFound {
                        session_id: input.session_id.clone(),
                    }
                })?;
                // Redact FIRST, on the whole ring — before any trim
                // and before framing. A pre-redaction trim could cut
                // a multi-line PEM block so its `-----BEGIN` falls
                // outside the window: the headless tail would no
                // longer match the PEM regex and would leak. Framing
                // also waits: a pattern that didn't expect the
                // leading `<session id=…>` could fail to match
                // boundary-anchored secrets.
                let mut redactor = self
                    .redactor
                    .lock()
                    .expect("conversation redactor mutex poisoned");
                // API-JSON responses skip the bare-hex identifier
                // catch-all (a hostId/consoleId is not a secret and the
                // agent needs it to build the next request); terminal
                // output takes the full catch-all, where a bare token can
                // be a keyless secret. `redact_json` still runs every
                // key-anchored secret pattern + PEM + base64-blob.
                let redacted = if snap.json {
                    redactor.redact_json(&snap.text)
                } else {
                    redactor.redact(&snap.text)
                };
                drop(redactor);
                // Pipeline (all strictly post-redact, emitting no
                // device bytes of their own):
                //   full ring → redact → tail-keep(max_bytes) → cap.
                // Tail-keep honors the tool's `max_bytes` as a
                // most-recent-bytes window (the budget the source
                // itself used to apply, pre-redaction — that was the
                // PEM-decapitation bug).
                // v6.1.x #4 — the match filter, strictly post-redact
                // (same §9 class as the caps: it can match a
                // [REDACTED:…] marker, never raw secret bytes). The
                // filtered view then flows through the same
                // window/cap/frame pipeline as a plain read. An empty
                // needle is handled INSIDE match_filter as match-all (an
                // honest whole-view read with total_matched set), so the
                // guard here is only Some-vs-None, not emptiness.
                //
                // `match_dropped` records whether the filter elided any
                // line, so `truncated` below stays honest even though
                // the window/cap measure the FILTERED text (a filter
                // that hid 99% of the ring must not report truncated:
                // false).
                let full_redacted_len = redacted.len();
                let (redacted, total_matched, match_dropped) = match input.match_.as_deref() {
                    Some(needle) => {
                        let context = input.context_lines.min(10);
                        let (filtered, n) = crate::text::match_filter(&redacted, needle, context);
                        let dropped = filtered.len() < full_redacted_len;
                        (filtered, Some(n), dropped)
                    }
                    None => (redacted, None, false),
                };
                let tail_trimmed = redacted.len() > input.max_bytes;
                let windowed = crate::text::tail_keep(&redacted, input.max_bytes);
                // Source-side cap (strictly post-redact): bound a
                // single snapshot so one huge read doesn't ride every
                // later turn. Keep `truncated` honest if the cap trims.
                const READ_SCROLLBACK_MAX_BYTES: usize = 16 * 1024;
                let cap_trimmed = windowed.len() > READ_SCROLLBACK_MAX_BYTES;
                let capped = crate::text::cap_head_tail(windowed, READ_SCROLLBACK_MAX_BYTES);
                // v6.1.1 — envelope carries the roster alias as the id
                // plus a `device="…"` echo: every result re-teaches the
                // session→device binding in-context, and a narrate-X-
                // read-Y slip becomes self-evident. The meta lookup uses
                // the SAME precedence as the app-side resolver (alias-map
                // FIRST, raw id second — two passes, never first-match-
                // in-list-order over an OR): the bytes above came from
                // alias-first resolution inside the scoped source, so a
                // list-order lookup could name a DIFFERENT session than
                // the bytes it wraps when a raw id collides with an
                // allocated alias. The attribute values are Transit-
                // authored (alias / inventory device id), sanitized in
                // `frame_session`; framing stays strictly AFTER
                // redact+cap and adds no device bytes.
                let list = self.source.list();
                let meta = list
                    .iter()
                    .find(|m| m.alias.as_deref() == Some(input.session_id.as_str()))
                    .or_else(|| list.iter().find(|m| m.session_id == input.session_id));
                let display_id = meta
                    .map(|m| m.agent_facing_id())
                    .unwrap_or(&input.session_id);
                let framed = crate::text::frame_session(
                    display_id,
                    meta.map(|m| m.device_id.as_str()),
                    &[],
                    &capped,
                );
                Ok(ToolResult::ReadScrollback(ReadScrollbackOutput {
                    text: framed,
                    truncated: snap.truncated || tail_trimmed || cap_trimmed || match_dropped,
                    total_matched,
                }))
            }

            ToolCall::ProposeCommand(_) => Err(AgentError::NotImplemented {
                tool: "propose_command",
            }),

            ToolCall::AskUser(_) => Err(AgentError::NotImplemented { tool: "ask_user" }),

            // Like propose_command, this is an approval-gated tool — the
            // read-only DefaultDispatcher never executes it (the
            // ApprovalDispatcher in transit_app does).
            ToolCall::ProposeApiCall(_) => Err(AgentError::NotImplemented {
                tool: "propose_api_call",
            }),

            // v6.0.0 PCaps. Served HERE rather than by the approval
            // dispatcher because it changes nothing: it reads a local
            // file the user opened, touches no device, and sends nothing.
            // A gate would have nothing to adjudicate and a modal would
            // be approval theatre (T18).
            ToolCall::QueryCapture(input) => {
                let Some(source) = self.captures.as_ref() else {
                    return Err(AgentError::NotImplemented {
                        tool: "query_capture",
                    });
                };
                let kind = wire_to_query(&input.query);
                let answer = source
                    .query(input.capture_id.as_deref(), &kind)
                    // The engine's refusals are written to be actionable
                    // by the model on its next call — "several captures
                    // are open, name one with capture_id: …" rather than
                    // a bare failure.
                    .map_err(|e| AgentError::InvalidArgument(e.to_string()))?;

                // Same redact-before-trim contract as scrollback, and for
                // a sharper reason. A capture's strings are chosen by
                // anyone who can put a frame on the monitored segment, so
                // this is the widest untrusted-input boundary Transit
                // has. The engine already sanitizes (control bytes, field
                // lengths) and the dissectors already refuse
                // credential-bearing fields; this is the third layer,
                // catching secret SHAPES — a token in a URL query string,
                // a key-looking blob in a header we do decode.
                let mut redactor = self
                    .redactor
                    .lock()
                    .expect("conversation redactor mutex poisoned");
                let redacted = redactor.redact(&answer.text);
                drop(redactor);

                // Cap AFTER redaction, never before: a pre-redaction trim
                // can shear a secret so the pattern that would have
                // caught it no longer matches.
                const QUERY_CAPTURE_MAX_BYTES: usize = 32 * 1024;
                let cap_trimmed = redacted.len() > QUERY_CAPTURE_MAX_BYTES;
                let capped = crate::text::cap_head_tail(&redacted, QUERY_CAPTURE_MAX_BYTES);

                // Framed as untrusted at the source, exactly like
                // `<session>`. Anything inside came off a wire.
                let framed = format!(
                    "<capture id=\"{}\">\n{}\n</capture>",
                    input.capture_id.as_deref().unwrap_or("open"),
                    capped
                );
                Ok(ToolResult::QueryCapture(QueryCaptureOutput {
                    text: framed,
                    total_matched: answer.total_matched,
                    truncated: answer.truncated || cap_trimmed,
                }))
            }
        }
    }
}
