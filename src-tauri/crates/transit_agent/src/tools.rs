//! The agent's tool surface — **exactly six tools**.
//!
//! Inviolable Rule 2 (CLAUDE.md §3): adding a variant is a deliberate
//! scope expansion that requires explicit user approval and an update to
//! the `transit-agent-firewall-test` skill. The fifth tool
//! (`propose_api_call`, v4.0.0) was signed off for read-only investigation
//! of UniFi API controllers; it is GET-only by construction. The sixth
//! (`query_capture`, v6.0.0) was signed off by the maintainer on 2026-08-06 for the
//! PCaps surface: it reads a local capture file the user opened, is
//! metadata-only by construction (no payload variant exists to ask
//! through), and touches nothing. The
//! `static_assertions` block at the bottom of this file is a
//! compile-time tripwire: change the variant count and the build
//! breaks until the assert is updated.
//!
//! Wire format: each enum variant carries its own input/output
//! struct, tagged via `serde(tag = "tool", rename_all =
//! "snake_case")`. Inputs use `deny_unknown_fields` so a future
//! LLM hallucinating an extra field rejects at deserialization
//! rather than silently passing through.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// ToolCall — what the model asks for.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "tool", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolCall {
    /// Enumerate currently-open SSH sessions. Inputs: none. Returns
    /// session metadata (id, device_id, vendor, opened_at) where
    /// `device_id` is the connection name the user gave the device
    /// ("R1") — the handle users reference sessions by in chat. The
    /// model uses this to discover which sessions are available
    /// before reading scrollback or proposing a command.
    ListOpenSessions(ListOpenSessionsInput),

    /// Read recent output from a session. The dispatcher pipes the
    /// scrollback through `RedactionFilter` BEFORE returning, so the
    /// model never sees raw secret bytes. Capped per call.
    ReadScrollback(ReadScrollbackInput),

    /// Propose a command to run in a session. Phase 5a does NOT
    /// execute the command — the dispatcher in Phase 6 routes through
    /// the policy gate (`transit_policy`) AND a UI approval modal.
    /// Both gates run for every proposed command, never one or the
    /// other (Rule 3, CLAUDE.md §3).
    ProposeCommand(ProposeCommandInput),

    /// Request a clarification from the user. The dispatcher in
    /// Phase 6 surfaces a UI prompt; the model receives the user's
    /// reply as the tool result.
    AskUser(AskUserInput),

    /// Propose a GET against an API/controller session (a UniFi
    /// `[[api_session]]`). **GET-only by construction** — there is NO
    /// `method` field, so the model cannot even express a write; a
    /// hallucinated `"method"` rejects via `deny_unknown_fields`, and
    /// the `transit_api` gate default-denies non-GET as defense in
    /// depth. Like `propose_command`, the dispatcher runs the gate
    /// (GET-only + host-pin) AND a UI approval modal — both, every call
    /// (Rule 3). `path` is relative to the controller's fixed API base;
    /// the host is never caller-chosen (no SSRF).
    ProposeApiCall(ProposeApiCallInput),

    /// Query an open packet capture (v6.0.0, the PCaps surface).
    ///
    /// **Read-only and metadata-only by construction.** It reads a local
    /// file the user opened; it touches no device, sends nothing, and
    /// changes nothing anywhere — so unlike `propose_command` and
    /// `propose_api_call` it needs no gate and no approval modal. Adding
    /// one would be approval theatre that trains users to click through,
    /// which is the T18 failure mode.
    ///
    /// The `query` enum has no payload variant and no field that returns
    /// raw bytes, so a request for wire payload is not expressible — the
    /// same structural move that makes `propose_api_call` GET-only. Raw
    /// packet bytes, flow reassembly and export exist, but only as human
    /// IPC, deliberately absent from the `CaptureSource` trait this tool
    /// is served through. Threat model T45.
    QueryCapture(QueryCaptureInput),
}

// ---------------------------------------------------------------------
// ToolResult — what the dispatcher returns.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum ToolResult {
    ListOpenSessions(ListOpenSessionsOutput),
    ReadScrollback(ReadScrollbackOutput),
    ProposeCommand(ProposeCommandOutput),
    AskUser(AskUserOutput),
    ProposeApiCall(ProposeApiCallOutput),
    QueryCapture(QueryCaptureOutput),
}

// ---------------------------------------------------------------------
// Per-variant input + output schemas.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListOpenSessionsInput {}

#[derive(Debug, Clone, Serialize)]
pub struct ListOpenSessionsOutput {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    /// The session's id AS THE MODEL SHOULD USE IT. v6.1.1: inside a
    /// chat this is the short per-chat alias (`s1`, `s2`, …) the scoped
    /// view allocated — the backend registry UUID is deliberately not
    /// surfaced (local models mangle 36-char UUIDs under multi-session
    /// load; the roster only ever needed stability). Raw registry ids
    /// remain ACCEPTED as tool input for backward compatibility.
    pub session_id: String,
    /// The user's connection name for the device (inventory `id`,
    /// e.g. "R1") — what the user calls this session in chat.
    pub device_id: String,
    /// Vendor tag (`Vendor::as_str` form, e.g. "junos"). A string
    /// rather than the enum: `Vendor` only derives `Serialize` in
    /// tests, and the model consumes the stable string tag anyway.
    pub vendor: String,
    /// Transport kind (`SessionKind::as_str` form: "ssh" / "console" /
    /// "api") — the fact tool choice depends on. `propose_api_call`'s
    /// contract says "API sessions use this, SSH/console use
    /// propose_command"; without the kind, that choice is a guess
    /// (vendor can't stand in — one UniFi box is reachable both ways).
    pub kind: String,
    /// RFC3339 timestamp.
    pub opened_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadScrollbackInput {
    pub session_id: String,
    /// Cap the bytes returned to the LLM. Each call is independently
    /// capped so a single tool invocation can't burn the entire
    /// context window. The dispatcher MAY enforce a smaller cap.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    /// v6.1.x #4 — keep only lines containing this LITERAL substring
    /// (never a regex on model input), ± `context_lines` around each
    /// hit. The window-death cure: a needle instead of a full ring.
    /// Applied strictly AFTER redaction (§9 class of the caps).
    #[serde(rename = "match", default)]
    pub match_: Option<String>,
    /// Context lines kept around each match. Dispatcher-capped at 10.
    #[serde(default = "default_context_lines")]
    pub context_lines: usize,
}

fn default_max_bytes() -> usize {
    16 * 1024
}

fn default_context_lines() -> usize {
    2
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadScrollbackOutput {
    /// Redacted scrollback. The dispatcher MUST run the snapshot
    /// through `RedactionFilter` before populating this field.
    pub text: String,
    /// True when the scrollback exceeded `max_bytes` and the head
    /// of the buffer was dropped. The model can decide to issue a
    /// follow-up call with a different `max_bytes` or accept the
    /// truncation.
    pub truncated: bool,
    /// v6.1.x #4 — how many lines matched when the `match` param was
    /// used (`Some(0)` = the needle appears nowhere). `None` — and
    /// absent from the wire — on plain reads, so the pre-match result
    /// shape is byte-unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_matched: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeCommandInput {
    pub session_id: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProposeCommandOutput {
    /// Filled with the command's PTY output once both gates pass
    /// AND the command actually runs. Phase 6 supplies the full
    /// flow; Phase 5a's MockDispatcher returns canned values.
    pub output: String,
    /// True when the user approved + the command ran. False when the
    /// user declined or the policy gate denied — `output` then
    /// contains the deny reason for the model's benefit.
    pub executed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AskUserInput {
    pub question: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AskUserOutput {
    /// User's response, verbatim. The dispatcher MAY truncate
    /// excessively long replies; the model should not assume
    /// arbitrary length.
    pub answer: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeApiCallInput {
    pub session_id: String,
    /// Path (with optional `?query`) relative to the controller's fixed
    /// API base, e.g. "/v1/sites". GET is implicit — there is
    /// deliberately NO `method` field, so a write can't be expressed;
    /// `deny_unknown_fields` rejects a smuggled `"method"`, and the gate
    /// default-denies non-GET.
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProposeApiCallOutput {
    /// The REDACTED GET response body once both gates pass AND the call
    /// runs. On denial/decline, carries the reason for the model's
    /// benefit (same shape as `ProposeCommandOutput`).
    pub output: String,
    /// True when the user approved + the GET ran. False when declined or
    /// gate-denied — `output` then holds the reason.
    pub executed: bool,
}

/// Input for [`ToolCall::QueryCapture`].
///
/// The `query` field is an enum-tagged union, so the set of things a
/// model can ask for is exactly the set enumerated in
/// [`CaptureQueryWire`] — nothing else parses.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryCaptureInput {
    /// Which open capture. Omit when exactly one is open; with several,
    /// the error names them.
    #[serde(default)]
    pub capture_id: Option<String>,
    pub query: CaptureQueryWire,
}

/// The queries a model may ask of a capture.
///
/// **There is deliberately no payload, bytes, or raw variant.** Wire
/// payload is the densest credential surface in a capture — cleartext
/// HTTP `Authorization`, SNMP communities, telnet logins — and the way to
/// keep it out of a model's context is to leave it unaskable rather than
/// to filter requests for it. `deny_unknown_fields` means a hallucinated
/// `{"kind": "payload"}` rejects at deserialization.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureQueryWire {
    /// Which captures are open.
    ///
    /// An empty STRUCT variant, not a unit variant, and that is
    /// load-bearing: serde silently ignores unknown fields on a unit
    /// variant of an internally-tagged enum even under
    /// `deny_unknown_fields`, so `{"kind":"list","payload":true}` would
    /// parse. Harmless today — the field is dropped, not honoured — but
    /// it breaks the contract this type exists to state, and it would
    /// become meaningful the moment someone gives the variant a field.
    /// The empty braces make the denial real.
    List {},
    /// The capture digest — start here. Size-independent, so this is the
    /// cheap way to understand a capture of any size.
    Overview {},
    /// Packet rows matching a view filter.
    Packets {
        #[serde(default)]
        filter: Option<String>,
        #[serde(default)]
        offset: u32,
        #[serde(default = "default_row_limit")]
        limit: u32,
    },
    /// The conversation table.
    Conversations {
        #[serde(default = "default_flow_sort")]
        by: String,
        #[serde(default = "default_row_limit")]
        limit: u32,
    },
    /// One conversation in detail.
    Flow { flow_id: u32 },
    /// One packet's dissected fields.
    Packet { number: u64 },
    /// Deterministic findings.
    Findings {
        #[serde(default)]
        severity: Option<String>,
        #[serde(default = "default_row_limit")]
        limit: u32,
    },
    /// Time-bucketed counters.
    Timeline {
        #[serde(default = "default_bucket_ms")]
        bucket_ms: u32,
        #[serde(default)]
        filter: Option<String>,
    },
}

fn default_row_limit() -> u32 {
    100
}

fn default_flow_sort() -> String {
    "bytes".to_string()
}

fn default_bucket_ms() -> u32 {
    1000
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryCaptureOutput {
    /// The REDACTED answer, framed as untrusted capture-derived content.
    pub text: String,
    /// Rows matching in total, when the query is row-shaped. The model is
    /// always told what it did not see.
    pub total_matched: Option<u64>,
    /// True when a limit elided rows.
    pub truncated: bool,
}

// ---------------------------------------------------------------------
// Compile-time tripwire on the tool surface.
//
// Counts the discriminants by enumerating each variant in a match.
// If a variant is added or removed, this stops compiling — and the
// assert below stops compiling — until the assert is updated, which
// is exactly when the `transit-agent-firewall-test` skill should be
// re-run and Rule 2 re-acknowledged.
// ---------------------------------------------------------------------

#[allow(dead_code)]
const TOOL_CALL_VARIANT_COUNT: usize = {
    // Match-arm-style "count by enumeration". The compiler verifies
    // the match is exhaustive; if a new variant is added without
    // updating this list, the build fails.
    use ToolCall::*;
    let _example: Option<ToolCall> = None;
    match _example {
        None => 6,
        Some(ListOpenSessions(_)) => 1,
        Some(ReadScrollback(_)) => 1,
        Some(ProposeCommand(_)) => 1,
        Some(AskUser(_)) => 1,
        Some(ProposeApiCall(_)) => 1,
        Some(QueryCapture(_)) => 1,
    }
};

static_assertions::const_assert_eq!(TOOL_CALL_VARIANT_COUNT, 6);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_count_is_exactly_six() {
        // Runtime mirror of the compile-time const_assert. If the
        // const_assert ever stops being a tripwire (e.g. someone
        // hardcodes the number in a future refactor), this catches it.
        assert_eq!(TOOL_CALL_VARIANT_COUNT, 6);
    }

    #[test]
    fn list_open_sessions_serde_round_trip() {
        let json = r#"{"tool":"list_open_sessions"}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        assert!(matches!(call, ToolCall::ListOpenSessions(_)));
    }

    #[test]
    fn read_scrollback_uses_default_max_bytes() {
        let json = r#"{"tool":"read_scrollback","session_id":"abc"}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::ReadScrollback(input) => {
                assert_eq!(input.session_id, "abc");
                assert_eq!(input.max_bytes, 16 * 1024);
            }
            _ => panic!("expected ReadScrollback"),
        }
    }

    #[test]
    fn read_scrollback_accepts_explicit_max_bytes() {
        let json = r#"{"tool":"read_scrollback","session_id":"abc","max_bytes":4096}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::ReadScrollback(input) => assert_eq!(input.max_bytes, 4096),
            _ => panic!("expected ReadScrollback"),
        }
    }

    #[test]
    fn deny_unknown_fields_rejects_hallucinated_input() {
        // A future LLM hallucinating an extra `priority: "high"` field
        // must NOT silently pass through. Pinning this means a tool
        // can never grow undocumented inputs by accident.
        let json =
            r#"{"tool":"read_scrollback","session_id":"abc","max_bytes":4096,"priority":"high"}"#;
        let result: Result<ToolCall, _> = serde_json::from_str(json);
        assert!(result.is_err(), "extra field must reject");
    }

    #[test]
    fn propose_command_serde_round_trip() {
        let json = r#"{"tool":"propose_command","session_id":"abc","command":"show version"}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::ProposeCommand(input) => {
                assert_eq!(input.session_id, "abc");
                assert_eq!(input.command, "show version");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ask_user_serde_round_trip() {
        let json = r#"{"tool":"ask_user","question":"Which device?"}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::AskUser(input) => assert_eq!(input.question, "Which device?"),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_tool_rejects() {
        let json = r#"{"tool":"run_arbitrary_code","payload":"rm -rf /"}"#;
        let result: Result<ToolCall, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown tool name must reject");
    }

    #[test]
    fn propose_api_call_serde_round_trip() {
        let json = r#"{"tool":"propose_api_call","session_id":"office-unifi","path":"/v1/sites"}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::ProposeApiCall(input) => {
                assert_eq!(input.session_id, "office-unifi");
                assert_eq!(input.path, "/v1/sites");
            }
            _ => panic!("expected ProposeApiCall"),
        }
    }

    #[test]
    fn query_capture_serde_round_trip() {
        let json = r#"{"tool":"query_capture","query":{"kind":"overview"}}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::QueryCapture(input) => {
                assert_eq!(input.capture_id, None);
                assert_eq!(input.query, CaptureQueryWire::Overview {});
            }
            _ => panic!("expected QueryCapture"),
        }
    }

    #[test]
    fn query_capture_row_limits_default() {
        let json = r#"{"tool":"query_capture","query":{"kind":"packets"}}"#;
        let call: ToolCall = serde_json::from_str(json).unwrap();
        match call {
            ToolCall::QueryCapture(input) => assert_eq!(
                input.query,
                CaptureQueryWire::Packets {
                    filter: None,
                    offset: 0,
                    limit: 100
                }
            ),
            _ => panic!(),
        }
    }

    /// **The structural half of "metadata only".** Wire payload is the
    /// densest credential surface a capture holds, and the way it stays
    /// out of the model's context is that there is no shape in which to
    /// ask for it — not a filter on requests, an absence of the request.
    #[test]
    fn query_capture_cannot_express_a_request_for_packet_payload() {
        for json in [
            r#"{"tool":"query_capture","query":{"kind":"payload","number":1}}"#,
            r#"{"tool":"query_capture","query":{"kind":"bytes","number":1}}"#,
            r#"{"tool":"query_capture","query":{"kind":"raw","number":1}}"#,
            r#"{"tool":"query_capture","query":{"kind":"follow_stream","flow_id":1}}"#,
            r#"{"tool":"query_capture","query":{"kind":"export","path":"/tmp/x"}}"#,
            // A payload field smuggled onto a legitimate variant.
            r#"{"tool":"query_capture","query":{"kind":"packet","number":1,"include_payload":true}}"#,
            r#"{"tool":"query_capture","query":{"kind":"packet","number":1,"bytes":true}}"#,
        ] {
            let result: Result<ToolCall, _> = serde_json::from_str(json);
            assert!(
                result.is_err(),
                "a request for packet payload must not parse: {json}"
            );
        }
    }

    #[test]
    fn propose_api_call_rejects_a_method_field() {
        // GET-only is structural: the input has no `method`, so a model
        // trying to smuggle a write rejects at deserialization (there is
        // no code path that reads a method from an api call).
        let json =
            r#"{"tool":"propose_api_call","session_id":"x","path":"/v1/sites","method":"POST"}"#;
        let result: Result<ToolCall, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "a `method` field must reject — GET is implicit"
        );
    }
}
