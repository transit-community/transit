//! The [`ToolSchema`]s the agent loop hands to the model.
//!
//! These are the public face of the tool surface — they're what the
//! provider (Anthropic / OpenAI) sees in the request body. The
//! `name` strings MUST match the `serde(tag = "tool", ...)`
//! discriminator on [`crate::tools::ToolCall`] so the agent loop can
//! parse a `ToolUseComplete { name, input, .. }` event back into a
//! typed `ToolCall` via:
//!
//! ```ignore
//! let payload = json!({"tool": name, ...input});
//! let call: ToolCall = serde_json::from_value(payload)?;
//! ```
//!
//! `description` is intentionally concise — fuller usage guidance
//! lives in `system_prompt`'s `ToolSchema` section. This text is
//! what the model sees when picking a tool, so it should describe
//! WHEN to call (and WHEN NOT to) without re-explaining the
//! redaction / policy machinery the system prompt already covers.
//!
//! `input_schema` is a JSON Schema describing the corresponding
//! `*Input` struct in `crate::tools`. The fields, defaults, and
//! `additionalProperties: false` mirror the `#[serde(deny_unknown_fields)]`
//! attribute — a model hallucinating an extra field rejects at
//! the provider OR at deserialization (defense in depth).

use serde_json::json;

use crate::llm::ToolSchema;

/// The canonical six-tool surface.
///
/// Order matches the [`crate::tools::ToolCall`] enum and is
/// load-bearing for the byte-stable insta snapshot in tests —
/// re-ordering breaks the snapshot, which is the intended trip-wire
/// (PR review must explicitly acknowledge a tool-surface change).
pub fn standard_tool_schemas() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "list_open_sessions".into(),
            description: "List currently-open sessions. \
Call this first when you need to know which devices are reachable. \
Takes no input. Returns each session's id, device id, vendor, transport \
kind, and opened-at timestamp. Session ids are short stable aliases \
(\"s1\", \"s2\", …) — use them verbatim in every session_id parameter. \
The device id is the connection name the user chose for the device \
(e.g. \"R1\") — when the user refers to a device by name, match it \
against device_id to pick the session."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolSchema {
            name: "read_scrollback".into(),
            description: "Read recent PTY output from an open session. \
Call this to observe what's already on the user's screen — config dumps, \
log lines, prompts. Output is filtered through the redaction filter \
before you see it (PEM keys, passwords, tokens replaced with [REDACTED:…] \
markers). PREFER a `match` needle over reading whole rings — it keeps \
only matching lines plus context and reports `total_matched`, so you \
spend context on the lines that answer the question. Cap plain reads \
with `max_bytes`."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Target session id from list_open_sessions (e.g. \"s1\")."
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum bytes to return. Defaults to 16384.",
                        "minimum": 1
                    },
                    "match": {
                        "type": "string",
                        "description": "Keep only lines containing this LITERAL substring (case-sensitive, not a regex), plus context_lines around each hit. The result reports total_matched so you know what you did not see."
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context kept around each match. Defaults to 2; capped at 10.",
                        "minimum": 0
                    }
                },
                "required": ["session_id"],
                "additionalProperties": false
            }),
        },
        ToolSchema {
            name: "propose_command".into(),
            description: "Propose a command to execute in a session. \
Every proposal runs through both the per-vendor policy gate AND a UI \
approval modal — both, never one or the other. The user can approve, \
deny, or approve-and-remember (a regex allowlist scoped to this chat \
session). On approval, the command runs and the captured output is \
returned (already redacted). A `capture=\"silence\"` attribute on the \
result envelope means the output ended on quiet with no prompt — the \
command may still be running; re-read the scrollback rather than \
inventing the missing tail. On deny / gate-block, `executed: false` \
plus a reason is returned so you can pivot."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Target session id from list_open_sessions (e.g. \"s1\")."
                    },
                    "command": {
                        "type": "string",
                        "description": "Single command line. Read-only verbs only — write/config commands are denied at the gate."
                    }
                },
                "required": ["session_id", "command"],
                "additionalProperties": false
            }),
        },
        ToolSchema {
            name: "ask_user".into(),
            description: "Ask the user a clarifying question. \
Use this when you genuinely need information you can't derive from \
scrollback — never as a substitute for proposing a command. The user's \
reply is returned verbatim."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Single, focused question. Multi-question prompts confuse the user."
                    }
                },
                "required": ["question"],
                "additionalProperties": false
            }),
        },
        ToolSchema {
            name: "propose_api_call".into(),
            description: "Propose a read-only GET against an API/controller \
session (e.g. a UniFi controller shown by list_open_sessions). GET-ONLY: \
there is deliberately no `method` field — you cannot request a write. Like \
propose_command it runs the gate (GET-only + host-pin) AND a user approval \
modal — both, every call. `path` is relative to the controller's fixed API \
base (e.g. \"/v1/sites\"); the host is fixed to the controller. On approval \
the GET runs and the already-redacted JSON body is returned; on deny/decline \
`executed: false` plus a reason. Use this for API/controller sessions; use \
propose_command for SSH/console sessions."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Target API session id from list_open_sessions (e.g. \"s2\")."
                    },
                    "path": {
                        "type": "string",
                        "description": "Path (with optional ?query) relative to the controller's API base, e.g. /v1/sites. GET only."
                    }
                },
                "required": ["session_id", "path"],
                "additionalProperties": false
            }),
        },
        ToolSchema {
            name: "query_capture".into(),
            description: "Query an open packet capture. \
START WITH `{\"kind\": \"overview\"}` — it is a precomputed digest \
(protocol mix, top talkers, conversations, TCP health, DNS/TLS/HTTP \
summaries, and deterministic findings) that costs the same whether the \
capture holds a thousand packets or ten million. Then drill in: `packets` \
for rows matching a view filter, `conversations` for the flow table, \
`flow` for one conversation\'s story, `packet` for one packet\'s fields, \
`findings` for the full problem list, `timeline` for rates over time. \
Findings carry a ready-made filter showing their evidence — use it. \
Filters use Transit\'s syntax: `tcp.port == 443 and ip.src == 10.0.0.0/24 \
and dns.rcode != 0`. This tool reads a local file and changes nothing. It \
returns dissected fields and summaries only; packet payload is not \
available through it."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capture_id": {
                        "type": "string",
                        "description": "Which open capture. Omit when only one is open."
                    },
                    "query": {
                        "type": "object",
                        "description": "What to ask. Pick one `kind`.",
                        "oneOf": [
                            {
                                "properties": {"kind": {"const": "list"}},
                                "required": ["kind"], "additionalProperties": false
                            },
                            {
                                "properties": {"kind": {"const": "overview"}},
                                "required": ["kind"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "packets"},
                                    "filter": {"type": "string", "description": "View filter, e.g. `tcp.port == 443`."},
                                    "offset": {"type": "integer", "minimum": 0},
                                    "limit": {"type": "integer", "minimum": 1, "maximum": 500}
                                },
                                "required": ["kind"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "conversations"},
                                    "by": {"type": "string", "enum": ["bytes", "packets", "duration", "retransmits", "start"]},
                                    "limit": {"type": "integer", "minimum": 1, "maximum": 500}
                                },
                                "required": ["kind"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "flow"},
                                    "flow_id": {"type": "integer", "minimum": 0}
                                },
                                "required": ["kind", "flow_id"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "packet"},
                                    "number": {"type": "integer", "minimum": 1}
                                },
                                "required": ["kind", "number"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "findings"},
                                    "severity": {"type": "string", "enum": ["info", "low", "med", "high"]},
                                    "limit": {"type": "integer", "minimum": 1, "maximum": 500}
                                },
                                "required": ["kind"], "additionalProperties": false
                            },
                            {
                                "properties": {
                                    "kind": {"const": "timeline"},
                                    "bucket_ms": {"type": "integer", "minimum": 1},
                                    "filter": {"type": "string"}
                                },
                                "required": ["kind"], "additionalProperties": false
                            }
                        ]
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolCall;
    use serde_json::Value;

    #[test]
    fn standard_tool_schemas_has_exactly_six() {
        // Mirrors `transit_agent::tools`'s
        // `static_assertions::const_assert_eq!(TOOL_CALL_VARIANT_COUNT,
        // 6)` at the schema level. A schema without a matching ToolCall
        // variant would deserialize-fail at the loop; a ToolCall variant
        // without a schema would mean the model can never call it.
        assert_eq!(standard_tool_schemas().len(), 6);
    }

    #[test]
    fn schema_names_match_tool_call_variants() {
        // Every schema name must round-trip as a ToolCall via the
        // serde `tool` discriminator. If a schema name drifts,
        // a tool the model invokes won't deserialize.
        for schema in standard_tool_schemas() {
            // Build a minimal-input payload per tool. Any required
            // fields get a placeholder; the parse just has to
            // succeed at the top-level discriminator + required
            // fields.
            let payload = match schema.name.as_str() {
                "list_open_sessions" => json!({"tool": "list_open_sessions"}),
                "read_scrollback" => {
                    json!({"tool": "read_scrollback", "session_id": "s"})
                }
                "propose_command" => {
                    json!({"tool": "propose_command", "session_id": "s", "command": "show version"})
                }
                "ask_user" => json!({"tool": "ask_user", "question": "q?"}),
                "propose_api_call" => {
                    json!({"tool": "propose_api_call", "session_id": "s", "path": "/v1/sites"})
                }
                "query_capture" => {
                    json!({"tool": "query_capture", "query": {"kind": "overview"}})
                }
                other => panic!("schema name {other} is not in the canonical six"),
            };
            let _: ToolCall = serde_json::from_value(payload)
                .unwrap_or_else(|e| panic!("ToolCall round-trip failed for {}: {e}", schema.name));
        }
    }

    #[test]
    fn schemas_round_trip_through_serde_json() {
        // Sanity: the input_schema is a serde_json::Value so it
        // round-trips trivially, but pin it as a regression test
        // against any future "make ToolSchema generic over its
        // schema type" refactor.
        for s in standard_tool_schemas() {
            let serialized = serde_json::to_value(&s.input_schema).unwrap();
            let parsed: Value = serde_json::from_value(serialized).unwrap();
            assert_eq!(parsed, s.input_schema);
        }
    }

    #[test]
    fn every_input_schema_locks_additional_properties_false() {
        // additionalProperties:false is the JSON Schema mirror of
        // #[serde(deny_unknown_fields)] on each *Input struct. If
        // the two ever drift, a hallucinated extra field could
        // pass the JSON-Schema check at the provider but reject
        // at our deserialization (false negative — the user sees
        // "tool error" instead of structured policy denial).
        for s in standard_tool_schemas() {
            assert_eq!(
                s.input_schema.get("additionalProperties"),
                Some(&json!(false)),
                "schema {} must lock additionalProperties:false",
                s.name
            );
        }
    }

    #[test]
    fn schemas_are_byte_stable_across_calls() {
        // The agent loop builds the request body fresh per turn,
        // but Anthropic's prompt cache keys off byte-for-byte
        // request equality. Two consecutive calls must produce
        // identical schemas; non-determinism (e.g. HashMap iter
        // order leaking into JSON output) would invalidate the
        // cache on every turn.
        let a = standard_tool_schemas();
        let b = standard_tool_schemas();
        assert_eq!(a.len(), b.len());
        for (sa, sb) in a.iter().zip(b.iter()) {
            assert_eq!(sa, sb);
        }
    }

    #[test]
    fn snapshot_pins_canonical_schemas() {
        // Insta snapshot of the full four-schema bundle. Every
        // tool-surface change shows up as a diff in PR review,
        // and the canonical layout test in system_prompt.rs has
        // a sibling cache-stability concern (the prompt's tool
        // section text vs. these structured schemas — the two
        // descriptions intentionally differ in length but should
        // never lie about the same tool).
        let schemas = standard_tool_schemas();
        // Wrap as a JSON array for readable snapshot output.
        let bundle: Vec<_> = schemas
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "description": s.description,
                    "input_schema": s.input_schema,
                })
            })
            .collect();
        // YAML rather than JSON because the workspace's `insta`
        // dep enables only the "yaml" feature (matches the
        // existing snapshot convention in `system_prompt.rs`).
        insta::assert_yaml_snapshot!(bundle);
    }
}
