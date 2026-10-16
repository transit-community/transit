//! Integration tests for [`transit_agent::DefaultDispatcher`].
//!
//! Pins the contract that `read_scrollback` returns
//! `<session id="…">\n<redacted>\n</session>` framing AND that the
//! redaction passes through `ConversationRedactor` so equivalence
//! ordinals survive. Phase 6 will plumb the policy gate + UI modal
//! through `propose_command` — for now we pin that it returns
//! `NotImplemented` so a future implementer doesn't accidentally
//! merge a partial Rule 3.

use std::sync::{Arc, Mutex};

use transit_agent::testing::MockScrollbackSource;
use transit_agent::{
    AgentError, ConversationRedactor, DefaultDispatcher, ListOpenSessionsInput,
    ProposeCommandInput, ReadScrollbackInput, SessionKind, SessionMeta, ToolCall, ToolDispatcher,
    ToolResult,
};
use transit_core::inventory::Vendor;

fn meta(id: &str, device: &str, vendor: Vendor) -> SessionMeta {
    SessionMeta {
        session_id: id.to_string(),
        device_id: device.to_string(),
        vendor,
        kind: SessionKind::Ssh,
        opened_at: "2026-05-09T00:00:00Z".to_string(),
        api_endpoints: Vec::new(),
        alias: None,
        commands_run: None,
        scrollback_bytes: None,
    }
}

fn dispatcher_with(source: MockScrollbackSource) -> DefaultDispatcher {
    let redactor = Arc::new(Mutex::new(ConversationRedactor::new()));
    DefaultDispatcher::new(Arc::new(source), redactor)
}

// ---------------------------------------------------------------------
// ListOpenSessions
// ---------------------------------------------------------------------

#[tokio::test]
async fn list_open_sessions_round_trip() {
    let source = MockScrollbackSource::new()
        .with_session(meta("s1", "vEX1", Vendor::Junos), "")
        .with_session(meta("s2", "vEX2", Vendor::CiscoIos), "");
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ListOpenSessions(ListOpenSessionsInput {}))
        .await
        .unwrap();
    match res {
        ToolResult::ListOpenSessions(o) => {
            assert_eq!(o.sessions.len(), 2);
            // Sorted by session_id (mock policy)
            assert_eq!(o.sessions[0].session_id, "s1");
            assert_eq!(o.sessions[0].device_id, "vEX1");
            assert_eq!(o.sessions[1].device_id, "vEX2");
        }
        _ => panic!("wrong tool result"),
    }
}

// ---------------------------------------------------------------------
// ReadScrollback — redaction + framing
// ---------------------------------------------------------------------

#[tokio::test]
async fn read_scrollback_redacts_then_frames() {
    let source = MockScrollbackSource::new().with_session(
        meta("s1", "vEX1", Vendor::Junos),
        "neighbor 10.0.0.1 password BgpKey42",
    );
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "s1".to_string(),
            max_bytes: 4096,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
    let text = match res {
        ToolResult::ReadScrollback(o) => o.text,
        _ => panic!("wrong tool result"),
    };

    // Secret bytes gone
    assert!(!text.contains("BgpKey42"));
    // Ordinal-tagged marker present
    assert!(text.contains("[REDACTED:bgp-md5#1]"));
    // Framing tags wrap the redacted body (v6.1.1: + device echo)
    assert!(text.starts_with("<session id=\"s1\" device=\"vEX1\">\n"));
    assert!(text.ends_with("\n</session>"));
}

#[tokio::test]
async fn read_scrollback_caps_oversized_output_after_redaction() {
    // A snapshot larger than the source-side cap (with a secret near
    // the top) must be (a) redacted, (b) trimmed head+tail, with the
    // secret surviving as a [REDACTED] marker — the cap runs AFTER
    // redaction, so it can never resurface a secret. `max_bytes` is
    // huge so the tail-keep window doesn't trim; only our cap does.
    // Filler is space-broken: an unbroken 40 KiB single-char run is
    // a 64+ base64-alphabet token and the high-entropy catch-all
    // would (correctly) collapse it to one marker, defeating the
    // size this fixture needs.
    let big = format!(
        "neighbor 10.0.0.1 password BgpKey42\n{}",
        "A ".repeat(20 * 1024)
    );
    let source = MockScrollbackSource::new().with_session(meta("s1", "vEX1", Vendor::Junos), big);
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "s1".to_string(),
            max_bytes: 128 * 1024, // snapshot returns the full blob; only our cap trims
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
    let (text, truncated) = match res {
        ToolResult::ReadScrollback(o) => (o.text, o.truncated),
        _ => panic!("wrong tool result"),
    };

    assert!(!text.contains("BgpKey42"), "secret plaintext must be gone");
    assert!(
        text.contains("[REDACTED:bgp-md5#1]"),
        "redaction marker must survive the cap"
    );
    assert!(
        text.contains("bytes elided by Transit output cap"),
        "the source-side cap must have fired"
    );
    assert!(
        text.len() < 17 * 1024,
        "capped output must be bounded, got {} bytes",
        text.len()
    );
    assert!(truncated, "truncated flag must be set when the cap trims");
}

#[tokio::test]
async fn list_open_sessions_prefers_alias_when_present() {
    // v6.1.1 — inside a chat the scoped view stamps an alias on each
    // meta; the tool result surfaces THAT as the session id (the
    // registry key was never load-bearing for the model).
    let mut m = meta(
        "3f6f4ac2-9d1a-4a10-8c6a-2b1f00000001",
        "vEX1",
        Vendor::Junos,
    );
    m.alias = Some("s1".into());
    m.commands_run = Some(3);
    let source = MockScrollbackSource::new().with_session(m, "x");
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ListOpenSessions(Default::default()))
        .await
        .unwrap();
    match res {
        ToolResult::ListOpenSessions(o) => {
            assert_eq!(o.sessions.len(), 1);
            assert_eq!(o.sessions[0].session_id, "s1");
            assert_eq!(o.sessions[0].device_id, "vEX1");
            assert!(
                !serde_json::to_string(&o).unwrap().contains("3f6f4ac2"),
                "the registry id must not leak into the tool result"
            );
        }
        _ => panic!("expected ListOpenSessions"),
    }
}

#[tokio::test]
async fn read_scrollback_envelope_frames_alias_and_device_from_meta() {
    // v6.1.1 — the envelope answers in the roster vocabulary (alias)
    // and echoes the device binding, even when the CALL used the raw
    // registry id (alias→registry resolution is app-side; this crate
    // only renders).
    let registry = "3f6f4ac2-9d1a-4a10-8c6a-2b1f00000001";
    let mut m = meta(registry, "vEX1", Vendor::Junos);
    m.alias = Some("s1".into());
    let source = MockScrollbackSource::new().with_session(m, "hello world");
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: registry.to_string(),
            max_bytes: 4096,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
    match res {
        ToolResult::ReadScrollback(o) => {
            assert!(
                o.text.starts_with("<session id=\"s1\" device=\"vEX1\">\n"),
                "envelope must frame alias + device, got: {}",
                o.text
            );
            assert!(o.text.contains("hello world"));
        }
        _ => panic!("expected ReadScrollback"),
    }
}

#[tokio::test]
async fn read_scrollback_match_filters_post_redact_and_reports_total() {
    // v6.1.x #4 — the window-death cure. The filter keeps matching
    // lines + context and reports total_matched; and because it runs
    // strictly AFTER redaction, a needle can find a [REDACTED:…]
    // marker but can never find raw secret bytes.
    let scroll = "junk line one\n\
                  neighbor 10.0.0.1 password BgpKey42\n\
                  BGP peer 10.0.0.1 Established\n\
                  middle junk\n\
                  BGP peer 10.0.0.2 Idle\n\
                  tail junk";
    let source =
        MockScrollbackSource::new().with_session(meta("s1", "vEX1", Vendor::Junos), scroll);
    let d = dispatcher_with(source);

    let read = |needle: &'static str| {
        let d = &d;
        async move {
            match d
                .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                    session_id: "s1".into(),
                    max_bytes: 4096,
                    match_: Some(needle.into()),
                    context_lines: 0,
                }))
                .await
                .unwrap()
            {
                ToolResult::ReadScrollback(o) => o,
                _ => panic!("wrong tool result"),
            }
        }
    };

    let o = read("BGP peer").await;
    assert_eq!(o.total_matched, Some(2));
    assert!(o.text.contains("BGP peer 10.0.0.1 Established"));
    assert!(o.text.contains("BGP peer 10.0.0.2 Idle"));
    assert!(
        !o.text.contains("junk"),
        "non-matching lines are elided: {}",
        o.text
    );
    assert!(o.text.contains("elided by match filter"));

    // The raw secret is GONE before the filter runs…
    let o = read("BgpKey42").await;
    assert_eq!(o.total_matched, Some(0), "raw secret bytes are unmatchable");
    assert!(o.text.contains("(no lines matched)"));
    // …while its redaction marker IS matchable (the model can still
    // locate where a credential appeared without seeing it).
    let o = read("[REDACTED:bgp-md5").await;
    assert_eq!(o.total_matched, Some(1));
}

#[tokio::test]
async fn read_scrollback_session_not_found() {
    let source = MockScrollbackSource::new();
    let d = dispatcher_with(source);

    let err = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "ghost".to_string(),
            max_bytes: 1024,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::SessionNotFound { ref session_id } if session_id == "ghost"));
}

#[tokio::test]
async fn same_secret_across_two_reads_collapses_to_one_ordinal() {
    // Two sessions, both showing the same BGP MD5 secret. The
    // dispatcher's shared `ConversationRedactor` must assign the
    // same ordinal to both — that's the diagnostic property.
    let source = MockScrollbackSource::new()
        .with_session(
            meta("s1", "vEX1", Vendor::Junos),
            "neighbor 10.0.0.1 password BGPAUTH123",
        )
        .with_session(
            meta("s2", "vEX2", Vendor::Junos),
            "neighbor 10.0.0.2 password BGPAUTH123",
        );
    let d = dispatcher_with(source);

    let read = |sid: &str| {
        let sid = sid.to_string();
        async {
            let res = d
                .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                    session_id: sid,
                    max_bytes: 4096,
                    match_: None,
                    context_lines: 2,
                }))
                .await
                .unwrap();
            match res {
                ToolResult::ReadScrollback(o) => o.text,
                _ => panic!(),
            }
        }
    };

    let a = read("s1").await;
    let b = read("s2").await;
    assert!(a.contains("[REDACTED:bgp-md5#1]"));
    assert!(
        b.contains("[REDACTED:bgp-md5#1]"),
        "same secret bytes must share ordinal — got: {b}"
    );
}

#[tokio::test]
async fn distinct_secrets_across_two_reads_get_distinct_ordinals() {
    let source = MockScrollbackSource::new()
        .with_session(
            meta("s1", "vEX1", Vendor::Junos),
            "neighbor 10.0.0.1 password KeyA",
        )
        .with_session(
            meta("s2", "vEX2", Vendor::Junos),
            "neighbor 10.0.0.2 password KeyB",
        );
    let d = dispatcher_with(source);

    let read = |sid: &str| {
        let sid = sid.to_string();
        async {
            let res = d
                .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
                    session_id: sid,
                    max_bytes: 4096,
                    match_: None,
                    context_lines: 2,
                }))
                .await
                .unwrap();
            match res {
                ToolResult::ReadScrollback(o) => o.text,
                _ => panic!(),
            }
        }
    };

    let a = read("s1").await;
    let b = read("s2").await;
    assert!(a.contains("[REDACTED:bgp-md5#1]"));
    assert!(b.contains("[REDACTED:bgp-md5#2]"));
}

#[tokio::test]
async fn read_scrollback_truncation_flag_propagates() {
    // The source returns the full ring; the dispatcher's post-redact
    // tail-keep window (max_bytes) trims it and must set `truncated`.
    // (Space-broken filler — see the catch-all note in the cap test.)
    let big = "x ".repeat(1000);
    let source = MockScrollbackSource::new().with_session(meta("s1", "vEX1", Vendor::Junos), big);
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "s1".to_string(),
            max_bytes: 100,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
    match res {
        ToolResult::ReadScrollback(o) => {
            assert!(o.truncated);
            // The window was actually applied: framing + ≤100 bytes
            // of body (v6.1.1 envelope carries the device echo).
            assert!(
                o.text.len() <= 100 + "<session id=\"s1\" device=\"vEX1\">\n\n</session>".len(),
                "tail-keep window must bound the body, got {} bytes",
                o.text.len()
            );
        }
        _ => panic!(),
    }
}

// ---------------------------------------------------------------------
// Redact-before-trim contract (D-3c)
// ---------------------------------------------------------------------

#[tokio::test]
async fn pem_block_straddling_the_max_bytes_window_is_redacted_whole() {
    // Under the OLD contract the SOURCE head-dropped raw scrollback
    // to `max_bytes` BEFORE redaction. Lay out the ring so the PEM
    // block's `-----BEGIN` line falls OUTSIDE the last `max_bytes`
    // raw bytes while its body + `-----END` fall INSIDE: the old
    // pipeline would hand the redactor a decapitated block that the
    // PEM regex can't match, leaking key-body base64 to the LLM.
    //
    // New pipeline: full ring → redact (block intact → one marker)
    // → tail-keep(max_bytes) → cap. The body bytes must be gone and
    // the window still applied.
    const PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----";
    let max_bytes = 1024usize;
    let prefix = "P\n".repeat(100); // 200 bytes before the block
    let suffix = "S\n".repeat(450); // 900 bytes after the block
    let ring = format!("{prefix}{PEM}\n{suffix}");

    // Geometry sanity for the scenario itself: the raw tail window
    // starts past the BEGIN line but before the END line.
    let raw_cut = ring.len() - max_bytes;
    let begin_end = prefix.len() + PEM.lines().next().unwrap().len();
    let end_start = prefix.len() + PEM.len() - "-----END RSA PRIVATE KEY-----".len();
    assert!(
        raw_cut > begin_end && raw_cut < end_start,
        "fixture must cut inside the PEM block (cut={raw_cut}, begin_end={begin_end}, end_start={end_start})"
    );

    let source = MockScrollbackSource::new().with_session(meta("s1", "vEX1", Vendor::Junos), ring);
    let d = dispatcher_with(source);

    let res = d
        .dispatch(ToolCall::ReadScrollback(ReadScrollbackInput {
            session_id: "s1".to_string(),
            max_bytes,
            match_: None,
            context_lines: 2,
        }))
        .await
        .unwrap();
    let (text, truncated) = match res {
        ToolResult::ReadScrollback(o) => (o.text, o.truncated),
        _ => panic!("wrong tool result"),
    };

    // The block was redacted while whole — no key-body bytes.
    assert!(!text.contains("MIIBOgIBAAJBAKj"), "PEM body leaked: {text}");
    assert!(
        !text.contains("KUpRKfFLfRYC"),
        "PEM body tail leaked: {text}"
    );
    assert!(!text.contains("PRIVATE KEY"), "PEM armor leaked: {text}");
    assert!(
        text.contains("[REDACTED:pem-block#1]"),
        "marker must survive inside the tail window: {text}"
    );
    // The window was still applied (budget + framing/marker slack).
    assert!(
        text.len() <= max_bytes + 64,
        "tail-keep window not applied, got {} bytes",
        text.len()
    );
    assert!(truncated, "tail-keep trim must set the truncated flag");
}

// ---------------------------------------------------------------------
// ProposeCommand + AskUser → NotImplemented (Phase 5b boundary)
// ---------------------------------------------------------------------

#[tokio::test]
async fn propose_command_returns_not_implemented() {
    let d = dispatcher_with(MockScrollbackSource::new());
    let err = d
        .dispatch(ToolCall::ProposeCommand(ProposeCommandInput {
            session_id: "s1".to_string(),
            command: "show version".to_string(),
        }))
        .await
        .unwrap_err();
    match err {
        AgentError::NotImplemented { tool } => assert_eq!(tool, "propose_command"),
        _ => panic!("expected NotImplemented for ProposeCommand"),
    }
}

#[tokio::test]
async fn ask_user_returns_not_implemented() {
    use transit_agent::AskUserInput;
    let d = dispatcher_with(MockScrollbackSource::new());
    let err = d
        .dispatch(ToolCall::AskUser(AskUserInput {
            question: "Which device?".to_string(),
        }))
        .await
        .unwrap_err();
    match err {
        AgentError::NotImplemented { tool } => assert_eq!(tool, "ask_user"),
        _ => panic!("expected NotImplemented for AskUser"),
    }
}
