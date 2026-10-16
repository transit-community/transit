//! Snapshot tests for `transit_agent::system_prompt::build`.
//!
//! Pins the rendered prompt across known fixture inventories so any
//! drift in the section text, ordering, or cache-breakpoint layout
//! is loud. Two snapshots — empty inventory and a mixed-vendor real
//! inventory — exercise both extremes.
//!
//! IMPORTANT: these snapshots are the **input cache prefix** that
//! every multi-turn investigation pays for once and then reads back
//! at 10% (Anthropic) / 50% (OpenAI). A change that re-orders or
//! reformats sections regresses cache hit rate across every user's
//! conversations. If the snapshot changes intentionally, the diff
//! review must include a per-turn cost-impact estimate.

use std::path::PathBuf;

use transit_agent::system_prompt::{self, SectionKind};
use transit_agent::{SessionKind, SessionMeta};
use transit_core::inventory::Vendor;
use transit_policy::{PolicyEngine, PolicySummary};

fn engine() -> PolicyEngine {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");
    PolicyEngine::load_from_dir(&dir).expect("policies/ loads cleanly")
}

fn summaries_all_vendors() -> Vec<(Vendor, PolicySummary)> {
    let e = engine();
    [
        Vendor::Junos,
        Vendor::CiscoIos,
        Vendor::CiscoIosXe,
        Vendor::CiscoIosXr,
        Vendor::NxOs,
        Vendor::AristaEos,
        Vendor::Linux,
        Vendor::PanOs,
    ]
    .into_iter()
    .filter_map(|v| e.summary(&v).map(|s| (v, s)))
    .collect()
}

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

#[test]
fn empty_inventory_snapshot() {
    // Headless / no-sessions case. The cached prefix should render
    // even when there are no open sessions; only the volatile
    // `OpenSessions` section reflects the empty state.
    let policies = summaries_all_vendors();
    let p = system_prompt::build(&[], &policies);
    insta::assert_snapshot!("empty_inventory", p.render());
}

#[test]
fn mixed_vendor_inventory_snapshot() {
    let policies = summaries_all_vendors();
    let sessions = vec![
        meta("s1", "vEX1", Vendor::Junos),
        meta("s2", "edge-1", Vendor::CiscoIos),
        meta("s3", "spine-7", Vendor::NxOs),
    ];
    let p = system_prompt::build(&sessions, &policies);
    insta::assert_snapshot!("mixed_vendor", p.render());
}

#[test]
fn cached_prefix_snapshot_stable_within_vendor_set() {
    // Pin the cached prefix bytes — this is what 5d/6 marks with
    // cache_control. Post-scoping the prefix keys on the open-vendor
    // SET: it must not change across session churn within the same
    // set (2nd session of an open vendor, id/label changes), and the
    // snapshot pins the single-Junos-session prefix bytes.
    let policies = summaries_all_vendors();
    let p_a = system_prompt::build(&[meta("s1", "vEX1", Vendor::Junos)], &policies);
    let p_b = system_prompt::build(
        &[
            meta("s1", "vEX1", Vendor::Junos),
            meta("s2", "vEX2", Vendor::Junos),
        ],
        &policies,
    );
    assert_eq!(p_a.cached_prefix(), p_b.cached_prefix());
    insta::assert_snapshot!("cached_prefix", p_a.cached_prefix());
}

#[test]
fn cached_prefix_token_estimate_is_in_expected_range() {
    // Regression-pin both ends of the scoped layout:
    //
    // FLOOR — the minimum-size prefix is now statics-only (no open
    // sessions → no vendor sections render). If it shrinks under the
    // OpenAI 1024-token caching minimum, OpenAI auto-caching silently
    // disables for no-session chats and the cost picture changes.
    // chars/4 is a rough estimate — if this assert ever sits within
    // ~15% of the line, re-measure with real tokenizer counts before
    // trusting it.
    //
    // CEILING — with every shipped vendor open at once the prefix
    // must stay within sane bounds; at ~5,000 tokens the per-message
    // TTFT savings of a pre-warm cron become perceptible (see
    // plans/ideas.md "Prompt cache pre-warm") and a revisit is due.
    let policies = summaries_all_vendors();

    let statics_only = system_prompt::build(&[], &policies);
    let floor = statics_only.cached_prefix_estimate_tokens();
    assert!(
        floor >= 1024,
        "statics-only cached prefix estimated at {floor} tokens — \
         falls below OpenAI auto-caching threshold"
    );

    use Vendor::*;
    let all = [
        Junos, CiscoIos, CiscoIosXe, CiscoIosXr, NxOs, AristaEos, Linux, PanOs,
    ];
    let metas: Vec<SessionMeta> = all
        .iter()
        .enumerate()
        .map(|(i, v)| meta(&format!("s{i}"), &format!("dev{i}"), v.clone()))
        .collect();
    let everything_open = system_prompt::build(&metas, &policies);
    let ceiling = everything_open.cached_prefix_estimate_tokens();
    assert!(
        ceiling <= 8000,
        "all-vendors-open cached prefix estimated at {ceiling} tokens — audit for accidental bloat"
    );
}

#[test]
fn injection_guard_text_present_in_render() {
    // Pin the load-bearing security text. If a refactor accidentally
    // moves this into a private const or weakens the warning, this
    // test breaks loudly.
    let p = system_prompt::build(&[], &[]);
    let r = p.render();
    assert!(r.contains("UNTRUSTED"));
    assert!(r.contains("prompt-injection"));
    assert!(r.contains("<session id="));
}

#[test]
fn ordinal_explanation_present_in_render() {
    let p = system_prompt::build(&[], &[]);
    let r = p.render();
    assert!(r.contains("[REDACTED:bgp-md5#1]"));
    assert!(r.contains("per-conversation ordinal"));
}

#[test]
fn open_sessions_section_is_last_section() {
    // The volatile section must be at the END so the LlmClient can
    // mark every preceding section as cached and only the trailing
    // bytes get re-sent fresh.
    let p = system_prompt::build(&[meta("s1", "vEX1", Vendor::Junos)], &[]);
    let last = p.sections.last().unwrap();
    assert_eq!(last.kind, SectionKind::OpenSessions);
}
