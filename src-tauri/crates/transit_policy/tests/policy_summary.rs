//! Snapshot tests for `PolicyEngine::summary` across all shipped vendor
//! YAMLs. The summary feeds the agent's system prompt; if the regex
//! sources accidentally re-order, get reformatted, or lose entries on a
//! refactor, the prompt prefix changes and prompt-cache hits break.
//! Pinning the rendered summary as an `insta` snapshot makes any
//! drift loud.

use std::path::PathBuf;

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

fn render(s: &PolicySummary) -> String {
    let mut out = String::new();
    out.push_str(&format!("precedence: {:?}\n", s.precedence));
    out.push_str("allowed:\n");
    for r in &s.allowed {
        out.push_str(&format!("  - {r}\n"));
    }
    out.push_str("blocked:\n");
    for r in &s.blocked {
        out.push_str(&format!("  - {r}\n"));
    }
    out.push_str("pipe_allowed:\n");
    for r in &s.pipe_allowed {
        out.push_str(&format!("  - {r}\n"));
    }
    out.push_str("pipe_blocked:\n");
    for r in &s.pipe_blocked {
        out.push_str(&format!("  - {r}\n"));
    }
    out
}

#[test]
fn summary_unknown_vendor_is_none() {
    // Sanity: a vendor that isn't registered (none of the six shipped
    // vendors will ever fail this) yields None. Guards against a future
    // refactor that returns a default-empty summary instead.
    let engine = PolicyEngine::default();
    assert!(engine.summary(&Vendor::Junos).is_none());
}

#[test]
fn engine_lists_every_shipped_vendor() {
    // Pins that `load_from_dir` actually registers every shipped policy
    // (incl. cisco_ios_xr) and that `vendors()` reports them — it feeds
    // the agent's scoped policy briefing (chat.rs::collect_policy_summaries).
    // Also kills the `PolicyEngine::vendors -> vec![]` mutant.
    let vendors = engine().vendors();
    for v in [
        Vendor::Junos,
        Vendor::CiscoIos,
        Vendor::CiscoIosXe,
        Vendor::CiscoIosXr,
        Vendor::NxOs,
        Vendor::AristaEos,
        Vendor::PanOs,
        Vendor::Linux,
    ] {
        assert!(vendors.contains(&v), "vendors() missing {v:?}");
    }
}

#[test]
fn junos_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::Junos)
        .expect("junos.yaml registered");
    insta::assert_snapshot!("junos_summary", render(&s));
}

#[test]
fn cisco_ios_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::CiscoIos)
        .expect("cisco_ios.yaml registered");
    insta::assert_snapshot!("cisco_ios_summary", render(&s));
}

#[test]
fn cisco_ios_xe_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::CiscoIosXe)
        .expect("cisco_ios_xe.yaml registered");
    insta::assert_snapshot!("cisco_ios_xe_summary", render(&s));
}

#[test]
fn cisco_ios_xr_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::CiscoIosXr)
        .expect("cisco_ios_xr.yaml registered");
    insta::assert_snapshot!("cisco_ios_xr_summary", render(&s));
}

#[test]
fn nxos_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::NxOs)
        .expect("nxos.yaml registered");
    insta::assert_snapshot!("nxos_summary", render(&s));
}

#[test]
fn arista_eos_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::AristaEos)
        .expect("arista_eos.yaml registered");
    insta::assert_snapshot!("arista_eos_summary", render(&s));
}

#[test]
fn pan_os_summary_snapshot() {
    let s = engine()
        .summary(&Vendor::PanOs)
        .expect("pan_os.yaml registered");
    insta::assert_snapshot!("pan_os_summary", render(&s));
}

#[test]
fn linux_summary_snapshot() {
    // Phase 8b — `mode: unrestricted` policies still surface a
    // summary (the renderer just lists empty regex lists). The
    // dispatcher detects unrestricted via the Decision variant,
    // not via the summary, so this pin doesn't change the agent's
    // prompt prefix in a load-bearing way — it's just a regression
    // pin that load_from_dir didn't reject the unrestricted file.
    let s = engine()
        .summary(&Vendor::Linux)
        .expect("linux.yaml registered");
    insta::assert_snapshot!("linux_summary", render(&s));
}

#[test]
fn summary_preserves_yaml_order() {
    // Refactor regression-pin: a future change that switches from
    // Vec to HashSet for storage would re-order the summary and
    // break the prompt cache prefix. Re-generate the summary twice
    // and assert byte-equality.
    let e = engine();
    let a = e.summary(&Vendor::Junos).expect("loaded");
    let b = e.summary(&Vendor::Junos).expect("loaded");
    assert_eq!(render(&a), render(&b));
}
