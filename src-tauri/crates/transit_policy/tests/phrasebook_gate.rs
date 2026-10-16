//! v6.1.x #1 — the phrasebook↔gate tie.
//!
//! Every `phrasebook:` entry in every shipped `policies/<vendor>.yaml`
//! must be ALLOWED by that vendor's own gate. The phrasebook is
//! prompt-side only (the gate never consults it — Rule 3's subject is
//! the regexes), so this test is what makes the phrasebook unable to
//! drift permissive: an entry the gate would deny is a BUILD failure,
//! not a runtime surprise where the prompt teaches a command the modal
//! then watches get refused.
//!
//! Also enforces the token budget: entries stay short (≤ 60 chars) and
//! per-vendor lists stay ≤ 20 (the renderer truncates beyond 20, and a
//! silently-truncated phrasebook is a curation bug, not a feature).

use std::path::PathBuf;

use transit_policy::{Decision, PolicyEngine};

fn engine() -> PolicyEngine {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");
    PolicyEngine::load_from_dir(&dir).expect("policies/ loads cleanly")
}

#[test]
fn every_phrasebook_entry_passes_the_gate() {
    let engine = engine();
    let mut failures = Vec::new();
    let mut total = 0usize;
    for vendor in engine.vendors() {
        let Some(summary) = engine.summary(&vendor) else {
            continue;
        };
        assert!(
            summary.phrasebook.len() <= 20,
            "{}: {} phrasebook entries — the renderer caps at 20; curate, don't pile",
            vendor.as_str(),
            summary.phrasebook.len()
        );
        for entry in &summary.phrasebook {
            total += 1;
            assert!(
                entry.len() <= 60,
                "{}: phrasebook entry too long ({} chars): `{}`",
                vendor.as_str(),
                entry.len(),
                entry
            );
            match engine.evaluate(&vendor, entry) {
                Decision::Allow | Decision::AllowUnrestricted { .. } => {}
                Decision::Deny { reason, .. } => {
                    failures.push(format!("{}: `{}` → {}", vendor.as_str(), entry, reason));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "phrasebook entries the gate DENIES (the prompt would teach refused commands):\n{}",
        failures.join("\n")
    );
    // Seeding sanity: the six corpus-backed vendors carry real lists.
    assert!(
        total >= 60,
        "phrasebook seeding looks gutted: only {total} entries across all vendors"
    );
}
