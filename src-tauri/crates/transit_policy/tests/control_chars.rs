//! Cross-vendor control-character refusal (security finding D-1).
//!
//! The dispatcher sends the RAW command bytes to the device PTY, so
//! an embedded `\n`/`\r` executes a second line the regex gate never
//! saw — canonicalization's `split_whitespace` flattens control
//! characters into single spaces before matching, so
//! `"show version\nconfigure terminal"` used to evaluate as ONE
//! allowed line. The gate now refuses ANY command containing a
//! control character, for EVERY shipped vendor — including the
//! unrestricted `linux` policy, whose short-circuit must not beat
//! the refusal (on Linux every embedded line would execute and the
//! approval modal would render the newline collapsed).

use std::path::PathBuf;

use transit_core::inventory::Vendor;
use transit_policy::{Decision, PolicyEngine};

fn engine() -> PolicyEngine {
    // CARGO_MANIFEST_DIR is the path of the crate being tested
    // (transit_policy). Repo root is two levels up: ../..
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");
    PolicyEngine::load_from_dir(&dir).expect("policies/ loads cleanly")
}

/// Every vendor with a shipped `policies/<vendor>.yaml` — gated AND
/// unrestricted. A new policy file should gain a row here.
const VENDORS: &[Vendor] = &[
    Vendor::Junos,
    Vendor::CiscoIos,
    Vendor::CiscoIosXe,
    Vendor::NxOs,
    Vendor::AristaEos,
    Vendor::PanOs,
    Vendor::Linux,
];

#[test]
fn control_characters_deny_for_every_vendor() {
    let engine = engine();
    let smuggles = [
        "show version\nconfigure terminal",
        "show version\rrun bash",
        "show\u{0000}version",
    ];
    for vendor in VENDORS {
        for cmd in &smuggles {
            match engine.evaluate(vendor, cmd) {
                Decision::Deny { reason, .. } => assert!(
                    reason.contains("control character"),
                    "{vendor:?} on {cmd:?}: expected the control-char reason, got {reason:?}"
                ),
                other => panic!("{vendor:?} must deny control chars for {cmd:?}, got {other:?}"),
            }
        }
    }
}

#[test]
fn linux_denies_control_chars_despite_unrestricted_mode() {
    // Pin the ordering explicitly: a clean command on the linux
    // policy short-circuits to AllowUnrestricted, but the SAME
    // command with an embedded newline must Deny — proving the
    // control-char check runs before the mode short-circuit rather
    // than the deny coming from some other path.
    let engine = engine();
    match engine.evaluate(&Vendor::Linux, "ls -la /var/log") {
        Decision::AllowUnrestricted { .. } => {}
        other => panic!("clean command should short-circuit, got {other:?}"),
    }
    match engine.evaluate(&Vendor::Linux, "ls -la /var/log\nrm -rf /") {
        Decision::Deny { reason, .. } => assert!(
            reason.contains("control character"),
            "expected the control-char reason, got {reason:?}"
        ),
        other => panic!("linux must deny embedded newline, got {other:?}"),
    }
}
