//! BYOP read-only floor — cross-vendor corpus + property test.
//!
//! Phase 2a (the scoped vendor policy and byop design notes (not included in this repository)): a user
//! policy layered over a shipped vendor may ADD read-only allows but can
//! NEVER punch through a shipped block. These tests build a layered
//! engine via `PolicyEngine::from_layers` with the real bundled
//! `policies/` set plus a deliberately hostile user layer — a Junos
//! policy that allows literally everything (`^.*`), tries to alias a
//! blocked head to an allowed one, and allows every pipe stage — then
//! asserts the floor still denies every blocked command, by DenyKind
//! (never by reason-string).
//!
//! The companion unit tests in `engine.rs` pin the mechanics on a
//! hand-built entry; this file proves it against the actual shipped
//! Junos YAML, which is what an attacker would face.

use std::path::PathBuf;

use proptest::prelude::*;
use regex::Regex;
use tempfile::TempDir;
use transit_core::inventory::Vendor;
use transit_policy::{Decision, DenyKind, PolicyEngine};

fn bundled_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies")
}

/// A maximally-hostile USER policy for Junos: allow everything, allow
/// every pipe stage, and try the two alias attacks (remap a blocked
/// head to an allowed one). Plus one *legitimate* read-only addition
/// (`traceroute6`, which the bundled `^traceroute( |$)` does NOT match)
/// so we can also prove the merge actually relaxes a bundled
/// default-deny.
const HOSTILE_USER_JUNOS: &str = r#"
precedence: block-wins
canonicalization:
  aliases:
    configure: show
    start: show
allowed:
  - "^.*"
  - "^traceroute6( |$)"
pipe_allowed:
  - "^.*"
"#;

/// Build a layered engine: real bundled `policies/` + a temp user dir
/// holding `HOSTILE_USER_JUNOS` as `junos.yaml`. Returns the engine and
/// the TempDir guard (kept alive for the engine's lifetime — the engine
/// reads the files at construction, but holding it is cheap insurance).
fn hostile_layered_engine() -> (PolicyEngine, TempDir) {
    let user_dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(user_dir.path().join("junos.yaml"), HOSTILE_USER_JUNOS)
        .expect("write user yaml");
    let loaded =
        PolicyEngine::from_layers(&bundled_dir(), user_dir.path()).expect("bundled loads cleanly");
    // The user layer sets precedence == bundled (block-wins) and adds no
    // mode override, so there should be NO override warnings — only the
    // load itself. (A precedence/mode override warning is pinned in the
    // engine unit tests.)
    assert!(
        loaded.warnings.is_empty(),
        "unexpected user-layer warnings: {:?}",
        loaded.warnings
    );
    (loaded.engine, user_dir)
}

/// Every one of these is blocked by the SHIPPED Junos policy. Under the
/// hostile "allow everything" user layer they must STILL deny with
/// `DenyKind::Blocked` — the read-only floor.
const MUST_STAY_BLOCKED: &[&str] = &[
    "configure",
    "configure terminal",
    "configure private",
    "commit",
    "commit confirmed",
    "start shell", // the shell escape — highest value
    "start shell user root",
    "request system reboot",
    "request system power-off",
    "restart routing",
    "rollback 0",
    "load override /tmp/x",
    "save /var/tmp/cfg",
    "clear bgp neighbor 10.0.0.1",
    "file delete /var/tmp/x",
    "file copy a b",
    "test policy foo bar",
    "edit interfaces",
];

/// Alias-attack inputs: the hostile user layer remaps the blocked head
/// `configure`/`start` to the allowed head `show`. Because the FLOOR
/// evaluates with BUNDLED aliases (which have no such remap), these must
/// still hit the bundled block.
const ALIAS_ATTACK_BLOCKED: &[&str] = &["configure terminal", "start shell"];

#[test]
fn floor_denies_every_blocked_command_under_hostile_allow_all() {
    let (engine, _guard) = hostile_layered_engine();
    for cmd in MUST_STAY_BLOCKED {
        match engine.evaluate(&Vendor::Junos, cmd) {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!(
                "floor must block {cmd:?} despite the allow-everything user layer, got {other:?}"
            ),
        }
    }
}

#[test]
fn floor_blocks_pipe_stage_under_hostile_allow_all() {
    // `show configuration` is allowed (head), but the `| save` stage is
    // pipe-blocked by the bundled policy. The hostile layer allows every
    // pipe stage; the floor must still deny.
    let (engine, _guard) = hostile_layered_engine();
    match engine.evaluate(&Vendor::Junos, "show configuration | save /tmp/x") {
        Decision::Deny {
            kind: DenyKind::Blocked,
            ..
        } => {}
        other => panic!("floor must block the `save` pipe stage, got {other:?}"),
    }
}

#[test]
fn floor_resists_user_alias_remap_of_blocked_head() {
    let (engine, _guard) = hostile_layered_engine();
    for cmd in ALIAS_ATTACK_BLOCKED {
        match engine.evaluate(&Vendor::Junos, cmd) {
            Decision::Deny {
                kind: DenyKind::Blocked,
                ..
            } => {}
            other => panic!(
                "user alias remapping a blocked head must not dodge the floor for {cmd:?}, \
                 got {other:?}"
            ),
        }
    }
}

#[test]
fn user_layer_relaxes_a_bundled_default_deny() {
    // The flip side: `traceroute6 …` is NOT matched by bundled
    // `^traceroute( |$)`, so bundled default-denies it (no block). The
    // user layer adds `^traceroute6( |$)`, so the merged effective
    // policy must ALLOW it — proving the merge actually works and the
    // floor's terminality is scoped to Blocked, not DefaultDeny.
    let (engine, _guard) = hostile_layered_engine();
    assert_eq!(
        engine.evaluate(&Vendor::Junos, "traceroute6 2001:db8::1"),
        Decision::Allow,
        "a user `allowed` addition must relax a bundled default-deny"
    );
}

#[test]
fn bundled_only_engine_has_no_user_relaxation() {
    // Sanity anchor: without the user layer, `traceroute6` stays
    // default-denied — confirms the previous test's Allow came from the
    // user layer, not from the bundled policy already permitting it.
    let engine = PolicyEngine::load_from_dir(&bundled_dir()).expect("bundled loads");
    match engine.evaluate(&Vendor::Junos, "traceroute6 2001:db8::1") {
        Decision::Deny {
            kind: DenyKind::DefaultDeny,
            ..
        } => {}
        other => panic!("bundled-only should default-deny traceroute6, got {other:?}"),
    }
}

/// Bundled Junos blocked heads — duplicated from `policies/junos.yaml`
/// (the engine's compiled Vec is private). Keep in sync with that file's
/// `blocked:` block. This duplication is the property-test cost: it
/// asserts the OUTSIDE description (YAML) agrees with the INSIDE
/// behavior (evaluate under a hostile layer).
fn junos_blocked_patterns() -> Vec<Regex> {
    [
        r"^start shell",
        r"^request system ",
        r"^request ",
        r"^restart ",
        r"^reboot",
        r"^reload",
        r"^reset ",
        r"^configure",
        r"^commit",
        r"^edit ",
        r"^rollback",
        r"^load ",
        r"^save ",
        r"^copy ",
        r"^file (copy|delete|rename|create) ",
        r"^clear ",
        r"^test ",
        r"^quit",
        r"^exit",
        r"^logout",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("test pattern compiles"))
    .collect()
}

proptest! {
    /// The headline floor property: under a maximally-permissive user
    /// layer (`^.*` allow + allow-every-pipe-stage + alias attacks), ANY
    /// input whose bundled-canonical head matches a shipped blocked
    /// pattern MUST still deny. Mirrors the engine's canonicalization
    /// (trim + collapse whitespace + lowercase; NFC and aliases skipped
    /// — the blocked patterns are full words, and the FLOOR ignores user
    /// aliases by design).
    #[test]
    fn no_user_layer_bypasses_a_shipped_block(s in "\\PC{0,200}") {
        let (engine, _guard) = hostile_layered_engine();
        let patterns = junos_blocked_patterns();

        let canonical: String = s
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !patterns.iter().any(|p| p.is_match(&canonical)) {
            return Ok(()); // not a blocked input — out of scope for this property
        }

        let decision = engine.evaluate(&Vendor::Junos, &s);
        prop_assert!(
            matches!(decision, Decision::Deny { kind: DenyKind::Blocked, .. }),
            "hostile user layer bypassed a shipped block: {s:?} -> {decision:?}"
        );
    }
}
