//! Property test: random commands cannot bypass blocked regexes.
//!
//! For any input where ANY pattern in the Junos `blocked` list
//! matches the canonicalized head, the engine MUST return `Deny`.
//! This catches the class of bug where a future refactor of
//! `evaluate` accidentally short-circuits past the blocklist (e.g.
//! a re-ordering that lets allow-wins fire even on a blocked head
//! when precedence is block-wins).
//!
//! Empty / no-match inputs are filtered out — they default-deny via
//! a different code path which the corpus tests already cover.

use std::path::PathBuf;

use proptest::prelude::*;
use regex::Regex;
use transit_core::inventory::Vendor;
use transit_policy::{Decision, PolicyEngine};

fn engine() -> PolicyEngine {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");
    PolicyEngine::load_from_dir(&dir).expect("policies/ loads cleanly")
}

/// Re-derive the head-blocked patterns from the YAML file. We
/// can't reach into the engine's compiled-regex Vec (private), so
/// duplicate the list here. Keep in sync with `policies/junos.yaml`'s
/// `blocked:` block.
///
/// This duplication is the property-test cost — without it, the
/// test is "evaluate matches itself", which proves nothing. With
/// it, we assert the OUTSIDE description (the YAML) agrees with
/// the inside behavior (evaluate's verdict).
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

/// Re-derive the head-blocked patterns from `policies/cisco_ios_xr.yaml`.
/// Keep in sync with that file's `blocked:` block (CLAUDE.md §7 step 7).
/// UniFi's shell-grammar armor (v6.1.0). These are the UNANCHORED
/// blocks — the ones that must hold no matter where in the line the
/// metacharacter appears, because on a real shell any allowed head can
/// be chained, redirected, or substituted into a write.
fn unifi_shell_grammar_patterns() -> Vec<Regex> {
    [r"[;&]", r"[<>]", r"`", r"\$\(", r"\.\."]
        .into_iter()
        .map(|p| Regex::new(p).expect("test pattern compiles"))
        .collect()
}

fn cisco_ios_xr_blocked_patterns() -> Vec<Regex> {
    [
        r"^enable( |$)",
        r"^disable( |$)",
        r"^configure",
        r"^conf t",
        r"^commit",
        r"^copy ",
        r"^delete ",
        r"^rmdir ",
        r"^mkdir ",
        r"^format ",
        r"^move ",
        r"^install ",
        r"^reload",
        r"^process ",
        r"^hw-module ",
        r"^clear ",
        r"^crypto ",
        r"^run( |$)",
        r"^bash",
        r"^tclsh",
        r"^script( |$)",
        r"^admin",
        r"^attach",
        r"^logout",
        r"^exit",
        r"^quit",
        r"^end",
        r"^show tech-support\b.*\b(file\b|disk[0-9]+:|harddisk:|bootflash:|nvram:|tftp:|ftp:|scp:|sftp:|rcp:|https?:)",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("test pattern compiles"))
    .collect()
}

fn any_blocked_matches(patterns: &[Regex], s: &str) -> bool {
    patterns.iter().any(|p| p.is_match(s))
}

proptest! {
    /// "\\PC" excludes control chars; we want printable-ish input
    /// that an attacker might actually try to feed us. 200-char cap
    /// keeps the fuzz cheap.
    #[test]
    fn no_random_string_bypasses_blocked(s in "\\PC{0,200}") {
        let engine = engine();
        let patterns = junos_blocked_patterns();

        // Trim + collapse internal whitespace + lowercase to mirror
        // the engine's canonicalization (keep in sync with
        // `src/canonicalize.rs` — integration tests can't see the
        // cfg(test)-only `canonicalize_for_tests` export). The engine
        // does NFC-normalize too; proptest's strategy doesn't
        // generate combining-character tricks at this size, so we
        // skip that step.
        let canonical: String = s
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !any_blocked_matches(&patterns, &canonical) {
            // Input doesn't match any blocked pattern. Engine may
            // allow or default-deny; either is fine for THIS test.
            return Ok(());
        }

        let decision = engine.evaluate(&Vendor::Junos, &s);
        prop_assert!(
            matches!(decision, Decision::Deny { .. }),
            "blocked pattern matched but engine allowed: {s:?} -> {decision:?}"
        );
    }

    /// No random string smuggles shell grammar past the UniFi gate
    /// (CLAUDE.md §7 step 7). UniFi is the only vendor whose policy has
    /// to defend a real shell, so this property is the one that matters
    /// most there: if a metacharacter survives, an allowed head becomes
    /// a launch pad.
    #[test]
    fn no_random_string_bypasses_unifi_shell_grammar(s in "\\PC{0,200}") {
        let engine = engine();
        let patterns = unifi_shell_grammar_patterns();

        let canonical: String = s
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !any_blocked_matches(&patterns, &canonical) {
            return Ok(());
        }

        let decision = engine.evaluate(&Vendor::UniFi, &s);
        prop_assert!(
            matches!(decision, Decision::Deny { .. }),
            "shell metacharacter matched but engine allowed: {s:?} -> {decision:?}"
        );
    }

    /// Same no-bypass property, scoped to Cisco IOS-XR (CLAUDE.md §7
    /// step 7). Patterns are matched against the HEAD (text before the
    /// first `|`) — mirroring the engine — because the `show tech-support
    /// … file` block contains `.*` and would otherwise be triggered by a
    /// `file` token living in a pipe stage rather than the head.
    #[test]
    fn no_random_string_bypasses_xr_blocked(s in "\\PC{0,200}") {
        let engine = engine();
        let patterns = cisco_ios_xr_blocked_patterns();

        let canonical: String = s
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let head = canonical.split('|').next().unwrap_or("").trim();
        if !any_blocked_matches(&patterns, head) {
            return Ok(());
        }

        let decision = engine.evaluate(&Vendor::CiscoIosXr, &s);
        prop_assert!(
            matches!(decision, Decision::Deny { .. }),
            "blocked pattern matched head but engine allowed: {s:?} -> {decision:?}"
        );
    }

    /// D-1 regression: inserting ANY control character anywhere in
    /// ANY otherwise-printable input must deny. The dispatcher sends
    /// the raw bytes to the PTY, so an embedded `\n`/`\r` smuggles a
    /// second line past the single-line regex gate (and a raw tab is
    /// masked by canonicalization / interpreted by the device as
    /// completion). No filtering here — even an input that would
    /// otherwise be allowed (or empty) must deny once a control
    /// char is present.
    #[test]
    fn any_control_char_insertion_denies(
        s in "\\PC{0,200}",
        ctl in prop::sample::select(vec!['\n', '\r', '\0', '\t', '\u{1b}']),
        pos in any::<prop::sample::Index>(),
    ) {
        let engine = engine();

        // Insert the control char at a random char boundary
        // (0..=char_count inclusive, so head/middle/tail are all hit).
        let chars: Vec<char> = s.chars().collect();
        let at = pos.index(chars.len() + 1);
        let mut mutated: String = chars[..at].iter().collect();
        mutated.push(ctl);
        mutated.extend(&chars[at..]);

        let decision = engine.evaluate(&Vendor::Junos, &mutated);
        prop_assert!(
            matches!(&decision, Decision::Deny { reason, .. } if reason.contains("control character")),
            "control char {ctl:?} at {at} must deny: {mutated:?} -> {decision:?}"
        );
    }
}
