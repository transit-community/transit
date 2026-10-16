//! Junos dangerous- + permitted-command corpus.
//!
//! Loads `policies/junos.yaml` from the repo (resolved via
//! `CARGO_MANIFEST_DIR`) and asserts the engine's verdict on every
//! row in a hand-curated table. New commands hit in the field
//! belong here as new rows — keep this corpus tight enough to
//! review by eye.
//!
//! When this test fails:
//! - **Expected Allow, got Deny** — either you broke the policy
//!   or the command needs to be added to `allowed`/`pipe_allowed`.
//! - **Expected Deny, got Allow** — DEFINITELY a regression. The
//!   gate just allowed something the corpus says is dangerous.
//!   Investigate, do not relax the corpus to match.

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

#[derive(Debug)]
enum Expect {
    Allow,
    Deny,
}

fn assert_corpus(rows: &[(&str, Expect)]) {
    let engine = engine();
    let mut failures: Vec<String> = Vec::new();
    for (cmd, expect) in rows {
        let got = engine.evaluate(&Vendor::Junos, cmd);
        let ok = matches!(
            (expect, &got),
            (Expect::Allow, Decision::Allow) | (Expect::Deny, Decision::Deny { .. })
        );
        if !ok {
            failures.push(format!("  {:?} on {cmd:?} -> {got:?}", expect));
        }
    }
    if !failures.is_empty() {
        panic!(
            "corpus mismatches ({} of {}):\n{}",
            failures.len(),
            rows.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn junos_allowed_corpus() {
    assert_corpus(&[
        // Bread-and-butter operational commands.
        ("show version", Expect::Allow),
        ("SHOW VERSION", Expect::Allow), // case-folded (D-4)
        ("show interfaces", Expect::Allow),
        ("show interfaces terse", Expect::Allow),
        ("show route", Expect::Allow),
        ("show route table inet.0", Expect::Allow),
        ("show bgp summary", Expect::Allow),
        ("show ospf neighbor", Expect::Allow),
        ("show log messages", Expect::Allow),
        ("show system uptime", Expect::Allow),
        ("show chassis hardware", Expect::Allow),
        // Network probes.
        ("ping 10.0.0.1", Expect::Allow),
        ("ping 10.0.0.1 count 5", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        ("monitor traffic interface ge-0/0/0", Expect::Allow),
        // Read-only file + operator scripts.
        ("file list /var/log", Expect::Allow),
        ("op cli", Expect::Allow),
        ("help reference show", Expect::Allow),
        // Aliased forms — routed through canonicalization.
        ("sh interfaces", Expect::Allow),
        ("sho route", Expect::Allow),
        ("p 10.0.0.1", Expect::Allow),
        ("tr 10.0.0.1", Expect::Allow),
        ("mon traffic interface ge-0/0/0", Expect::Allow),
        // Whitespace tolerance — spaces only. Tabs are control
        // characters and deny outright (D-1; see the blocked corpus).
        ("   show   version  ", Expect::Allow),
        // Pipe stages — all on the allow list.
        ("show route | match BGP", Expect::Allow),
        ("show route | match BGP | count", Expect::Allow),
        ("show config | display set", Expect::Allow),
        ("show interfaces | display xml", Expect::Allow),
        ("show log messages | last 50", Expect::Allow),
        ("show route | except direct | count", Expect::Allow),
        ("show route | find 10.0.0.0/24", Expect::Allow),
        ("show config | no-more", Expect::Allow),
    ]);
}

#[test]
fn junos_blocked_corpus() {
    assert_corpus(&[
        // Configuration-mode entry + commits.
        ("configure", Expect::Deny),
        ("configure exclusive", Expect::Deny),
        // Case variants — the CLI is case-insensitive, so the gate
        // case-folds; these must hit the blocklist patterns (D-4).
        ("CONFIGURE", Expect::Deny),
        ("START SHELL", Expect::Deny),
        ("commit", Expect::Deny),
        ("commit confirmed", Expect::Deny),
        ("rollback", Expect::Deny),
        ("rollback 1", Expect::Deny),
        ("edit interfaces ge-0/0/0", Expect::Deny),
        ("load merge terminal", Expect::Deny),
        ("save /tmp/config.txt", Expect::Deny),
        ("copy /tmp/a /tmp/b", Expect::Deny),
        // Shell escape — fully bypasses the gate. NEVER allow.
        ("start shell", Expect::Deny),
        ("start shell user root", Expect::Deny),
        // System-level actions.
        ("request system reboot", Expect::Deny),
        ("request system halt", Expect::Deny),
        ("request system snapshot", Expect::Deny),
        (
            "request system software add /tmp/jinstall.tgz",
            Expect::Deny,
        ),
        ("restart routing", Expect::Deny),
        ("restart pfe", Expect::Deny),
        ("reboot", Expect::Deny),
        ("reload", Expect::Deny),
        // Counter / state mutations.
        ("clear bgp neighbor 10.0.0.1", Expect::Deny),
        ("clear arp", Expect::Deny),
        ("clear interfaces statistics all", Expect::Deny),
        ("test commit", Expect::Deny),
        // File ops with side effects.
        ("file copy /tmp/a /tmp/b", Expect::Deny),
        ("file delete /var/log/messages", Expect::Deny),
        ("file rename /tmp/a /tmp/b", Expect::Deny),
        ("file create /tmp/foo", Expect::Deny),
        // Session control.
        ("quit", Expect::Deny),
        ("exit", Expect::Deny),
        ("logout", Expect::Deny),
        // Default-deny: nothing matches.
        ("telnet 1.2.3.4", Expect::Deny),
        ("ssh user@10.0.0.1", Expect::Deny),
        ("rm -rf /", Expect::Deny),
        ("totally-novel-command --with-args", Expect::Deny),
        ("", Expect::Deny),
        ("   ", Expect::Deny),
        // Pipe-stage abuse — head allowed, but a stage writes/commits.
        ("show config | save /tmp/cfg.txt", Expect::Deny),
        ("show interfaces | save /tmp/foo", Expect::Deny),
        ("show route | request foo", Expect::Deny),
        ("show route | commit", Expect::Deny),
        // Empty pipe stage.
        ("show route |", Expect::Deny),
        // Unknown pipe stage default-denies.
        ("show route | weird-pipe", Expect::Deny),
        ("show route | bash", Expect::Deny),
        // Control characters — multi-line smuggling + raw tab (D-1).
        ("show version\nconfigure", Expect::Deny),
        ("\tshow\tversion", Expect::Deny),
    ]);
}

#[test]
fn junos_write_and_exfil_bypasses_are_blocked() {
    // Security review 2026-07 (findings #1/#12).
    assert_corpus(&[
        // #12 — `monitor traffic … write-file` persists a pcap on-box.
        (
            "monitor traffic interface ge-0/0/0 write-file /var/tmp/cap.pcap",
            Expect::Deny,
        ),
        // #1 — blocked pipe verb (`save`) hidden behind an unbalanced quote.
        (
            "show configuration | match x\" | save /tmp/cfg",
            Expect::Deny,
        ),
        // Regression guard: bare `monitor traffic` stays allowed.
        ("monitor traffic interface ge-0/0/0", Expect::Allow),
    ]);
}
