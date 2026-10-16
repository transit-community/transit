//! Cisco IOS-XR dangerous- + permitted-command corpus.
//!
//! IOS-XR (ASR 9000 / NCS / CRS / XRv) shares classic IOS's read-only
//! grammar but diverges in its config model (two-stage commit) and its
//! shell escapes (`run` / `bash` / `script` / `attach` / `admin`). Same
//! shape as the other corpus tests; new field-encountered commands belong
//! here as new rows. Design rationale: `policies/cisco_ios_xr.README.md`.

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
        let got = engine.evaluate(&Vendor::CiscoIosXr, cmd);
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
fn cisco_ios_xr_allowed_corpus() {
    assert_corpus(&[
        // Operational status.
        ("show version", Expect::Allow),
        ("SHOW VERSION", Expect::Allow), // case-folded (D-4)
        ("show running-config", Expect::Allow),
        (
            "show running-config interface GigabitEthernet0/0/0/0",
            Expect::Allow,
        ),
        ("show interfaces brief", Expect::Allow),
        ("show ipv4 interface brief", Expect::Allow),
        ("show ipv6 interface brief", Expect::Allow),
        ("show route ipv4", Expect::Allow),
        ("show route ipv6", Expect::Allow),
        ("show bgp summary", Expect::Allow),
        ("show bgp ipv4 unicast summary", Expect::Allow),
        ("show ospf neighbor", Expect::Allow),
        ("show isis neighbors", Expect::Allow),
        ("show mpls forwarding", Expect::Allow),
        ("show cdp neighbors", Expect::Allow),
        ("show lldp neighbors", Expect::Allow),
        ("show arp", Expect::Allow),
        ("show logging", Expect::Allow),
        ("show processes cpu", Expect::Allow),
        ("show platform", Expect::Allow),
        ("show inventory", Expect::Allow),
        ("show controllers", Expect::Allow),
        ("show redundancy", Expect::Allow),
        ("show configuration commit list", Expect::Allow),
        // `show install ...` is read-only — head is `show`, not `install`.
        ("show install active", Expect::Allow),
        ("show install committed", Expect::Allow),
        // `show tech-support` (to terminal) is read-only and allowed; only
        // its file-writing forms are blocked (see blocked corpus).
        ("show tech-support", Expect::Allow),
        ("show tech-support bgp", Expect::Allow),
        // THE shell-escape safety row: `sh run` aliases to head `show run`
        // (read-only show running-config), NOT the `run` task shell.
        ("sh run", Expect::Allow),
        ("show run", Expect::Allow),
        // Probes.
        ("ping 10.0.0.1", Expect::Allow),
        ("ping ipv4 10.0.0.1", Expect::Allow),
        ("traceroute 10.0.0.1", Expect::Allow),
        // Read-only file/storage + session-local terminal settings.
        ("dir disk0:", Expect::Allow),
        ("dir harddisk:", Expect::Allow),
        ("more disk0:/test.txt", Expect::Allow),
        ("terminal length 0", Expect::Allow),
        ("terminal width 200", Expect::Allow),
        ("terminal monitor", Expect::Allow),
        // Aliased forms.
        ("sh version", Expect::Allow),
        ("sho route ipv4", Expect::Allow),
        ("shw bgp summary", Expect::Allow),
        ("p 10.0.0.1", Expect::Allow),
        ("tr 10.0.0.1", Expect::Allow),
        // Pipe stages — XR read-only filters.
        ("show running-config | include router", Expect::Allow),
        ("show route ipv4 | exclude connected", Expect::Allow),
        ("show bgp summary | begin Neighbor", Expect::Allow),
        ("show route ipv4 | count", Expect::Allow),
        // Quote-aware: the `|` inside the regex arg is NOT a pipe split.
        (
            "show running-config | include \"interface|router\"",
            Expect::Allow,
        ),
    ]);
}

#[test]
fn cisco_ios_xr_blocked_corpus() {
    assert_corpus(&[
        // Privilege-exec guards (XR has no enable mode; defense-in-depth).
        ("enable", Expect::Deny),
        ("disable", Expect::Deny),
        // Two-stage commit config model.
        ("configure", Expect::Deny),
        ("configure terminal", Expect::Deny),
        ("configure exclusive", Expect::Deny),
        ("configure private", Expect::Deny),
        ("conf t", Expect::Deny),
        ("CONFIGURE TERMINAL", Expect::Deny), // case-folded (D-4)
        ("commit", Expect::Deny),
        ("commit replace", Expect::Deny),
        // Shell / scripting escapes — the high-impact XR bypasses.
        ("run", Expect::Deny),
        ("run bash", Expect::Deny),
        ("bash", Expect::Deny),
        ("bash -c id", Expect::Deny),
        ("tclsh", Expect::Deny),
        ("script run my-script", Expect::Deny),
        ("script", Expect::Deny),
        ("admin", Expect::Deny),
        ("admin show platform", Expect::Deny), // sysadmin-plane read, intentionally blocked
        ("attach location 0/RP0/CPU0", Expect::Deny),
        // Reload / process / hardware / clear.
        ("reload", Expect::Deny),
        ("reload location 0/RP0/CPU0", Expect::Deny),
        ("process restart ifmgr", Expect::Deny),
        ("hw-module location 0/0/CPU0 reload", Expect::Deny),
        ("clear counters", Expect::Deny),
        ("clear bgp ipv4 unicast *", Expect::Deny),
        // Software lifecycle + file mutation.
        ("install activate id 0x1", Expect::Deny),
        ("install add source tftp://1.1.1.1 pkg.rpm", Expect::Deny),
        ("copy running-config disk0:backup.cfg", Expect::Deny),
        ("copy disk0:a disk0:b", Expect::Deny),
        ("delete disk0:foo", Expect::Deny),
        ("rmdir disk0:bar", Expect::Deny),
        ("mkdir disk0:baz", Expect::Deny),
        ("format disk0:", Expect::Deny),
        ("move disk0:a disk0:b", Expect::Deny),
        ("crypto key generate rsa", Expect::Deny),
        // Session control.
        ("logout", Expect::Deny),
        ("exit", Expect::Deny),
        ("quit", Expect::Deny),
        ("end", Expect::Deny),
        // Default-deny.
        ("telnet 1.2.3.4", Expect::Deny),
        ("totally-novel-command", Expect::Deny),
        ("", Expect::Deny),
        // `show tech-support` file-writing forms — block-wins overrides the
        // broad `^show` allow.
        ("show tech-support file disk0:tech.tgz", Expect::Deny),
        ("show tech-support bgp file harddisk:/b.txt", Expect::Deny),
        // Destination token WITHOUT the literal `file` keyword.
        ("show tech-support routing tftp://1.1.1.1/r", Expect::Deny),
        // Pipe-stage write / escape vectors.
        ("show running-config | file disk0:run.cfg", Expect::Deny),
        ("show running-config | redirect disk0:run.txt", Expect::Deny),
        ("show running-config | utility wc -l", Expect::Deny),
        ("show running-config | tee disk0:run.txt", Expect::Deny),
        (
            "show running-config | append disk0:archive.txt",
            Expect::Deny,
        ),
        // Empty pipe stage.
        ("show running-config |", Expect::Deny),
        // Unknown pipe stage.
        ("show running-config | weird-pipe", Expect::Deny),
    ]);
}
