//! Palo Alto PAN-OS dangerous- + permitted-command corpus.
//!
//! Same shape as `cisco_ios_corpus.rs`. New rows for commands hit
//! in the field belong here. When this test fails, see the
//! failure-mode comment in `junos_corpus.rs`.

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
        let got = engine.evaluate(&Vendor::PanOs, cmd);
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
fn pan_os_allowed_corpus() {
    assert_corpus(&[
        // Operational status workhorses.
        ("show system info", Expect::Allow),
        ("SHOW SYSTEM INFO", Expect::Allow), // case-folded (D-4)
        ("show system resources", Expect::Allow),
        ("show config running", Expect::Allow),
        ("show config candidate", Expect::Allow),
        ("show interface all", Expect::Allow),
        ("show interface management", Expect::Allow),
        ("show routing route", Expect::Allow),
        ("show routing protocol bgp peer", Expect::Allow),
        ("show running security-policy", Expect::Allow),
        ("show running nat-policy", Expect::Allow),
        ("show session all", Expect::Allow),
        ("show session info", Expect::Allow),
        ("show counter global", Expect::Allow),
        ("show counter interface", Expect::Allow),
        ("show high-availability state", Expect::Allow),
        ("show vpn ipsec-sa", Expect::Allow),
        ("show user user-ids", Expect::Allow),
        ("show log traffic", Expect::Allow),
        ("show jobs all", Expect::Allow),
        ("show jobs id 42", Expect::Allow),
        // Network probes.
        ("ping host 10.0.0.1", Expect::Allow),
        ("traceroute host 10.0.0.1", Expect::Allow),
        // Aliased forms.
        ("sh system info", Expect::Allow),
        ("sho running security-policy", Expect::Allow),
        ("p host 10.0.0.1", Expect::Allow),
        // Read-only file/log viewers — PAN-OS grammar only (the heads
        // are anchored to a `<area>-log` token / `find command`; see
        // the blocked corpus for the GNU shapes that must NOT match).
        ("less mp-log appweb3-sslvpn.log", Expect::Allow),
        ("less dp-log dp-monitor.log", Expect::Allow),
        ("tail follow yes mp-log appweb3-sslvpn.log", Expect::Allow),
        ("tail lines 100 mp-log mp-monitor.log", Expect::Allow),
        (
            "tail follow yes lines 50 dp-log dp-monitor.log",
            Expect::Allow,
        ),
        ("find command", Expect::Allow),
        ("find command keyword session", Expect::Allow),
        ("grep mp-log mp-monitor.log pattern fail", Expect::Allow),
        (
            "grep count yes mp-log mp-monitor.log pattern error",
            Expect::Allow,
        ),
        // CLI cosmetics — operational-only `set` carve-outs.
        ("set cli pager off", Expect::Allow),
        ("set cli pager on", Expect::Allow),
        ("set cli terminal type ansi", Expect::Allow),
        ("set cli terminal width 200", Expect::Allow),
        ("set cli timeout 0", Expect::Allow),
        ("set cli timeout 30", Expect::Allow),
        // Pipe stages.
        ("show system info | match version", Expect::Allow),
        (
            "show running security-policy | except disabled",
            Expect::Allow,
        ),
        ("show interface all | count", Expect::Allow),
        // View-only candidate-config.
        ("view-config running", Expect::Allow),
    ]);
}

#[test]
fn pan_os_blocked_corpus() {
    assert_corpus(&[
        // Configuration-mode entry + mutators.
        ("configure", Expect::Deny),
        // Case variant — the CLI is case-insensitive, so the gate
        // case-folds; this must hit the blocklist pattern (D-4).
        ("CONFIGURE", Expect::Deny),
        ("edit network interface ethernet1/1", Expect::Deny),
        ("set network interface ethernet1/1 layer3", Expect::Deny),
        ("delete network interface ethernet1/1", Expect::Deny),
        // Commit variants — pushes candidate to running.
        ("commit", Expect::Deny),
        ("commit description \"oops\"", Expect::Deny),
        ("commit force", Expect::Deny),
        ("commit-all", Expect::Deny),
        // Config persistence.
        ("load config from saved.xml", Expect::Deny),
        ("save config to backup.xml", Expect::Deny),
        ("revert config", Expect::Deny),
        ("rename address oldname new-name", Expect::Deny),
        ("move address oldname before other", Expect::Deny),
        ("copy running-config to startup-config", Expect::Deny),
        // File / transfer operations.
        (
            "scp export configuration to user@1.2.3.4:cfg.xml",
            Expect::Deny,
        ),
        (
            "scp import configuration from user@1.2.3.4:cfg.xml",
            Expect::Deny,
        ),
        ("tftp export configuration to 1.2.3.4", Expect::Deny),
        ("ftp export configuration to 1.2.3.4", Expect::Deny),
        ("clear session all", Expect::Deny),
        ("clear counter all", Expect::Deny),
        // ---- THE CRITICAL BLOCKS ----
        // Shell escape — drops to root Linux on the firewall.
        ("debug software shell", Expect::Deny),
        ("debug software shell --user admin", Expect::Deny),
        // System-state debug verbs.
        ("debug system maint-mode", Expect::Deny),
        ("debug system loadcfg saved.xml", Expect::Deny),
        (
            "debug system disk-image upgrade-to PanOS_10.2.0",
            Expect::Deny,
        ),
        // Reboot / shutdown.
        ("request restart system", Expect::Deny),
        ("request restart software", Expect::Deny),
        ("request shutdown system", Expect::Deny),
        // System operations outside the read-only contract.
        ("request system license install", Expect::Deny),
        ("request system certificate generate", Expect::Deny),
        (
            "request platform-software install version 11.0.0",
            Expect::Deny,
        ),
        ("request high-availability state functional", Expect::Deny),
        ("request password-hash password admin123", Expect::Deny),
        // Session / mode manipulation.
        ("exit", Expect::Deny),
        ("quit", Expect::Deny),
        ("logout", Expect::Deny),
        ("run show interface all", Expect::Deny), // config-mode escape
        // Default-deny: nothing matches.
        ("telnet 1.2.3.4", Expect::Deny),
        ("ssh -l user 10.0.0.1", Expect::Deny),
        ("rm -rf /", Expect::Deny),
        ("totally-novel-command", Expect::Deny),
        ("", Expect::Deny),
        // GNU shapes of the PAN-OS viewer heads — the grammar-anchored
        // allow patterns must NOT match these (a mislabeled Linux box,
        // or any future loosening of the head regexes, would otherwise
        // hand the agent arbitrary filesystem reads).
        ("less /etc/passwd", Expect::Deny),
        ("less .ssh/id_rsa", Expect::Deny),
        ("tail -f /var/log/messages", Expect::Deny),
        ("tail /var/log/syslog", Expect::Deny),
        ("find / -name *.key", Expect::Deny),
        ("find . -exec rm {} ;", Expect::Deny),
        ("grep -r password /etc", Expect::Deny),
        ("grep root /etc/passwd", Expect::Deny),
        // The `set` carve-outs MUST NOT leak to other set verbs.
        ("set deviceconfig hostname FW1", Expect::Deny),
        ("set cli config-output-format set", Expect::Deny), // close to cli but not one of the three
        // Pipe-stage abuse.
        (
            "show config running | redirect to 1.2.3.4:cfg",
            Expect::Deny,
        ),
        ("show config running | tee saved.txt", Expect::Deny),
        // Empty pipe stage.
        ("show system info |", Expect::Deny),
        // Unknown pipe stage.
        ("show system info | weird-pipe", Expect::Deny),
    ]);
}
