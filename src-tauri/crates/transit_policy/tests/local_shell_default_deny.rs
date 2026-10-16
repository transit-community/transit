//! v4.4.0 §2 defense-in-depth — `Vendor::LocalShell` must default-deny.
//!
//! The local OS terminal is HUMAN-only: the agent is structurally blind
//! to it (never composed into the agent's unified session sources in
//! `chat.rs`), so a local shell never actually reaches this gate. This
//! test pins the SECOND line of defense: if a local session ever WERE
//! routed to the gate, it must DEFAULT-DENY — never inherit a permissive
//! policy, and above all never `Vendor::Linux`'s unrestricted carve-out
//! (written for a reimageable remote box, not the user's own filesystem
//! holding their SSH keys / `~/.aws/credentials`).
//!
//! Concretely this asserts NO `policies/local_shell.yaml` ships: an
//! unregistered vendor yields `DenyKind::DefaultDeny` ("no policy
//! registered"). If someone adds a permissive local_shell policy — or
//! maps LocalShell onto an unrestricted mode — these tests fail loudly.

use std::path::PathBuf;

use transit_core::inventory::Vendor;
use transit_policy::{Decision, DenyKind, PolicyEngine};

fn engine() -> PolicyEngine {
    // CARGO_MANIFEST_DIR is transit_policy; the repo-root `policies/`
    // is three levels up (crate → crates → src-tauri → repo).
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");
    PolicyEngine::load_from_dir(&dir).expect("policies/ loads cleanly")
}

#[test]
fn local_shell_default_denies_every_command() {
    let engine = engine();
    // Even the most benign, read-only-looking local commands must
    // default-deny: there is no `local_shell.yaml`, and the agent is
    // blind to local shells regardless — this is defense in depth.
    for cmd in ["ls", "git status", "cat /etc/hosts", "whoami"] {
        match engine.evaluate(&Vendor::LocalShell, cmd) {
            Decision::Deny {
                kind: DenyKind::DefaultDeny,
                reason,
            } => assert!(
                reason.contains("no policy registered"),
                "expected 'no policy registered' for {cmd:?}, got {reason:?}"
            ),
            other => panic!(
                "Vendor::LocalShell must DEFAULT-DENY {cmd:?} (never inherit a \
                 permissive/unrestricted policy), got {other:?}"
            ),
        }
    }
}

#[test]
fn local_shell_never_shares_linux_unrestricted_carveout() {
    // The specific footgun the distinct variant exists to prevent:
    // LocalShell must NOT behave like `Vendor::Linux` (mode:
    // unrestricted → AllowUnrestricted). Prove the two diverge on the
    // SAME command.
    let engine = engine();
    assert!(
        matches!(
            engine.evaluate(&Vendor::Linux, "ls"),
            Decision::AllowUnrestricted { .. }
        ),
        "sanity: the linux policy is unrestricted"
    );
    assert!(
        matches!(
            engine.evaluate(&Vendor::LocalShell, "ls"),
            Decision::Deny { .. }
        ),
        "LocalShell must NOT share Linux's unrestricted carve-out"
    );
}
