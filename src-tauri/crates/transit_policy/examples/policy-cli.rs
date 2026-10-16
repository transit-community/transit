//! Manual smoke-test driver for the policy engine. Same purpose as
//! `transit_ssh::examples::connect-cli` — exercises the engine
//! without spinning up the full Tauri app, which is useful when
//! adding a new vendor policy and you want to sanity-check the
//! allow/deny decisions on a few commands by eye.
//!
//! Usage:
//!   cargo run --manifest-path src-tauri/Cargo.toml -p transit_policy \
//!     --example policy-cli -- <vendor> <command...>
//!
//!   <vendor> = junos | cisco_ios | cisco_ios_xe | nxos | arista_eos
//!
//! Examples:
//!   policy-cli junos "show interfaces terse"          -> Allow
//!   policy-cli junos "configure"                      -> Deny ...
//!   policy-cli cisco_ios "wr mem"                     -> Deny ...
//!   policy-cli nxos     "show running-config | grep vlan"  -> Allow

use std::path::PathBuf;
use std::process::ExitCode;

use transit_core::inventory::Vendor;
use transit_policy::{Decision, PolicyEngine};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: policy-cli <vendor> <command...>");
        return ExitCode::from(2);
    }

    let vendor = match args[0].as_str() {
        "junos" => Vendor::Junos,
        "cisco_ios" => Vendor::CiscoIos,
        "cisco_ios_xe" => Vendor::CiscoIosXe,
        "nxos" | "cisco_nxos" => Vendor::NxOs,
        "arista_eos" => Vendor::AristaEos,
        "pan_os" => Vendor::PanOs,
        "linux" => Vendor::Linux,
        other => {
            eprintln!("unknown vendor: {other}");
            return ExitCode::from(2);
        }
    };
    let command = args[1..].join(" ");

    // Resolve `policies/` relative to the workspace root, two levels
    // above this crate. Mirrors the debug-build path resolution in
    // `transit_app::commands::resolve_policies_dir()`.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("policies");

    let engine = match PolicyEngine::load_from_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("failed to load policies from {}: {e}", dir.display());
            return ExitCode::from(1);
        }
    };

    let decision = engine.evaluate(&vendor, &command);
    match decision {
        Decision::Allow => {
            println!("ALLOW");
            ExitCode::SUCCESS
        }
        Decision::AllowUnrestricted { warning } => {
            println!("ALLOW (unrestricted) — {warning}");
            ExitCode::SUCCESS
        }
        Decision::Deny { reason, .. } => {
            println!("DENY: {reason}");
            ExitCode::from(1)
        }
    }
}
