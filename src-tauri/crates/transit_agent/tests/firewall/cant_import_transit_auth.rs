//! This file MUST NOT compile. The agent firewall depends on
//! `transit_auth` being unreachable from `transit_agent`. If this
//! compiles, someone broke the firewall — see Cargo.toml and the
//! `deny.toml` `[[bans.deny]]` for the enforcement layers.

use transit_auth::SecretRegistry;

fn main() {
    let _ = SecretRegistry::standard();
}
