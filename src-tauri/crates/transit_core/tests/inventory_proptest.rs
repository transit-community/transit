//! Property tests for the inventory loader's TOML round-trip.
//!
//! Generates random valid InventoryFile structs, serializes them to
//! TOML, parses them back via `load()`, asserts structural equality.
//! Catches edge cases the fixture corpus misses (special characters in
//! ids and hostnames, ports near u16::MAX, all backend variants, etc.).

use std::collections::BTreeMap;

use proptest::prelude::*;
use transit_core::inventory::{load, AuthProfile, Device, InventoryFile, SecretRef, Vendor};

// ---------------------------------------------------------------------
// Strategies.
// ---------------------------------------------------------------------

fn arb_id() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,15}".prop_map(String::from)
}

fn arb_host() -> impl Strategy<Value = String> {
    // Conservative hostname / IP shape: alphanumerics, dots, hyphens.
    "[a-zA-Z0-9][a-zA-Z0-9.-]{0,30}[a-zA-Z0-9]".prop_map(String::from)
}

fn arb_port() -> impl Strategy<Value = u16> {
    1u16..=65535
}

fn arb_vendor() -> impl Strategy<Value = Vendor> {
    prop_oneof![
        Just(Vendor::Junos),
        Just(Vendor::CiscoIos),
        Just(Vendor::CiscoIosXe),
        Just(Vendor::AristaEos),
    ]
}

fn arb_secret_ref() -> impl Strategy<Value = SecretRef> {
    prop_oneof![
        "[a-z][a-z0-9_/-]{0,30}".prop_map(|key| SecretRef::Keyring { key }),
        Just(SecretRef::SshAgent {
            public_key_fingerprint: None
        }),
        "[A-Z][A-Z0-9_]{1,15}".prop_map(|var| SecretRef::Env { var }),
        "[a-z][a-z0-9_/]{0,30}".prop_map(|key| SecretRef::Op {
            reference: format!("op://Vault/{key}/password")
        }),
    ]
}

fn arb_auth_profile() -> impl Strategy<Value = AuthProfile> {
    ("[a-z][a-z_]{1,15}", arb_secret_ref())
        .prop_map(|(username, secret)| AuthProfile { username, secret })
}

fn arb_group() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        "[A-Z][a-zA-Z]{1,15}".prop_map(|g| Some(g.to_string())),
        ("[A-Z][a-zA-Z]{1,10}", "[A-Z][a-zA-Z]{1,10}")
            .prop_map(|(top, sub)| Some(format!("{top}/{sub}"))),
    ]
}

fn arb_device(auth_keys: Vec<String>) -> impl Strategy<Value = Device> {
    let pick_auth = prop::sample::select(auth_keys);
    (
        arb_id(),
        arb_host(),
        arb_port(),
        arb_vendor(),
        arb_group(),
        pick_auth,
        // syntax_highlighting + quick_copy_paste + allow_weak_crypto:
        // cover all three states (None / Some(true) / Some(false)) so
        // the round-trip path exercises both "field absent" and "field
        // present" serialization branches for each preference
        // independently.
        prop::option::of(any::<bool>()),
        prop::option::of(any::<bool>()),
        prop::option::of(any::<bool>()),
        // color: None or a curated palette token — mirror of `group`,
        // fully serialized + asserted below (unlike the bool prefs, which
        // the manual serializer omits).
        prop::option::of("(red|amber|green|blue|purple|cyan|slate)".prop_map(String::from)),
    )
        .prop_map(
            |(
                id,
                host,
                port,
                vendor,
                group,
                auth,
                syntax_highlighting,
                quick_copy_paste,
                allow_weak_crypto,
                color,
            )| Device {
                id,
                host,
                port,
                vendor,
                group,
                color,
                tags: Vec::new(),
                auth,
                syntax_highlighting,
                quick_copy_paste,
                // v4.1.0 appearance fields: the manual serializer omits
                // them (like the bool prefs), so they round-trip as None;
                // their write→load path is covered in the mutator corpus.
                font_family: None,
                font_size: None,
                bold_color: None,
                allow_weak_crypto,
                // v6.2.0 sync key — same treatment: write→load covered by
                // the mutator corpus + import::netbox tests.
                netbox_id: None,
                // v6.5.0 — wired in `arb_inventory` (a jump ref needs
                // ANOTHER device's id, unknown at per-device time).
                jump_via: None,
                forward_agent: None,
            },
        )
}

fn arb_inventory() -> impl Strategy<Value = InventoryFile> {
    // 1-5 auth profiles, then 1-8 devices that reference them.
    prop::collection::btree_map(
        "[a-z][a-z0-9_-]{0,15}".prop_map(String::from),
        arb_auth_profile(),
        1..=5,
    )
    .prop_flat_map(|auth_profiles| {
        let auth_keys: Vec<String> = auth_profiles.keys().cloned().collect();
        let device_strategy = arb_device(auth_keys);
        let devices_strategy = prop::collection::vec(device_strategy, 1..=8);
        (devices_strategy, Just(auth_profiles))
    })
    .prop_filter("device ids must be unique", |(devices, _)| {
        let mut seen = std::collections::HashSet::new();
        devices.iter().all(|d| seen.insert(d.id.clone()))
    })
    .prop_flat_map(|(devices, auth_profiles)| {
        // v6.5.0 — wire jump refs that are ACYCLIC BY CONSTRUCTION:
        // only device 0 is ever a jump TARGET and it never jumps
        // itself, so every chain is exactly one hop. The loader's
        // cycle/depth walk has its own corpus tests; the property here
        // is serializer↔loader round-trip fidelity, which needs valid
        // inputs. `forward_agent` carries no referential constraint,
        // so it's plain per-device randomness.
        let n = devices.len();
        (
            Just(devices),
            Just(auth_profiles),
            prop::collection::vec(proptest::arbitrary::any::<bool>(), n),
            prop::collection::vec(prop::option::of(proptest::arbitrary::any::<bool>()), n),
        )
    })
    .prop_map(|(mut devices, auth_profiles, jump_flags, forward_flags)| {
        let hub = devices[0].id.clone();
        for (i, d) in devices.iter_mut().enumerate() {
            d.forward_agent = forward_flags[i];
            if i > 0 && jump_flags[i] {
                d.jump_via = Some(hub.clone());
            }
        }
        InventoryFile {
            devices,
            auth_profiles,
            groups: Vec::new(),
            api_sessions: Vec::new(),
        }
    })
}

// ---------------------------------------------------------------------
// Manual TOML serializer.
//
// We can't use `toml::to_string` directly because the public types only
// derive `Serialize` under #[cfg(test)] in this crate's test harness —
// which IS this harness, so technically we could. Doing it manually
// keeps the round-trip test independent of serde's serialization
// choices and exercises the loader's parser against output that
// closely mirrors what a human would type.
// ---------------------------------------------------------------------

fn serialize_inventory(inv: &InventoryFile) -> String {
    let mut out = String::new();

    for d in &inv.devices {
        out.push_str("[[device]]\n");
        out.push_str(&format!("id = \"{}\"\n", d.id));
        out.push_str(&format!("host = \"{}\"\n", d.host));
        out.push_str(&format!("port = {}\n", d.port));
        out.push_str(&format!("vendor = \"{}\"\n", d.vendor.as_str()));
        if let Some(g) = &d.group {
            out.push_str(&format!("group = \"{g}\"\n"));
        }
        if let Some(c) = &d.color {
            out.push_str(&format!("color = \"{c}\"\n"));
        }
        if let Some(j) = &d.jump_via {
            out.push_str(&format!("jump_via = \"{j}\"\n"));
        }
        if let Some(fa) = d.forward_agent {
            out.push_str(&format!("forward_agent = {fa}\n"));
        }
        out.push_str(&format!("auth = \"{}\"\n\n", d.auth));
    }

    for (name, p) in &inv.auth_profiles {
        out.push_str(&format!("[auth.{name}]\n"));
        out.push_str(&format!("username = \"{}\"\n", p.username));
        out.push_str(&format!("secret = {}\n\n", serialize_secret_ref(&p.secret)));
    }

    out
}

fn serialize_secret_ref(s: &SecretRef) -> String {
    match s {
        SecretRef::Keyring { key } => format!("{{ backend = \"keyring\", key = \"{key}\" }}"),
        SecretRef::SshAgent {
            public_key_fingerprint,
        } => match public_key_fingerprint {
            Some(fp) => format!("{{ backend = \"ssh_agent\", public_key_fingerprint = \"{fp}\" }}"),
            None => "{ backend = \"ssh_agent\" }".to_string(),
        },
        SecretRef::Op { reference } => {
            format!("{{ backend = \"op\", reference = \"{reference}\" }}")
        }
        SecretRef::Env { var } => format!("{{ backend = \"env\", var = \"{var}\" }}"),
        SecretRef::SshKey { path, passphrase } => {
            let path_s = path.to_string_lossy();
            match passphrase {
                Some(_) => unreachable!("strategy doesn't generate ssh_key with passphrase"),
                None => format!("{{ backend = \"ssh_key\", path = \"{path_s}\" }}"),
            }
        }
        SecretRef::EncryptedFile { path } => {
            format!(
                "{{ backend = \"encrypted_file\", path = \"{}\" }}",
                path.to_string_lossy()
            )
        }
        SecretRef::Prompt => "{ backend = \"prompt\" }".to_string(),
    }
}

// ---------------------------------------------------------------------
// Round-trip property.
// ---------------------------------------------------------------------

fn roundtrip_via_loader(inv: &InventoryFile) {
    let serialized = serialize_inventory(inv);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    std::fs::write(&path, serialized.as_bytes()).unwrap();

    let parsed = load(&path).expect("loader accepts our generated TOML");

    // Devices: same length, same field-by-field equality.
    assert_eq!(parsed.devices.len(), inv.devices.len(), "device count");
    for (a, b) in parsed.devices.iter().zip(inv.devices.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.host, b.host);
        assert_eq!(a.port, b.port);
        assert_eq!(a.vendor, b.vendor);
        assert_eq!(a.group, b.group);
        assert_eq!(a.color, b.color);
        assert_eq!(a.auth, b.auth);
        assert_eq!(a.jump_via, b.jump_via);
        assert_eq!(a.forward_agent, b.forward_agent);
    }

    // Auth profiles: same key set, same values (BTreeMap order stable).
    assert_eq!(parsed.auth_profiles.len(), inv.auth_profiles.len());
    let parsed_keys: BTreeMap<_, _> = parsed
        .auth_profiles
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let original_keys: BTreeMap<_, _> = inv
        .auth_profiles
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    for k in original_keys.keys() {
        assert!(parsed_keys.contains_key(k), "missing auth profile {k}");
        assert_eq!(parsed_keys[k].username, original_keys[k].username);
        assert_eq!(parsed_keys[k].secret, original_keys[k].secret);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn random_valid_inventory_round_trips(inv in arb_inventory()) {
        roundtrip_via_loader(&inv);
    }
}
