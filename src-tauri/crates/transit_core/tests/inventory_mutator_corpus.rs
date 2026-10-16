//! Integration tests for `transit_core::inventory::mutator`.
//!
//! Unit tests inside the module cover the per-call behavior. These
//! tests cover end-to-end flows that involve the filesystem and (in
//! one case) multiple threads — closer to how `commands.rs` will
//! drive the mutator from Tauri at runtime.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use transit_core::inventory::{
    load,
    mutator::{add_device, add_group, delete_group, set_device_group, write_atomic, DocumentMut},
    AuthProfile, Device, SecretRef, Vendor,
};

fn keyring_profile_text(name: &str, user: &str) -> String {
    format!(
        r#"
[auth.{name}]
username = "{user}"
secret = {{ backend = "keyring", key = "transit/{name}" }}
"#
    )
}

fn baseline_text() -> String {
    format!(
        r#"# Curated by Transit. Edits via the GUI are safe; manual edits stick.

[[device]]
id = "vEX1"
host = "192.0.2.35"
vendor = "junos"
group = "Lab/Junos"
auth = "lab-pw"
{}"#,
        keyring_profile_text("lab-pw", "alice")
    )
}

fn write_baseline(path: &Path) {
    write_atomic(path, &baseline_text()).unwrap();
}

fn make_device(idx: usize) -> Device {
    Device {
        id: format!("vEX{idx:03}"),
        host: format!("10.0.0.{idx}"),
        port: 22,
        vendor: Vendor::Junos,
        group: Some("Lab/Junos".to_string()),
        color: None,
        tags: Vec::new(),
        auth: "lab-pw".to_string(),
        syntax_highlighting: None,
        quick_copy_paste: None,
        font_family: None,
        font_size: None,
        bold_color: None,
        allow_weak_crypto: None,
        netbox_id: None,
        jump_via: None,
        forward_agent: None,
    }
}

#[test]
fn round_trip_ten_sequential_adds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_baseline(&path);

    for i in 0..10 {
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut doc: DocumentMut = raw.parse().unwrap();
        add_device(&mut doc, &make_device(i + 100)).unwrap();
        write_atomic(&path, &doc.to_string()).unwrap();
    }

    let parsed = load(&path).expect("final state parses");
    assert_eq!(parsed.devices.len(), 11); // baseline + 10 adds.
    for i in 0..10 {
        assert!(
            parsed
                .devices
                .iter()
                .any(|d| d.id == format!("vEX{:03}", i + 100)),
            "missing vEX{}",
            i + 100
        );
    }
}

#[test]
fn comments_survive_repeated_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_baseline(&path);

    for i in 0..5 {
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut doc: DocumentMut = raw.parse().unwrap();
        add_device(&mut doc, &make_device(i + 200)).unwrap();
        write_atomic(&path, &doc.to_string()).unwrap();
    }

    let final_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        final_text.contains("# Curated by Transit"),
        "leading comment should survive 5 round-trips: {final_text}"
    );
}

#[test]
fn write_atomic_leaves_no_orphan_tempfiles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_atomic(&path, "v1").unwrap();
    write_atomic(&path, "v2").unwrap();
    write_atomic(&path, "v3").unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "expected one file, got: {entries:?}");
}

#[test]
fn concurrent_serialized_adds_all_land() {
    // The runtime invariant (set up in commands.rs Task #37) is that
    // every write goes through a single async write-lock. This test
    // simulates that invariant with std::sync::Mutex + threads, since
    // transit_core has no async runtime. The point is to verify that
    // under serialized read-modify-write, no add is lost.
    const N: usize = 16;
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("transit.toml"));
    write_baseline(&path);

    let lock = Arc::new(Mutex::new(()));
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let path = Arc::clone(&path);
            let lock = Arc::clone(&lock);
            thread::spawn(move || {
                let _guard = lock.lock().unwrap();
                let raw = std::fs::read_to_string(path.as_path()).unwrap();
                let mut doc: DocumentMut = raw.parse().unwrap();
                add_device(&mut doc, &make_device(i + 500)).unwrap();
                write_atomic(path.as_path(), &doc.to_string()).unwrap();
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let parsed = load(path.as_path()).expect("final state parses");
    assert_eq!(parsed.devices.len(), N + 1);
    for i in 0..N {
        let want = format!("vEX{:03}", i + 500);
        assert!(
            parsed.devices.iter().any(|d| d.id == want),
            "missing {want}"
        );
    }
}

#[test]
fn add_then_load_through_full_validator() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_baseline(&path);

    let raw = std::fs::read_to_string(&path).unwrap();
    let mut doc: DocumentMut = raw.parse().unwrap();
    let new_device = Device {
        id: "ssh-agent-host".to_string(),
        host: "10.10.10.1".to_string(),
        port: 22,
        vendor: Vendor::AristaEos,
        group: None,
        color: Some("blue".to_string()),
        tags: vec!["prod".to_string(), "core".to_string()],
        auth: "agent-only".to_string(),
        syntax_highlighting: None,
        quick_copy_paste: None,
        font_family: Some("JetBrains Mono".to_string()),
        font_size: Some(15),
        bold_color: Some(true),
        allow_weak_crypto: None,
        netbox_id: Some("1234".to_string()),
        jump_via: None,
        // v6.5.0 — exercised through the full validator on the write
        // path; the jump_via write→load pair lives in mutator.rs tests
        // (a Some value here would need a second device to reference).
        forward_agent: Some(true),
    };
    let new_profile = AuthProfile {
        username: "ops".to_string(),
        secret: SecretRef::SshAgent {
            public_key_fingerprint: Some("SHA256:abc".to_string()),
        },
    };

    transit_core::inventory::mutator::add_auth_profile(&mut doc, "agent-only", &new_profile)
        .unwrap();
    add_device(&mut doc, &new_device).unwrap();
    write_atomic(&path, &doc.to_string()).unwrap();

    let parsed = load(&path).expect("must round-trip through real loader");
    assert!(parsed.auth_profiles.contains_key("agent-only"));
    assert!(parsed.devices.iter().any(|d| d.id == "ssh-agent-host"));
    // Exercises build_device_table's color-write branch (Phase 1): the
    // proptest covers loader *parsing*, but only the mutator writes via
    // build_device_table, so assert the value survives write → load here.
    assert_eq!(
        parsed
            .devices
            .iter()
            .find(|d| d.id == "ssh-agent-host")
            .and_then(|d| d.color.as_deref()),
        Some("blue"),
    );
    // v4.1.0 — the appearance fields survive build_device_table's write
    // branches (font_family/font_size/bold_color) → loader parse.
    {
        let dev = parsed
            .devices
            .iter()
            .find(|d| d.id == "ssh-agent-host")
            .unwrap();
        assert_eq!(dev.font_family.as_deref(), Some("JetBrains Mono"));
        assert_eq!(dev.font_size, Some(15));
        assert_eq!(dev.bold_color, Some(true));
    }
    // Tags survive the mutator's array write + loader parse.
    assert_eq!(
        parsed
            .devices
            .iter()
            .find(|d| d.id == "ssh-agent-host")
            .map(|d| d.tags.clone())
            .unwrap_or_default(),
        vec!["prod".to_string(), "core".to_string()],
    );
    let agent = &parsed.auth_profiles["agent-only"];
    match &agent.secret {
        SecretRef::SshAgent {
            public_key_fingerprint,
        } => assert_eq!(public_key_fingerprint.as_deref(), Some("SHA256:abc")),
        other => panic!("expected SshAgent, got {other:?}"),
    }
}

#[test]
fn group_lifecycle_round_trips_through_full_validator() {
    // Compose the whole GUI flow: create an empty group, drop a device
    // into it, move the device back out, confirm the empty group
    // survives, then delete it (reparenting). Every step persists +
    // reloads through the real loader.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_baseline(&path);
    let mut doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();

    // Empty group created → persists.
    add_group(&mut doc, "Lab/Staging").unwrap();
    write_atomic(&path, &doc.to_string()).unwrap();
    assert!(load(&path)
        .unwrap()
        .groups
        .contains(&"Lab/Staging".to_string()));

    // Drop the baseline device vEX1 into it, then back out.
    set_device_group(&mut doc, "vEX1", Some("Lab/Staging")).unwrap();
    set_device_group(&mut doc, "vEX1", Some("Lab/Junos")).unwrap();
    write_atomic(&path, &doc.to_string()).unwrap();
    let parsed = load(&path).unwrap();
    assert_eq!(
        parsed
            .devices
            .iter()
            .find(|d| d.id == "vEX1")
            .unwrap()
            .group
            .as_deref(),
        Some("Lab/Junos")
    );
    // The empty group still exists despite no device living in it.
    assert!(parsed.groups.contains(&"Lab/Staging".to_string()));

    // Delete it → reparents to "Lab" (here: just drops the leaf, no
    // devices under it), registry entry collapses to "Lab".
    delete_group(&mut doc, "Lab/Staging").unwrap();
    write_atomic(&path, &doc.to_string()).unwrap();
    let parsed = load(&path).unwrap();
    assert!(!parsed.groups.contains(&"Lab/Staging".to_string()));
    assert!(parsed.groups.contains(&"Lab".to_string()));
}
