//! End-to-end import corpus: parse synthetic exports → dedup identities
//! → map to inventory types → feed the REAL mutator + loader → assert the
//! output is loader-valid. This is the guarantee that matters: whatever
//! the importer produces must round-trip through `transit.toml`.
//!
//! All samples here are synthetic (fake hosts/users, no real ciphertext).
//! A real SecureCRT export used as a private reference fixture
//! is reference-only and never committed.

use std::collections::{HashMap, HashSet};

use transit_core::import::{
    analyze, identity_key, parse, sanitize_id, to_auth_profile, to_device, ImportSource,
};
use transit_core::inventory::load;
use transit_core::inventory::mutator::{add_auth_profile, add_device, write_atomic, DocumentMut};

const SSH_CONFIG: &str = "\
Host core-rtr
    HostName 10.0.0.1
    User netops
    Port 2222
    IdentityFile /keys/id_ed25519

Host *
    User ignored

Host edge
    HostName 10.0.0.2
    ProxyJump core-rtr
";

const CSV: &str = "\
name,host,port,username,vendor,group,key_path
core,10.0.0.1,2222,netops,junos,Lab/Junos,/keys/id
edge,10.0.0.2,,root,,,
dup,10.0.0.1,,root,,,
";

const SECURECRT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Credentials">
    <key name="shared">
      <string name="Username">ubuntu</string>
      <string name="SSH2 Authentications V2">publickey</string>
      <string name="Identity Filename V2">/keys/shared.pub</string>
    </key>
  </key>
  <key name="Sessions">
    <key name="Default"><string name="Hostname">skip</string><string name="Protocol Name">SSH2</string></key>
    <key name="alpha">
      <string name="Hostname">10.1.0.1</string>
      <dword name="[SSH2] Port">6922</dword>
      <string name="Username">root</string>
      <string name="Protocol Name">SSH2</string>
      <string name="SSH2 Authentications V2">password</string>
      <string name="Password V2">03:never-read</string>
    </key>
    <key name="Lab">
      <key name="beta">
        <string name="Hostname">10.1.0.2</string>
        <string name="Protocol Name">SSH2</string>
        <string name="Credential Title">shared</string>
      </key>
    </key>
  </key>
</VanDyke>"#;

const MTPUTTY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MTPutty version="1.0">
  <Servers>
    <Putty>
      <Node Type="0">
        <DisplayName>Lab</DisplayName>
        <Node Type="1">
          <DisplayName>vEX1</DisplayName>
          <ServerName>10.2.0.1</ServerName>
          <PuttyConType>4</PuttyConType>
          <Port>2222</Port>
          <UserName>admin</UserName>
          <Password>bmV2ZXItcmVhZA==</Password>
        </Node>
      </Node>
      <Node Type="1">
        <DisplayName>registry-only</DisplayName>
        <SavedSession>desert</SavedSession>
        <ServerName></ServerName>
        <CLParams>-load desert</CLParams>
      </Node>
      <Node Type="1">
        <DisplayName>keybox</DisplayName>
        <ServerName>10.2.0.3</ServerName>
        <Port>22</Port>
        <CLParams>-l netops -i C:\keys\lab.ppk</CLParams>
      </Node>
    </Putty>
  </Servers>
</MTPutty>"#;

const MOBAXTERM: &str = "\
[Bookmarks]
SubRep=
ImgNum=42
core-sw1=#109#0%10.3.0.1%22%admin%%-1%-1#0# #-1

[Bookmarks_1]
SubRep=Lab\\Core
ImgNum=41
vEX2=#109#0%10.3.0.2%2222%netops%%-1%-1%%%%%0%0%0%_CurrentDrive_:\\keys\\lab.ppk%%-1#0# #-1
rdp-box=#91#4%10.3.0.9%3389%admin#0# #-1
";

/// Map a parsed source through analyze + the mappers into a fresh
/// inventory document, exactly as the import command will: one auth
/// profile per deduped identity, profiles added before devices, device
/// ids made unique within the batch.
fn import_to_doc(source: ImportSource, text: &str) -> DocumentMut {
    let parsed = parse(source, text).expect("parse");
    let identities = analyze(&parsed.connections);

    let mut doc = DocumentMut::new();
    let mut profile_for: HashMap<String, String> = HashMap::new();
    for (i, identity) in identities.iter().enumerate() {
        let name = format!("imp-{}-{i}", sanitize_id(&identity.login, "user"));
        let profile = to_auth_profile(&identity.login, &identity.secret, &name);
        add_auth_profile(&mut doc, &name, &profile).expect("profile is loader-valid");
        profile_for.insert(identity.key.clone(), name);
    }

    let mut used: HashSet<String> = HashSet::new();
    for conn in &parsed.connections {
        let base = sanitize_id(&conn.source_name, &conn.host);
        let mut id = base.clone();
        let mut n = 2;
        while !used.insert(id.clone()) {
            id = format!("{base}-{n}");
            n += 1;
        }
        let profile = &profile_for[&identity_key(conn)];
        add_device(&mut doc, &to_device(conn, &id, profile)).expect("device is loader-valid");
    }
    doc
}

/// Write the doc, load it through the real validator, and assert every
/// device's auth reference resolves (the loader enforces this; we assert
/// to make the intent explicit and return the parsed inventory).
fn load_round_trip(doc: &DocumentMut) -> transit_core::inventory::InventoryFile {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    write_atomic(&path, &doc.to_string()).unwrap();
    let inv = load(&path).expect("import output must be loader-valid");
    for d in &inv.devices {
        assert!(
            inv.auth_profiles.contains_key(&d.auth),
            "device {} references missing auth {}",
            d.id,
            d.auth
        );
    }
    inv
}

#[test]
fn ssh_config_round_trips_through_loader() {
    let inv = load_round_trip(&import_to_doc(ImportSource::SshConfig, SSH_CONFIG));
    // `Host *` skipped → core-rtr + edge.
    let ids: HashSet<&str> = inv.devices.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, HashSet::from(["core-rtr", "edge"]));
    let core = inv.devices.iter().find(|d| d.id == "core-rtr").unwrap();
    assert_eq!(core.port, 2222);
    assert_eq!(core.vendor.as_str(), "unknown");
}

#[test]
fn csv_round_trips_and_dedupes_ids() {
    let inv = load_round_trip(&import_to_doc(ImportSource::Csv, CSV));
    assert_eq!(inv.devices.len(), 3);
    let core = inv.devices.iter().find(|d| d.id == "core").unwrap();
    assert_eq!(core.vendor.as_str(), "junos");
    assert_eq!(core.group.as_deref(), Some("Lab/Junos"));
}

#[test]
fn mtputty_round_trips_with_folders_and_clparams_fallbacks() {
    let inv = load_round_trip(&import_to_doc(ImportSource::MtPutty, MTPUTTY));
    // registry-only (PuTTY saved session) skipped → vEX1 + keybox.
    let ids: HashSet<&str> = inv.devices.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, HashSet::from(["vEX1", "keybox"]));
    let vex = inv.devices.iter().find(|d| d.id == "vEX1").unwrap();
    assert_eq!(vex.port, 2222);
    assert_eq!(vex.group.as_deref(), Some("Lab"));
    assert_eq!(vex.vendor.as_str(), "unknown");
    // keybox's login + key came from CLParams; profile is key-based.
    let keybox = inv.devices.iter().find(|d| d.id == "keybox").unwrap();
    assert_eq!(inv.auth_profiles[&keybox.auth].username, "netops");
}

#[test]
fn mobaxterm_round_trips_with_folders_and_key_path() {
    let inv = load_round_trip(&import_to_doc(ImportSource::MobaXterm, MOBAXTERM));
    // RDP session skipped → core-sw1 + vEX2.
    let ids: HashSet<&str> = inv.devices.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, HashSet::from(["core-sw1", "vEX2"]));
    let vex = inv.devices.iter().find(|d| d.id == "vEX2").unwrap();
    assert_eq!(vex.port, 2222);
    assert_eq!(vex.group.as_deref(), Some("Lab/Core"));
    assert_eq!(inv.auth_profiles[&vex.auth].username, "netops");
}

#[test]
fn securecrt_round_trips_with_folders_and_shared_credential() {
    let inv = load_round_trip(&import_to_doc(ImportSource::SecureCrt, SECURECRT));
    // Default skipped → alpha + beta.
    let ids: HashSet<&str> = inv.devices.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, HashSet::from(["alpha", "beta"]));
    let beta = inv.devices.iter().find(|d| d.id == "beta").unwrap();
    assert_eq!(beta.group.as_deref(), Some("Lab"));
    // beta resolved its username from the shared credential.
    assert_eq!(inv.auth_profiles[&beta.auth].username, "ubuntu");
}
