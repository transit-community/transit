//! Inventory → CSV export — the reverse of [`crate::import::csv`], sharing
//! its exact column contract so a Transit-exported CSV re-imports cleanly
//! (`name,host,port,username,vendor,group,key_path`).
//!
//! **Pure**: no I/O, no Tauri, no async. The caller (a Tauri command)
//! reads the parsed inventory and hands in an [`InventoryFile`]; this
//! module serializes it to a CSV string that the command writes to disk.
//!
//! **Rule 1 (no secret bytes):** the CSV carries only usernames, key-file
//! *paths*, and inventory metadata — never a credential value. There is
//! deliberately no password column (the importer has none either), and a
//! key passphrase (`SecretRef::SshKey.passphrase`, itself a nested
//! reference) is never written. Every backend other than an on-disk
//! `ssh_key` contributes an empty `key_path`, so no secret can leak
//! through this path even as the backend set grows.

use crate::inventory::{InventoryFile, SecretRef};

/// Canonical export column order. Matches the header the CSV importer
/// recognizes (`crate::import::csv`), so `export → import` is a faithful
/// round-trip for every field the importer reads.
pub const CSV_HEADER: [&str; 7] = [
    "name", "host", "port", "username", "vendor", "group", "key_path",
];

/// Failure serializing the inventory to CSV. In practice the in-memory
/// `csv::Writer<Vec<u8>>` never errors on write/flush and the bytes are
/// always valid UTF-8 (every field is), but the API surfaces these rather
/// than panicking.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("CSV serialization error: {0}")]
    Csv(String),
    #[error("CSV output was not valid UTF-8: {0}")]
    Utf8(String),
}

/// Serialize every device in `inv` to an import-compatible CSV string.
///
/// For each device, `username` and `key_path` are resolved from the
/// referenced auth profile (`inv.auth_profiles[device.auth]`): the
/// username verbatim, and `key_path` ONLY when the profile's secret is an
/// on-disk [`SecretRef::SshKey`] (its `path` — never the nested
/// passphrase). All other backends leave `key_path` empty. A device whose
/// `auth` doesn't resolve exports with an empty username + key_path
/// (defensive; the loader normally guarantees the reference resolves).
///
/// Device order is preserved from `inv.devices` so the output is stable.
pub fn connections_to_csv(inv: &InventoryFile) -> Result<String, ExportError> {
    let mut wtr = ::csv::Writer::from_writer(Vec::new());
    wtr.write_record(CSV_HEADER)
        .map_err(|e| ExportError::Csv(e.to_string()))?;

    for device in &inv.devices {
        let profile = inv.auth_profiles.get(&device.auth);
        let username = profile.map(|p| p.username.as_str()).unwrap_or("");
        // key_path is a file-path *reference*, never a secret. Only the
        // ssh_key backend has one; the nested passphrase is intentionally
        // dropped (it is itself a SecretRef and must not be exported).
        let key_path = profile
            .and_then(|p| match &p.secret {
                SecretRef::SshKey { path, .. } => Some(path.to_string_lossy().into_owned()),
                _ => None,
            })
            .unwrap_or_default();

        // Owned temporaries so every record cell is a `&str` (a
        // write_record array must be homogeneous).
        let port = device.port.to_string();
        let group = device.group.as_deref().unwrap_or("");

        wtr.write_record([
            device.id.as_str(),
            device.host.as_str(),
            port.as_str(),
            username,
            device.vendor.as_str(),
            group,
            key_path.as_str(),
        ])
        .map_err(|e| ExportError::Csv(e.to_string()))?;
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| ExportError::Csv(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| ExportError::Utf8(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{parse, ImportSource};
    use crate::inventory::{AuthProfile, Device, SecretRef, Vendor};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn device(
        id: &str,
        host: &str,
        port: u16,
        vendor: Vendor,
        group: Option<&str>,
        auth: &str,
    ) -> Device {
        Device {
            id: id.into(),
            host: host.into(),
            port,
            vendor,
            group: group.map(String::from),
            color: None,
            tags: Vec::new(),
            auth: auth.into(),
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

    fn inv(devices: Vec<Device>, profiles: Vec<(&str, AuthProfile)>) -> InventoryFile {
        InventoryFile {
            devices,
            auth_profiles: profiles
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect::<BTreeMap<_, _>>(),
            groups: Vec::new(),
            api_sessions: Vec::new(),
        }
    }

    #[test]
    fn header_is_the_canonical_import_order() {
        let csv = connections_to_csv(&inv(vec![], vec![])).unwrap();
        // `lines()` strips the trailing \r (csv writes CRLF), so this
        // compares the logical header regardless of line terminator.
        assert_eq!(
            csv.lines().next(),
            Some("name,host,port,username,vendor,group,key_path")
        );
    }

    #[test]
    fn round_trips_through_the_importer() {
        let profiles = vec![
            (
                "key-profile",
                AuthProfile {
                    username: "netops".into(),
                    secret: SecretRef::SshKey {
                        path: PathBuf::from("/home/alice/.ssh/id_ed25519"),
                        passphrase: None,
                    },
                },
            ),
            (
                "pw-profile",
                AuthProfile {
                    username: "admin".into(),
                    secret: SecretRef::Keyring {
                        key: "lab-pw".into(),
                    },
                },
            ),
        ];
        let devices = vec![
            device(
                "core",
                "10.0.0.1",
                2222,
                Vendor::Junos,
                Some("Lab/Junos"),
                "key-profile",
            ),
            device("edge", "10.0.0.2", 22, Vendor::CiscoIos, None, "pw-profile"),
        ];
        let csv = connections_to_csv(&inv(devices, profiles)).unwrap();

        let parsed = parse(ImportSource::Csv, &csv).expect("export re-imports cleanly");
        assert_eq!(parsed.connections.len(), 2);

        let core = &parsed.connections[0];
        assert_eq!(core.source_name, "core");
        assert_eq!(core.host, "10.0.0.1");
        assert_eq!(core.port, 2222);
        assert_eq!(core.username.as_deref(), Some("netops"));
        assert_eq!(core.vendor_hint.as_deref(), Some("junos"));
        assert_eq!(core.group_path.as_deref(), Some("Lab/Junos"));
        assert_eq!(
            core.key_path.as_deref(),
            Some(PathBuf::from("/home/alice/.ssh/id_ed25519").as_path())
        );

        let edge = &parsed.connections[1];
        assert_eq!(edge.source_name, "edge");
        assert_eq!(edge.port, 22);
        assert_eq!(edge.username.as_deref(), Some("admin"));
        assert_eq!(edge.vendor_hint.as_deref(), Some("cisco_ios"));
        assert!(edge.group_path.is_none());
        // A password (keyring) profile exports NO key_path.
        assert!(edge.key_path.is_none());
    }

    #[test]
    fn never_exports_a_key_passphrase_or_any_secret_reference() {
        // An ssh_key whose passphrase itself lives in the keyring: the
        // key PATH is a safe reference and must export; the passphrase
        // reference must NOT appear anywhere in the output.
        let profiles = vec![(
            "key-with-pass",
            AuthProfile {
                username: "root".into(),
                secret: SecretRef::SshKey {
                    path: PathBuf::from("/keys/id_rsa"),
                    passphrase: Some(Box::new(SecretRef::Keyring {
                        key: "PASSPHRASE-REF-MUST-NOT-LEAK".into(),
                    })),
                },
            },
        )];
        let devices = vec![device(
            "r1",
            "192.0.2.1",
            22,
            Vendor::Junos,
            None,
            "key-with-pass",
        )];
        let csv = connections_to_csv(&inv(devices, profiles)).unwrap();

        assert!(csv.contains("/keys/id_rsa"), "the key path should export");
        assert!(
            !csv.contains("PASSPHRASE-REF-MUST-NOT-LEAK"),
            "a nested passphrase reference must never be exported: {csv}"
        );
    }

    #[test]
    fn non_key_backends_export_empty_key_path() {
        // Every backend that isn't ssh_key leaves key_path blank, so no
        // backend-specific reference (op:// path, env var, keyring key,
        // agent fingerprint, age-file path) can leak into the CSV.
        let profiles = vec![
            (
                "op",
                AuthProfile {
                    username: "u1".into(),
                    secret: SecretRef::Op {
                        reference: "op://Vault/Item/field".into(),
                    },
                },
            ),
            (
                "env",
                AuthProfile {
                    username: "u2".into(),
                    secret: SecretRef::Env {
                        var: "SECRET_ENV_VAR".into(),
                    },
                },
            ),
            (
                "agent",
                AuthProfile {
                    username: "u3".into(),
                    secret: SecretRef::SshAgent {
                        public_key_fingerprint: Some("SHA256:deadbeef".into()),
                    },
                },
            ),
            (
                "encfile",
                AuthProfile {
                    username: "u4".into(),
                    secret: SecretRef::EncryptedFile {
                        path: PathBuf::from("/enc/creds.age"),
                    },
                },
            ),
        ];
        let devices = vec![
            device("a", "h1", 22, Vendor::Linux, None, "op"),
            device("b", "h2", 22, Vendor::Linux, None, "env"),
            device("c", "h3", 22, Vendor::Linux, None, "agent"),
            device("d", "h4", 22, Vendor::Linux, None, "encfile"),
        ];
        let csv = connections_to_csv(&inv(devices, profiles)).unwrap();

        for leak in [
            "op://Vault/Item/field",
            "SECRET_ENV_VAR",
            "SHA256:deadbeef",
            "/enc/creds.age",
        ] {
            assert!(!csv.contains(leak), "reference '{leak}' must not export");
        }
        // Every data row ends with an empty key_path cell.
        for line in csv.lines().skip(1) {
            assert!(
                line.ends_with(','),
                "row should end with empty key_path: {line}"
            );
        }
    }

    #[test]
    fn custom_and_unknown_vendors_round_trip() {
        let profiles = vec![(
            "p",
            AuthProfile {
                username: "u".into(),
                secret: SecretRef::SshAgent {
                    public_key_fingerprint: None,
                },
            },
        )];
        let devices = vec![
            device(
                "custom-dev",
                "h1",
                22,
                Vendor::Custom("paloalto_custom".into()),
                None,
                "p",
            ),
            device("unknown-dev", "h2", 22, Vendor::Unknown, None, "p"),
        ];
        let csv = connections_to_csv(&inv(devices, profiles)).unwrap();
        let parsed = parse(ImportSource::Csv, &csv).unwrap();
        assert_eq!(
            parsed.connections[0].vendor_hint.as_deref(),
            Some("paloalto_custom")
        );
        assert_eq!(
            parsed.connections[1].vendor_hint.as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn dangling_auth_reference_exports_blanks_not_a_panic() {
        // A device pointing at a missing profile must export cleanly with
        // empty username + key_path rather than panicking.
        let devices = vec![device(
            "orphan",
            "h",
            22,
            Vendor::Junos,
            None,
            "does-not-exist",
        )];
        let csv = connections_to_csv(&inv(devices, vec![])).unwrap();
        let parsed = parse(ImportSource::Csv, &csv).unwrap();
        assert_eq!(parsed.connections.len(), 1);
        assert_eq!(parsed.connections[0].source_name, "orphan");
        assert!(parsed.connections[0].username.is_none());
        assert!(parsed.connections[0].key_path.is_none());
    }

    #[test]
    fn embedded_commas_are_quoted_and_survive_round_trip() {
        // A group name with a comma must not corrupt the CSV — the csv
        // crate quotes it, and the importer unquotes it.
        let profiles = vec![(
            "p",
            AuthProfile {
                username: "u".into(),
                secret: SecretRef::Keyring { key: "k".into() },
            },
        )];
        let devices = vec![device(
            "d",
            "h",
            22,
            Vendor::Junos,
            Some("Prod, US/Core"),
            "p",
        )];
        let csv = connections_to_csv(&inv(devices, profiles)).unwrap();
        let parsed = parse(ImportSource::Csv, &csv).unwrap();
        assert_eq!(
            parsed.connections[0].group_path.as_deref(),
            Some("Prod, US/Core")
        );
    }
}
