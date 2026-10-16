//! Bulk-import parsing for external SSH-client configs (ssh_config, CSV,
//! SecureCRT, MTPuTTY, MobaXterm).
//!
//! **Pure**: no I/O, no Tauri, no async. The caller (a Tauri command)
//! reads the file bytes and hands in `&str`; this module parses,
//! normalizes, and dedups into a format-agnostic [`ImportedConnection`]
//! IR, then maps that IR onto inventory [`Device`] / [`AuthProfile`]
//! values.
//!
//! **Rule 1 (no secret bytes):** every type here carries only usernames,
//! key-file *paths*, and references — never a credential value. SecureCRT
//! `Password V2` ciphertext is never read (see `securecrt.rs`).

mod csv;
mod mobaxterm;
mod mtputty;
pub mod netbox;
mod securecrt;
mod ssh_config;

use std::collections::HashMap;
use std::path::PathBuf;

use crate::inventory::{AuthProfile, Device, SecretRef, Vendor};

pub use csv::parse_csv;
pub use mobaxterm::parse_mobaxterm;
pub use mtputty::parse_mtputty;
pub use securecrt::parse_securecrt;
pub use ssh_config::parse_ssh_config;

/// Which external format a blob of text is. Deserialized from the
/// `preview_import` IPC argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    SshConfig,
    Csv,
    SecureCrt,
    MtPutty,
    MobaXterm,
}

/// A hard parse failure. `ssh_config` never produces one (best-effort
/// scan); CSV, SecureCRT, MTPuTTY, and MobaXterm can (malformed
/// structure).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("CSV parse error: {0}")]
    Csv(String),
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("nothing importable found: {0}")]
    Empty(String),
}

/// Inferred authentication method — drives the suggested [`SecretRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum AuthKind {
    /// publickey with an explicit key-file path.
    PublicKeyFile,
    /// publickey, no explicit path (agent / global key).
    Agent,
    /// password / keyboard-interactive — the user enrolls the secret
    /// later via `enroll_secret`.
    Password,
    /// Couldn't tell; treated like `Password` but flagged for the user.
    Unknown,
}

/// One parsed connection, format-agnostic. Carries NO secret bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ImportedConnection {
    /// Source-format name (ssh_config `Host` alias, CSV name/id column,
    /// SecureCRT session key). Sanitized to a [`Device::id`] later.
    pub source_name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// `/`-separated folder path (SecureCRT folder chain, CSV `group`).
    pub group_path: Option<String>,
    /// ssh_config `ProxyJump` / SecureCRT `Firewall Name` (≠ `None`).
    /// Surfaced to the user; not auto-resolved to a device in v1.
    pub jump_host: Option<String>,
    /// Key-file path (ssh_config `IdentityFile`, SecureCRT
    /// `Identity Filename V2`). `~` already expanded.
    pub key_path: Option<PathBuf>,
    /// Vendor tag hint (CSV `vendor` column only). Routed through
    /// [`Vendor::from_tag`]; absent ⇒ [`Vendor::Unknown`].
    pub vendor_hint: Option<String>,
    pub auth_kind: AuthKind,
    /// SecureCRT `Credential Title` — a dedup link to a shared
    /// credential. The session's username/key are resolved from the
    /// named credential during parsing, so dedup keys on this when set.
    pub credential_link: Option<String>,
}

/// A parser's output: the connections plus any non-fatal notes (skipped
/// wildcard blocks, unfollowed includes, non-SSH sessions, …).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ParsedImport {
    pub connections: Vec<ImportedConnection>,
    pub warnings: Vec<String>,
}

/// Parse a source blob into the normalized IR.
pub fn parse(source: ImportSource, text: &str) -> Result<ParsedImport, ImportError> {
    match source {
        ImportSource::SshConfig => Ok(parse_ssh_config(text)),
        ImportSource::Csv => parse_csv(text),
        ImportSource::SecureCrt => parse_securecrt(text),
        ImportSource::MtPutty => parse_mtputty(text),
        ImportSource::MobaXterm => parse_mobaxterm(text),
    }
}

/// A suggested credential reference for an identity — references only,
/// never a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum SuggestedSecret {
    /// publickey + key path → [`SecretRef::SshKey`].
    SshKey { path: PathBuf },
    /// publickey, no path → [`SecretRef::SshAgent`].
    Agent,
    /// password → [`SecretRef::Keyring`]; the user enrolls the value
    /// later via `enroll_secret`.
    KeyringEnrollLater,
}

/// A deduped login identity across the parsed connections. The wizard's
/// credential step renders one of these per distinct login.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ImportIdentity {
    /// Stable dedup key; also recomputable per-connection via
    /// [`identity_key`] so a grid row maps back to its identity.
    pub key: String,
    /// Display login (the username, or a placeholder when absent).
    pub login: String,
    /// How many connections share this identity.
    pub count: usize,
    pub auth_kind: AuthKind,
    pub secret: SuggestedSecret,
}

/// Stable dedup key for a connection's login identity.
///
/// A SecureCRT session naming a shared credential dedups by that
/// credential; everything else dedups by `(username, key file)`.
///
/// `auth_kind` is deliberately NOT in the key: SecureCRT records a
/// per-session *ordering* of auth methods (`publickey,password,…`), so
/// the same real login splits into spurious "agent" vs "password"
/// identities if keyed on it. A login keys to one identity unless it
/// uses a different key *file* (which is a genuinely different
/// credential — e.g. one user with two SSH keys across host groups).
pub fn identity_key(conn: &ImportedConnection) -> String {
    if let Some(link) = &conn.credential_link {
        return format!("cred:{link}");
    }
    let user = conn.username.as_deref().unwrap_or("");
    let key = conn
        .key_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("user:{user}|{key}")
}

/// Dedup connections into login identities, preserving first-seen order.
pub fn analyze(connections: &[ImportedConnection]) -> Vec<ImportIdentity> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, ImportIdentity> = HashMap::new();
    for conn in connections {
        let key = identity_key(conn);
        if let Some(existing) = map.get_mut(&key) {
            existing.count += 1;
        } else {
            order.push(key.clone());
            map.insert(
                key.clone(),
                ImportIdentity {
                    key,
                    login: conn
                        .username
                        .clone()
                        .unwrap_or_else(|| "(default user)".to_string()),
                    count: 1,
                    auth_kind: conn.auth_kind,
                    secret: suggest_secret(conn),
                },
            );
        }
    }
    order.into_iter().filter_map(|k| map.remove(&k)).collect()
}

fn suggest_secret(conn: &ImportedConnection) -> SuggestedSecret {
    match (conn.auth_kind, &conn.key_path) {
        (AuthKind::PublicKeyFile, Some(path)) => SuggestedSecret::SshKey { path: path.clone() },
        (AuthKind::Agent, _) | (AuthKind::PublicKeyFile, None) => SuggestedSecret::Agent,
        (AuthKind::Password | AuthKind::Unknown, _) => SuggestedSecret::KeyringEnrollLater,
    }
}

/// Map an [`ImportedConnection`] + a resolved id + auth-profile name to a
/// [`Device`]. Does NOT enforce id uniqueness — the command's collision
/// check and the mutator own that.
pub fn to_device(conn: &ImportedConnection, id: &str, auth_profile_name: &str) -> Device {
    Device {
        id: id.to_string(),
        host: conn.host.clone(),
        port: conn.port,
        vendor: conn
            .vendor_hint
            .as_deref()
            .map_or(Vendor::Unknown, Vendor::from_tag),
        group: conn.group_path.clone(),
        color: None,
        tags: Vec::new(),
        auth: auth_profile_name.to_string(),
        syntax_highlighting: None,
        quick_copy_paste: None,
        font_family: None,
        font_size: None,
        bold_color: None,
        allow_weak_crypto: None,
        // File imports are one-shot; only the NetBox sync (import::netbox)
        // stamps an external match key.
        netbox_id: None,
        // `ImportedConnection.jump_host` is a raw hostname/label from the
        // source file; the import UI resolves it against the in-batch
        // devices and writes the resolved reference onto `DeviceInput`
        // directly (v6.5.0). Unresolved values are dropped with a
        // per-row warning, never guessed here.
        jump_via: None,
        forward_agent: None,
    }
}

/// Map a username + suggested secret to an [`AuthProfile`]. For a
/// password profile the keyring key is the profile name (the user
/// enrolls the value afterwards via `enroll_secret`).
pub fn to_auth_profile(
    username: &str,
    secret: &SuggestedSecret,
    profile_name: &str,
) -> AuthProfile {
    let secret = match secret {
        SuggestedSecret::SshKey { path } => SecretRef::SshKey {
            path: path.clone(),
            passphrase: None,
        },
        SuggestedSecret::Agent => SecretRef::SshAgent {
            public_key_fingerprint: None,
        },
        SuggestedSecret::KeyringEnrollLater => SecretRef::Keyring {
            key: profile_name.to_string(),
        },
    };
    AuthProfile {
        username: username.to_string(),
        secret,
    }
}

/// Sanitize a source name into a valid [`Device::id`] body
/// (`^[A-Za-z0-9_-]+$`). Runs of other characters collapse to `-`; falls
/// back to a host-derived name, then a constant, when nothing survives.
pub fn sanitize_id(source_name: &str, host: &str) -> String {
    let from_name = sanitize_token(source_name);
    if !from_name.is_empty() {
        return from_name;
    }
    let from_host = sanitize_token(host);
    if !from_host.is_empty() {
        return from_host;
    }
    "device".to_string()
}

fn sanitize_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Decode import-file bytes: UTF-8 when valid, otherwise Windows-1252.
///
/// MobaXterm writes `.mxtsessions` / `.mobaconf` / `MobaXterm.ini` in
/// Windows-1252 (per Mobatek's own format notes), and other Windows
/// terminal exports follow suit — an accented session name would fail a
/// strict `read_to_string`. Windows-1252 decodes exactly and infallibly:
/// 0x00–0x7F is ASCII, 0xA0–0xFF matches the Unicode code point, and the
/// 0x80–0x9F range uses the table below (unmapped bytes → U+FFFD).
pub fn decode_import_bytes(bytes: &[u8]) -> String {
    match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => e
            .as_bytes()
            .iter()
            .map(|&b| match b {
                0x00..=0x7F | 0xA0..=0xFF => b as char,
                _ => CP1252_80_9F[(b - 0x80) as usize],
            })
            .collect(),
    }
}

/// Windows-1252 0x80–0x9F → Unicode (the only range that differs from
/// Latin-1). `\u{FFFD}` marks the five unassigned bytes.
const CP1252_80_9F: [char; 32] = [
    '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}', '\u{017D}', '\u{FFFD}',
    '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
];

/// Expand a leading `~` against `$HOME` / `%USERPROFILE%`. Pure except
/// for the env read (transit_core already reads env via the log filter).
/// Non-`~` paths pass through verbatim.
pub(crate) fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(
        name: &str,
        user: Option<&str>,
        kind: AuthKind,
        key: Option<&str>,
    ) -> ImportedConnection {
        ImportedConnection {
            source_name: name.to_string(),
            host: format!("{name}.example.net"),
            port: 22,
            username: user.map(String::from),
            group_path: None,
            jump_host: None,
            key_path: key.map(PathBuf::from),
            vendor_hint: None,
            auth_kind: kind,
            credential_link: None,
        }
    }

    #[test]
    fn decode_import_bytes_utf8_and_cp1252() {
        // Valid UTF-8 passes through untouched.
        assert_eq!(decode_import_bytes("héllo".as_bytes()), "héllo");
        // Windows-1252: é = 0xE9 (Latin-1 range), € = 0x80, ' = 0x92.
        assert_eq!(
            decode_import_bytes(&[b'r', 0xE9, b's', b'e', b'a', b'u', b' ', 0x80, 0x92]),
            "réseau €’"
        );
        // Unassigned CP1252 byte → U+FFFD, never a panic.
        assert_eq!(decode_import_bytes(&[0x81]), "\u{FFFD}");
    }

    #[test]
    fn sanitize_id_cleans_and_falls_back() {
        assert_eq!(sanitize_id("vEX1", "h"), "vEX1");
        assert_eq!(sanitize_id("monad-mn-nr", "h"), "monad-mn-nr");
        assert_eq!(
            sanitize_id("jguard.juicystake.io", "h"),
            "jguard-juicystake-io"
        );
        assert_eq!(sanitize_id("BTR-SUI-2831 (dead)", "h"), "BTR-SUI-2831-dead");
        assert_eq!(sanitize_id("   ", "10.0.0.1"), "10-0-0-1");
        assert_eq!(sanitize_id("", ""), "device");
    }

    #[test]
    fn analyze_dedups_by_identity_preserving_order() {
        let conns = vec![
            conn("a", Some("root"), AuthKind::Password, None),
            conn("b", Some("ubuntu"), AuthKind::PublicKeyFile, Some("/k/id")),
            conn("c", Some("root"), AuthKind::Password, None), // dup of a
            conn("d", Some("ubuntu"), AuthKind::PublicKeyFile, Some("/k/id")), // dup of b
        ];
        let ids = analyze(&conns);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].login, "root");
        assert_eq!(ids[0].count, 2);
        assert_eq!(ids[0].secret, SuggestedSecret::KeyringEnrollLater);
        assert_eq!(ids[1].login, "ubuntu");
        assert_eq!(ids[1].count, 2);
        assert_eq!(
            ids[1].secret,
            SuggestedSecret::SshKey {
                path: PathBuf::from("/k/id")
            }
        );
    }

    #[test]
    fn credential_link_dedups_across_usernames() {
        let mut a = conn("a", Some("ubuntu"), AuthKind::Agent, None);
        let mut b = conn("b", Some("ubuntu"), AuthKind::Agent, None);
        a.credential_link = Some("ec2".to_string());
        b.credential_link = Some("ec2".to_string());
        let ids = analyze(&[a, b]);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].key, "cred:ec2");
        assert_eq!(ids[0].count, 2);
    }

    #[test]
    fn to_device_defaults_vendor_unknown_and_maps_fields() {
        let mut c = conn("vEX1", Some("admin"), AuthKind::Password, None);
        c.group_path = Some("Lab/Junos".to_string());
        let d = to_device(&c, "vEX1", "admin-pw");
        assert_eq!(d.id, "vEX1");
        assert_eq!(d.host, "vEX1.example.net");
        assert_eq!(d.vendor, Vendor::Unknown);
        assert_eq!(d.group.as_deref(), Some("Lab/Junos"));
        assert_eq!(d.auth, "admin-pw");

        c.vendor_hint = Some("junos".to_string());
        assert_eq!(to_device(&c, "vEX1", "x").vendor, Vendor::Junos);
        c.vendor_hint = Some("paloalto_custom".to_string());
        assert!(matches!(
            to_device(&c, "vEX1", "x").vendor,
            Vendor::Custom(_)
        ));
    }

    #[test]
    fn to_auth_profile_maps_secret_kinds() {
        let p = to_auth_profile(
            "ubuntu",
            &SuggestedSecret::SshKey {
                path: "/k/id".into(),
            },
            "n",
        );
        assert!(matches!(p.secret, SecretRef::SshKey { .. }));
        let p = to_auth_profile("ubuntu", &SuggestedSecret::Agent, "n");
        assert!(matches!(p.secret, SecretRef::SshAgent { .. }));
        let p = to_auth_profile("root", &SuggestedSecret::KeyringEnrollLater, "root-pw");
        assert_eq!(
            p.secret,
            SecretRef::Keyring {
                key: "root-pw".to_string()
            }
        );
    }
}
