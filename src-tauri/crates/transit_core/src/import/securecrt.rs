//! SecureCRT importer for the modern single-file `SCRTConfig.xml` export
//! (`<VanDyke version="3.0">` serialization). Parsed as real XML via
//! `roxmltree` — the file is full of entities (`&quot;` etc.), so a regex
//! scan would be wrong.
//!
//! Layout: a `<key name="Sessions">` dictionary whose nested `<key>`
//! elements are folders (no `Hostname`) or sessions (a non-empty
//! `<string name="Hostname">`). A sibling `<key name="Credentials">`
//! holds named shared credentials referenced by a session's
//! `Credential Title`.
//!
//! **`Password V2` is NEVER read** (it is the AES / config-passphrase
//! ciphertext). This parser does not bind it even to a discarded local.

use std::collections::HashMap;
use std::path::PathBuf;

use roxmltree::Node;

use super::{expand_tilde, AuthKind, ImportError, ImportedConnection, ParsedImport};

/// SecureCRT's built-in template "sessions" — skipped on import.
const SKIP_NAMES: &[&str] = &["Default", "Default_LocalShell", "Default_RDP"];

pub fn parse_securecrt(text: &str) -> Result<ParsedImport, ImportError> {
    let doc = roxmltree::Document::parse(text).map_err(|e| ImportError::Xml(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "VanDyke" {
        return Err(ImportError::Xml(
            "not a SecureCRT config (missing <VanDyke> root)".into(),
        ));
    }

    let credentials = find_named_key(root, "Credentials")
        .map(parse_credentials)
        .unwrap_or_default();

    let sessions = find_named_key(root, "Sessions")
        .ok_or_else(|| ImportError::Empty("no <key name=\"Sessions\"> dictionary".into()))?;

    let mut out = ParsedImport::default();
    walk(sessions, &mut Vec::new(), &credentials, &mut out);
    Ok(out)
}

/// A named shared credential from `<key name="Credentials">`.
#[derive(Default)]
struct Credential {
    username: Option<String>,
    key_path: Option<PathBuf>,
    auth_methods: Option<String>,
}

fn parse_credentials(node: Node<'_, '_>) -> HashMap<String, Credential> {
    let mut map = HashMap::new();
    for child in element_keys(node) {
        if let Some(name) = child.attribute("name") {
            map.insert(
                name.to_string(),
                Credential {
                    username: string_field(child, "Username"),
                    key_path: string_field(child, "Identity Filename V2").map(|s| expand_tilde(&s)),
                    auth_methods: string_field(child, "SSH2 Authentications V2"),
                },
            );
        }
    }
    map
}

fn walk(
    parent: Node<'_, '_>,
    path: &mut Vec<String>,
    credentials: &HashMap<String, Credential>,
    out: &mut ParsedImport,
) {
    for child in element_keys(parent) {
        let name = match child.attribute("name") {
            Some(n) => n,
            None => continue,
        };
        if SKIP_NAMES.contains(&name) {
            continue;
        }
        if is_session(child) {
            let protocol = string_field(child, "Protocol Name").unwrap_or_default();
            if protocol != "SSH2" {
                out.warnings.push(format!(
                    "skipped non-SSH session '{name}' (protocol: {})",
                    if protocol.is_empty() { "?" } else { &protocol }
                ));
                continue;
            }
            out.connections
                .push(build_session(child, name, path, credentials));
        } else {
            path.push(name.replace('/', "-"));
            walk(child, path, credentials, out);
            path.pop();
        }
    }
}

fn build_session(
    node: Node<'_, '_>,
    name: &str,
    path: &[String],
    credentials: &HashMap<String, Credential>,
) -> ImportedConnection {
    let host = string_field(node, "Hostname").unwrap_or_default();
    let port = dword_field(node, "[SSH2] Port")
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(22);
    let jump_host = string_field(node, "Firewall Name").filter(|f| !f.eq_ignore_ascii_case("None"));
    let credential_link = string_field(node, "Credential Title");

    // Prefer the session's own auth fields; fall back to the named
    // shared credential when the session references one.
    let mut username = string_field(node, "Username");
    let mut key_path = string_field(node, "Identity Filename V2").map(|s| expand_tilde(&s));
    let mut auth_methods = string_field(node, "SSH2 Authentications V2");
    if let Some(cred) = credential_link.as_deref().and_then(|l| credentials.get(l)) {
        username = username.or_else(|| cred.username.clone());
        key_path = key_path.or_else(|| cred.key_path.clone());
        auth_methods = auth_methods.or_else(|| cred.auth_methods.clone());
    }

    ImportedConnection {
        source_name: name.to_string(),
        host,
        port,
        username,
        group_path: (!path.is_empty()).then(|| path.join("/")),
        jump_host,
        key_path: key_path.clone(),
        vendor_hint: None,
        auth_kind: classify_auth(auth_methods.as_deref(), key_path.is_some()),
        credential_link,
    }
}

/// Map `SSH2 Authentications V2` (comma list, preference order) +
/// key-path presence to an [`AuthKind`].
fn classify_auth(methods: Option<&str>, has_key: bool) -> AuthKind {
    let primary = methods
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .find(|m| !m.is_empty());
    match primary {
        Some("publickey") if has_key => AuthKind::PublicKeyFile,
        Some("publickey") => AuthKind::Agent,
        Some("password") | Some("keyboard-interactive") => AuthKind::Password,
        _ if has_key => AuthKind::PublicKeyFile,
        Some(_) => AuthKind::Unknown,
        None => AuthKind::Unknown,
    }
}

/// A `<key>` is a session iff it has a non-empty `<string name="Hostname">`.
fn is_session(node: Node<'_, '_>) -> bool {
    string_field(node, "Hostname").is_some()
}

/// Direct child `<key>` elements of `parent`.
fn element_keys<'a, 'input>(parent: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    parent
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "key")
}

fn find_named_key<'a, 'input>(parent: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    element_keys(parent).find(|n| n.attribute("name") == Some(name))
}

/// Text of a direct child `<string name="X">`, trimmed; `None` if absent
/// or empty (self-closing).
fn string_field(node: Node<'_, '_>, name: &str) -> Option<String> {
    typed_field(node, "string", name)
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Decimal value of a direct child `<dword name="X">`.
fn dword_field(node: Node<'_, '_>, name: &str) -> Option<u32> {
    typed_field(node, "dword", name)
        .and_then(|n| n.text())
        .and_then(|t| t.trim().parse().ok())
}

fn typed_field<'a, 'input>(
    node: Node<'a, 'input>,
    tag: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag && n.attribute("name") == Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Credentials">
    <key name="ec2">
      <string name="Username">ubuntu</string>
      <string name="SSH2 Authentications V2">publickey</string>
      <string name="Identity Filename V2"/>
    </key>
  </key>
  <key name="Sessions">
    <key name="Default">
      <string name="Hostname">should-be-skipped</string>
      <string name="Protocol Name">SSH2</string>
    </key>
    <key name="archnode">
      <string name="Hostname">10.0.0.9</string>
      <dword name="[SSH2] Port">6922</dword>
      <string name="Username">netops</string>
      <string name="Protocol Name">SSH2</string>
      <string name="Firewall Name">None</string>
      <string name="SSH2 Authentications V2">password,keyboard-interactive</string>
      <string name="Identity Filename V2"/>
      <string name="Credential Title"/>
      <string name="Password V2">03:deadbeef</string>
    </key>
    <key name="Lab">
      <key name="vEX1">
        <string name="Hostname">10.0.1.1</string>
        <string name="Protocol Name">SSH2</string>
        <string name="Username">admin</string>
        <string name="SSH2 Authentications V2">publickey</string>
        <string name="Identity Filename V2">/keys/lab.pub</string>
        <string name="Firewall Name">jumpbox</string>
      </key>
      <key name="serial-thing">
        <string name="Hostname">10.0.1.2</string>
        <string name="Protocol Name">Local Shell</string>
      </key>
    </key>
    <key name="ec2box">
      <string name="Hostname">1.2.3.4</string>
      <string name="Protocol Name">SSH2</string>
      <string name="Credential Title">ec2</string>
    </key>
  </key>
</VanDyke>"#;

    #[test]
    fn parses_sessions_folders_and_credentials() {
        let out = parse_securecrt(SAMPLE).unwrap();
        let names: Vec<&str> = out
            .connections
            .iter()
            .map(|c| c.source_name.as_str())
            .collect();
        assert_eq!(names, vec!["archnode", "vEX1", "ec2box"]); // Default + Local Shell skipped

        let arch = &out.connections[0];
        assert_eq!(arch.host, "10.0.0.9");
        assert_eq!(arch.port, 6922); // decimal, non-standard
        assert_eq!(arch.username.as_deref(), Some("netops"));
        assert_eq!(arch.auth_kind, AuthKind::Password);
        assert!(arch.jump_host.is_none()); // "None"

        let vex = &out.connections[1];
        assert_eq!(vex.group_path.as_deref(), Some("Lab"));
        assert_eq!(vex.key_path, Some(PathBuf::from("/keys/lab.pub")));
        assert_eq!(vex.auth_kind, AuthKind::PublicKeyFile);
        assert_eq!(vex.jump_host.as_deref(), Some("jumpbox"));

        // Credential Title resolves username/auth from the shared credential.
        let ec2 = &out.connections[2];
        assert_eq!(ec2.credential_link.as_deref(), Some("ec2"));
        assert_eq!(ec2.username.as_deref(), Some("ubuntu"));
        assert_eq!(ec2.auth_kind, AuthKind::Agent); // publickey, no key file

        assert!(out.warnings.iter().any(|w| w.contains("Local Shell")));
    }

    #[test]
    fn rejects_non_securecrt_xml() {
        assert!(matches!(
            parse_securecrt("<other/>"),
            Err(ImportError::Xml(_))
        ));
        assert!(matches!(
            parse_securecrt("not xml"),
            Err(ImportError::Xml(_))
        ));
    }

    #[test]
    fn errors_when_no_sessions_dict() {
        assert!(matches!(
            parse_securecrt(r#"<VanDyke version="3.0"></VanDyke>"#),
            Err(ImportError::Empty(_))
        ));
    }
}
