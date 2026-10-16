//! MTPuTTY importer for the `mtputty.xml` server list (TTY Plus
//! Multi-Tabbed PuTTY). Parsed as real XML via `roxmltree`.
//!
//! Layout: `<Servers>` → one or more tab containers (`<Putty>`, …) → a
//! tree of `<Node>` elements. A node with `Type="1"` is a server; any
//! other node (`Type="0"`) is a folder named by its `<DisplayName>`
//! child.
//!
//! Two root shapes exist in the wild and both are accepted:
//! - **`<Servers>` root** — what MTPuTTY's *Export* menu actually
//!   writes (verified against a real 2026 export).
//! - **`<MTPutty version="…">` root wrapping `<Globals>` + `<Servers>`**
//!   — the app's own saved config file (`%APPDATA%\TTYPlus\mtputty.xml`),
//!   which users may copy directly.
//!
//! Two structural caveats this parser surfaces as warnings instead of
//! silently dropping:
//! - An entry may reference only a **PuTTY saved session**
//!   (`<SavedSession>`) with an empty `<ServerName>` — its host/port
//!   live in the Windows registry, not in this file. Skipped with a
//!   warning naming the session.
//! - `<PuttyConType>` values other than SSH (4) — telnet/rlogin/raw/
//!   serial — are skipped with a warning.
//!
//! **`Password` / `PlainPassword` values are NEVER read.** Only the
//! *presence* of a password element is consulted (to classify the auth
//! kind); the ciphertext/plaintext bytes are not bound to any local.
//!
//! `<CLParams>` (extra PuTTY command-line flags) is scanned best-effort
//! for `-l <user>`, `-P <port>`, and `-i <keyfile>` as fallbacks for
//! fields the XML elements leave empty.

use std::path::PathBuf;

use roxmltree::Node;

use super::{expand_tilde, AuthKind, ImportError, ImportedConnection, ParsedImport};

pub fn parse_mtputty(text: &str) -> Result<ParsedImport, ImportError> {
    let doc = roxmltree::Document::parse(text).map_err(|e| ImportError::Xml(e.to_string()))?;
    let root = doc.root_element();
    let servers = match root.tag_name().name() {
        // The Export menu's shape: <Servers> IS the root.
        "Servers" => root,
        // The app config-file shape: <MTPutty> wraps <Servers>.
        "MTPutty" => root
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "Servers")
            .ok_or_else(|| ImportError::Empty("no <Servers> element".into()))?,
        _ => {
            return Err(ImportError::Xml(
                "not an MTPuTTY server list (expected a <Servers> or <MTPutty> root)".into(),
            ))
        }
    };

    let mut out = ParsedImport::default();
    // <Servers> holds one container element per tab type (<Putty>, …);
    // walk each container's node tree.
    for container in servers.children().filter(|n| n.is_element()) {
        walk(container, &mut Vec::new(), &mut out);
    }
    Ok(out)
}

fn walk(parent: Node<'_, '_>, path: &mut Vec<String>, out: &mut ParsedImport) {
    for node in parent
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Node")
    {
        if node.attribute("Type") == Some("1") {
            build_server(node, path, out);
        } else {
            // Folder (Type="0"); unnamed folders still recurse.
            let name = child_text(node, "DisplayName").unwrap_or_default();
            if name.is_empty() {
                walk(node, path, out);
            } else {
                path.push(name.replace('/', "-"));
                walk(node, path, out);
                path.pop();
            }
        }
    }
}

fn build_server(node: Node<'_, '_>, path: &[String], out: &mut ParsedImport) {
    let saved_session = child_text(node, "SavedSession").unwrap_or_default();
    let display_name = child_text(node, "DisplayName")
        .or_else(|| child_text(node, "ServerName"))
        .unwrap_or_else(|| saved_session.clone());
    let cl = child_text(node, "CLParams").unwrap_or_default();
    let cl = parse_cl_params(&cl);

    let host = child_text(node, "ServerName")
        .or_else(|| cl.host.clone())
        .unwrap_or_default();
    if host.is_empty() {
        if saved_session.is_empty() {
            out.warnings
                .push(format!("skipped '{display_name}': no host"));
        } else {
            out.warnings.push(format!(
                "skipped '{display_name}': its connection details live in the PuTTY saved \
                 session '{saved_session}' (Windows registry), not in mtputty.xml"
            ));
        }
        return;
    }

    // <PuttyConType>: 1 raw, 2 telnet, 3 rlogin, 4 SSH, 5 serial.
    // Absent ⇒ assume SSH (older exports omit it).
    match child_text(node, "PuttyConType").as_deref() {
        None | Some("4") => {}
        Some(other) => {
            let proto = match other {
                "1" => "raw",
                "2" => "telnet",
                "3" => "rlogin",
                "5" => "serial",
                _ => other,
            };
            out.warnings.push(format!(
                "skipped non-SSH server '{display_name}' (connection type: {proto})"
            ));
            return;
        }
    }

    let port = child_text(node, "Port")
        .and_then(|p| p.parse::<u16>().ok())
        .or(cl.port)
        .unwrap_or(22);
    let username = child_text(node, "UserName").or_else(|| cl.username.clone());

    // Presence-only check — the encrypted/plain value is never read.
    let has_password_element = node.children().any(|n| {
        n.is_element()
            && matches!(n.tag_name().name(), "Password" | "PlainPassword")
            && n.text().is_some_and(|t| !t.trim().is_empty())
    });
    let key_path = cl.key_path.clone();
    let auth_kind = if key_path.is_some() {
        AuthKind::PublicKeyFile
    } else if has_password_element {
        AuthKind::Password
    } else {
        AuthKind::Unknown
    };

    out.connections.push(ImportedConnection {
        source_name: display_name,
        host,
        port,
        username,
        group_path: (!path.is_empty()).then(|| path.join("/")),
        jump_host: None,
        key_path,
        vendor_hint: None,
        auth_kind,
        credential_link: None,
    });
}

/// Best-effort fallbacks pulled from `<CLParams>` (PuTTY flags). Naive
/// whitespace tokenization — quoted paths with spaces are not handled
/// (they surface later as an unreadable key path in the credential step).
#[derive(Default)]
struct ClParams {
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    key_path: Option<PathBuf>,
}

fn parse_cl_params(cl: &str) -> ClParams {
    let mut out = ClParams::default();
    let mut tokens = cl.split_whitespace().peekable();
    while let Some(tok) = tokens.next() {
        match tok {
            "-l" => out.username = tokens.next().map(String::from),
            "-P" => out.port = tokens.next().and_then(|p| p.parse().ok()),
            "-i" => out.key_path = tokens.next().map(expand_tilde),
            // `-load <session>`: the next token is a session name, not a
            // host — consume it so it can't be mistaken for one.
            "-load" => {
                tokens.next();
            }
            _ if tok.starts_with('-') => {}
            // First bare token that isn't a flag argument = host.
            _ => {
                if out.host.is_none() {
                    // `user@host` form.
                    if let Some((user, host)) = tok.split_once('@') {
                        out.username.get_or_insert_with(|| user.to_string());
                        out.host = Some(host.to_string());
                    } else {
                        out.host = Some(tok.to_string());
                    }
                }
            }
        }
    }
    out
}

/// Text of a direct child element `<name>`, trimmed; `None` if absent or
/// empty (self-closing).
fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MTPutty version="1.0">
  <Globals>
    <PuttyLocation>C:\Tools\putty.exe</PuttyLocation>
  </Globals>
  <Servers>
    <Putty>
      <Node Type="0">
        <DisplayName>Lab/Core</DisplayName>
        <Node Type="1">
          <SavedSession></SavedSession>
          <DisplayName>vEX1</DisplayName>
          <ServerName>10.0.1.1</ServerName>
          <PuttyConType>4</PuttyConType>
          <Port>2222</Port>
          <UserName>admin</UserName>
          <Password>k6LrFZbnRFk=</Password>
          <PasswordDelay>0</PasswordDelay>
          <CLParams>10.0.1.1 -ssh -P 2222</CLParams>
          <ScriptDelay>0</ScriptDelay>
        </Node>
        <Node Type="1">
          <SavedSession>desert</SavedSession>
          <DisplayName>registry-only</DisplayName>
          <ServerName></ServerName>
          <PuttyConType>4</PuttyConType>
          <Port>22</Port>
          <CLParams>-load desert</CLParams>
        </Node>
      </Node>
      <Node Type="1">
        <DisplayName>console-1</DisplayName>
        <ServerName>10.0.9.9</ServerName>
        <PuttyConType>5</PuttyConType>
        <Port>22</Port>
      </Node>
      <Node Type="1">
        <DisplayName>keybox</DisplayName>
        <ServerName>10.0.3.3</ServerName>
        <Port>22</Port>
        <CLParams>-i C:\keys\lab.ppk -l netops</CLParams>
      </Node>
    </Putty>
  </Servers>
</MTPutty>"#;

    #[test]
    fn parses_servers_folders_and_warnings() {
        let out = parse_mtputty(SAMPLE).unwrap();
        let names: Vec<&str> = out
            .connections
            .iter()
            .map(|c| c.source_name.as_str())
            .collect();
        assert_eq!(names, vec!["vEX1", "keybox"]);

        let vex = &out.connections[0];
        assert_eq!(vex.host, "10.0.1.1");
        assert_eq!(vex.port, 2222);
        assert_eq!(vex.username.as_deref(), Some("admin"));
        // Folder name containing '/' is sanitized to '-'.
        assert_eq!(vex.group_path.as_deref(), Some("Lab-Core"));
        // Password element present (value never read) → Password.
        assert_eq!(vex.auth_kind, AuthKind::Password);

        // CLParams fallbacks: -i key + -l user; PuttyConType absent ⇒ SSH.
        let keybox = &out.connections[1];
        assert_eq!(keybox.username.as_deref(), Some("netops"));
        assert_eq!(keybox.key_path, Some(PathBuf::from(r"C:\keys\lab.ppk")));
        assert_eq!(keybox.auth_kind, AuthKind::PublicKeyFile);
        assert!(keybox.group_path.is_none());

        // Registry-only session + serial server → warnings, not rows.
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("registry-only") && w.contains("desert")));
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("console-1") && w.contains("serial")));
    }

    #[test]
    fn cl_params_user_at_host_form() {
        let cl = parse_cl_params("netops@10.0.4.4 -ssh");
        assert_eq!(cl.host.as_deref(), Some("10.0.4.4"));
        assert_eq!(cl.username.as_deref(), Some("netops"));

        // -load's argument is a session name, never a host.
        let cl = parse_cl_params("-load prod-fw");
        assert!(cl.host.is_none());
    }

    /// The Export menu's real output: bare <Servers> root, no <MTPutty>
    /// wrapper, UID children, SavedSession = "Default Settings" with a
    /// populated ServerName (⇒ imports; not registry-only).
    #[test]
    fn parses_export_menu_servers_root_shape() {
        let sample = r#"<?xml version="1.0" encoding="UTF-8"?>
<Servers>
	<Putty>
		<Node Type="1">
			<SavedSession>Default Settings</SavedSession>
			<DisplayName>2.2.2.2</DisplayName>
			<UID>{215F401B-2260-43AD-AD10-97A6C7B9C828}</UID>
			<ServerName>2.2.2.2</ServerName>
			<PuttyConType>4</PuttyConType>
			<Port>22</Port>
			<UserName>alice</UserName>
			<Password>bmV2ZXItcmVhZA==</Password>
			<PasswordDelay>0</PasswordDelay>
			<CLParams>2.2.2.2 -ssh -P 22 -l alice</CLParams>
			<ScriptDelay>0</ScriptDelay>
		</Node>
	</Putty>
</Servers>"#;
        let out = parse_mtputty(sample).unwrap();
        assert_eq!(out.connections.len(), 1);
        let c = &out.connections[0];
        assert_eq!(c.host, "2.2.2.2");
        assert_eq!(c.port, 22);
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.auth_kind, AuthKind::Password);
        assert!(out.warnings.is_empty());
    }

    #[test]
    fn rejects_non_mtputty_xml() {
        assert!(matches!(
            parse_mtputty("<other/>"),
            Err(ImportError::Xml(_))
        ));
        assert!(matches!(parse_mtputty("not xml"), Err(ImportError::Xml(_))));
    }

    #[test]
    fn errors_when_no_servers_element() {
        assert!(matches!(
            parse_mtputty(r#"<MTPutty version="1.0"><Globals/></MTPutty>"#),
            Err(ImportError::Empty(_))
        ));
    }
}
