//! Best-effort OpenSSH `~/.ssh/config` parser.
//!
//! Line-oriented and tolerant — unknown keywords are ignored, exactly as
//! OpenSSH itself does, so this never errors. Wildcard-only `Host`
//! blocks (`Host *`) are defaults, not hosts, and are skipped.

use super::{expand_tilde, AuthKind, ImportedConnection, ParsedImport};

/// Parse ssh_config text into the IR. Infallible.
pub fn parse_ssh_config(text: &str) -> ParsedImport {
    let mut out = ParsedImport::default();
    let mut current: Option<Block> = None;
    let mut include_count = 0usize;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, value) = split_directive(line);
        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                if let Some(block) = current.take() {
                    push_block(block, &mut out);
                }
                current = Some(Block::new(value));
            }
            "include" => include_count += 1, // recorded, not followed (no I/O)
            other => {
                if let Some(block) = current.as_mut() {
                    block.set(other, value);
                }
            }
        }
    }
    if let Some(block) = current.take() {
        push_block(block, &mut out);
    }
    if include_count > 0 {
        out.warnings.push(format!(
            "{include_count} `Include` directive(s) not followed — only the chosen file was read"
        ));
    }
    out
}

struct Block {
    patterns: Vec<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    proxy_jump: Option<String>,
    identity_file: Option<String>,
}

impl Block {
    fn new(host_value: &str) -> Self {
        Block {
            patterns: host_value.split_whitespace().map(String::from).collect(),
            hostname: None,
            user: None,
            port: None,
            proxy_jump: None,
            identity_file: None,
        }
    }

    /// `keyword` is already lowercased.
    fn set(&mut self, keyword: &str, value: &str) {
        match keyword {
            "hostname" => self.hostname = Some(value.to_string()),
            "user" => self.user = Some(value.to_string()),
            "port" => self.port = value.parse().ok(),
            "proxyjump" if !value.eq_ignore_ascii_case("none") => {
                self.proxy_jump = Some(value.to_string());
            }
            // First IdentityFile wins (OpenSSH tries them in order).
            "identityfile" if self.identity_file.is_none() => {
                self.identity_file = Some(value.to_string());
            }
            _ => {}
        }
    }
}

fn push_block(block: Block, out: &mut ParsedImport) {
    // A token is "concrete" if it isn't a glob or negation.
    let concrete: Vec<&String> = block
        .patterns
        .iter()
        .filter(|p| !p.contains('*') && !p.contains('?') && !p.starts_with('!'))
        .collect();
    if concrete.is_empty() {
        if !block.patterns.is_empty() {
            out.warnings.push(format!(
                "skipped wildcard-only `Host {}` (a defaults block, not a host)",
                block.patterns.join(" ")
            ));
        }
        return;
    }
    let source_name = concrete[0].clone();
    let host = block
        .hostname
        .clone()
        .unwrap_or_else(|| source_name.clone());
    let key_path = block.identity_file.as_deref().map(expand_tilde);
    let auth_kind = if key_path.is_some() {
        AuthKind::PublicKeyFile
    } else {
        AuthKind::Agent
    };
    out.connections.push(ImportedConnection {
        source_name,
        host,
        port: block.port.unwrap_or(22),
        username: block.user.clone(),
        group_path: None,
        jump_host: block.proxy_jump.clone(),
        key_path,
        vendor_hint: None,
        auth_kind,
        credential_link: None,
    });
}

/// Split `Key Value` or `Key=Value`. Returns `(keyword, value)`.
fn split_directive(line: &str) -> (String, &str) {
    if let Some((k, v)) = line.split_once('=') {
        // Only treat `=` as the separator if it precedes any whitespace.
        if !k.contains(char::is_whitespace) {
            return (k.trim().to_string(), v.trim());
        }
    }
    match line.split_once(char::is_whitespace) {
        Some((k, v)) => (k.trim().to_string(), v.trim()),
        None => (line.to_string(), ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_blocks_and_skips_wildcards() {
        let text = "\
# my hosts
Host core-rtr
    HostName 10.0.0.1
    User netops
    Port 2222
    IdentityFile /home/netops/.ssh/id_ed25519

Host *
    User admin

Host edge
    HostName edge.example.net
    ProxyJump core-rtr
";
        let out = parse_ssh_config(text);
        assert_eq!(out.connections.len(), 2);

        let core = &out.connections[0];
        assert_eq!(core.source_name, "core-rtr");
        assert_eq!(core.host, "10.0.0.1");
        assert_eq!(core.port, 2222);
        assert_eq!(core.username.as_deref(), Some("netops"));
        assert_eq!(
            core.key_path,
            Some(PathBuf::from("/home/netops/.ssh/id_ed25519"))
        );
        assert_eq!(core.auth_kind, AuthKind::PublicKeyFile);

        let edge = &out.connections[1];
        assert_eq!(edge.source_name, "edge");
        assert_eq!(edge.host, "edge.example.net");
        assert_eq!(edge.port, 22);
        assert_eq!(edge.jump_host.as_deref(), Some("core-rtr"));
        assert_eq!(edge.auth_kind, AuthKind::Agent); // no IdentityFile

        assert!(out.warnings.iter().any(|w| w.contains("wildcard-only")));
    }

    #[test]
    fn handles_equals_form_and_first_identityfile_wins() {
        let text = "Host=h1\nHostName=1.2.3.4\nIdentityFile=/a\nIdentityFile=/b\n";
        let out = parse_ssh_config(text);
        assert_eq!(out.connections.len(), 1);
        assert_eq!(out.connections[0].host, "1.2.3.4");
        assert_eq!(out.connections[0].key_path, Some(PathBuf::from("/a")));
    }

    #[test]
    fn records_includes_without_following() {
        let out = parse_ssh_config("Include ~/.ssh/work/*\nHost h\nHostName x\n");
        assert_eq!(out.connections.len(), 1);
        assert!(out.warnings.iter().any(|w| w.contains("Include")));
    }
}
