//! Inventory file loader + validator.
//!
//! Validation order, top-down:
//!   1. File exists.
//!   2. Symlink target stays inside the parent directory.
//!   3. File size <= 4 MiB (MAX_INVENTORY_SIZE).
//!   4. Inline-secret prescan (regex over raw text — lossy-decoded, so
//!      it runs even when UTF-8 conversion would fail).
//!   5. UTF-8 conversion.
//!   6. TOML parse with file:line errors.
//!   7. Cross-validation: device fields sane (non-empty id/host, port
//!      != 0); auth refs resolve; device IDs unique; api_session fields
//!      sane (id + endpoint-kind requirements) + api_session IDs unique.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use super::errors::InventoryError;
use super::types::{ApiEndpointKind, InventoryFile, SecretRef};

/// Maximum size in bytes for a `transit.toml`. Larger files are
/// rejected before parsing. 4 MiB holds ~10k+ devices; the old 256 KiB
/// cap (~870 devices) was too small once bulk import (100s–1000s of
/// SecureCRT sessions) landed.
pub const MAX_INVENTORY_SIZE: u64 = 4 * 1024 * 1024;

/// Maximum jump-host hops a device's `jump_via` chain may traverse
/// (v6.5.0). The loader enforces it here; the app-side chain resolver
/// re-checks defensively before connecting.
pub const MAX_JUMP_CHAIN: usize = 4;

/// Compiled inline-secret patterns. Lazy-initialized; the regexes are
/// static so compilation only happens once per process.
///
/// Each key pattern fires after start-of-line, `#`, `{`, or `,` — not
/// just at line start. That catches (a) secrets smuggled mid-line into
/// an inline table (`secret = { backend = "keyring", password = "..." }`,
/// which the internally-tagged `SecretRef` enum would otherwise
/// silently DROP, leaving the plaintext in the file) and (b)
/// commented-out credentials (`# password = "..."`). The trailing
/// `["']` keeps the structured forms valid: `secret = { backend = ... }`
/// and a nested `passphrase = { backend = ... }` are followed by `{`,
/// not a quote, so they never match.
fn inline_secret_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (
                r#"(?im)(?:^|[#{,])\s*password\s*=\s*["']"#,
                r#"password = "...""#,
            ),
            (
                r#"(?im)(?:^|[#{,])\s*passphrase\s*=\s*["']"#,
                r#"passphrase = "...""#,
            ),
            (
                r#"(?im)(?:^|[#{,])\s*private_key\s*=\s*["']"#,
                r#"private_key = "...""#,
            ),
            (
                r#"(?im)(?:^|[#{,])\s*api_key\s*=\s*["']"#,
                r#"api_key = "...""#,
            ),
            (r#"(?im)(?:^|[#{,])\s*token\s*=\s*["']"#, r#"token = "...""#),
            // `secret = { backend = ... }` is valid; only literal-string `secret = "..."` is rejected.
            (
                r#"(?im)(?:^|[#{,])\s*secret\s*=\s*["']"#,
                r#"secret = "...""#,
            ),
            (
                r#"-----BEGIN [A-Z ]+ PRIVATE KEY-----"#,
                "PEM private key block",
            ),
        ];
        raw.iter()
            .map(|(rx, label)| (Regex::new(rx).expect("static pattern"), *label))
            .collect()
    })
}

/// Load `transit.toml` from a specific path with full validation.
pub fn load(path: &Path) -> Result<InventoryFile, InventoryError> {
    // 1. Existence + metadata.
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(InventoryError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(InventoryError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    // 2. Symlink rejection (if target resolves outside the parent dir).
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|source| InventoryError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let absolute_target = if target.is_absolute() {
            target.clone()
        } else {
            path.parent()
                .map(|p| p.join(&target))
                .unwrap_or_else(|| target.clone())
        };
        let canonical_target = absolute_target
            .canonicalize()
            .unwrap_or(absolute_target.clone());
        // Containment must fail CLOSED: if the parent can't be
        // canonicalized, surface the error instead of comparing against
        // an empty path (`starts_with("")` is true for everything,
        // which would silently allow any symlink target).
        let parent = path.parent().ok_or_else(|| InventoryError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                ErrorKind::InvalidInput,
                "inventory path has no parent directory",
            ),
        })?;
        // A bare relative path (`transit.toml`) has the empty parent;
        // canonicalize the CWD in that case rather than erroring.
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let canonical_parent = parent.canonicalize().map_err(|source| InventoryError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        if !canonical_target.starts_with(&canonical_parent) {
            return Err(InventoryError::SymlinkRejected {
                path: path.to_path_buf(),
                target: canonical_target,
            });
        }
    }

    // 3. File-size cap.
    let size = metadata.len();
    if size > MAX_INVENTORY_SIZE {
        return Err(InventoryError::TooLarge {
            size,
            max: MAX_INVENTORY_SIZE,
        });
    }

    // 4. Read raw bytes (still pre-UTF-8).
    let raw = fs::read(path).map_err(|source| InventoryError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    // 5. Inline-secret pre-scan over potentially-partial UTF-8 (so a
    // bad-encoded file with a literal secret still surfaces the secret
    // error rather than the encoding one). `from_utf8_lossy` replaces
    // invalid bytes with U+FFFD; valid lines — including any inline
    // secret — survive intact for the scan.
    prescan_inline_secrets(&String::from_utf8_lossy(&raw), path)?;

    // 6. UTF-8 conversion (final).
    let text = std::str::from_utf8(&raw).map_err(|e| InventoryError::ParseFailed {
        path: path.to_path_buf(),
        line: 0,
        message: format!("file is not valid UTF-8 (at byte {})", e.valid_up_to()),
    })?;

    // 7+8. Parse + cross-validate (shared with mutator's pre-write check).
    parse_and_validate(text, path)
}

/// Run inline-secret prescan + TOML parse + cross-validation on a
/// raw text blob. `path` is for error context only — it isn't read.
///
/// Used by [`load`] after file IO and by the mutator after every
/// in-memory edit to catch any regression that would have produced a
/// file the loader would itself reject.
pub(super) fn parse_and_validate(text: &str, path: &Path) -> Result<InventoryFile, InventoryError> {
    prescan_inline_secrets(text, path)?;

    // Belt to the regex prescan's suspenders: the line regex anchors on
    // `^`/`{`/`,`/`#`, so a quoted (`"password" = "…"`) or dotted
    // (`secret.password = "…"`) key spelling slips past it — and serde
    // then silently drops the unknown nested field, leaving the plaintext
    // at rest. Walk the PARSED tree (all key spellings normalized to the
    // same name) to catch every form. On a TOML syntax error we skip
    // silently; the typed parse just below reports it with a line number.
    if let Ok(table) = toml::from_str::<toml::Table>(text) {
        scan_parsed_for_inline_secret(&table, path)?;
    }

    let parsed: InventoryFile = toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .map(|span| text[..span.start].matches('\n').count() + 1)
            .unwrap_or(0);
        let mut message = e.message().to_string();
        // `deny_unknown_fields` rejects a key this build doesn't know. The
        // common cause is a config written by a NEWER Transit that added
        // fields (e.g. `color`, `tags`) — point the user at the real fix
        // instead of a bare serde "unknown field" message.
        if message.contains("unknown field") {
            message.push_str(
                "\n\nThis usually means the config was saved by a newer version of \
                 Transit than the one you are running. Upgrade Transit to the latest \
                 version to open it.",
            );
        }
        InventoryError::ParseFailed {
            path: path.to_path_buf(),
            line,
            message,
        }
    })?;

    validate_inventory(&parsed, text)?;
    Ok(parsed)
}

/// Reject any line that matches a known inline-secret pattern.
fn prescan_inline_secrets(text: &str, path: &Path) -> Result<(), InventoryError> {
    for (line_idx, line) in text.lines().enumerate() {
        for (rx, label) in inline_secret_patterns() {
            if rx.is_match(line) {
                return Err(InventoryError::InlineSecret {
                    path: path.to_path_buf(),
                    line: line_idx + 1,
                    pattern: (*label).to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Secret-bearing key names that must never carry an inline STRING value
/// (they belong in a `SecretRef` / backend, never as plaintext at rest).
/// Matched case-insensitively against PARSED key names, so every TOML
/// spelling — bare, `"quoted"`, or dotted — collapses to the same name.
/// `secret` is legal as a TABLE (a `SecretRef`); only a *string* value is
/// a plaintext leak, so the scan keys on the value type, not just the name.
const FORBIDDEN_INLINE_SECRET_KEYS: &[&str] = &[
    "password",
    "passphrase",
    "private_key",
    "api_key",
    "token",
    "secret",
];

/// Walk a parsed TOML tree and reject any [`FORBIDDEN_INLINE_SECRET_KEYS`]
/// key whose value is a string literal. Complements
/// [`prescan_inline_secrets`] (which only catches the bare / inline-table
/// spellings the line regex anchors on).
fn scan_parsed_for_inline_secret(table: &toml::Table, path: &Path) -> Result<(), InventoryError> {
    fn walk_table(t: &toml::Table, path: &Path) -> Result<(), InventoryError> {
        for (key, val) in t {
            if val.is_str()
                && FORBIDDEN_INLINE_SECRET_KEYS.contains(&key.to_ascii_lowercase().as_str())
            {
                return Err(InventoryError::InlineSecret {
                    path: path.to_path_buf(),
                    // toml::Value carries no source span; the pattern names
                    // the offending key so the user can still find it.
                    line: 0,
                    pattern: format!("{key} = \"...\""),
                });
            }
            walk_value(val, path)?;
        }
        Ok(())
    }
    fn walk_value(v: &toml::Value, path: &Path) -> Result<(), InventoryError> {
        match v {
            toml::Value::Table(t) => walk_table(t, path),
            toml::Value::Array(a) => a.iter().try_for_each(|item| walk_value(item, path)),
            _ => Ok(()),
        }
    }
    walk_table(table, path)
}

/// Cross-validate an already-parsed inventory: device fields are sane,
/// auth refs resolve, device IDs are unique. Source `text` is only used
/// to decorate the DuplicateDevice error with line numbers (the parsed
/// struct doesn't carry source spans).
fn validate_inventory(inv: &InventoryFile, text: &str) -> Result<(), InventoryError> {
    // Per-device field sanity. The empty-id rejection also closes the
    // duplicate-detection blind spot for `id = ""` (the old text scan's
    // capture group required 1+ chars, so two empty ids never collided).
    for device in &inv.devices {
        if device.id.is_empty() {
            return Err(InventoryError::InvalidDevice {
                reason: format!("device with host '{}' has an empty id", device.host),
            });
        }
        if device.host.is_empty() {
            return Err(InventoryError::InvalidDevice {
                reason: format!("device '{}' has an empty host", device.id),
            });
        }
        if device.port == 0 {
            return Err(InventoryError::InvalidDevice {
                reason: format!("device '{}' has port 0 (must be 1-65535)", device.id),
            });
        }
    }

    // Auth refs.
    for device in &inv.devices {
        if !inv.auth_profiles.contains_key(&device.auth) {
            return Err(InventoryError::UnknownAuth {
                id: device.id.clone(),
                auth: device.auth.clone(),
            });
        }
    }

    // Unique device IDs — detected on PARSED data so exotic quoting
    // (escaped quotes, literal strings) can neither evade detection nor
    // falsely collide. The text scan below only supplies line numbers
    // for the error message, falling back to 0 when it can't find them.
    let mut seen: HashSet<&str> = HashSet::new();
    for device in &inv.devices {
        if !seen.insert(device.id.as_str()) {
            let id_lines = find_id_lines(text);
            let (first, second) = match id_lines.get(&device.id).map(Vec::as_slice) {
                Some([first, second, ..]) => (*first, *second),
                Some([only]) => (*only, 0),
                _ => (0, 0),
            };
            return Err(InventoryError::DuplicateDevice {
                id: device.id.clone(),
                first,
                second,
            });
        }
    }

    // v6.5.0 — jump-host refs. Placed AFTER the duplicate-id check so
    // the id → device mapping the chain walk relies on is unambiguous
    // (`seen` above already holds every device id). Every `jump_via`
    // must (a) resolve to an existing device, (b) form no cycle —
    // self-reference is the degenerate 1-cycle — and (c) chain at most
    // MAX_JUMP_CHAIN hops deep. This is the single choke point: disk
    // loads, every mutator revalidate, and `bulk_update_devices`'
    // trailing revalidate all pass through here, so a batch that would
    // create a cycle rolls back as a whole.
    let jump_of: HashMap<&str, &str> = inv
        .devices
        .iter()
        .filter_map(|d| d.jump_via.as_deref().map(|j| (d.id.as_str(), j)))
        .collect();
    for device in &inv.devices {
        let Some(first_hop) = device.jump_via.as_deref() else {
            continue;
        };
        if !seen.contains(first_hop) {
            return Err(InventoryError::UnknownJumpHost {
                id: device.id.clone(),
                jump_via: first_hop.to_string(),
            });
        }
        let mut chain: Vec<String> = vec![device.id.clone()];
        let mut visited: HashSet<&str> = HashSet::from([device.id.as_str()]);
        let mut cursor = first_hop;
        loop {
            chain.push(cursor.to_string());
            if !visited.insert(cursor) {
                return Err(InventoryError::JumpCycle { chain });
            }
            // `chain` holds the device plus its hops, so hops = len - 1.
            if chain.len() - 1 > MAX_JUMP_CHAIN {
                return Err(InventoryError::JumpChainTooDeep {
                    chain,
                    max: MAX_JUMP_CHAIN,
                });
            }
            match jump_of.get(cursor) {
                // A dangling ref mid-chain ends the walk here; the owner
                // of that ref gets its own UnknownJumpHost when the outer
                // loop reaches it.
                Some(next) => cursor = next,
                None => break,
            }
        }
    }

    // v4.0.0 — per-api-session field sanity + endpoint-kind requirements.
    for s in &inv.api_sessions {
        if s.id.is_empty() {
            return Err(InventoryError::InvalidApiSession {
                reason: format!("api session with name '{}' has an empty id", s.name),
            });
        }
        match s.kind {
            ApiEndpointKind::NetworkLocal => {
                if s.host.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(InventoryError::InvalidApiSession {
                        reason: format!(
                            "api session '{}' (network_local) needs a non-empty host",
                            s.id
                        ),
                    });
                }
            }
            ApiEndpointKind::ConnectorProxy => {
                if s.console_id.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(InventoryError::InvalidApiSession {
                        reason: format!(
                            "api session '{}' (connector_proxy) needs a non-empty console_id",
                            s.id
                        ),
                    });
                }
            }
            // SiteManager needs no host/console_id; Generic's base_url is
            // validated separately below (alongside the auth ↔ secret check).
            ApiEndpointKind::SiteManager | ApiEndpointKind::Generic => {}
        }

        // The API key must live on a VALUE backend — one whose
        // `resolve_value` yields the key bytes. Sign-only backends
        // (`ssh_agent` / `ssh_key`) return `Unsupported`, so a hand-edited
        // api_session pointing at one would fail every Send with a
        // confusing generic error. Reject it up front. (The Add dialog
        // only offers keyring/op/env; `encrypted_file` is also a value
        // backend and is allowed.)
        // Auth ↔ secret consistency: a scheme that presents a credential must
        // have one; `none` needs none. (The Add dialog enforces this too;
        // this is the loader backstop for a hand-edited file.)
        if s.auth.needs_secret() && s.secret.is_none() {
            return Err(InventoryError::InvalidApiSession {
                reason: format!(
                    "api session '{}' auth scheme needs a secret, but none is set",
                    s.id
                ),
            });
        }
        // A generic controller needs a base URL to pin.
        if s.kind == ApiEndpointKind::Generic
            && s.base_url.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err(InventoryError::InvalidApiSession {
                reason: format!("api session '{}' is generic but has no base_url", s.id),
            });
        }
        if matches!(
            s.secret,
            Some(SecretRef::SshAgent { .. }) | Some(SecretRef::SshKey { .. })
        ) {
            return Err(InventoryError::InvalidApiSession {
                reason: format!(
                    "api session '{}' uses a sign-only key backend (ssh_agent/ssh_key); \
                     an API key needs a value backend (keyring, op, env, or encrypted_file)",
                    s.id
                ),
            });
        }
    }

    // Unique api_session ids (a separate namespace from device ids).
    let mut seen_api: HashSet<&str> = HashSet::new();
    for s in &inv.api_sessions {
        if !seen_api.insert(s.id.as_str()) {
            return Err(InventoryError::DuplicateApiSession { id: s.id.clone() });
        }
    }

    Ok(())
}

/// Walk the raw text and record every `id = "..."` line. Used ONLY to
/// decorate the DuplicateDevice error with file:line numbers —
/// detection itself runs on the parsed devices (see
/// [`validate_inventory`]). Best-effort: escaped quotes or exotic
/// string syntax make a line invisible here, in which case the error
/// falls back to line 0.
fn find_id_lines(text: &str) -> BTreeMap<String, Vec<usize>> {
    static ID_RE: OnceLock<Regex> = OnceLock::new();
    let id_re = ID_RE
        .get_or_init(|| Regex::new(r#"^\s*id\s*=\s*['"]([^'"]+)['"]"#).expect("static pattern"));

    let mut by_id: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(caps) = id_re.captures(line) {
            if let Some(matched) = caps.get(1) {
                by_id
                    .entry(matched.as_str().to_string())
                    .or_default()
                    .push(line_idx + 1);
            }
        }
    }
    by_id
}

#[cfg(test)]
mod tests {
    use super::super::types::{ApiEndpointKind, Vendor};
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write");
        f
    }

    #[test]
    fn loads_minimal_valid_file() {
        let contents = r#"
[[device]]
id = "vEX1"
host = "192.0.2.35"
port = 22
vendor = "junos"
auth = "lab-pw"

[auth.lab-pw]
username = "alice"
secret = { backend = "keyring", key = "transit/lab-pw" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.devices.len(), 1);
        assert_eq!(inv.devices[0].id, "vEX1");
        assert_eq!(inv.auth_profiles.len(), 1);
    }

    #[test]
    fn missing_file_yields_not_found() {
        let path = std::path::PathBuf::from("/definitely/not/here/transit.toml");
        match load(&path) {
            Err(InventoryError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn rejects_inline_password() {
        let contents = r#"
[[device]]
id = "vEX1"
host = "192.0.2.35"
vendor = "junos"
auth = "lab-pw"

[auth.lab-pw]
username = "alice"
password = "Juniper"
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { line, pattern, .. }) => {
                assert_eq!(line, 10);
                assert!(pattern.contains("password"));
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    #[test]
    fn rejects_pem_private_key_block() {
        let contents =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n";
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { pattern, .. }) => {
                assert!(pattern.contains("PEM"));
            }
            other => panic!("expected InlineSecret PEM, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_auth_reference() {
        let contents = r#"
[[device]]
id = "vEX1"
host = "h"
vendor = "junos"
auth = "missing-profile"

[auth.lab-pw]
username = "alice"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::UnknownAuth { id, auth }) => {
                assert_eq!(id, "vEX1");
                assert_eq!(auth, "missing-profile");
            }
            other => panic!("expected UnknownAuth, got {other:?}"),
        }
    }

    // v6.5.0 — jump-host reference validation. Fixture builder keeps
    // each case to the parts it varies: `jump` is a list of
    // (id, jump_via-or-None) pairs sharing one auth profile.
    fn jump_fixture(devices: &[(&str, Option<&str>)]) -> String {
        let mut s = String::new();
        for (id, jump) in devices {
            s.push_str(&format!(
                "[[device]]\nid = \"{id}\"\nhost = \"h\"\nvendor = \"junos\"\nauth = \"lab-pw\"\n"
            ));
            if let Some(j) = jump {
                s.push_str(&format!("jump_via = \"{j}\"\n"));
            }
            s.push('\n');
        }
        s.push_str(
            "[auth.lab-pw]\nusername = \"alice\"\nsecret = { backend = \"keyring\", key = \"k\" }\n",
        );
        s
    }

    #[test]
    fn rejects_unknown_jump_host_reference() {
        let f = write_temp(&jump_fixture(&[("vEX1", Some("no-such-device"))]));
        match load(f.path()) {
            Err(InventoryError::UnknownJumpHost { id, jump_via }) => {
                assert_eq!(id, "vEX1");
                assert_eq!(jump_via, "no-such-device");
            }
            other => panic!("expected UnknownJumpHost, got {other:?}"),
        }
    }

    #[test]
    fn rejects_self_jump_as_degenerate_cycle() {
        let f = write_temp(&jump_fixture(&[("vEX1", Some("vEX1"))]));
        match load(f.path()) {
            Err(InventoryError::JumpCycle { chain }) => {
                assert_eq!(chain, vec!["vEX1".to_string(), "vEX1".to_string()]);
            }
            other => panic!("expected JumpCycle, got {other:?}"),
        }
    }

    #[test]
    fn rejects_two_device_jump_cycle() {
        let f = write_temp(&jump_fixture(&[("a", Some("b")), ("b", Some("a"))]));
        match load(f.path()) {
            Err(InventoryError::JumpCycle { chain }) => {
                // Walk starts from the first device: a -> b -> a.
                assert_eq!(chain, vec!["a", "b", "a"]);
            }
            other => panic!("expected JumpCycle, got {other:?}"),
        }
    }

    #[test]
    fn accepts_chain_at_the_depth_cap_and_rejects_one_past_it() {
        // e -> d -> c -> b -> a is exactly MAX_JUMP_CHAIN (4) hops: OK.
        let ok = jump_fixture(&[
            ("a", None),
            ("b", Some("a")),
            ("c", Some("b")),
            ("d", Some("c")),
            ("e", Some("d")),
        ]);
        let f = write_temp(&ok);
        load(f.path()).expect("a 4-hop chain is within the cap");

        // f -> e -> d -> c -> b -> a is 5 hops: one past the cap.
        let too_deep = jump_fixture(&[
            ("a", None),
            ("b", Some("a")),
            ("c", Some("b")),
            ("d", Some("c")),
            ("e", Some("d")),
            ("f", Some("e")),
        ]);
        let f2 = write_temp(&too_deep);
        match load(f2.path()) {
            Err(InventoryError::JumpChainTooDeep { chain, max }) => {
                assert_eq!(max, MAX_JUMP_CHAIN);
                assert_eq!(chain.first().map(String::as_str), Some("f"));
            }
            other => panic!("expected JumpChainTooDeep, got {other:?}"),
        }
    }

    #[test]
    fn accepts_valid_jump_reference_and_shared_jump_host() {
        // Two devices jumping through the same bastion — the customer
        // topology — plus forward_agent round-tripping alongside.
        let mut s = jump_fixture(&[
            ("bastion", None),
            ("r1", Some("bastion")),
            ("r2", Some("bastion")),
        ]);
        s.push_str("\n[[device]]\nid = \"fwd\"\nhost = \"h\"\nvendor = \"linux\"\nauth = \"lab-pw\"\nforward_agent = true\n");
        let f = write_temp(&s);
        let inv = load(f.path()).expect("valid jump refs load");
        assert_eq!(inv.devices[1].jump_via.as_deref(), Some("bastion"));
        assert_eq!(inv.devices[2].jump_via.as_deref(), Some("bastion"));
        assert_eq!(inv.devices[3].forward_agent, Some(true));
    }

    #[test]
    fn rejects_duplicate_device_ids() {
        let contents = r#"
[[device]]
id = "dup"
host = "h"
vendor = "junos"
auth = "p"

[[device]]
id = "dup"
host = "h2"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::DuplicateDevice { id, first, second }) => {
                assert_eq!(id, "dup");
                assert!(first < second);
            }
            other => panic!("expected DuplicateDevice, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let contents = r#"
unknown_root_field = "oops"

[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::ParseFailed { .. }) => {}
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_field_error_suggests_upgrading_transit() {
        // Simulates a config written by a newer Transit that added a device
        // field this build doesn't recognize. The bare serde message is
        // unhelpful; the loader appends upgrade guidance.
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"
field_from_a_newer_version = "surprise"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::ParseFailed { message, .. }) => {
                assert!(
                    message.contains("unknown field"),
                    "expected the serde cause, got: {message}"
                );
                assert!(
                    message.contains("Upgrade Transit"),
                    "expected upgrade guidance, got: {message}"
                );
            }
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_file() {
        let mut contents = String::from("# pad\n");
        // Just over the cap, sized off the constant so this test never
        // needs updating when the cap changes.
        contents.push_str(&"#".repeat(MAX_INVENTORY_SIZE as usize + 1024));
        let f = write_temp(&contents);
        match load(f.path()) {
            Err(InventoryError::TooLarge { size, max }) => {
                assert!(size > max);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn vendor_custom_for_unrecognized_string() {
        // BYOP Phase 2b: an unrecognized vendor tag now becomes
        // `Custom(<tag>)` (so a user can supply `<tag>.yaml`), NOT the
        // `Unknown` sentinel. `as_str` round-trips the tag verbatim. A
        // Custom vendor with no loaded policy still default-denies in
        // the gate, exactly like Unknown did — only the classification
        // (and thus eligibility for a user policy) changed.
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "made_up_vendor"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(
            inv.devices[0].vendor,
            Vendor::Custom("made_up_vendor".into())
        );
        assert_eq!(inv.devices[0].vendor.as_str(), "made_up_vendor");
    }

    #[test]
    fn vendor_unknown_for_explicit_unknown_tag() {
        // The `unknown` tag still resolves to the explicit sentinel.
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "unknown"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.devices[0].vendor, Vendor::Unknown);
    }

    #[test]
    fn ssh_agent_default_no_pin() {
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        match &inv.auth_profiles["p"].secret {
            super::super::types::SecretRef::SshAgent {
                public_key_fingerprint,
            } => {
                assert!(public_key_fingerprint.is_none());
            }
            other => panic!("expected SshAgent, got {other:?}"),
        }
    }

    #[test]
    fn defaults_ssh_port_to_22() {
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.devices[0].port, 22);
    }

    #[test]
    fn rejects_password_inside_inline_table() {
        // The internally-tagged SecretRef enum silently drops unknown
        // fields, so without the prescan this plaintext would survive
        // in the file while parsing "successfully".
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k", password = "hunter2" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { line, pattern, .. }) => {
                assert_eq!(line, 10);
                assert!(pattern.contains("password"));
                assert!(!pattern.contains("hunter2"), "never echo the value");
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    #[test]
    fn rejects_quoted_password_key_inside_secret_table() {
        // A QUOTED key evades the line regex (which anchors on ^/{/,/#),
        // and the internally-tagged SecretRef then drops the unknown
        // field — so this plaintext would persist at rest. The parsed-tree
        // scan must reject it (security review 2026-07 finding #8).
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k", "password" = "hunter2" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { pattern, .. }) => {
                assert!(pattern.contains("password"));
                assert!(!pattern.contains("hunter2"), "never echo the value");
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    #[test]
    fn accepts_legitimate_secret_reference_table() {
        // Regression guard for the parsed-tree scan: a real `secret`
        // TABLE (a SecretRef) must NOT be rejected — only a *string* value
        // is a plaintext leak, so the scan keys on the value type.
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        assert!(
            load(f.path()).is_ok(),
            "a valid secret-reference table must still load"
        );
    }

    #[test]
    fn rejects_commented_out_password() {
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
# password = "hunter2"
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { line, pattern, .. }) => {
                assert_eq!(line, 11);
                assert!(pattern.contains("password"));
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    #[test]
    fn structured_secret_forms_still_pass_prescan() {
        // The widened anchors must not regress the legitimate shapes:
        // `secret = {` and a nested `passphrase = {` are followed by a
        // brace, not a quote.
        let contents = r#"
[[device]]
id = "x"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_key", path = "/k", passphrase = { backend = "keyring", key = "k" } }
"#;
        let f = write_temp(contents);
        load(f.path()).expect("structured secret refs are not inline secrets");
    }

    #[test]
    fn inline_secret_beats_utf8_error() {
        // A file with both a broken byte and an inline password must
        // report InlineSecret, not the encoding error — the prescan
        // runs over the lossy decoding first.
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"# broken byte: \xff\npassword = \"hunter2\"\n")
            .expect("write");
        match load(f.path()) {
            Err(InventoryError::InlineSecret { line, pattern, .. }) => {
                assert_eq!(line, 2);
                assert!(pattern.contains("password"));
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_device_id() {
        let contents = r#"
[[device]]
id = ""
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidDevice { reason }) => {
                assert!(reason.contains("empty id"), "reason: {reason}");
            }
            other => panic!("expected InvalidDevice, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_host() {
        let contents = r#"
[[device]]
id = "x"
host = ""
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidDevice { reason }) => {
                assert!(reason.contains("empty host"), "reason: {reason}");
            }
            other => panic!("expected InvalidDevice, got {other:?}"),
        }
    }

    #[test]
    fn rejects_port_zero() {
        let contents = r#"
[[device]]
id = "x"
host = "h"
port = 0
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidDevice { reason }) => {
                assert!(reason.contains("port 0"), "reason: {reason}");
            }
            other => panic!("expected InvalidDevice, got {other:?}"),
        }
    }

    #[test]
    fn two_empty_ids_no_longer_evade_validation() {
        // Previously the duplicate scan's regex required 1+ chars in
        // the id capture, so two `id = ""` devices loaded fine. The
        // empty-id rejection closes that hole (InvalidDevice fires
        // before duplicate detection is even reached).
        let contents = r#"
[[device]]
id = ""
host = "h1"
vendor = "junos"
auth = "p"

[[device]]
id = ""
host = "h2"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidDevice { .. }) => {}
            other => panic!("expected InvalidDevice, got {other:?}"),
        }
    }

    #[test]
    fn escaped_quote_ids_do_not_falsely_collide() {
        // `id = "a\"b"` and `id = "a\"c"` are distinct ids, but the old
        // text-scan-based duplicate detection captured `a\` for both and
        // reported a false DuplicateDevice. Detection now runs on parsed
        // ids; this file must load.
        let contents = r#"
[[device]]
id = "a\"b"
host = "h1"
vendor = "junos"
auth = "p"

[[device]]
id = "a\"c"
host = "h2"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("distinct escaped-quote ids must load");
        assert_eq!(inv.devices.len(), 2);
        assert_eq!(inv.devices[0].id, "a\"b");
        assert_eq!(inv.devices[1].id, "a\"c");
    }

    #[test]
    fn duplicate_ids_with_escaped_quotes_still_detected() {
        // Same parsed id twice, written with escapes the line scanner
        // can't read — detection still fires (on parsed data) and the
        // line numbers fall back to 0.
        let contents = r#"
[[device]]
id = "a\"b"
host = "h1"
vendor = "junos"
auth = "p"

[[device]]
id = "a\"b"
host = "h2"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::DuplicateDevice { id, first, second }) => {
                assert_eq!(id, "a\"b");
                // Scanner can't see escaped-quote ids — decoration falls back.
                assert_eq!((first, second), (0, 0));
            }
            other => panic!("expected DuplicateDevice, got {other:?}"),
        }
    }

    #[test]
    fn group_field_parses_when_present() {
        let contents = r#"
[[device]]
id = "vEX1"
host = "h"
vendor = "junos"
group = "Lab/Junos"
auth = "p"

[[device]]
id = "vEX2"
host = "h2"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.devices[0].group.as_deref(), Some("Lab/Junos"));
        assert_eq!(inv.devices[1].group, None);
    }

    // --- v4.0.0 [[api_session]] ------------------------------------

    #[test]
    fn loads_api_session_site_manager() {
        let contents = r#"
[[api_session]]
id = "office-unifi"
name = "Office UniFi"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "keyring", key = "transit/api-office-unifi" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.api_sessions.len(), 1);
        let s = &inv.api_sessions[0];
        assert_eq!(s.id, "office-unifi");
        // v6.1.0: `unifi` is a BUILT-IN vendor now (it gained a shipped
        // CLI policy), so this tag resolves to `Vendor::UniFi` rather than
        // `Custom("unifi")`. Harmless for an API session — those are gated
        // by the structural GET+confine floor, never by `PolicyEngine` —
        // and `as_str()` still returns "unifi", so every string round-trip
        // (collection selection, the API_VENDOR_OPTIONS picker, TOML
        // serialization) is byte-identical to before.
        assert_eq!(s.vendor, Vendor::UniFi);
        assert_eq!(s.kind, ApiEndpointKind::SiteManager);
        assert!(s.host.is_none());
    }

    #[test]
    fn loads_api_session_local_and_connector_proxy() {
        let contents = r#"
[[api_session]]
id = "udm"
name = "UDM Pro"
vendor = "unifi"
kind = "network_local"
host = "192.168.1.1"
secret = { backend = "keyring", key = "k1" }

[[api_session]]
id = "clientA"
name = "Client A"
vendor = "unifi"
kind = "connector_proxy"
console_id = "AAAA-BBBB"
secret = { backend = "op", reference = "op://Vault/Item/key" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert_eq!(inv.api_sessions.len(), 2);
        assert_eq!(inv.api_sessions[0].kind, ApiEndpointKind::NetworkLocal);
        assert_eq!(inv.api_sessions[0].host.as_deref(), Some("192.168.1.1"));
        assert_eq!(inv.api_sessions[1].kind, ApiEndpointKind::ConnectorProxy);
        assert_eq!(inv.api_sessions[1].console_id.as_deref(), Some("AAAA-BBBB"));
    }

    #[test]
    fn pre_v4_inventory_without_api_sessions_still_loads() {
        let contents = r#"
[[device]]
id = "vEX1"
host = "h"
vendor = "junos"
auth = "p"

[auth.p]
username = "u"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("should parse");
        assert!(inv.api_sessions.is_empty());
    }

    #[test]
    fn rejects_network_local_without_host() {
        let contents = r#"
[[api_session]]
id = "udm"
name = "UDM"
vendor = "unifi"
kind = "network_local"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidApiSession { reason }) => {
                assert!(reason.contains("network_local"), "reason: {reason}");
                assert!(reason.contains("host"), "reason: {reason}");
            }
            other => panic!("expected InvalidApiSession, got {other:?}"),
        }
    }

    #[test]
    fn rejects_connector_proxy_without_console_id() {
        let contents = r#"
[[api_session]]
id = "cp"
name = "CP"
vendor = "unifi"
kind = "connector_proxy"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidApiSession { reason }) => {
                assert!(reason.contains("connector_proxy"), "reason: {reason}");
                assert!(reason.contains("console_id"), "reason: {reason}");
            }
            other => panic!("expected InvalidApiSession, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_api_session_id() {
        let contents = r#"
[[api_session]]
id = ""
name = "X"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidApiSession { reason }) => {
                assert!(reason.contains("empty id"), "reason: {reason}");
            }
            other => panic!("expected InvalidApiSession, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_api_session_id() {
        let contents = r#"
[[api_session]]
id = "dup"
name = "A"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "keyring", key = "k1" }

[[api_session]]
id = "dup"
name = "B"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "keyring", key = "k2" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::DuplicateApiSession { id }) => assert_eq!(id, "dup"),
            other => panic!("expected DuplicateApiSession, got {other:?}"),
        }
    }

    #[test]
    fn rejects_api_session_with_sign_only_backend() {
        // A hand-edited api_session pointing its API key at a sign-only
        // backend (ssh_agent) resolves to `Unsupported` at send time; the
        // loader must reject it with a clear message instead.
        let contents = r#"
[[api_session]]
id = "bad"
name = "Bad"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "ssh_agent" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InvalidApiSession { reason }) => {
                assert!(reason.contains("value backend"), "reason: {reason}");
            }
            other => panic!("expected InvalidApiSession, got {other:?}"),
        }
    }

    #[test]
    fn allows_api_session_with_env_and_encrypted_file_backends() {
        // Both are value backends (resolve_value yields the key), so both
        // must load — only ssh_agent/ssh_key are rejected.
        let contents = r#"
[[api_session]]
id = "envk"
name = "Env"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "env", var = "TRANSIT_UNIFI_KEY" }

[[api_session]]
id = "encf"
name = "Enc"
vendor = "unifi"
kind = "site_manager"
secret = { backend = "encrypted_file", path = "/tmp/k.age" }
"#;
        let f = write_temp(contents);
        let inv = load(f.path()).expect("value backends should load");
        assert_eq!(inv.api_sessions.len(), 2);
    }

    #[test]
    fn rejects_inline_api_key_in_api_session() {
        // A literal api_key string must be caught by the inline-secret
        // prescan (before parse) — never persisted at rest.
        let contents = r#"
[[api_session]]
id = "bad"
name = "Bad"
vendor = "unifi"
kind = "site_manager"
api_key = "plaintext-oops"
secret = { backend = "keyring", key = "k" }
"#;
        let f = write_temp(contents);
        match load(f.path()) {
            Err(InventoryError::InlineSecret { pattern, .. }) => {
                assert!(pattern.contains("api_key"), "pattern: {pattern}");
            }
            other => panic!("expected InlineSecret, got {other:?}"),
        }
    }
}
