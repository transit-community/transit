//! MobaXterm importer for `MobaXterm.ini` bookmark sections and
//! `.mxtsessions` exports (same format). Hand-rolled line scanner — the
//! format is INI-shaped but the session values have their own encoding,
//! so a generic INI crate buys nothing.
//!
//! Layout: `[Bookmarks]` / `[Bookmarks_N]` sections, one per folder.
//! Each section carries `SubRep=` (the `\`-separated folder path; empty
//! at the root) and `ImgNum=` (folder icon, ignored), and then one
//! `Name=#Icon#Type%field%field%…` line per session:
//!
//! - `#Icon` — icon number, ignored.
//! - `#Type` — session type; **only SSH (0) is imported**. Others
//!   (telnet 1, RDP 4, VNC 5, SFTP 7, browser 11, …) are skipped with a
//!   warning naming the type.
//! - `%`-separated fields for SSH: `[1]` host, `[2]` port, `[3]`
//!   username, `[14]` private-key path (position is version-dependent —
//!   treated as best-effort).
//!
//! Values use MobaXterm's escape tokens (`__PIPE__`, `__PERCENT__`, …)
//! and `_CurrentDrive_` for the install drive letter (assumed `C:` —
//! a wrong guess surfaces as an unreadable key path in the credential
//! step, never a wrong import).
//!
//! **Stored passwords are NEVER read**: MobaXterm keeps session
//! passwords in its own credential store (not in the bookmark line), so
//! there is nothing to refuse — but key *paths* are the only
//! credential-adjacent field this parser touches.

use std::path::PathBuf;

use super::{AuthKind, ImportError, ImportedConnection, ParsedImport};

pub fn parse_mobaxterm(text: &str) -> Result<ParsedImport, ImportError> {
    let mut out = ParsedImport::default();
    let mut in_bookmarks = false;
    let mut saw_bookmarks_section = false;
    let mut group_path: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_bookmarks = section == "Bookmarks" || section.starts_with("Bookmarks_");
            saw_bookmarks_section |= in_bookmarks;
            group_path = None;
            continue;
        }
        if !in_bookmarks {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "SubRep" => {
                group_path = (!value.is_empty()).then(|| {
                    value
                        .split('\\')
                        .map(|seg| unescape(seg).replace('/', "-"))
                        .collect::<Vec<_>>()
                        .join("/")
                });
            }
            "ImgNum" => {}
            _ if value.starts_with('#') => {
                build_session(key, value, group_path.as_deref(), &mut out);
            }
            _ => {}
        }
    }

    if !saw_bookmarks_section {
        return Err(ImportError::Empty(
            "no [Bookmarks] section found (not a MobaXterm.ini / .mxtsessions file?)".into(),
        ));
    }
    Ok(out)
}

fn build_session(name: &str, value: &str, group_path: Option<&str>, out: &mut ParsedImport) {
    let name = unescape(name);
    let fields: Vec<&str> = value.split('%').collect();
    // fields[0] is the `#Icon#Type` prefix.
    let session_type = fields[0].rsplit('#').next().unwrap_or("");
    if session_type != "0" {
        let proto = match session_type {
            "1" => "telnet".to_string(),
            "2" => "rsh".to_string(),
            "3" => "xdmcp".to_string(),
            "4" => "RDP".to_string(),
            "5" => "VNC".to_string(),
            "6" => "FTP".to_string(),
            "7" => "SFTP".to_string(),
            "9" => "browser".to_string(),
            "10" => "mosh".to_string(),
            // Verified against a real 2026 .mobaconf (WSL-Ubuntu* entries).
            "14" => "WSL".to_string(),
            other => format!("session type {other}"),
        };
        out.warnings
            .push(format!("skipped non-SSH session '{name}' ({proto})"));
        return;
    }

    let field = |i: usize| -> Option<String> {
        fields
            .get(i)
            .map(|s| unescape(s.trim()))
            .filter(|s| !s.is_empty())
    };

    let Some(host) = field(1) else {
        out.warnings.push(format!("skipped '{name}': no host"));
        return;
    };
    let port = field(2).and_then(|p| p.parse::<u16>().ok()).unwrap_or(22);
    let username = field(3);
    // Best-effort: the private-key slot moved across MobaXterm versions;
    // only accept a value that actually looks like a path.
    let key_path = field(14)
        .filter(|v| v.contains('\\') || v.contains('/'))
        .map(PathBuf::from);

    let auth_kind = if key_path.is_some() {
        AuthKind::PublicKeyFile
    } else {
        // Moba stores passwords in its own credential store — invisible
        // here, so the honest answer is "unknown" (flagged to the user).
        AuthKind::Unknown
    };

    out.connections.push(ImportedConnection {
        source_name: name,
        host,
        port,
        username,
        group_path: group_path.map(String::from),
        jump_host: None,
        key_path,
        vendor_hint: None,
        auth_kind,
        credential_link: None,
    });
}

/// Undo MobaXterm's value-escaping tokens.
fn unescape(s: &str) -> String {
    s.replace("__PIPE__", "|")
        .replace("__PERCENT__", "%")
        .replace("__PTVIRG__", ";")
        .replace("__DBLQUO__", "\"")
        .replace("__DIEZE__", "#")
        .replace("_CurrentDrive_", "C")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"[Bookmarks]
SubRep=
ImgNum=42
core-sw1=#109#0%10.0.1.1%22%admin%%-1%-1%%%%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%-1%_Std_Colors_0_%80%24%0%1%-1%<none>%%0#0# #-1
web-ui=#313#9%https://10.0.1.1%0%%%-1%-1%%%%%0%0%0%%%-1%0%0%0#0# #-1

[Bookmarks_1]
SubRep=Lab\Core
ImgNum=41
vEX2=#109#0%10.0.2.1%2222%netops%%-1%-1%%%%%0%0%0%_CurrentDrive_:\keys\lab.ppk%%-1%0%0%0%%1080%%0%0%1#0# #-1
old-rtr=#98#1%10.0.2.9%23%%%-1%-1#0# #-1

[Bookmarks_2]
SubRep=Odd__PIPE__Name\Sub/Folder
ImgNum=41
weird__DIEZE__box=#109#0%10.0.3.1%22%%%-1%-1#0# #-1
";

    #[test]
    fn parses_sessions_folders_and_warnings() {
        let out = parse_mobaxterm(SAMPLE).unwrap();
        let names: Vec<&str> = out
            .connections
            .iter()
            .map(|c| c.source_name.as_str())
            .collect();
        assert_eq!(names, vec!["core-sw1", "vEX2", "weird#box"]);

        let sw1 = &out.connections[0];
        assert_eq!(sw1.host, "10.0.1.1");
        assert_eq!(sw1.port, 22);
        assert_eq!(sw1.username.as_deref(), Some("admin"));
        assert!(sw1.group_path.is_none()); // root [Bookmarks], empty SubRep
        assert_eq!(sw1.auth_kind, AuthKind::Unknown);

        let vex = &out.connections[1];
        assert_eq!(vex.port, 2222);
        assert_eq!(vex.group_path.as_deref(), Some("Lab/Core"));
        assert_eq!(vex.key_path, Some(PathBuf::from(r"C:\keys\lab.ppk")));
        assert_eq!(vex.auth_kind, AuthKind::PublicKeyFile);

        // Escapes: folder name pipe restored; '/' in a segment sanitized.
        let weird = &out.connections[2];
        assert_eq!(weird.group_path.as_deref(), Some("Odd|Name/Sub-Folder"));

        // Non-SSH sessions → warnings naming the type.
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("web-ui") && w.contains("browser")));
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("old-rtr") && w.contains("telnet")));
    }

    #[test]
    fn errors_without_bookmarks_section() {
        assert!(matches!(
            parse_mobaxterm("[SomethingElse]\nfoo=bar\n"),
            Err(ImportError::Empty(_))
        ));
        assert!(matches!(
            parse_mobaxterm("not an ini at all"),
            Err(ImportError::Empty(_))
        ));
    }

    #[test]
    fn empty_bookmarks_section_is_ok_but_empty() {
        let out = parse_mobaxterm("[Bookmarks]\nSubRep=\nImgNum=42\n").unwrap();
        assert!(out.connections.is_empty());
        assert!(out.warnings.is_empty());
    }
}
