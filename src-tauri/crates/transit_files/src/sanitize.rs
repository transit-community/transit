//! The T43 boundary: **remote-supplied names are hostile input.**
//!
//! A compromised or malicious device answers `SSH_FXP_READDIR` with any
//! bytes it likes — `..`, `../../.ssh/authorized_keys`, an embedded
//! separator, a NUL. Every one of those names would otherwise be joined
//! onto a user-chosen local directory during a recursive download, which
//! is a path-traversal write primitive. So: **no remote name influences a
//! local path (or a remote path we construct) without passing through
//! here first.**
//!
//! The rules are deliberately *structural*, not a blocklist of known-bad
//! strings: a valid entry name is exactly one path component, so anything
//! that could be read as more than one component is refused. Unicode is
//! fine (`конфиг.txt`, `設定.conf`, `naïve`) — it cannot escape a
//! directory.

use crate::error::NameError;

/// Validate a single directory-entry name for use as one path component.
///
/// Called on every name a listing or a recursive walk yields, in both
/// directions (a *local* name is about to become a remote path component
/// on upload, so it gets the same treatment).
///
/// `\` is refused unconditionally, not just on Windows: a name is
/// validated once, in the crate, and may be joined onto a local path on
/// any of the three platforms Transit ships on. Rejecting it everywhere
/// means a macOS user and a Windows user get the same answer for the same
/// device.
pub fn validate_remote_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name == "." || name == ".." {
        return Err(NameError::DotSegment);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(NameError::Separator);
    }
    if name.chars().any(char::is_control) {
        return Err(NameError::ControlChar);
    }
    Ok(())
}

/// Validate a name that is about to be written to the **local** disk.
///
/// Everything [`validate_remote_name`] refuses, plus the Windows-only
/// unusable forms — reserved device names (`CON`, `NUL`, `COM3`…), the
/// characters Win32 forbids, and trailing dots/spaces. Those are enforced
/// only when the local side actually is Windows: on macOS/Linux a file
/// legitimately named `aux` or `report.` must still download.
pub(crate) fn validate_local_write_name(name: &str) -> Result<(), NameError> {
    validate_remote_name(name)?;
    #[cfg(windows)]
    if windows_unsafe_name(name) {
        return Err(NameError::WindowsReserved);
    }
    Ok(())
}

/// Whether `name` is unusable as a Windows file name.
///
/// A pure predicate compiled on **every** platform so the corpus test
/// covers it from a macOS dev machine — the cfg gate lives in
/// [`validate_local_write_name`], not here. On non-Windows the only
/// non-test caller (that cfg branch) is compiled out, so allow it to be
/// "dead" there now that it is crate-internal and no longer re-exported
/// (finding D4).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows_unsafe_name(name: &str) -> bool {
    const FORBIDDEN: [char; 9] = ['<', '>', ':', '"', '|', '?', '*', '/', '\\'];
    const RESERVED_STEMS: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

    if name.is_empty() {
        return true;
    }
    if name.chars().any(|c| FORBIDDEN.contains(&c)) {
        return true;
    }
    // Win32 silently strips these, so `report.` and `report` would
    // collide — and a "download" could overwrite an unrelated file.
    if name.ends_with('.') || name.ends_with(' ') {
        return true;
    }
    // Reserved device names apply to the stem, with or without an
    // extension: `NUL`, `nul.txt`, `COM4.log` are all unopenable.
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        return true;
    }
    if let Some(digit) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    {
        // COM1-COM9 / LPT1-LPT9 (COM0 is not reserved).
        if digit.len() == 1 && matches!(digit.as_bytes()[0], b'1'..=b'9') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The T43 corpus. Every entry here is a name a hostile device could
    /// return from `readdir`; none may ever reach a path join.
    #[test]
    fn rejects_traversal_and_separator_shapes() {
        let cases: &[(&str, NameError)] = &[
            ("", NameError::Empty),
            (".", NameError::DotSegment),
            ("..", NameError::DotSegment),
            ("a/b", NameError::Separator),
            ("../evil", NameError::Separator),
            ("../../.ssh/authorized_keys", NameError::Separator),
            ("/etc/passwd", NameError::Separator),
            ("dir/", NameError::Separator),
            ("..\\evil", NameError::Separator),
            ("C:\\Windows\\System32", NameError::Separator),
            ("nul\0byte", NameError::ControlChar),
            ("bell\u{7}", NameError::ControlChar),
            ("line\nbreak", NameError::ControlChar),
            // A CSI sequence in a filename would otherwise repaint the
            // queue strip / a log line.
            ("\u{1b}[2Kspoof", NameError::ControlChar),
        ];
        for (name, expected) in cases {
            assert_eq!(
                validate_remote_name(name),
                Err(*expected),
                "expected {name:?} to be refused as {expected:?}"
            );
        }
    }

    #[test]
    fn accepts_ordinary_and_unicode_names() {
        for name in [
            "juniper.conf",
            ".bashrc",
            "...",
            "..hidden",
            "a..b",
            "report 2026.txt",
            "конфиг.txt",
            "設定.conf",
            "naïve",
            "emoji-🚀.log",
            // A single trailing space is legal on POSIX; only the
            // Windows-local writer refuses it.
            "trailing ",
        ] {
            assert_eq!(
                validate_remote_name(name),
                Ok(()),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn windows_reserved_names_are_detected_on_every_platform() {
        for name in [
            "CON",
            "con",
            "NUL",
            "nul.txt",
            "AUX",
            "prn",
            "COM1",
            "com9",
            "LPT3",
            "lpt1.log",
            "report.",
            "trailing ",
            "a:b",
            "q?",
            "star*",
            "pipe|x",
            "lt<gt>",
        ] {
            assert!(
                windows_unsafe_name(name),
                "expected {name:?} to be flagged unusable on Windows"
            );
        }
        for name in [
            "COM0",
            "COM10",
            "console.log",
            "nullify.txt",
            "auxiliary",
            "juniper.conf",
            "конфиг.txt",
        ] {
            assert!(
                !windows_unsafe_name(name),
                "expected {name:?} to be usable on Windows"
            );
        }
    }

    /// The local-write gate must be at least as strict as the remote one
    /// on every platform (it adds rules, never removes them).
    #[test]
    fn local_write_gate_is_a_superset_of_the_remote_gate() {
        for name in ["", ".", "..", "a/b", "x\0y"] {
            assert!(validate_local_write_name(name).is_err());
        }
        assert!(validate_local_write_name("juniper.conf").is_ok());
        #[cfg(windows)]
        assert_eq!(
            validate_local_write_name("NUL"),
            Err(NameError::WindowsReserved)
        );
        #[cfg(not(windows))]
        assert!(validate_local_write_name("NUL").is_ok());
    }
}
