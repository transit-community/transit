//! Wire types for the local-PTY transport.

use serde::Deserialize;

/// Fallback terminal geometry when a launch omits one. The frontend
/// re-sends the real size via `resize` as soon as the pane mounts, so
/// this only shapes the first fraction of a second.
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;

/// Parameters for spawning a local shell in a PTY.
///
/// `Deserialize` only — this is IPC input from the frontend launcher.
///
/// **There is deliberately no `vendor` field.** A local shell is ALWAYS
/// [`transit_core::inventory::Vendor::LocalShell`] (set inside
/// [`crate::Session::open`]), never a caller-chosen network vendor. The
/// agent is structurally blind to local shells, and fixing the vendor
/// here keeps a hostile or confused frontend from labelling a local
/// shell as, say, `linux` — which carries the unrestricted-vendor
/// carve-out written for a reimageable remote box, not the user's own
/// filesystem. See the local terminal surface design notes (not included in this repository)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OpenParams {
    /// The shell executable — an absolute path or a bare name resolved
    /// on `PATH` (e.g. `/bin/zsh`, `pwsh.exe`, `cmd.exe`).
    pub program: String,

    /// Argv passed to the shell (e.g. `["-l"]` for an interactive login
    /// shell on Unix). Empty is fine.
    #[serde(default)]
    pub args: Vec<String>,

    /// Working directory. `None` → the user's home directory (a bare
    /// shell should not inherit the app's CWD).
    #[serde(default)]
    pub cwd: Option<String>,

    /// Extra environment entries layered on top of the inherited env
    /// (after the transport's own `TERM` / `COLORTERM`). Ordered.
    /// Unused by the v1 launcher (reserved for named profiles).
    #[serde(default)]
    pub env: Vec<(String, String)>,

    /// Friendly tab label (e.g. `zsh`). Purely cosmetic.
    pub label: String,

    /// Initial column count.
    #[serde(default = "default_cols")]
    pub cols: u16,

    /// Initial row count.
    #[serde(default = "default_rows")]
    pub rows: u16,
}

fn default_cols() -> u16 {
    DEFAULT_COLS
}

fn default_rows() -> u16 {
    DEFAULT_ROWS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_minimal_launch() {
        // The launcher can send just program + label; geometry defaults
        // and the optional fields are absent.
        let json = r#"{ "program": "/bin/zsh", "label": "zsh" }"#;
        let p: OpenParams = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.program, "/bin/zsh");
        assert_eq!(p.label, "zsh");
        assert_eq!(p.cols, DEFAULT_COLS);
        assert_eq!(p.rows, DEFAULT_ROWS);
        assert!(p.args.is_empty());
        assert!(p.cwd.is_none());
    }

    #[test]
    fn deserializes_full_launch() {
        let json = r#"{
            "program": "/bin/bash",
            "args": ["-l"],
            "cwd": "/tmp",
            "label": "bash",
            "cols": 120,
            "rows": 40
        }"#;
        let p: OpenParams = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.args, vec!["-l"]);
        assert_eq!(p.cwd.as_deref(), Some("/tmp"));
        assert_eq!(p.cols, 120);
        assert_eq!(p.rows, 40);
    }
}
