//! v6.3.0 — Save-to-file on assistant code blocks (Settings → Agent Chat).
//!
//! The community ask was "let the AI create scripts and place the files on
//! your computer." The literal version is a seventh agent tool — a Rule 2 /
//! §8 event with a prompt-injection story (scrollback convincing the model
//! to write `~/.bashrc`) — and was deliberately refused; the v7 design
//! reserves the next tool expansion for `query_context`. This is the
//! human-gated 90% answer: a Save button on the code block, and the click
//! is the entire authority.
//!
//! Design constraints, in order of load-bearing-ness:
//!
//! - **The command takes NO path parameter.** It opens the native save
//!   dialog RUST-side and writes wherever the human picked. Existing save
//!   flows (session export, settings bundle) accept a webview-supplied
//!   `destination` — fine for user-authored data, but this content is
//!   AGENT-authored, so we hold the stricter line: a compromised webview
//!   cannot direct where model output lands. First Rust-side dialog use in
//!   the codebase (capabilities gate webview→plugin IPC only, so no
//!   capability entry is involved — the `open_log_dir` precedent).
//! - **Refuses when the feature is disabled** — the command-side check is
//!   the gate; the UI hiding the button is convention
//!   (`resolve_chat_snippets`, default OFF, `[agent_chat]` config).
//! - **No re-redaction, deliberately (WYSIWYG).** The visible block is
//!   already post-redaction — device bytes were redacted before they ever
//!   entered the conversation — and a redaction pass over an
//!   assistant-authored script would mangle secret-shaped placeholders the
//!   user just reviewed on screen. What you see is exactly what lands on
//!   disk.
//! - **Never sets an execute bit; nothing ever runs the file.** Atomic
//!   write via the same tempfile+persist helper the inventory uses.
//! - `suggested_name` is sanitized HERE, not trusted from the webview —
//!   `set_file_name` reaches native dialogs, and GTK accepts path-like
//!   names.
//!
//! Threat model: T43-adjacent (the Files-pane upload argument, one notch
//! weaker — human-gated write, agent has no path to the trigger, the
//! path, or the timing).

use std::path::PathBuf;

use tauri_plugin_dialog::DialogExt;
use transit_core::inventory::mutator::write_atomic;

/// Code blocks are text; a multi-megabyte "snippet" is not a snippet.
const MAX_SNIPPET_BYTES: usize = 4 * 1024 * 1024;
const MAX_NAME_LEN: usize = 64;
const FALLBACK_NAME: &str = "snippet.txt";

/// Strip anything that could make the dialog's pre-filled name path-like
/// or invisible: keep only the final path segment, drop control chars and
/// the forbidden Win32 set (`< > : " | ? *` — the dialog pre-fill reaches
/// native shells on every OS), strip leading dots (hidden files) and
/// trailing dots/spaces (Win32 rejects them), cap the length, refuse
/// reserved Windows device stems (`CON`, `NUL`, `COM1`… — a model can
/// fence a block as ```con), and fall back to a boring name when nothing
/// survives.
fn sanitize_suggested_name(raw: &str) -> String {
    const WIN_FORBIDDEN: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
    let tail = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = tail
        .chars()
        .filter(|c| !c.is_control() && !WIN_FORBIDDEN.contains(c))
        .collect();
    let trimmed = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' ']);
    let capped: String = trimmed.chars().take(MAX_NAME_LEN).collect();
    let stem = capped.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if capped.trim().is_empty() || reserved {
        FALLBACK_NAME.to_string()
    } else {
        capped
    }
}

/// Save one chat code block to a file the USER picks in the native save
/// dialog. Returns the chosen path for the toast, or `None` when the user
/// cancelled the dialog (not an error).
#[tauri::command]
pub async fn save_chat_snippet(
    app: tauri::AppHandle,
    contents: String,
    suggested_name: String,
) -> Result<Option<String>, String> {
    let feature = crate::commands::resolve_chat_snippets()?;
    if !feature.enabled {
        return Err(
            "Saving chat code blocks is turned off — enable it in Settings → Agent Chat."
                .to_string(),
        );
    }
    if contents.len() > MAX_SNIPPET_BYTES {
        return Err("This code block is too large to save (4 MiB limit).".to_string());
    }

    let name = sanitize_suggested_name(&suggested_name);
    // Best-effort: the dialog opens at the configured folder; creating it
    // here means a fresh config never points the dialog at a missing dir.
    let _ = std::fs::create_dir_all(&feature.dir);

    // `save_file` takes a callback (it hops to the main thread
    // internally); a oneshot bridges it back to this async command. Do
    // NOT use `blocking_save_file` — it parks a tokio worker for the
    // dialog's lifetime.
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_directory(&feature.dir)
        .set_file_name(&name)
        .save_file(move |picked| {
            let _ = tx.send(picked);
        });
    let picked = rx
        .await
        .map_err(|_| "couldn't open the save dialog".to_string())?;
    let Some(file_path) = picked else {
        return Ok(None); // user cancelled — not an error
    };
    let path: PathBuf = file_path
        .into_path()
        .map_err(|e| format!("unusable save location: {e}"))?;

    // tempfile + rename; the tempfile's default permissions carry no
    // execute bit, and `persist` preserves them.
    write_atomic(&path, &contents).map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The webview's suggestion is DATA: separators become dashes, control
    /// chars vanish, dot-prefixes (hidden files) are stripped, and an
    /// empty/hostile result falls back to a boring name.
    #[test]
    fn suggested_name_is_sanitized() {
        assert_eq!(sanitize_suggested_name("show_run.txt"), "show_run.txt");
        // Path-like suggestions keep only their final segment.
        assert_eq!(sanitize_suggested_name("scripts/deploy.sh"), "deploy.sh");
        assert_eq!(sanitize_suggested_name("../../.bashrc"), "bashrc");
        assert_eq!(sanitize_suggested_name("a/b\\c:d"), "cd");
        assert_eq!(sanitize_suggested_name("evil\u{0007}name"), "evilname");
        // Win32-forbidden chars vanish; trailing dots/spaces trimmed.
        assert_eq!(sanitize_suggested_name("a<b>c\"d|e?f*g.txt"), "abcdefg.txt");
        assert_eq!(sanitize_suggested_name("report. "), "report");
        // Reserved Windows device stems fall back — the OS can't create
        // them, and the dialog pre-fill reaches native shells.
        assert_eq!(sanitize_suggested_name("nul.txt"), FALLBACK_NAME);
        assert_eq!(sanitize_suggested_name("CON.sh"), FALLBACK_NAME);
        assert_eq!(sanitize_suggested_name("com1"), FALLBACK_NAME);
        assert_eq!(sanitize_suggested_name("console.log"), "console.log");
        assert_eq!(sanitize_suggested_name("   "), FALLBACK_NAME);
        assert_eq!(sanitize_suggested_name(".."), FALLBACK_NAME);
        assert_eq!(sanitize_suggested_name(""), FALLBACK_NAME);
        assert!(sanitize_suggested_name(&"x".repeat(500)).chars().count() <= MAX_NAME_LEN);
    }

    /// Unix: the written file must carry no execute bit. (The dialog can't
    /// run headless, so this pins the write helper's permissions instead —
    /// the same helper the command uses.)
    #[cfg(unix)]
    #[test]
    fn snippet_file_has_no_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snippet.sh");
        write_atomic(&path, "#!/bin/sh\necho hi\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0, "no execute bit for anyone (mode {mode:o})");
    }
}
