//! v6.3.0 — opt-in chat-history persistence (Settings → Agent Chat).
//!
//! The durable state is the chat's wire log (`Vec<ChatMessage>`) — NOT the
//! agent `Conversation`, which `chat_send_message` rebuilds from this log
//! every turn anyway. So a restored chat's next send reuses the exact
//! replay path a live chat's turn 2 uses, and nothing in `transit_agent`
//! is touched by this feature.
//!
//! Invariants, in order of load-bearing-ness:
//!
//! - **Security state never persists.** `ChatHistoryFile` structurally has
//!   no field for the always-allow map (T18), the device scope (T31), the
//!   API auto-approve flag, or the session ledger — their "in-memory only,
//!   never persisted" doc comments in chat.rs stay true, and a restored
//!   chat is rebuilt with factory-fresh security state.
//! - **`chat_id` is UUID-validated before EVERY filesystem join.** The id
//!   reaching `persist`/`delete` originates from the webview
//!   (`chat_destroy`), so an unvalidated `dir.join(format!("{id}.json"))`
//!   would be a path-traversal write/delete primitive. The loader trusts
//!   only UUID-parseable filename stems for the same reason — the history
//!   dir is user-writable.
//! - **Re-redaction at the disk boundary.** Everything in the log is
//!   post-redaction by construction (device bytes are redacted before they
//!   ever enter a conversation), but both existing device-derived disk
//!   writers (session_export, session_log) re-run the filter at the write
//!   boundary as defense in depth, and this writer follows suit — field by
//!   field, BEFORE serialization, so a marker substitution can never break
//!   the JSON structure.
//! - **Lenient, bounded loading.** A corrupt/oversized/foreign file is
//!   skipped with a warning, never fatal (`load_user_dir` posture); per-
//!   file size cap before read; tail-keep message cap; newest-`cap` files
//!   by `saved_at` (a backend session without a tab would be unreachable —
//!   the frontend caps tabs). Files beyond the cap are never opened and
//!   never deleted: the dir is the user's.
//!
//! Threat model: chat-history data-at-rest entry (threat-model.md, v6.3.0).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;
use transit_agent::RedactionFilter;
use uuid::Uuid;

use crate::chat::ChatMessage;

/// Bump when the on-disk shape changes; the loader skips versions it
/// doesn't know rather than guessing.
pub const HISTORY_FORMAT_VERSION: u32 = 1;
/// A transcript is text; a multi-megabyte file is not one of ours.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Tail-keep bound applied at load — the replay path re-sends history to
/// the model each turn, so an unbounded restored log is an unbounded
/// prompt (T34 refuses oversized sends on local models; this bounds the
/// cloud case too).
const MAX_MESSAGES: usize = 400;

/// The persisted shape. Structurally excludes security state — adding
/// such a field is a threat-model event, not a convenience.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChatHistoryFile {
    pub version: u32,
    pub chat_id: String,
    pub model: String,
    /// Unix seconds at write; restore orders by this.
    pub saved_at: u64,
    pub messages: Vec<ChatMessage>,
}

/// One restorable chat, loader-validated.
pub struct RestoredChat {
    pub chat_id: String,
    pub model: String,
    pub saved_at: u64,
    pub messages: Vec<ChatMessage>,
}

fn require_uuid(chat_id: &str) -> Result<(), String> {
    Uuid::parse_str(chat_id)
        .map(|_| ())
        .map_err(|_| format!("refusing a non-UUID chat id: {chat_id:?}"))
}

fn file_for(dir: &Path, chat_id: &str) -> PathBuf {
    dir.join(format!("{chat_id}.json"))
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One process-wide filter. `RedactionFilter::standard()` compiles ~75
/// regexes; rebuilding it per persist (a per-turn hot path) threw away
/// milliseconds every turn (review finding — session_log's per-chunk
/// path already hoists its filter the same way).
static FILTER: std::sync::LazyLock<RedactionFilter> =
    std::sync::LazyLock::new(RedactionFilter::standard);

/// Field-level defense-in-depth pass, IN PLACE on the caller's owned
/// snapshot. Operates on the message fields BEFORE serialization so a
/// `[REDACTED:…]` substitution can never break the JSON structure, and
/// mutates rather than rebuilding — the snapshot is already the persist
/// path's private copy, and a second full Vec (with deep `input` Value
/// clones that are never redacted) was pure waste.
fn redact_messages(messages: &mut [ChatMessage]) {
    for m in messages {
        match m {
            ChatMessage::User { text } | ChatMessage::Assistant { text } => {
                *text = FILTER.redact(text);
            }
            ChatMessage::ToolUse { output, .. } => {
                *output = FILTER.redact(output);
            }
        }
    }
}

/// Persist one chat's transcript (the snapshot is taken BY VALUE — it's
/// the caller's private copy, redacted in place here). No file until the
/// first message exists (empty chats never restore). Atomic write —
/// overwrite-in-place is the write-through model's contract. Compact
/// JSON, deliberately: the file is the app's, not a human artifact, and
/// pretty-printing costs ~25% more bytes against the size cap.
pub fn persist_chat(
    dir: &Path,
    chat_id: &str,
    model: &str,
    mut messages: Vec<ChatMessage>,
) -> Result<(), String> {
    require_uuid(chat_id)?;
    if messages.is_empty() {
        return Ok(());
    }
    redact_messages(&mut messages);
    let record = ChatHistoryFile {
        version: HISTORY_FORMAT_VERSION,
        chat_id: chat_id.to_string(),
        model: model.to_string(),
        saved_at: now_unix(),
        messages,
    };
    let json = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create the history folder: {e}"))?;
    transit_core::inventory::mutator::write_atomic(&file_for(dir, chat_id), &json)
        .map_err(|e| e.to_string())
}

/// Delete one chat's history file, best-effort ("close means gone" —
/// unconditionally, so a chat closed while the feature was off doesn't
/// resurrect when it's re-enabled).
pub fn delete_chat(dir: &Path, chat_id: &str) -> Result<(), String> {
    require_uuid(chat_id)?;
    match std::fs::remove_file(file_for(dir, chat_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove the chat history file: {e}")),
    }
}

/// Log only the FILE NAME, never the full path: `history_dir` can point
/// at a shared or synced folder, and a diagnostic log a customer can
/// read is one they can publish — sibling filenames from such a folder
/// don't belong in it (§10 posture).
fn log_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "<unnamed>".into())
}

/// Load the newest `cap` restorable chats in `dir` by `saved_at`,
/// returned oldest→newest (left-to-right tab order).
///
/// Two-pass: candidate paths are filtered and mtime-ranked WITHOUT
/// reading them, and only the newest few are parsed — launch must not
/// pay a full read+parse of every file ever accumulated to keep 8
/// (review finding). mtime is only the PRE-selection heuristic; the
/// authoritative order is the parsed `saved_at`, so the pre-selection
/// takes a 2× margin to absorb mtime ties/drift.
pub fn load_all(dir: &Path, cap: usize) -> Vec<RestoredChat> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    // Pass 1 — path-level filter (extension, UUID stem, size cap) and
    // mtime ranking. No file contents are touched.
    let mut candidates: Vec<(std::time::SystemTime, PathBuf, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
            continue;
        };
        if Uuid::parse_str(&stem).is_err() {
            warn!(file = %log_name(&path), "ignoring non-UUID file in the chat history folder");
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            warn!(file = %log_name(&path), bytes = meta.len(), "skipping oversized chat history file");
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        candidates.push((mtime, path, stem));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(b.2.cmp(&a.2)));
    let margin = cap.saturating_mul(2).max(cap);
    if candidates.len() > margin {
        warn!(
            skipped = candidates.len() - margin,
            "older chat histories left on disk (tab cap); they are not deleted"
        );
        candidates.truncate(margin);
    }

    // Pass 2 — read + parse only the pre-selected few.
    let mut out: Vec<RestoredChat> = Vec::new();
    for (_, path, stem) in candidates {
        let Ok(text) = std::fs::read_to_string(&path) else {
            warn!(file = %log_name(&path), "skipping unreadable chat history file");
            continue;
        };
        let Ok(mut record) = serde_json::from_str::<ChatHistoryFile>(&text) else {
            warn!(file = %log_name(&path), "skipping corrupt chat history file");
            continue;
        };
        if record.version != HISTORY_FORMAT_VERSION {
            warn!(
                file = %log_name(&path),
                version = record.version,
                "skipping chat history from an unknown format version"
            );
            continue;
        }
        if record.messages.len() > MAX_MESSAGES {
            let excess = record.messages.len() - MAX_MESSAGES;
            record.messages.drain(..excess);
        }
        if record.messages.is_empty() {
            continue;
        }
        // The VALIDATED filename stem is authoritative for the id — the
        // JSON body is user-editable and must not redirect a delete.
        // Constructing directly from `stem` makes that structural: the
        // untrusted `record.chat_id` is never moved out.
        out.push(RestoredChat {
            chat_id: stem,
            model: record.model,
            saved_at: record.saved_at,
            messages: record.messages,
        });
    }
    out.sort_by(|a, b| a.saved_at.cmp(&b.saved_at).then(a.chat_id.cmp(&b.chat_id)));
    if out.len() > cap {
        let excess = out.len() - cap;
        out.drain(..excess);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_user(text: &str) -> ChatMessage {
        ChatMessage::User {
            text: text.to_string(),
        }
    }

    fn msg_assistant(text: &str) -> ChatMessage {
        ChatMessage::Assistant {
            text: text.to_string(),
        }
    }

    fn uuid() -> String {
        Uuid::new_v4().to_string()
    }

    /// The on-disk shape structurally excludes security state: the words
    /// simply cannot appear in a serialized file unless a message body
    /// contains them.
    #[test]
    fn history_file_never_contains_security_state() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        persist_chat(dir.path(), &id, "claude-opus-4-7", vec![msg_user("hello")]).unwrap();
        let text = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
        for forbidden in ["always_allow", "scope", "ledger", "auto_approve"] {
            assert!(
                !text.contains(forbidden),
                "persisted file must not contain {forbidden:?}"
            );
        }
    }

    #[test]
    fn persist_then_load_round_trips_messages_and_model() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        let messages = vec![msg_user("show version"), msg_assistant("Junos 23.4R2")];
        persist_chat(dir.path(), &id, "claude-sonnet-4-6", messages.clone()).unwrap();
        let restored = load_all(dir.path(), 8);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].chat_id, id);
        assert_eq!(restored[0].model, "claude-sonnet-4-6");
        assert_eq!(
            serde_json::to_value(&restored[0].messages).unwrap(),
            serde_json::to_value(&messages).unwrap()
        );
    }

    #[test]
    fn persist_overwrites_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        persist_chat(dir.path(), &id, "m", vec![msg_user("one")]).unwrap();
        persist_chat(
            dir.path(),
            &id,
            "m",
            vec![msg_user("one"), msg_assistant("two")],
        )
        .unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(files.len(), 1, "overwrite in place, no siblings/tempfiles");
        let restored = load_all(dir.path(), 8);
        assert_eq!(restored[0].messages.len(), 2);
    }

    /// Defense-in-depth: a secret-shaped token in a message body must hit
    /// the redaction filter at the write boundary — the file bytes carry
    /// the marker, never the raw token (session_export precedent).
    #[test]
    fn persist_re_redacts_at_the_write_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        let key = "AKIAIOSFODNN7EXAMPLE";
        persist_chat(
            dir.path(),
            &id,
            "m",
            vec![msg_assistant(&format!("found credential {key} in config"))],
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
        assert!(
            !text.contains(key),
            "raw AWS-shaped key must not reach disk"
        );
        assert!(text.contains("REDACTED"), "the marker replaces it");
    }

    #[test]
    fn persist_and_delete_refuse_non_uuid_ids() {
        let dir = tempfile::tempdir().unwrap();
        for hostile in ["../evil", "..", "x/y", "not-a-uuid"] {
            assert!(persist_chat(dir.path(), hostile, "m", vec![msg_user("x")]).is_err());
            assert!(delete_chat(dir.path(), hostile).is_err());
        }
    }

    #[test]
    fn empty_chats_write_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        persist_chat(dir.path(), &id, "m", Vec::new()).unwrap();
        assert!(!dir.path().join(format!("{id}.json")).exists());
    }

    #[test]
    fn delete_is_best_effort_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        delete_chat(dir.path(), &id).unwrap(); // nothing there — fine
        persist_chat(dir.path(), &id, "m", vec![msg_user("x")]).unwrap();
        delete_chat(dir.path(), &id).unwrap();
        assert!(!dir.path().join(format!("{id}.json")).exists());
    }

    #[test]
    fn load_ignores_non_uuid_filenames_and_corrupt_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.json"), "{}").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hi").unwrap();
        let id = uuid();
        std::fs::write(dir.path().join(format!("{id}.json")), "{ not json").unwrap();
        let good = uuid();
        persist_chat(dir.path(), &good, "m", vec![msg_user("x")]).unwrap();
        let restored = load_all(dir.path(), 8);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].chat_id, good);
    }

    #[test]
    fn load_refuses_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        let big = "x".repeat((MAX_FILE_BYTES + 1) as usize);
        std::fs::write(dir.path().join(format!("{id}.json")), big).unwrap();
        assert!(load_all(dir.path(), 8).is_empty());
    }

    #[test]
    fn load_tail_keeps_messages_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        let messages: Vec<ChatMessage> = (0..MAX_MESSAGES + 3)
            .map(|i| msg_user(&format!("m{i}")))
            .collect();
        persist_chat(dir.path(), &id, "m", messages).unwrap();
        let restored = load_all(dir.path(), 8);
        assert_eq!(restored[0].messages.len(), MAX_MESSAGES);
        // Tail-keep: the OLDEST messages fall off.
        match &restored[0].messages[0] {
            ChatMessage::User { text } => assert_eq!(text, "m3"),
            other => panic!("unexpected head: {other:?}"),
        }
    }

    #[test]
    fn load_caps_at_newest_by_saved_at_in_tab_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut ids = Vec::new();
        for i in 0..10u64 {
            let id = uuid();
            let record = ChatHistoryFile {
                version: HISTORY_FORMAT_VERSION,
                chat_id: id.clone(),
                model: "m".into(),
                saved_at: 1000 + i,
                messages: vec![msg_user(&format!("chat {i}"))],
            };
            std::fs::write(
                dir.path().join(format!("{id}.json")),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            ids.push(id);
        }
        let restored = load_all(dir.path(), 8);
        assert_eq!(restored.len(), 8, "newest 8 only");
        // Oldest two (saved_at 1000, 1001) dropped; result ascending.
        assert_eq!(restored[0].chat_id, ids[2]);
        assert_eq!(restored[7].chat_id, ids[9]);
        assert!(restored.windows(2).all(|w| w[0].saved_at <= w[1].saved_at));
    }

    #[test]
    fn load_skips_unknown_format_versions() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid();
        let record = ChatHistoryFile {
            version: HISTORY_FORMAT_VERSION + 1,
            chat_id: id.clone(),
            model: "m".into(),
            saved_at: 1,
            messages: vec![msg_user("future")],
        };
        std::fs::write(
            dir.path().join(format!("{id}.json")),
            serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
        assert!(load_all(dir.path(), 8).is_empty());
    }
}
