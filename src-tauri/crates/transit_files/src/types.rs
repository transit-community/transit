//! Wire types shared by the remote (SFTP) and local panes, plus the
//! transfer-queue vocabulary.
//!
//! These serialize straight to the frontend over Tauri IPC, so the field
//! names are the contract (`snake_case`, matching every other Transit
//! payload). Per Rule 1 nothing here can carry a credential — names,
//! paths, sizes, timestamps and counts only.

use serde::{Deserialize, Serialize};

/// What a directory entry is. `Symlink` is reported as its own kind
/// rather than resolved: the recursive walker refuses to follow remote
/// links (T43), and the UI needs to say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl EntryKind {
    pub fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
    pub fn is_symlink(self) -> bool {
        matches!(self, Self::Symlink)
    }
}

/// One row in a pane. uid/gid are deliberately omitted in v1 (§6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Single path component — always validated (`crate::sanitize`)
    /// before it lands here, so it can never contain a separator.
    pub name: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    /// Modification time, whole seconds since the Unix epoch.
    pub mtime: Option<i64>,
    /// `"rwxr-xr-x"`, derived from POSIX mode bits. `None` when the
    /// platform/server doesn't report a mode (e.g. a local listing on
    /// Windows).
    pub perms: Option<String>,
    /// Populated by `stat` only — a listing would need one extra
    /// round-trip per link, which is not worth it for a 10k-entry
    /// directory.
    pub symlink_target: Option<String>,
}

/// A directory listing. `path` is the **canonical** path the server (or
/// the local OS) resolved, which is what the path bar must display and
/// what navigation must build on — never the string the user typed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<FileEntry>,
    /// True when the directory held more than the cap
    /// ([`crate::FilesConfig::max_entries`]) and the tail was dropped.
    /// Bounds the IPC payload; the UI says so explicitly.
    pub truncated: bool,
}

/// A local filesystem root for the local pane's dropdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRoot {
    pub path: String,
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Local → remote.
    Upload,
    /// Remote → local.
    Download,
}

/// What to do when the destination already holds a file of that name.
/// Decided **pre-flight** for the whole batch (`files_check_conflicts` →
/// one dialog), never per file mid-transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverwritePolicy {
    Overwrite,
    Skip,
}

/// One queued item: move `source_path` into the directory `dest_dir`.
/// For [`Direction::Upload`] the source is local and the destination
/// remote; for [`Direction::Download`] the reverse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferItem {
    pub source_path: String,
    pub dest_dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferState {
    Queued,
    Running,
    Done,
    Error,
    Cancelled,
}

impl TransferState {
    /// Terminal states are always emitted, never throttled away.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Error | Self::Cancelled)
    }
}

/// Progress for one transfer. Emitted on every state transition, on the
/// terminal state, and otherwise at most ~10 Hz per transfer.
///
/// `bytes_total` / `files_total` are `Option` because a recursive
/// directory transfer has no pre-scan in v1 — the totals are unknown
/// until the walk finishes, so the UI shows a byte counter and a rate
/// instead of a percentage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEvent {
    pub id: String,
    pub direction: Direction,
    pub state: TransferState,
    /// The file currently moving (a single component), or the top-level
    /// item's name before/after the walk.
    pub name: String,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub files_done: u64,
    pub files_total: Option<u64>,
    pub rate_bps: Option<u64>,
    /// Entries deliberately not transferred: existing destinations under
    /// [`OverwritePolicy::Skip`], symlinks met during a recursive walk,
    /// and names refused by [`crate::sanitize`].
    pub skipped: u64,
    /// Human-readable notes for the skips above, capped so a hostile
    /// directory can't inflate the payload.
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

/// What [`crate::FilesSession::enqueue`] hands back per item so the
/// frontend can render a queue row before the first event arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDescriptor {
    pub id: String,
    pub direction: Direction,
    pub name: String,
}
