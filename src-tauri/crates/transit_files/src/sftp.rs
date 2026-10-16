//! The remote half: a [`WatchedStream`] that synthesizes a closed signal,
//! and [`RemoteFs`] — browse + mutation wrappers over `russh-sftp`'s
//! `SftpSession`.
//!
//! # Why the stream is wrapped (plan §4, the lifecycle risk)
//!
//! `Channel::into_stream()` consumes the russh channel, destroying the
//! `ChannelMsg::Eof` / `Close` observation point every other transport's
//! `closed_rx` is built on, and russh-sftp swallows EOF into an internal
//! cancellation token it doesn't expose. Without a replacement signal the
//! pane would show a live file browser over a dead socket. So the stream
//! is wrapped on the way in: a 0-byte read, a read error, or a write
//! error flips a level-triggered `watch<bool>` — the same shape
//! `transit_localpty` / `transit_console` expose, so
//! `transit_app::files` can bridge it to `files:{id}:closed` with the
//! same borrow-and-update discipline as the PTY bridge.
//!
//! Belt and braces: [`RemoteFs`] additionally flips the flag when an
//! operation fails in a *session-fatal* way (the request couldn't be
//! handed to russh-sftp's writer task, or its reader task is gone), which
//! covers a socket that dies while no read is in flight.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::File;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::error::FilesError;
use crate::path;
use crate::sanitize::validate_remote_name;
use crate::types::{DirListing, EntryKind, FileEntry};

/// Hard cap on how many entries a single recursive delete may remove.
/// A safety rail, not a performance knob: a mistaken recursive delete on
/// `/` should stop with an error, not grind through the device.
const MAX_DELETE_ENTRIES: usize = 50_000;

/// Depth cap for recursive remote walks (delete + directory transfer).
/// Symlinked directories are never followed, so a cycle needs real nested
/// directories — but a hostile server can synthesize those indefinitely.
pub(crate) const MAX_WALK_DEPTH: usize = 64;

/// Shared, level-triggered "this session is finished" flag.
///
/// `watch::Sender::send_replace` takes `&self`, so one `Arc` is shared by
/// the stream wrapper and the op layer.
#[derive(Clone)]
pub(crate) struct ClosedFlag(Arc<watch::Sender<bool>>);

impl ClosedFlag {
    pub(crate) fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self(Arc::new(tx)), rx)
    }

    pub(crate) fn mark_closed(&self) {
        // `send_replace` (not `send`) so the flip lands even with no
        // receiver currently parked — a late subscriber still reads
        // `true`.
        if !*self.0.borrow() {
            tracing::debug!("files session stream closed");
        }
        self.0.send_replace(true);
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.0.borrow()
    }
}

/// AsyncRead/AsyncWrite passthrough that trips a [`ClosedFlag`] on EOF or
/// error. Adds no buffering — every poll goes straight to the inner
/// stream — so it cannot reorder or lose bytes.
pub(crate) struct WatchedStream<S> {
    inner: S,
    closed: ClosedFlag,
}

impl<S> WatchedStream<S> {
    pub(crate) fn new(inner: S, closed: ClosedFlag) -> Self {
        Self { inner, closed }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WatchedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // A completed read that filled nothing IS EOF — the one
                // signal russh-sftp keeps to itself.
                if buf.filled().len() == before {
                    this.closed.mark_closed();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                this.closed.mark_closed();
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WatchedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Err(e)) => {
                this.closed.mark_closed();
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Err(e)) => {
                this.closed.mark_closed();
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A shutdown means we're done with this stream either way.
        let res = Pin::new(&mut this.inner).poll_shutdown(cx);
        if res.is_ready() {
            this.closed.mark_closed();
        }
        res
    }
}

/// Browse + mutation surface over one SFTP session.
///
/// `SftpSession` isn't `Clone`, but every method takes `&self` and its
/// in-flight request map is a dashmap keyed by request id, so one session
/// genuinely serves concurrent requests — browsing while a transfer runs
/// works on a single `Arc<RemoteFs>` (verified from the crate source; see
/// plan §5).
pub struct RemoteFs {
    sftp: SftpSession,
    closed: ClosedFlag,
    max_entries: usize,
}

impl RemoteFs {
    pub(crate) fn new(sftp: SftpSession, closed: ClosedFlag, max_entries: usize) -> Self {
        Self {
            sftp,
            closed,
            max_entries,
        }
    }

    /// Classify an SFTP error, flipping the closed flag for the shapes
    /// that mean the *session* (not the operation) is finished.
    ///
    /// The fatal/per-operation split lives in the pure [`is_session_fatal`]
    /// (so it is unit-testable without a live `SftpSession`). A `Status` (no
    /// such file, permission denied) or a `Timeout` is per-operation and
    /// deliberately does NOT close the session: a slow WAN listing must not
    /// tear down the pane.
    ///
    /// The server's status text is attacker-influenceable input headed for a
    /// `tracing::warn!` and `TransferEvent.error`, so it is passed through
    /// [`sanitize_detail`] before it lands in `FilesError::Remote.detail`
    /// (finding A8 / security-review L2).
    fn classify(&self, op: &'static str, path: &str, err: SftpError) -> FilesError {
        if is_session_fatal(&err) {
            self.closed.mark_closed();
            tracing::warn!(op, "sftp session failed fatally");
            return FilesError::SessionClosed;
        }
        FilesError::Remote {
            op,
            path: path.to_string(),
            detail: sanitize_detail(&err.to_string()),
        }
    }

    fn guard_open(&self) -> Result<(), FilesError> {
        if self.closed.is_closed() {
            return Err(FilesError::SessionClosed);
        }
        Ok(())
    }

    /// The session's starting directory — whatever the server resolves
    /// `.` to (the login directory for essentially every server).
    pub async fn home(&self) -> Result<String, FilesError> {
        self.canonicalize(".").await
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String, FilesError> {
        self.guard_open()?;
        self.sftp
            .canonicalize(path.to_string())
            .await
            .map(|p| path::normalize(&p))
            .map_err(|e| self.classify("canonicalize", path, e))
    }

    /// List a directory. The returned `path` is the server-canonical one:
    /// navigation and the path bar build on that, never on the string the
    /// user typed (plan §6).
    ///
    /// Entries whose names fail the T43 gate are **dropped** — a name
    /// that can't be a single path component has no legitimate use in the
    /// UI and must never reach a path join.
    pub async fn list_dir(&self, path: &str) -> Result<DirListing, FilesError> {
        let canonical = self.canonicalize(path).await?;
        let (entries, truncated) = self.read_entries(&canonical).await?;
        Ok(DirListing {
            parent: path::parent(&canonical),
            path: canonical,
            entries,
            truncated,
        })
    }

    /// Raw listing of an already-canonical directory: no second
    /// `realpath` round-trip. Used by the recursive walkers.
    pub(crate) async fn read_entries(
        &self,
        canonical: &str,
    ) -> Result<(Vec<FileEntry>, bool), FilesError> {
        self.guard_open()?;
        // NOTE: `read_dir` drains the WHOLE directory before returning
        // (verified from the crate source), which is why the request
        // timeout is raised to 60 s at connect time and why the entry
        // count is capped here rather than by asking for less.
        let listing = self
            .sftp
            .read_dir(canonical.to_string())
            .await
            .map_err(|e| self.classify("list", canonical, e))?;

        let mut entries = Vec::new();
        let mut truncated = false;
        let mut refused = 0usize;
        for entry in listing {
            if entries.len() >= self.max_entries {
                truncated = true;
                break;
            }
            let name = entry.file_name();
            if validate_remote_name(&name).is_err() {
                refused += 1;
                continue;
            }
            let meta = entry.metadata();
            entries.push(FileEntry {
                name,
                kind: kind_of(&meta),
                size: meta.size,
                mtime: meta.mtime.map(i64::from),
                perms: Some(meta.permissions().to_string()),
                symlink_target: None,
            });
        }
        if refused > 0 {
            // Names are hostile input; log the COUNT, never the bytes.
            tracing::warn!(refused, "dropped directory entries with unsafe names (T43)");
        }
        tracing::debug!(entries = entries.len(), truncated, "remote listing");
        Ok((entries, truncated))
    }

    /// Properties for one path. Follows the link (`stat`) but reports the
    /// entry's own kind (`lstat`) and, for a link, its target — so the UI
    /// can say "symlink → /var/log" while still showing the real size.
    pub async fn stat(&self, path: &str) -> Result<FileEntry, FilesError> {
        self.guard_open()?;
        let link_meta = self
            .sftp
            .symlink_metadata(path.to_string())
            .await
            .map_err(|e| self.classify("stat", path, e))?;
        let kind = kind_of(&link_meta);

        let (meta, symlink_target) = if kind.is_symlink() {
            let target = self.sftp.read_link(path.to_string()).await.ok();
            // A dangling link still has to render, so fall back to the
            // link's own attributes when the target can't be stat'ed.
            let followed = self.sftp.metadata(path.to_string()).await.ok();
            (followed.unwrap_or_else(|| link_meta.clone()), target)
        } else {
            (link_meta, None)
        };

        Ok(FileEntry {
            name: path::basename(path),
            kind,
            size: meta.size,
            mtime: meta.mtime.map(i64::from),
            perms: Some(meta.permissions().to_string()),
            symlink_target,
        })
    }

    /// The entry's own kind without following links — what the recursive
    /// walkers must use.
    pub(crate) async fn lstat_kind(&self, path: &str) -> Result<EntryKind, FilesError> {
        self.guard_open()?;
        let meta = self
            .sftp
            .symlink_metadata(path.to_string())
            .await
            .map_err(|e| self.classify("stat", path, e))?;
        Ok(kind_of(&meta))
    }

    /// Size + mtime of a file, following links (the transfer engine's
    /// pre-flight for `bytes_total` and mtime preservation).
    pub(crate) async fn file_meta(&self, path: &str) -> Result<FileAttributes, FilesError> {
        self.guard_open()?;
        self.sftp
            .metadata(path.to_string())
            .await
            .map_err(|e| self.classify("stat", path, e))
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), FilesError> {
        self.guard_open()?;
        self.sftp
            .create_dir(path.to_string())
            .await
            .map_err(|e| self.classify("mkdir", path, e))
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FilesError> {
        self.guard_open()?;
        self.sftp
            .rename(from.to_string(), to.to_string())
            .await
            .map_err(|e| self.classify("rename", from, e))
    }

    pub async fn try_exists(&self, path: &str) -> Result<bool, FilesError> {
        self.guard_open()?;
        self.sftp
            .try_exists(path.to_string())
            .await
            .map_err(|e| self.classify("stat", path, e))
    }

    pub(crate) async fn remove_file(&self, path: &str) -> Result<(), FilesError> {
        self.guard_open()?;
        self.sftp
            .remove_file(path.to_string())
            .await
            .map_err(|e| self.classify("delete", path, e))
    }

    async fn remove_dir(&self, path: &str) -> Result<(), FilesError> {
        self.guard_open()?;
        self.sftp
            .remove_dir(path.to_string())
            .await
            .map_err(|e| self.classify("delete", path, e))
    }

    /// Delete a path. `recursive` is required for a non-empty directory.
    ///
    /// **Never recurses through a symlink.** The kind comes from `lstat`,
    /// so a link to a directory is removed as a *link* — deleting the
    /// link's target tree (possibly outside the tree the user pointed at)
    /// would be a traversal bug, not a convenience.
    pub async fn delete(&self, path: &str, recursive: bool) -> Result<(), FilesError> {
        let kind = self.lstat_kind(path).await?;
        if kind.is_symlink() || !kind.is_dir() {
            return self.remove_file(path).await;
        }
        if !recursive {
            return self.remove_dir(path).await;
        }

        // Breadth-first discovery, then unlink files as we go and remove
        // directories deepest-first (BFS order reversed).
        let mut dirs: Vec<(String, usize)> = vec![(path::normalize(path), 0)];
        let mut idx = 0;
        let mut removed = 0usize;
        while idx < dirs.len() {
            let (dir, depth) = dirs[idx].clone();
            idx += 1;
            if depth >= MAX_WALK_DEPTH {
                return Err(FilesError::LimitExceeded {
                    what: "recursive delete depth",
                    limit: MAX_WALK_DEPTH,
                });
            }
            let (entries, truncated) = self.read_entries(&dir).await?;
            if truncated {
                // We would silently leave files behind and then fail to
                // rmdir a "deleted" directory. Refuse instead.
                return Err(FilesError::LimitExceeded {
                    what: "entries in one directory of a recursive delete",
                    limit: self.max_entries,
                });
            }
            for entry in entries {
                removed += 1;
                if removed > MAX_DELETE_ENTRIES {
                    return Err(FilesError::LimitExceeded {
                        what: "entries in a recursive delete",
                        limit: MAX_DELETE_ENTRIES,
                    });
                }
                let child = path::join(&dir, &entry.name);
                // Symlink first: a link to a directory is unlinked, not
                // descended into.
                if entry.kind.is_dir() && !entry.kind.is_symlink() {
                    dirs.push((child, depth + 1));
                } else {
                    self.remove_file(&child).await?;
                }
            }
        }
        for (dir, _) in dirs.iter().rev() {
            self.remove_dir(dir).await?;
        }
        tracing::info!(removed, "recursive remote delete complete");
        Ok(())
    }

    pub(crate) async fn open_read(&self, path: &str) -> Result<File, FilesError> {
        self.guard_open()?;
        self.sftp
            .open(path.to_string())
            .await
            .map_err(|e| self.classify("read", path, e))
    }

    /// Open for writing, creating and truncating. Uploads point this at a
    /// unique `{name}.{transfer_id}.transitpart` temp and rename it onto the
    /// real destination on success (finding A1), so an interrupted or
    /// cancelled upload never truncates a pre-existing remote file. The
    /// unique per-transfer temp name means `TRUNCATE` can only ever clear our
    /// own fresh temp, never someone else's file.
    pub(crate) async fn create_write(&self, path: &str) -> Result<File, FilesError> {
        self.guard_open()?;
        self.sftp
            .open_with_flags(
                path.to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .await
            .map_err(|e| self.classify("write", path, e))
    }

    /// Best-effort mtime restore after an upload. Only the time fields
    /// are set — v1 deliberately does not touch permissions or ownership.
    pub(crate) async fn set_mtime(&self, path: &str, mtime: u32) -> Result<(), FilesError> {
        self.guard_open()?;
        let attrs = FileAttributes {
            atime: Some(mtime),
            mtime: Some(mtime),
            ..FileAttributes::default()
        };
        self.sftp
            .set_metadata(path.to_string(), attrs)
            .await
            .map_err(|e| self.classify("set times", path, e))
    }

    /// Close the SFTP session politely (best effort — the caller is
    /// tearing the connection down regardless).
    pub(crate) async fn close(&self) {
        if let Err(e) = self.sftp.close().await {
            tracing::debug!("sftp close returned: {e}");
        }
        self.closed.mark_closed();
    }
}

fn kind_of(meta: &FileAttributes) -> EntryKind {
    match meta.file_type() {
        FileType::Dir => EntryKind::Dir,
        FileType::File => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        FileType::Other => EntryKind::Other,
    }
}

/// Whether an SFTP error means the whole *session* is finished (vs. one
/// operation failing recoverably).
///
/// `Error::IO` is the stream itself failing. For a dead session,
/// russh-sftp 2.4.0 returns `UnexpectedBehavior` with one of two exact
/// strings (verified against the crate's `client/rawsession.rs`): the mpsc
/// channel to the writer task is closed → `"session closed"`, or the
/// oneshot response sender was dropped because the reader task died →
/// `"sender dropped"`. The `SendError` / `RecvError` spellings only appear
/// in a narrow send race (`From` impls in `client/error.rs`), so match all
/// four — the earlier code matched ONLY the two rare-race spellings, so the
/// session-death fallback never fired and a dead link surfaced as a generic
/// remote error instead of `SessionClosed` (finding A8). A `Status` /
/// `Timeout` / `UnexpectedPacket` is per-operation and NOT fatal.
pub(crate) fn is_session_fatal(err: &SftpError) -> bool {
    match err {
        SftpError::IO(_) => true,
        SftpError::UnexpectedBehavior(detail) => {
            detail.contains("session closed")
                || detail.contains("sender dropped")
                || detail.contains("SendError")
                || detail.contains("RecvError")
        }
        _ => false,
    }
}

/// Sanitize server-supplied SFTP status text before it reaches a log line
/// or `TransferEvent.error`.
///
/// A malicious/compromised device controls the `error_message` of every
/// status packet; unescaped it could inject newlines/ANSI into logs or the
/// queue strip, or run unbounded in length. Keep printable ASCII + space,
/// drop everything else, cap the length — the exact approach
/// `transit_ssh::connection::sanitize_server_text` uses for the
/// `SSH_MSG_DISCONNECT` reason (v2.3.3). Security-review L2 / finding A8.
pub(crate) fn sanitize_detail(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn watched_stream_trips_the_flag_on_eof() {
        let (a, b) = tokio::io::duplex(64);
        let (closed, rx) = ClosedFlag::new();
        let mut watched = WatchedStream::new(a, closed);
        assert!(!*rx.borrow(), "fresh stream is open");

        // Drop the far end → the next read completes with 0 bytes.
        drop(b);
        let mut buf = [0u8; 8];
        let n = watched.read(&mut buf).await.expect("read after peer drop");
        assert_eq!(n, 0);
        assert!(*rx.borrow(), "EOF must flip the closed flag");
    }

    #[tokio::test]
    async fn watched_stream_passes_bytes_through_unchanged() {
        let (a, mut b) = tokio::io::duplex(64);
        let (closed, rx) = ClosedFlag::new();
        let mut watched = WatchedStream::new(a, closed);

        watched.write_all(b"transit").await.expect("write");
        watched.flush().await.expect("flush");
        let mut buf = [0u8; 7];
        b.read_exact(&mut buf).await.expect("peer read");
        assert_eq!(&buf, b"transit");
        assert!(!*rx.borrow(), "a healthy write must not close the session");
    }

    #[tokio::test]
    async fn watched_stream_trips_the_flag_on_write_error() {
        let (a, b) = tokio::io::duplex(8);
        let (closed, rx) = ClosedFlag::new();
        let mut watched = WatchedStream::new(a, closed);
        drop(b);
        // Writing to a duplex whose peer is gone is a BrokenPipe error.
        let err = watched.write_all(b"transit").await;
        assert!(err.is_err(), "write to a dropped peer must fail");
        assert!(*rx.borrow(), "a write error must flip the closed flag");
    }

    #[test]
    fn session_death_strings_classify_as_fatal_but_per_op_errors_do_not() {
        use russh_sftp::client::error::Error as E;
        // The two strings russh-sftp 2.4.0 actually produces on session death
        // (finding A8) — the earlier classifier matched neither.
        assert!(is_session_fatal(&E::UnexpectedBehavior(
            "session closed".into()
        )));
        assert!(is_session_fatal(&E::UnexpectedBehavior(
            "sender dropped".into()
        )));
        // The rare-race spellings still count.
        assert!(is_session_fatal(&E::UnexpectedBehavior(
            "SendError: channel closed".into()
        )));
        assert!(is_session_fatal(&E::UnexpectedBehavior(
            "RecvError: channel closed".into()
        )));
        assert!(is_session_fatal(&E::IO("broken pipe".into())));
        // Per-operation failures must NOT tear the session down.
        assert!(!is_session_fatal(&E::Timeout));
        assert!(!is_session_fatal(&E::UnexpectedPacket));
        assert!(!is_session_fatal(&E::UnexpectedBehavior(
            "no such file".into()
        )));
    }

    #[test]
    fn sanitize_detail_strips_control_bytes_and_caps_length() {
        let dirty = format!("bad\nmess\u{1b}[2Kage{}", "x".repeat(300));
        let clean = sanitize_detail(&dirty);
        assert!(!clean.contains('\n'), "newlines dropped");
        assert!(!clean.contains('\u{1b}'), "ANSI escapes dropped");
        assert!(clean.len() <= 160, "capped to 160, got {}", clean.len());
        assert!(clean.starts_with("badmessage") || clean.starts_with("badmess"));
        // Non-ASCII is dropped, not passed through.
        assert_eq!(sanitize_detail("naïve"), "nave");
    }

    #[test]
    fn closed_flag_is_level_triggered_not_edge_triggered() {
        let (closed, rx) = ClosedFlag::new();
        assert!(!*rx.borrow());
        closed.mark_closed();
        // A late clone still READS `true` without having awaited
        // `changed()` — the `spawn_output_bridge` lesson (ssh.rs:885) in
        // flag form: a bridge that starts after the close still emits it.
        let late = rx.clone();
        assert!(*late.borrow());
        assert!(closed.is_closed());
        // Idempotent: a second flip is harmless (the op layer and the
        // stream wrapper both mark, independently).
        closed.mark_closed();
        assert!(*rx.borrow());
    }
}
