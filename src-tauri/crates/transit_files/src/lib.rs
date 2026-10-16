//! v5.0.0 — SFTP browse + file-transfer engine for the **Files** surface.
//!
//! Design + threat model:
//! the files pane sftp design notes (not included in this repository) (§5) and `docs/security/threat-model.md` T43.
//!
//! # Transport-agnostic by design (plan decision 11)
//!
//! This crate depends on **neither `transit_ssh` nor `transit_auth` nor
//! `russh`**. It consumes any `AsyncRead + AsyncWrite + Unpin + Send +
//! 'static` stream, so:
//!
//! - the SSH plumbing (auth resolution, host-key TOFU, cipher policy)
//!   stays in `transit_app`, which hands over an already-open subsystem
//!   stream from `transit_ssh::Connection::open_subsystem_stream`;
//! - `deny.toml`'s `transit_auth` wrapper list needs no change — there is
//!   no path from here to a credential;
//! - the whole engine is testable over `tokio::io::duplex` against
//!   russh-sftp's own server half, with no SSH server and no network.
//!
//! # Agent-blindness (load-bearing — plan §2, threat model T43)
//!
//! File transfer is a **human** productivity surface, exactly like the
//! v4.4.0 local terminal (T42), the button bar, and the broadcast bar. The
//! agent cannot list, browse, read, or transfer files: no `FilesState` is
//! passed to any agent-side constructor, this crate appears in neither
//! `UnifiedScrollbackSource` nor `UnifiedSessionExecutor` (built per chat
//! turn in `chat.rs`), and `deny.toml` bans any dependency on
//! `transit_files` outside `transit_app` — so the blindness is a property
//! of the dependency graph, not a review comment. Rule 2 stays at five
//! tools. **Do NOT add a `FilesState`/`FilesSession` argument to any
//! agent-side seam.**
//!
//! Because nothing from a Files session ever reaches the LLM, there is no
//! redaction boundary here to get wrong.

mod error;
mod localfs;
mod path;
mod sanitize;
mod sftp;
mod transfer;
mod types;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};

use crate::sftp::{ClosedFlag, RemoteFs, WatchedStream};
use crate::transfer::TransferQueue;

pub use crate::error::{FilesError, NameError};
pub use crate::sanitize::validate_remote_name;
pub use crate::types::{
    DirListing, Direction, EntryKind, FileEntry, LocalRoot, OverwritePolicy, TransferDescriptor,
    TransferEvent, TransferItem, TransferState,
};

// Trimmed public surface (finding D4): the `RemoteFs as RemoteFileSystem`
// alias, the `remote_path` module, and the `validate_local_write_name` /
// `windows_unsafe_name` re-exports had zero external callers, and
// `local::exists` is an engine-internal conflict check — none belong in the
// crate's public API. `crate::path` and `crate::sanitize` remain available
// internally for the modules that use them.

/// Local-pane operations (`files_local_*` IPC). Free functions rather than
/// a type: there is no per-session local state.
pub mod local {
    pub use crate::localfs::{delete, home, list_dir, mkdir, rename, roots};
}

/// How long teardown waits for the worker to drain the queue (emitting
/// `Cancelled` for whatever was still parked) before giving up.
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct FilesConfig {
    /// Per-request timeout handed to russh-sftp. Its default is **10 s**,
    /// which is tighter than the ~45 s SSH keepalive budget, and `read_dir`
    /// drains an entire directory before returning — a large listing over a
    /// WAN link would fail spuriously. Transit sets 60 s explicitly
    /// (plan §4 "Timeouts").
    pub request_timeout_secs: u64,
    /// SFTP packet cap; negotiates down against the server's limits.
    pub max_packet_len: u32,
    /// Pipelined writes in flight per file handle.
    pub max_concurrent_writes: usize,
    /// Entries returned per directory listing before `truncated` is set.
    /// Bounds the IPC payload; the UI virtualizes regardless.
    pub max_entries: usize,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: 60,
            max_packet_len: 262_144,
            max_concurrent_writes: 8,
            max_entries: 20_000,
        }
    }
}

/// One live file-transfer session: an SFTP session plus its transfer
/// worker and the synthesized closed signal.
pub struct FilesSession {
    remote: Arc<RemoteFs>,
    queue: TransferQueue,
    closed_rx: watch::Receiver<bool>,
    closed: ClosedFlag,
    /// Handed to the IPC layer once, which forwards events as
    /// `files:transfer:update`. Unbounded + single-consumer so a terminal
    /// state can never be dropped by backpressure or lag.
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<TransferEvent>>>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl FilesSession {
    /// Start an SFTP session on an already-open stream (for Transit: an
    /// `sftp` subsystem channel; for tests: one end of a duplex).
    ///
    /// The stream is wrapped in [`WatchedStream`] **before** russh-sftp
    /// sees it, which is what makes `closed_rx` work at all — see
    /// `sftp.rs`.
    pub async fn connect<S>(stream: S, config: FilesConfig) -> Result<Self, FilesError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (closed, closed_rx) = ClosedFlag::new();
        let watched = WatchedStream::new(stream, closed.clone());

        let sftp = russh_sftp::client::SftpSession::new_with_config(
            watched,
            russh_sftp::client::Config {
                max_packet_len: config.max_packet_len,
                max_concurrent_writes: config.max_concurrent_writes,
                request_timeout_secs: config.request_timeout_secs,
            },
        )
        .await
        .map_err(|e| {
            // A failed INIT means this stream is finished, whatever the
            // reason — don't leave a "live" flag behind.
            closed.mark_closed();
            // Server-influenceable text → sanitize before it becomes a UI
            // toast / log line (finding A8).
            FilesError::Init {
                detail: crate::sftp::sanitize_detail(&e.to_string()),
            }
        })?;

        let remote = Arc::new(RemoteFs::new(sftp, closed.clone(), config.max_entries));
        let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let cancels = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = tokio_util::sync::CancellationToken::new();

        let worker = tokio::spawn(transfer::worker_loop(
            Arc::clone(&remote),
            jobs_rx,
            events_tx.clone(),
            Arc::clone(&cancels),
            shutdown.clone(),
            config.max_entries,
        ));

        Ok(Self {
            remote,
            queue: TransferQueue::new(jobs_tx, events_tx, cancels, shutdown),
            closed_rx,
            closed,
            events_rx: Mutex::new(Some(events_rx)),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Level-triggered "this session is finished" signal — `true` whenever
    /// the caller looks, no matter when the stream died. Same contract as
    /// `transit_localpty` / `transit_console`, so `transit_app` bridges it
    /// to `files:{id}:closed` with the usual `borrow_and_update` discipline.
    pub fn closed_rx(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_closed()
    }

    /// Take the transfer-event stream. `Some` exactly once per session.
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<TransferEvent>> {
        self.events_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// The remote surface, for callers that want to compose several ops.
    pub fn remote(&self) -> &RemoteFs {
        &self.remote
    }

    // -- remote browse / mutate (thin pass-throughs so the IPC layer has
    //    one object to talk to) --------------------------------------

    pub async fn home(&self) -> Result<String, FilesError> {
        self.remote.home().await
    }

    pub async fn list_dir(&self, path: &str) -> Result<DirListing, FilesError> {
        self.remote.list_dir(path).await
    }

    pub async fn stat(&self, path: &str) -> Result<FileEntry, FilesError> {
        self.remote.stat(path).await
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), FilesError> {
        self.remote.mkdir(path).await
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FilesError> {
        self.remote.rename(from, to).await
    }

    pub async fn delete(&self, path: &str, recursive: bool) -> Result<(), FilesError> {
        self.remote.delete(path, recursive).await
    }

    // -- transfers -------------------------------------------------

    /// Destinations that already exist for a prospective batch — the
    /// pre-flight behind the single Overwrite-all / Skip-existing dialog.
    pub async fn check_conflicts(
        &self,
        direction: Direction,
        items: &[TransferItem],
    ) -> Result<Vec<String>, FilesError> {
        transfer::check_conflicts(&self.remote, direction, items).await
    }

    /// Queue one transfer per item (FIFO within this session).
    ///
    /// Refused outright once the stream is gone: a queue row that can only
    /// ever fail is worse than a clear "reconnect first".
    pub fn enqueue(
        &self,
        direction: Direction,
        items: Vec<TransferItem>,
        policy: OverwritePolicy,
    ) -> Result<Vec<TransferDescriptor>, FilesError> {
        if self.closed.is_closed() {
            return Err(FilesError::SessionClosed);
        }
        self.queue.enqueue(direction, items, policy)
    }

    /// Cancel one transfer. `false` = not this session's transfer.
    pub fn cancel_transfer(&self, transfer_id: &str) -> bool {
        self.queue.cancel(transfer_id)
    }

    /// Cancel every queued + running transfer (disconnect / reconnect).
    pub fn cancel_all(&self) {
        self.queue.cancel_all();
    }

    /// Whether any transfer is queued or running. The transfer-aware quit
    /// guard's question: an idle Files session must never veto quit, a
    /// mid-transfer one must (§6).
    pub fn has_active_transfers(&self) -> bool {
        self.queue.has_active()
    }

    /// Teardown: cancel everything, let the worker drain the queue so
    /// parked transfers report `Cancelled` rather than vanishing, then
    /// close the SFTP session.
    ///
    /// Bounded by [`CLOSE_DRAIN_TIMEOUT`] — a wedged transfer must not turn
    /// closing a tab into a hang.
    pub async fn close(self) {
        self.queue.cancel_all();
        let worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        // Closing the job channel makes the worker exit once it has drained
        // whatever is left (each parked job emits `Cancelled`).
        self.queue.close_channel();
        if let Some(mut worker) = worker {
            // Time out on `&mut worker`, then `abort()` on expiry (finding
            // A9). `timeout(dur, worker)` would only DROP the JoinHandle on
            // expiry, which DETACHES the task (it keeps running) rather than
            // aborting it — a wedged worker would keep writing to the device
            // or the user's disk after the tab is gone. The graceful drain
            // stays the happy path.
            if tokio::time::timeout(CLOSE_DRAIN_TIMEOUT, &mut worker)
                .await
                .is_err()
            {
                worker.abort();
                tracing::warn!(
                    "files transfer worker did not drain within the close timeout; aborted"
                );
            }
        }
        self.remote.close().await;
    }
}

impl Drop for FilesSession {
    fn drop(&mut self) {
        // Belt and braces for a session dropped without `close()`: stop the
        // worker so an in-flight transfer can't keep writing to a device (or
        // the user's disk) after its tab is gone.
        self.queue.cancel_all();
        if let Some(worker) = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            worker.abort();
        }
    }
}
