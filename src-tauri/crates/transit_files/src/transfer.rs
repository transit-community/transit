//! The transfer engine: one FIFO worker per session, one
//! `CancellationToken` per transfer, chunked copies, throttled progress.
//!
//! # Shape (plan §5, decision 8)
//!
//! Per-session FIFO, cross-session parallelism: each [`crate::FilesSession`]
//! owns exactly one worker task draining an unbounded job channel, so two
//! transfers to the same device never interleave (SFTP window contention
//! makes that slower, not faster), while two devices transfer at once.
//!
//! # Safety properties this module is responsible for
//!
//! - **Every name that crosses a path boundary is validated** — remote
//!   names via [`crate::sanitize::validate_remote_name`] plus
//!   [`crate::sanitize::validate_local_write_name`] before they touch a
//!   local path, local names via `validate_remote_name` before they become
//!   a remote path component (T43).
//! - **Recursive walks never follow symlinks** in either direction. A link
//!   met during a walk is counted and reported, not descended into and not
//!   copied — a remote link could point anywhere on the device, and a
//!   local one anywhere on the user's disk.
//! - **Both directions are atomic: write to a unique
//!   `<name>.<transfer_id>.transitpart`, then rename onto the real
//!   destination on success** (finding A1/A2). An interrupted, cancelled, or
//!   failed transfer only ever removes its own `.transitpart` and NEVER
//!   touches a pre-existing file wearing the real name — the earlier upload
//!   path opened the destination `WRITE|CREATE|TRUNCATE` and deleted it on
//!   any error, so a cancelled upload destroyed the file it was replacing.
//!   The transfer id makes the temp name collision-proof, so a stale part
//!   from a crashed run can never block a retry or be renamed away.
//! - **Bounded walks**: depth and total-ENTRY caps mean a hostile server
//!   cannot make a recursive transfer visit unbounded entries or nest
//!   unboundedly. This is NOT a byte bound — an individual file's size is
//!   not pre-capped, so a hostile server can still stream large content
//!   within the entry budget; the guarantee here is on walk shape, not
//!   total bytes (finding L4).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::FilesError;
use crate::localfs;
use crate::path as rpath;
use crate::sanitize::{validate_local_write_name, validate_remote_name};
use crate::sftp::{RemoteFs, MAX_WALK_DEPTH};
use crate::types::{
    Direction, EntryKind, OverwritePolicy, TransferDescriptor, TransferEvent, TransferItem,
    TransferState,
};
use russh_sftp::client::fs::File;

/// Copy buffer. Comfortably inside russh-sftp's 256 KiB packet cap and
/// 4× the SSH channel packet size, so the pipeline stays full without
/// forcing the library to split every read.
const CHUNK: usize = 128 * 1024;

/// Progress events are throttled to at most one per this interval per
/// transfer (~10 Hz). State transitions and terminal states always emit.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Total entries one recursive transfer may visit. A safety rail against a
/// server that synthesizes directories forever (symlinks are already never
/// followed, so a cycle needs real nesting).
const MAX_WALK_ENTRIES: usize = 100_000;

/// How many skip reasons a single transfer reports verbatim; beyond this
/// only the `skipped` counter grows, so a hostile directory of 10k bad
/// names can't inflate the IPC payload.
const MAX_WARNINGS: usize = 20;

/// The suffix a download writes under until it completes.
const PART_SUFFIX: &str = ".transitpart";

pub(crate) struct Job {
    pub id: String,
    pub direction: Direction,
    pub item: TransferItem,
    pub policy: OverwritePolicy,
    pub cancel: CancellationToken,
}

/// Session-side handle: enqueue, cancel, and the cancel registry the
/// worker prunes as jobs finish.
///
/// Deliberately does NOT hold the worker's `Arc<RemoteFs>` or its
/// receiver: dropping the queue must close the job channel so the worker
/// drains and exits (see [`crate::FilesSession::close`]).
pub(crate) struct TransferQueue {
    /// `Option` so teardown can drop the sender — and thus close the
    /// channel and let the worker finish — from `&self`
    /// ([`Self::close_channel`]); `FilesSession` has a `Drop` impl, so its
    /// fields can never be moved out.
    jobs: Mutex<Option<mpsc::UnboundedSender<Job>>>,
    events: mpsc::UnboundedSender<TransferEvent>,
    cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
    /// Session-wide cancel, tripped on disconnect so jobs still sitting in
    /// the channel report `Cancelled` instead of vanishing.
    shutdown: CancellationToken,
}

impl TransferQueue {
    pub(crate) fn new(
        jobs: mpsc::UnboundedSender<Job>,
        events: mpsc::UnboundedSender<TransferEvent>,
        cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            jobs: Mutex::new(Some(jobs)),
            events,
            cancels,
            shutdown,
        }
    }

    /// Drop the job sender: the worker drains whatever is queued (emitting
    /// `Cancelled` for each, since `cancel_all` ran first) and then exits.
    pub(crate) fn close_channel(&self) {
        let _ = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Queue one transfer per item, FIFO. Returns a descriptor per item so
    /// the UI can render the row before the first event lands.
    ///
    /// **All-or-nothing (finding A6).** The ENTIRE batch is validated first —
    /// every item's transfer name is computed and passed through the T43
    /// sanitizer, and the session-open check runs — before ANY item is
    /// registered, emitted, or dispatched. The earlier per-item loop
    /// `?`-returned on the first bad item while earlier items were already
    /// transferring, so the frontend (which skips `registerTransferTargets`
    /// for the whole call on an error) desynced against live transfers. Now
    /// a bad item means zero side effects and a clean error.
    pub(crate) fn enqueue(
        &self,
        direction: Direction,
        items: Vec<TransferItem>,
        policy: OverwritePolicy,
    ) -> Result<Vec<TransferDescriptor>, FilesError> {
        if self.shutdown.is_cancelled() {
            return Err(FilesError::SessionClosed);
        }

        // Pass 1 — validate the whole batch with NO side effects. A `?` here
        // returns before anything is registered/emitted/dispatched.
        struct Prepared {
            id: String,
            name: String,
            cancel: CancellationToken,
            item: TransferItem,
        }
        let mut prepared = Vec::with_capacity(items.len());
        for item in items {
            // The transfer name is a single path component that will be
            // joined onto a local (download) or remote (upload) directory, so
            // it passes the same T43 gate the recursive walkers apply. A
            // compromised webview calling `files_enqueue` directly with a
            // crafted `source_path` is the "second layer" the listing-time
            // drop normally shadows (finding M7).
            let name = match direction {
                Direction::Download => {
                    let n = rpath::basename(&item.source_path);
                    validate_remote_name(&n).map_err(|e| FilesError::unsafe_name(&n, e))?;
                    validate_local_write_name(&n).map_err(|e| FilesError::unsafe_name(&n, e))?;
                    n
                }
                Direction::Upload => {
                    let n = local_file_name(Path::new(&item.source_path))?;
                    validate_remote_name(&n).map_err(|e| FilesError::unsafe_name(&n, e))?;
                    n
                }
            };
            prepared.push(Prepared {
                id: Uuid::new_v4().to_string(),
                name,
                cancel: CancellationToken::new(),
                item,
            });
        }

        // Pass 2 — register + emit + dispatch. The job sender is checked
        // FIRST (still under the guard) so a closed channel is caught before
        // any token is registered; once it is `Some`, the receiver (the live
        // worker) cannot have gone, so no send can fail partway and leave a
        // partial batch.
        let mut out = Vec::with_capacity(prepared.len());
        let guard = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let sender = guard.as_ref().ok_or(FilesError::SessionClosed)?;
        {
            let mut cancels = self.cancels.lock().unwrap_or_else(|e| e.into_inner());
            for p in &prepared {
                cancels.insert(p.id.clone(), p.cancel.clone());
            }
        }
        for p in prepared {
            // Emit `Queued` before sending, so the event order the frontend
            // sees is always queued → running → terminal even if the worker
            // is idle and picks the job up instantly.
            let _ = self.events.send(TransferEvent {
                id: p.id.clone(),
                direction,
                state: TransferState::Queued,
                name: p.name.clone(),
                bytes_done: 0,
                bytes_total: None,
                files_done: 0,
                files_total: None,
                rate_bps: None,
                skipped: 0,
                warnings: Vec::new(),
                error: None,
            });
            sender
                .send(Job {
                    id: p.id.clone(),
                    direction,
                    item: p.item,
                    policy,
                    cancel: p.cancel,
                })
                .map_err(|_| FilesError::SessionClosed)?;
            out.push(TransferDescriptor {
                id: p.id,
                direction,
                name: p.name,
            });
        }
        drop(guard);
        tracing::info!(count = out.len(), ?direction, "transfers queued");
        Ok(out)
    }

    /// Cancel one transfer by id. `false` = this session doesn't own it
    /// (the IPC layer then tries the next session).
    pub(crate) fn cancel(&self, transfer_id: &str) -> bool {
        let token = self
            .cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(transfer_id)
            .cloned();
        match token {
            Some(token) => {
                token.cancel();
                tracing::info!(transfer = %transfer_id, "transfer cancel requested");
                true
            }
            None => false,
        }
    }

    /// Cancel everything — running and queued — for teardown. Queued jobs
    /// still emit `Cancelled` as the worker drains them, so no queue row is
    /// left stuck on "queued" in the UI.
    pub(crate) fn cancel_all(&self) {
        self.shutdown.cancel();
        let tokens: Vec<CancellationToken> = self
            .cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for token in &tokens {
            token.cancel();
        }
        if !tokens.is_empty() {
            tracing::info!(count = tokens.len(), "cancelling session transfers");
        }
    }

    /// Whether any transfer is queued or running — the transfer-aware quit
    /// guard's question (§6). A finished transfer is deregistered by the
    /// worker, so a non-empty map means work is outstanding.
    pub(crate) fn has_active(&self) -> bool {
        !self
            .cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

/// The per-session worker. Runs one job at a time to completion.
///
/// Each job runs in its own task (finding A10). A panic in a transfer
/// therefore fails only that task — not the worker loop — so the worker
/// keeps draining later jobs and, critically, the job's `cancels` entry is
/// still removed below. The earlier design ran the job body inline: a panic
/// killed the whole loop, the panicked job's cancel token was never removed
/// (so `has_active()` — the quit guard's question — stayed `true` forever,
/// vetoing quit permanently), and every later queued job stalled unread.
/// Every job emits **exactly one** terminal event via [`run_one_job`]; if it
/// panics before doing so, we synthesize a terminal `Error` here.
pub(crate) async fn worker_loop(
    remote: Arc<RemoteFs>,
    mut jobs: mpsc::UnboundedReceiver<Job>,
    events: mpsc::UnboundedSender<TransferEvent>,
    cancels: Arc<Mutex<HashMap<String, CancellationToken>>>,
    shutdown: CancellationToken,
    max_entries: usize,
) {
    while let Some(job) = jobs.recv().await {
        let id = job.id.clone();
        let direction = job.direction;
        let name = job_display_name(&job);
        let task = tokio::spawn(run_one_job(
            Arc::clone(&remote),
            job,
            max_entries,
            events.clone(),
            shutdown.clone(),
        ));
        if let Err(join_err) = task.await {
            // A panic (or an abort during teardown) means `run_one_job` never
            // emitted its terminal event. Synthesize one so no queue row is
            // left non-terminal forever (finding A10). A duplicate is
            // impossible: the only terminal emit in `run_one_job` is its last
            // statement.
            if join_err.is_panic() {
                tracing::error!(transfer = %id, "files transfer job panicked");
                let mut progress = Progress::new(id.clone(), direction, name, events.clone());
                progress.finish(
                    TransferState::Error,
                    Some("the transfer failed unexpectedly".to_string()),
                );
            }
        }
        // ALWAYS free the slot — success, error, cancel, or panic — or the
        // quit guard wedges (finding A10).
        cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }
    // Reaching here is normal ONLY on teardown (the job sender dropped). Log
    // it so an unexpected early exit is visible rather than silent.
    tracing::debug!("files transfer worker exited");
}

/// Run a single job to a terminal event. Extracted from [`worker_loop`] so
/// each job can run in its own task (panic isolation, finding A10). Emits
/// exactly one terminal `TransferEvent` on every path.
async fn run_one_job(
    remote: Arc<RemoteFs>,
    job: Job,
    max_entries: usize,
    events: mpsc::UnboundedSender<TransferEvent>,
    shutdown: CancellationToken,
) {
    let id = job.id.clone();
    let name = job_display_name(&job);
    let mut progress = Progress::new(id.clone(), job.direction, name, events);

    if job.cancel.is_cancelled() || shutdown.is_cancelled() {
        progress.finish(TransferState::Cancelled, None);
        return;
    }
    progress.emit(TransferState::Running);
    let result = match job.direction {
        Direction::Download => download_item(&remote, &job, max_entries, &mut progress).await,
        Direction::Upload => upload_item(&remote, &job, max_entries, &mut progress).await,
    };
    match result {
        Ok(()) => progress.finish(TransferState::Done, None),
        Err(FilesError::Cancelled) => progress.finish(TransferState::Cancelled, None),
        Err(e) => {
            tracing::warn!(transfer = %id, "transfer failed: {e}");
            progress.finish(TransferState::Error, Some(e.to_string()));
        }
    }
}

/// The display name for a job's transfer events — the final path component,
/// falling back to the raw source only if it somehow has none (a job that
/// reached the worker already passed enqueue's name validation).
fn job_display_name(job: &Job) -> String {
    match job.direction {
        Direction::Download => rpath::basename(&job.item.source_path),
        Direction::Upload => local_file_name(Path::new(&job.item.source_path))
            .unwrap_or_else(|_| job.item.source_path.clone()),
    }
}

/// Destination paths that already exist for a prospective batch — the
/// pre-flight behind the one-shot overwrite dialog (§6). A directory item
/// conflicts when its destination directory already exists (v1 resolves
/// conflicts at the item level, not per nested file).
pub(crate) async fn check_conflicts(
    remote: &RemoteFs,
    direction: Direction,
    items: &[TransferItem],
) -> Result<Vec<String>, FilesError> {
    let mut out = Vec::new();
    for item in items {
        match direction {
            Direction::Download => {
                let name = rpath::basename(&item.source_path);
                if validate_remote_name(&name).is_err() || validate_local_write_name(&name).is_err()
                {
                    continue;
                }
                let dest = Path::new(&item.dest_dir).join(&name);
                if localfs::exists(&dest.display().to_string()).await? {
                    out.push(dest.display().to_string());
                }
            }
            Direction::Upload => {
                let name = local_file_name(Path::new(&item.source_path))?;
                if validate_remote_name(&name).is_err() {
                    continue;
                }
                let dest = rpath::join(&item.dest_dir, &name);
                if remote.try_exists(&dest).await? {
                    out.push(dest);
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Download (remote → local)
// ---------------------------------------------------------------------

async fn download_item(
    remote: &RemoteFs,
    job: &Job,
    max_entries: usize,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    let source = rpath::normalize(&job.item.source_path);
    let name = rpath::basename(&source);
    validate_remote_name(&name).map_err(|e| FilesError::unsafe_name(&name, e))?;
    validate_local_write_name(&name).map_err(|e| FilesError::unsafe_name(&name, e))?;
    let dest_dir = PathBuf::from(&job.item.dest_dir);

    // The item the user explicitly selected is followed (`metadata`), so
    // "download this symlink" does what it says. Links met *inside* a walk
    // are never followed — see `download_dir`.
    let meta = remote.file_meta(&source).await?;
    if meta.file_type().is_dir() {
        let local_root = dest_dir.join(&name);
        download_dir(
            remote,
            &source,
            &local_root,
            job.policy,
            &job.cancel,
            &job.id,
            max_entries,
            progress,
        )
        .await
    } else {
        // A single, known file: the engine knows the total is one (shared
        // frontend contract — `files_total` distinguishes a single-file job
        // from a not-yet-scanned recursive one).
        progress.set_files_total(Some(1));
        download_file(
            remote,
            &source,
            &dest_dir,
            &name,
            job.policy,
            &job.cancel,
            &job.id,
            progress,
        )
        .await
        .map(|_| ())
    }
}

/// Breadth-first recursive download. Directories are created as they are
/// discovered; files stream one at a time (same FIFO discipline as the
/// queue itself).
#[allow(clippy::too_many_arguments)]
async fn download_dir(
    remote: &RemoteFs,
    root_remote: &str,
    local_root: &Path,
    policy: OverwritePolicy,
    cancel: &CancellationToken,
    transfer_id: &str,
    max_entries: usize,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    // T43 / finding A3: a pre-existing LOCAL symlink at the destination root
    // must not be written *through*. `create_dir_all` on a symlink-to-dir
    // succeeds by following the link, so every file below would land at the
    // link target — outside the chosen destination. Refuse, don't descend.
    if localfs::is_symlink(local_root).await {
        progress.warn(format!(
            "refused {}: a symlink already exists at the download destination",
            local_root.display()
        ));
        return Ok(());
    }
    localfs::mkdir_all(local_root).await?;
    let mut queue: Vec<(String, PathBuf, usize)> =
        vec![(root_remote.to_string(), local_root.to_path_buf(), 0)];
    let mut idx = 0;
    let mut visited = 0usize;

    while idx < queue.len() {
        let (remote_dir, local_dir, depth) = queue[idx].clone();
        idx += 1;
        if depth >= MAX_WALK_DEPTH {
            return Err(FilesError::LimitExceeded {
                what: "directory depth in a recursive download",
                limit: MAX_WALK_DEPTH,
            });
        }
        let (entries, truncated) = remote.read_entries(&remote_dir).await?;
        if truncated {
            progress.warn(format!(
                "{} holds more than {} entries — the rest were skipped",
                remote_dir, max_entries
            ));
        }
        for entry in entries {
            if cancel.is_cancelled() {
                return Err(FilesError::Cancelled);
            }
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return Err(FilesError::LimitExceeded {
                    what: "entries in a recursive download",
                    limit: MAX_WALK_ENTRIES,
                });
            }
            // Hostile-name gate before ANY path join (T43). `read_entries`
            // already dropped structurally-unsafe names; this also covers
            // the Windows-only unusable forms for the local write.
            if let Err(reason) = validate_local_write_name(&entry.name) {
                progress.warn(format!("skipped an entry: {reason}"));
                continue;
            }
            let child_remote = rpath::join(&remote_dir, &entry.name);
            match entry.kind {
                EntryKind::Symlink => {
                    // Never followed: a remote link can point anywhere on
                    // the device (cycle + traversal risk). Reported, not
                    // silently dropped.
                    progress.warn(format!("skipped symlink {}", entry.name));
                }
                EntryKind::Dir => {
                    let child_local = local_dir.join(&entry.name);
                    // T43 / finding A3: never create-or-descend through a
                    // pre-existing local symlink — writes below it would
                    // escape the chosen destination. Combined with the
                    // `create_new` part-file open below (which refuses a
                    // symlink at the file path), a recursive download can no
                    // longer be redirected through any pre-existing link.
                    if localfs::is_symlink(&child_local).await {
                        progress.warn(format!(
                            "skipped {} (a local symlink already exists at the destination)",
                            entry.name
                        ));
                        continue;
                    }
                    localfs::mkdir_all(&child_local).await?;
                    queue.push((child_remote, child_local, depth + 1));
                }
                EntryKind::File => {
                    download_file(
                        remote,
                        &child_remote,
                        &local_dir,
                        &entry.name,
                        policy,
                        cancel,
                        transfer_id,
                        progress,
                    )
                    .await?;
                }
                EntryKind::Other => {
                    progress.warn(format!("skipped {} (not a regular file)", entry.name));
                }
            }
        }
    }
    Ok(())
}

/// Stream one remote file to `<dest_dir>/<name>`, via a unique
/// `<name>.<transfer_id>.transitpart`. Returns `false` when the file was
/// skipped.
#[allow(clippy::too_many_arguments)]
async fn download_file(
    remote: &RemoteFs,
    remote_path: &str,
    dest_dir: &Path,
    name: &str,
    policy: OverwritePolicy,
    cancel: &CancellationToken,
    transfer_id: &str,
    progress: &mut Progress,
) -> Result<bool, FilesError> {
    validate_local_write_name(name).map_err(|e| FilesError::unsafe_name(name, e))?;
    let dest = dest_dir.join(name);
    let dest_display = dest.display().to_string();

    if policy == OverwritePolicy::Skip && localfs::exists(&dest_display).await? {
        progress.warn(format!("skipped {name} (already exists)"));
        return Ok(false);
    }

    let meta = remote.file_meta(remote_path).await?;
    progress.begin_file(name, meta.size);

    // The transfer id makes the part name unique (finding A2), so a stale
    // `<name>.transitpart` from a crashed run — or a real file/symlink a
    // hostile listing named `<name>.transitpart` — is never truncated or
    // renamed away, and two concurrent runs never collide. `copy` opens it
    // `create_new`, refusing any pre-existing path (including a symlink).
    let part = dest_dir.join(format!("{name}.{transfer_id}{PART_SUFFIX}"));
    let result = copy_remote_to_local(remote, remote_path, &part, cancel, progress).await;
    if let Err(e) = result {
        // Never leave a truncated `.transitpart` behind.
        let _ = localfs::delete(&part.display().to_string(), false).await;
        return Err(e);
    }

    if let Some(mtime) = meta.mtime {
        set_local_mtime(&part, i64::from(mtime)).await;
    }

    // `std::fs::rename` replaces an existing file on Unix; on Windows it
    // fails if the destination is a directory and can trip on read-only
    // attributes, so clear the way first when the user asked to overwrite.
    #[cfg(windows)]
    if policy == OverwritePolicy::Overwrite && localfs::exists(&dest_display).await? {
        let _ = localfs::delete(&dest_display, false).await;
    }
    if let Err(e) = localfs::rename(&part.display().to_string(), &dest_display).await {
        let _ = localfs::delete(&part.display().to_string(), false).await;
        return Err(e);
    }
    progress.finish_file();
    Ok(true)
}

/// Release a remote handle on the CANCEL path without waiting for it.
///
/// `File::close` awaits every in-flight request before sending the close.
/// russh-sftp 3.0 pipelines up to `max_concurrent_reads` reads, so on a
/// slow link that wait is up to sixteen round-trips — long enough that
/// `FilesSession::close`'s drain timeout aborted the worker before the
/// job could emit its `Cancelled` event (seen on the slower CI runners).
/// Cancellation must be prompt. Since 3.0 a dropped `File` sends the
/// server a close without waiting (`Drop` → `close_nowait`), so dropping
/// is the right cancel-path release. The SUCCESS paths keep the awaited
/// close, because there the close status (and any pending write error)
/// is the result.
fn close_detached(handle: File) {
    drop(handle);
}

async fn copy_remote_to_local(
    remote: &RemoteFs,
    remote_path: &str,
    part: &Path,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    let mut reader = remote.open_read(remote_path).await?;
    // `create_new` (O_EXCL): fail if the part path already exists (finding
    // A2). It never truncates a pre-existing file and — crucially — refuses
    // to open through a pre-existing SYMLINK, so a hostile listing that
    // named an entry `<name>.<id>.transitpart` cannot redirect the write
    // (half of finding A3). The unique per-transfer id means this only ever
    // fails on a genuine collision, never on our own stale part.
    let mut writer = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(part)
        .await
        .map_err(|e| FilesError::Local {
            op: "create",
            path: part.display().to_string(),
            detail: e.to_string(),
        })?;

    let mut buf = vec![0u8; CHUNK];
    loop {
        let read = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                close_detached(reader);
                return Err(FilesError::Cancelled);
            }
            r = reader.read(&mut buf) => r,
        };
        let n = match read {
            Ok(n) => n,
            Err(e) => {
                return Err(FilesError::Remote {
                    op: "read",
                    path: remote_path.to_string(),
                    detail: e.to_string(),
                })
            }
        };
        if n == 0 {
            break;
        }
        writer
            .write_all(&buf[..n])
            .await
            .map_err(|e| FilesError::Local {
                op: "write",
                path: part.display().to_string(),
                detail: e.to_string(),
            })?;
        progress.add_bytes(n as u64);
    }
    writer.flush().await.map_err(|e| FilesError::Local {
        op: "write",
        path: part.display().to_string(),
        detail: e.to_string(),
    })?;
    // Close deliberately: on a plain drop russh-sftp discards the close
    // status (and any pending write error with it).
    let _ = reader.close().await;
    Ok(())
}

// ---------------------------------------------------------------------
// Upload (local → remote)
// ---------------------------------------------------------------------

async fn upload_item(
    remote: &RemoteFs,
    job: &Job,
    max_entries: usize,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    let source = PathBuf::from(&job.item.source_path);
    let name = local_file_name(&source)?;
    // A local name is about to become a remote path component.
    validate_remote_name(&name).map_err(|e| FilesError::unsafe_name(&name, e))?;

    let is_dir = tokio::fs::metadata(&source)
        .await
        .map_err(|e| FilesError::Local {
            op: "stat",
            path: job.item.source_path.clone(),
            detail: e.to_string(),
        })?
        .is_dir();

    if is_dir {
        let remote_root = rpath::join(&job.item.dest_dir, &name);
        upload_dir(
            remote,
            &source,
            &remote_root,
            job.policy,
            &job.cancel,
            &job.id,
            max_entries,
            progress,
        )
        .await
    } else {
        // Single, known file: the engine knows the total is one (shared
        // frontend `files_total` contract).
        progress.set_files_total(Some(1));
        upload_file(
            remote,
            &source,
            &job.item.dest_dir,
            &name,
            job.policy,
            &job.cancel,
            &job.id,
            progress,
        )
        .await
        .map(|_| ())
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_dir(
    remote: &RemoteFs,
    local_root: &Path,
    remote_root: &str,
    policy: OverwritePolicy,
    cancel: &CancellationToken,
    transfer_id: &str,
    max_entries: usize,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    ensure_remote_dir(remote, remote_root).await?;
    let mut queue: Vec<(PathBuf, String, usize)> =
        vec![(local_root.to_path_buf(), remote_root.to_string(), 0)];
    let mut idx = 0;
    let mut visited = 0usize;

    while idx < queue.len() {
        let (local_dir, remote_dir, depth) = queue[idx].clone();
        idx += 1;
        if depth >= MAX_WALK_DEPTH {
            return Err(FilesError::LimitExceeded {
                what: "directory depth in a recursive upload",
                limit: MAX_WALK_DEPTH,
            });
        }
        let listing =
            localfs::list_dir(Some(&local_dir.display().to_string()), max_entries).await?;
        if listing.truncated {
            progress.warn(format!(
                "{} holds more than {} entries — the rest were skipped",
                listing.path, max_entries
            ));
        }
        for entry in listing.entries {
            if cancel.is_cancelled() {
                return Err(FilesError::Cancelled);
            }
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return Err(FilesError::LimitExceeded {
                    what: "entries in a recursive upload",
                    limit: MAX_WALK_ENTRIES,
                });
            }
            if let Err(reason) = validate_remote_name(&entry.name) {
                progress.warn(format!("skipped an entry: {reason}"));
                continue;
            }
            let child_local = local_dir.join(&entry.name);
            let child_remote = rpath::join(&remote_dir, &entry.name);
            match entry.kind {
                EntryKind::Symlink => {
                    // Same rule as the download side, mirrored.
                    progress.warn(format!("skipped symlink {}", entry.name));
                }
                EntryKind::Dir => {
                    ensure_remote_dir(remote, &child_remote).await?;
                    queue.push((child_local, child_remote, depth + 1));
                }
                EntryKind::File => {
                    upload_file(
                        remote,
                        &child_local,
                        &remote_dir,
                        &entry.name,
                        policy,
                        cancel,
                        transfer_id,
                        progress,
                    )
                    .await?;
                }
                EntryKind::Other => {
                    progress.warn(format!("skipped {} (not a regular file)", entry.name));
                }
            }
        }
    }
    Ok(())
}

/// `mkdir` that tolerates an existing directory — a recursive upload into
/// a tree that partly exists is normal, and SFTP has no `mkdir -p`.
async fn ensure_remote_dir(remote: &RemoteFs, path: &str) -> Result<(), FilesError> {
    match remote.mkdir(path).await {
        Ok(()) => Ok(()),
        Err(FilesError::SessionClosed) => Err(FilesError::SessionClosed),
        Err(e) => {
            if remote.try_exists(path).await.unwrap_or(false) {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Stream one local file to `<remote_dir>/<name>`, ATOMICALLY: write a
/// unique `<name>.<transfer_id>.transitpart` on the device, then rename it
/// onto the real destination (finding A1). A cancel/error only ever removes
/// the temp — NEVER the real destination — so an interrupted upload can no
/// longer destroy the file it was replacing. Returns `false` when skipped.
#[allow(clippy::too_many_arguments)]
async fn upload_file(
    remote: &RemoteFs,
    local_path: &Path,
    remote_dir: &str,
    name: &str,
    policy: OverwritePolicy,
    cancel: &CancellationToken,
    transfer_id: &str,
    progress: &mut Progress,
) -> Result<bool, FilesError> {
    validate_remote_name(name).map_err(|e| FilesError::unsafe_name(name, e))?;
    let dest = rpath::join(remote_dir, name);

    if policy == OverwritePolicy::Skip && remote.try_exists(&dest).await? {
        progress.warn(format!("skipped {name} (already exists)"));
        return Ok(false);
    }

    let meta = tokio::fs::metadata(local_path)
        .await
        .map_err(|e| FilesError::Local {
            op: "stat",
            path: local_path.display().to_string(),
            detail: e.to_string(),
        })?;
    progress.begin_file(name, Some(meta.len()));

    // Unique temp beside the destination (same dir → the rename is a cheap
    // metadata op, not a cross-directory copy). The id makes it collision-
    // proof, so we never truncate a real file or a stale part.
    let temp = rpath::join(remote_dir, &format!("{name}.{transfer_id}{PART_SUFFIX}"));

    let result = copy_local_to_remote(remote, local_path, &temp, cancel, progress).await;
    if let Err(e) = result {
        // Clean up OUR temp only. The real destination is untouched — this is
        // the whole point of finding A1 (the old code truncated `dest` at
        // byte 0 and then `remove_file(dest)`'d it on cancel).
        let _ = remote.remove_file(&temp).await;
        return Err(e);
    }

    // Preserve mtime on the temp BEFORE the rename (rename carries it over),
    // mirroring the download side's ordering. Best-effort (§ decision 8):
    // plenty of servers refuse setstat.
    if let Some(mtime) = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
    {
        if let Err(e) = remote.set_mtime(&temp, mtime as u32).await {
            tracing::debug!("could not preserve mtime on upload: {e}");
        }
    }

    // SFTP v3 `rename` fails if the destination exists (unlike POSIX
    // rename), so under Overwrite clear the way just before the final swap —
    // the remote mirror of the download side's Windows-overwrite unlink. The
    // window between remove and rename is unavoidable in SFTP v3; keep it as
    // small as possible by doing it here, last.
    if policy == OverwritePolicy::Overwrite && remote.try_exists(&dest).await? {
        let _ = remote.remove_file(&dest).await;
    }
    if let Err(e) = remote.rename(&temp, &dest).await {
        let _ = remote.remove_file(&temp).await;
        return Err(e);
    }

    progress.finish_file();
    Ok(true)
}

/// Stream `local_path` to the given remote path (the caller passes the
/// unique temp; the rename onto the real destination happens in
/// [`upload_file`]).
async fn copy_local_to_remote(
    remote: &RemoteFs,
    local_path: &Path,
    remote_path: &str,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<(), FilesError> {
    let mut reader = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| FilesError::Local {
            op: "read",
            path: local_path.display().to_string(),
            detail: e.to_string(),
        })?;
    let mut writer = remote.create_write(remote_path).await?;

    let mut buf = vec![0u8; CHUNK];
    loop {
        if cancel.is_cancelled() {
            close_detached(writer);
            return Err(FilesError::Cancelled);
        }
        let n = reader.read(&mut buf).await.map_err(|e| FilesError::Local {
            op: "read",
            path: local_path.display().to_string(),
            detail: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        let write = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                close_detached(writer);
                return Err(FilesError::Cancelled);
            }
            w = writer.write_all(&buf[..n]) => w,
        };
        write.map_err(|e| FilesError::Remote {
            op: "write",
            path: remote_path.to_string(),
            detail: e.to_string(),
        })?;
        progress.add_bytes(n as u64);
    }
    // MUST close, not drop: `File::close` awaits the pending writes and the
    // close status, and russh-sftp discards both on a plain drop — a
    // dropped handle can report success for an upload the server rejected.
    writer.close().await.map_err(|e| FilesError::Remote {
        op: "write",
        path: remote_path.to_string(),
        detail: e.to_string(),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Progress bookkeeping
// ---------------------------------------------------------------------

/// Per-transfer progress state + the throttle.
///
/// `bytes_done` / `bytes_total` describe the **current file** so a
/// percentage is always meaningful (a recursive transfer has no pre-scan,
/// so a job-wide total doesn't exist); `files_done` counts completed
/// files, and `rate_bps` is measured over the whole job for a steadier
/// number.
struct Progress {
    id: String,
    direction: Direction,
    name: String,
    bytes_done: u64,
    bytes_total: Option<u64>,
    files_done: u64,
    /// Total files, when known up front: `Some(1)` for a single-file /
    /// non-directory job, `None` for a recursive directory job (no pre-scan
    /// in v1). The frontend renders a "file N" counter only when this is
    /// null or > 1 (shared contract with the Files pane).
    files_total: Option<u64>,
    skipped: u64,
    warnings: Vec<String>,
    /// Cumulative bytes across every file in this job — rate only.
    moved_total: u64,
    started: Instant,
    last_emit: Option<Instant>,
    events: mpsc::UnboundedSender<TransferEvent>,
}

impl Progress {
    fn new(
        id: String,
        direction: Direction,
        name: String,
        events: mpsc::UnboundedSender<TransferEvent>,
    ) -> Self {
        Self {
            id,
            direction,
            name,
            bytes_done: 0,
            bytes_total: None,
            files_done: 0,
            files_total: None,
            skipped: 0,
            warnings: Vec::new(),
            moved_total: 0,
            started: Instant::now(),
            last_emit: None,
            events,
        }
    }

    fn snapshot(&self, state: TransferState, error: Option<String>) -> TransferEvent {
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.05 && self.moved_total > 0 {
            Some((self.moved_total as f64 / elapsed) as u64)
        } else {
            None
        };
        TransferEvent {
            id: self.id.clone(),
            direction: self.direction,
            state,
            name: self.name.clone(),
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            files_done: self.files_done,
            files_total: self.files_total,
            rate_bps: rate,
            skipped: self.skipped,
            warnings: self.warnings.clone(),
            error,
        }
    }

    /// Force an emit (state transitions + terminal states).
    fn emit(&mut self, state: TransferState) {
        self.last_emit = Some(Instant::now());
        let _ = self.events.send(self.snapshot(state, None));
    }

    fn finish(&mut self, state: TransferState, error: Option<String>) {
        self.last_emit = Some(Instant::now());
        let _ = self.events.send(self.snapshot(state, error));
    }

    /// Throttled progress emit — at most one per [`PROGRESS_INTERVAL`].
    fn tick(&mut self) {
        let due = match self.last_emit {
            Some(at) => at.elapsed() >= PROGRESS_INTERVAL,
            None => true,
        };
        if due {
            self.emit(TransferState::Running);
        }
    }

    /// Set the known total file count (`Some(1)` for a single-file job).
    fn set_files_total(&mut self, total: Option<u64>) {
        self.files_total = total;
    }

    /// Begin a new file. Throttled via `tick()` — NOT an unconditional emit.
    /// A 10k-file recursive job used to emit ≥2 events per file here and in
    /// `finish_file` (≥20k events vs. the documented ~10 Hz); routing both
    /// through the throttle coalesces the burst (finding A11). The new
    /// file's name / total / running counters ride the next throttled emit
    /// (within `PROGRESS_INTERVAL`) or the always-emitted terminal event, so
    /// nothing is lost — the frontend's "file N" display still advances.
    fn begin_file(&mut self, name: &str, total: Option<u64>) {
        self.name = name.to_string();
        self.bytes_done = 0;
        self.bytes_total = total;
        self.tick();
    }

    fn add_bytes(&mut self, n: u64) {
        self.bytes_done += n;
        self.moved_total += n;
        self.tick();
    }

    /// Finish the current file. Throttled like `begin_file`; the final
    /// `files_done` always survives on the job's terminal event, which is
    /// never throttled.
    fn finish_file(&mut self) {
        self.files_done += 1;
        self.tick();
    }

    fn warn(&mut self, message: String) {
        self.skipped += 1;
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(message);
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Final component of a local path, as a `String`. Errors when there
/// isn't one (`/`, `C:\`) — there'd be nothing to name the transfer.
fn local_file_name(path: &Path) -> Result<String, FilesError> {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| FilesError::NoFileName {
            path: path.display().to_string(),
        })
}

/// Best-effort local mtime restore after a download. `set_modified` is
/// stable since Rust 1.75 and the workspace floor is 1.77.2.
async fn set_local_mtime(path: &Path, secs: i64) {
    let path = path.to_path_buf();
    let when = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    };
    let Some(when) = when else { return };
    let _ = tokio::task::spawn_blocking(move || set_modified_blocking(&path, when)).await;
}

fn set_modified_blocking(path: &Path, when: SystemTime) {
    match std::fs::File::options().write(true).open(path) {
        Ok(file) => {
            if let Err(e) = file.set_modified(when) {
                tracing::debug!("could not preserve mtime on download: {e}");
            }
        }
        Err(e) => tracing::debug!("could not reopen for mtime restore: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_file_name_rejects_rootish_paths() {
        assert_eq!(
            local_file_name(Path::new("/tmp/config.txt")).unwrap(),
            "config.txt"
        );
        assert!(local_file_name(Path::new("/")).is_err());
    }

    #[test]
    fn progress_throttles_running_but_never_terminal_states() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut p = Progress::new("t1".into(), Direction::Download, "f".into(), tx);
        p.emit(TransferState::Running);
        // Two immediate byte batches: the throttle collapses them.
        p.add_bytes(10);
        p.add_bytes(10);
        p.finish(TransferState::Done, None);

        let mut states = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            states.push(ev.state);
        }
        assert_eq!(
            states,
            vec![TransferState::Running, TransferState::Done],
            "throttled progress must collapse, terminal state must survive"
        );
    }

    #[test]
    fn per_file_transitions_are_throttled_and_counters_survive_on_terminal() {
        // Finding A11: begin_file/finish_file are throttled, not unconditional
        // emits. A burst of per-file transitions inside one PROGRESS_INTERVAL
        // must coalesce — but the running counters (files_done, current
        // name/total) still land on the always-emitted terminal event.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut p = Progress::new("t2".into(), Direction::Upload, "a".into(), tx);
        p.set_files_total(None); // a recursive (directory) job
        p.emit(TransferState::Running); // one forced running emit
        for i in 0..50 {
            p.begin_file(&format!("f{i}.txt"), Some(100));
            p.add_bytes(100);
            p.finish_file();
        }
        p.finish(TransferState::Done, None);

        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            events.len() < 10,
            "50 files must not emit ~150 events; got {}",
            events.len()
        );
        let last = events.last().unwrap();
        assert_eq!(last.state, TransferState::Done, "terminal always emits");
        assert_eq!(
            last.files_done, 50,
            "the final file count survives on the terminal event"
        );
        assert_eq!(last.files_total, None, "a directory job reports no total");
    }

    #[test]
    fn single_file_job_reports_files_total_of_one() {
        // Shared frontend contract: a single-file job carries files_total = 1
        // so the pane does NOT render a "file N" counter for it.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut p = Progress::new("t4".into(), Direction::Download, "x".into(), tx);
        p.set_files_total(Some(1));
        p.begin_file("x.conf", Some(10));
        p.add_bytes(10);
        p.finish_file();
        p.finish(TransferState::Done, None);
        let last = std::iter::from_fn(|| rx.try_recv().ok()).last().unwrap();
        assert_eq!(last.files_total, Some(1));
    }

    #[test]
    fn enqueue_is_all_or_nothing_when_a_later_item_is_invalid() {
        // Finding A6: a bad item late in the batch must not leave earlier
        // items already registered/emitted/dispatched.
        let (jobs_tx, mut jobs_rx) = mpsc::unbounded_channel();
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let cancels = Arc::new(Mutex::new(HashMap::new()));
        let queue = TransferQueue::new(
            jobs_tx,
            events_tx,
            Arc::clone(&cancels),
            CancellationToken::new(),
        );

        let err = queue.enqueue(
            Direction::Upload,
            vec![
                TransferItem {
                    source_path: "/tmp/good.conf".into(),
                    dest_dir: "/var/tmp".into(),
                },
                // `/` has no file name — invalid, and it is the SECOND item.
                TransferItem {
                    source_path: "/".into(),
                    dest_dir: "/var/tmp".into(),
                },
            ],
            OverwritePolicy::Overwrite,
        );
        assert!(matches!(err, Err(FilesError::NoFileName { .. })));
        assert!(
            jobs_rx.try_recv().is_err(),
            "no job may be dispatched when any item is invalid"
        );
        assert!(
            events_rx.try_recv().is_err(),
            "no Queued event may be emitted for a rejected batch"
        );
        assert!(
            !queue.has_active(),
            "no cancel token may be registered for a rejected batch"
        );
    }

    #[test]
    fn enqueue_rejects_a_traversal_basename_as_unsafe() {
        // Finding M7: enqueue is the "second layer" of the T43 gate (the
        // listing-time drop is the first). A crafted source_path whose
        // basename is `..` must be refused with UnsafeName, nothing dispatched.
        let (jobs_tx, mut jobs_rx) = mpsc::unbounded_channel();
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let queue = TransferQueue::new(
            jobs_tx,
            events_tx,
            Arc::new(Mutex::new(HashMap::new())),
            CancellationToken::new(),
        );
        let err = queue.enqueue(
            Direction::Download,
            vec![TransferItem {
                source_path: "/home/alice/..".into(),
                dest_dir: "/tmp".into(),
            }],
            OverwritePolicy::Overwrite,
        );
        assert!(
            matches!(err, Err(FilesError::UnsafeName { .. })),
            "a `..` basename must be refused as UnsafeName, got {err:?}"
        );
        assert!(jobs_rx.try_recv().is_err(), "nothing dispatched");
        assert!(events_rx.try_recv().is_err(), "nothing emitted");
    }

    #[test]
    fn warnings_are_capped_but_the_skip_count_is_not() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut p = Progress::new("t3".into(), Direction::Download, "d".into(), tx);
        for i in 0..(MAX_WARNINGS + 5) {
            p.warn(format!("skipped {i}"));
        }
        p.finish(TransferState::Done, None);
        let ev = std::iter::from_fn(|| rx.try_recv().ok()).last().unwrap();
        assert_eq!(ev.skipped, (MAX_WARNINGS + 5) as u64);
        assert_eq!(ev.warnings.len(), MAX_WARNINGS);
    }

    #[test]
    fn queue_cancel_reports_ownership() {
        let (jobs_tx, _jobs_rx) = mpsc::unbounded_channel();
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let cancels = Arc::new(Mutex::new(HashMap::new()));
        let queue = TransferQueue::new(
            jobs_tx,
            events_tx,
            Arc::clone(&cancels),
            CancellationToken::new(),
        );

        assert!(!queue.has_active());
        let descriptors = queue
            .enqueue(
                Direction::Download,
                vec![TransferItem {
                    source_path: "/var/log/messages".into(),
                    dest_dir: "/tmp".into(),
                }],
                OverwritePolicy::Overwrite,
            )
            .expect("enqueue");
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].name, "messages");
        assert!(queue.has_active(), "a queued transfer counts as active");

        let queued = events_rx.try_recv().expect("queued event");
        assert_eq!(queued.state, TransferState::Queued);

        assert!(!queue.cancel("not-a-transfer"), "unknown id → not ours");
        assert!(queue.cancel(&descriptors[0].id), "known id → ours");
        assert!(cancels.lock().unwrap()[&descriptors[0].id].is_cancelled());
    }

    #[test]
    fn enqueue_refuses_after_shutdown() {
        let (jobs_tx, _jobs_rx) = mpsc::unbounded_channel();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let queue = TransferQueue::new(
            jobs_tx,
            events_tx,
            Arc::new(Mutex::new(HashMap::new())),
            shutdown.clone(),
        );
        shutdown.cancel();
        let err = queue.enqueue(
            Direction::Upload,
            vec![TransferItem {
                source_path: "/tmp/x".into(),
                dest_dir: "/var/tmp".into(),
            }],
            OverwritePolicy::Skip,
        );
        assert!(matches!(err, Err(FilesError::SessionClosed)));
    }
}
