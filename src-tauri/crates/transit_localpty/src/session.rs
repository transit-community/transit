//! [`Session`] — a live local-shell connection over a pseudo-terminal.
//!
//! Mirrors `transit_console::Session`'s actor pattern so the Tauri side
//! treats every transport uniformly, with one structural difference:
//! `portable-pty`'s reader/writer are BLOCKING `std::io`, so the two
//! background loops are dedicated **OS threads** rather than tokio
//! tasks. The reader thread owns the child so it can reap its exit code
//! on EOF; the control thread owns the writer + master so it can service
//! `Data` writes and — the console has no analog for this — real
//! `Resize` (`master.resize`). Teardown kills the child (its blocking
//! read then returns EOF) and drops the command sender.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use portable_pty::{native_pty_system, Child, ChildKiller, CommandBuilder, MasterPty, PtySize};
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tracing::{debug, error, info, warn};
use transit_core::inventory::Vendor;
use transit_core::scrollback::ScrollbackRing;
use transit_core::session::TerminalSession;

use crate::error::LocalPtyError;
use crate::types::OpenParams;

/// Output broadcast size. Holds bursts of unprocessed bytes for the
/// slowest live subscriber. Identical sizing to the SSH / console crates.
pub const OUTPUT_CHANNEL_SIZE: usize = 256;

/// Keystroke / control channel size. Generous so a long paste never
/// blocks the frontend.
pub const INPUT_CHANNEL_SIZE: usize = 256;

/// Reader buffer size. 8 KiB — a local PTY delivers larger reads than a
/// serial cable (`cat` a file, a build log), so a bigger buffer means
/// fewer syscalls under bursty output.
const READ_BUF_SIZE: usize = 8192;

/// Per-session metadata. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    /// The shell program that was spawned (resolved path or bare name).
    pub program: String,
    /// Friendly label for the tab (e.g. `zsh`).
    pub label: String,
    /// ALWAYS [`Vendor::LocalShell`] — a local shell is never a network
    /// vendor. See [`OpenParams`]. This crate stores it but never reads
    /// it (the agent is structurally blind to local shells).
    pub vendor: Vendor,
    pub opened_at: time::OffsetDateTime,
}

/// Live local-shell session. Drop or [`close`](Session::close) to kill
/// the shell and tear down the background threads.
pub struct Session {
    /// 32K lines / 4 MiB rolling buffer, read by the frontend on tab
    /// attach. (The agent never reads a local shell — §2.)
    pub scrollback: Arc<ScrollbackRing>,
    /// Command channel to the control thread. `Option` so
    /// [`Session::close`] can `take()` + drop the sender (ending the
    /// control loop) without conflicting with `Drop`.
    cmd_tx: Option<mpsc::Sender<SessionCmd>>,
    /// Output broadcast. Use [`Self::subscribe`] for a receiver.
    output_tx: broadcast::Sender<Bytes>,
    /// Edge-triggered "session ended" signal, kept for the
    /// `TerminalSession` surface. Prefer [`Self::closed_rx`].
    ended: Arc<Notify>,
    /// Level-triggered twin of `ended`: flips to `true` when the shell
    /// exits and STAYS true, so a bridge that checks late still observes
    /// the close.
    closed_rx: watch::Receiver<bool>,
    /// Best-effort child exit code, populated by the REAPER thread once
    /// the shell exits. `None` while running (and if reaping failed).
    exit_code: Arc<Mutex<Option<i32>>>,
    /// Kills the child on close / drop. A clone of the child's killer,
    /// held here so teardown never depends on the control thread being
    /// scheduled.
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    meta: SessionMeta,
    reader_handle: Option<std::thread::JoinHandle<()>>,
    /// Reaper thread: owns the child, `wait()`s on it, and flips `closed`
    /// when it exits. Split from the reader because on Windows ConPTY does
    /// NOT EOF the master read when the child exits — so close-detection
    /// must key on `child.wait()` (reliable on every OS), not the reader.
    reaper_handle: Option<std::thread::JoinHandle<()>>,
    control_handle: Option<std::thread::JoinHandle<()>>,
}

#[derive(Debug)]
enum SessionCmd {
    /// Keystrokes / paste bytes → the PTY master's writer.
    Data(Bytes),
    /// Window resize → `master.resize`. Console has no analog (serial
    /// has no geometry); a real PTY must resize or full-screen programs
    /// render at the wrong size.
    Resize { cols: u16, rows: u16 },
}

impl Session {
    /// Spawn `params.program` in a fresh pseudo-terminal and start the
    /// reader + control threads. Returns once the shell is spawned;
    /// output starts flowing immediately (the shell prints its prompt).
    pub fn open(params: OpenParams) -> Result<Self, LocalPtyError> {
        let pty_system = native_pty_system();
        let size = PtySize {
            rows: params.rows.max(1),
            cols: params.cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        };
        let pair = pty_system
            .openpty(size)
            .map_err(|e| LocalPtyError::OpenFailed {
                program: params.program.clone(),
                detail: e.to_string(),
            })?;

        // Build the command: shell + argv, cwd (home when unset), and a
        // sane terminal env. `TERM`/`COLORTERM` first, then caller env
        // (profiles) layered on top.
        let mut cmd = CommandBuilder::new(&params.program);
        for a in &params.args {
            cmd.arg(a);
        }
        match &params.cwd {
            Some(cwd) => cmd.cwd(cwd),
            None => {
                if let Some(home) = dirs::home_dir() {
                    cmd.cwd(home);
                }
            }
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        for (k, v) in &params.env {
            cmd.env(k, v);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| LocalPtyError::SpawnFailed {
                program: params.program.clone(),
                detail: e.to_string(),
            })?;

        // Drop the slave so the child is the only holder of the slave
        // end: when it exits, the master read returns EOF. Keeping the
        // slave open would wedge the reader forever (no EOF).
        drop(pair.slave);

        // A killer clone drives teardown from close()/Drop without depending
        // on the control thread — and cleans up the child if either background
        // thread fails to spawn below (the child handle is moved into the
        // reader closure, so the killer is then the only way to reach it).
        let mut killer = child.clone_killer();

        let master = pair.master;
        let reader = master.try_clone_reader().map_err(|e| LocalPtyError::Io {
            detail: format!("clone reader: {e}"),
        })?;
        let writer = master.take_writer().map_err(|e| LocalPtyError::Io {
            detail: format!("take writer: {e}"),
        })?;

        let scrollback = Arc::new(ScrollbackRing::new());
        let (output_tx, _) = broadcast::channel(OUTPUT_CHANNEL_SIZE);
        let (cmd_tx, cmd_rx) = mpsc::channel(INPUT_CHANNEL_SIZE);
        let ended = Arc::new(Notify::new());
        let (closed_tx, closed_rx) = watch::channel(false);
        let exit_code = Arc::new(Mutex::new(None));

        info!(program = %params.program, "local shell session opened");

        let reader_handle = match std::thread::Builder::new()
            .name("localpty-reader".into())
            .spawn({
                let scrollback = Arc::clone(&scrollback);
                let output_tx = output_tx.clone();
                let program = params.program.clone();
                move || reader_loop(reader, scrollback, output_tx, program)
            }) {
            Ok(h) => h,
            Err(e) => {
                // `reader` dropped with the failed closure; the child + master
                // are still owned here and drop at scope end. Kill so the shell
                // isn't orphaned.
                let _ = killer.kill();
                return Err(LocalPtyError::Io {
                    detail: format!("spawn reader thread: {e}"),
                });
            }
        };

        let reaper_handle = match std::thread::Builder::new()
            .name("localpty-reaper".into())
            .spawn({
                let ended = Arc::clone(&ended);
                let exit_code = Arc::clone(&exit_code);
                let program = params.program.clone();
                move || reaper_loop(child, ended, closed_tx, exit_code, program)
            }) {
            Ok(h) => h,
            Err(e) => {
                // The child was moved into (and dropped with) the failed
                // closure, but dropping its handle does NOT kill the process.
                // Kill via the clone; the running reader unblocks when the
                // master drops at scope end.
                let _ = killer.kill();
                return Err(LocalPtyError::Io {
                    detail: format!("spawn reaper thread: {e}"),
                });
            }
        };

        let control_handle = match std::thread::Builder::new()
            .name("localpty-control".into())
            .spawn({
                let program = params.program.clone();
                move || control_loop(master, writer, cmd_rx, program)
            }) {
            Ok(h) => h,
            Err(e) => {
                // reader + reaper are already running; killing the child makes
                // the reaper return, and dropping the master at scope end makes
                // the reader hit EOF. Both (detached) threads then finish.
                let _ = killer.kill();
                return Err(LocalPtyError::Io {
                    detail: format!("spawn control thread: {e}"),
                });
            }
        };

        let meta = SessionMeta {
            program: params.program,
            label: params.label,
            vendor: Vendor::LocalShell,
            opened_at: time::OffsetDateTime::now_utc(),
        };

        Ok(Self {
            scrollback,
            cmd_tx: Some(cmd_tx),
            output_tx,
            ended,
            closed_rx,
            exit_code,
            killer: Mutex::new(killer),
            meta,
            reader_handle: Some(reader_handle),
            reaper_handle: Some(reaper_handle),
            control_handle: Some(control_handle),
        })
    }

    pub fn meta(&self) -> &SessionMeta {
        &self.meta
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    /// Edge-triggered "ended" signal, kept for the `TerminalSession`
    /// surface. Prefer [`Self::closed_rx`].
    pub fn ended_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    /// Level-triggered "ended" signal: reads `true` once the shell has
    /// exited, whenever the caller looks. Consumed by
    /// `transit_app::ssh::spawn_output_bridge`.
    pub fn closed_rx(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    /// Best-effort exit code of the shell once it has exited; `None`
    /// while it is still running (or if reaping failed). Drives the
    /// frontend's "process exited (code N) — press Enter" affordance.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code.lock().ok().and_then(|g| *g)
    }

    /// Queue keystrokes / paste bytes to the shell.
    pub async fn send_input(&self, bytes: Bytes) -> Result<(), LocalPtyError> {
        let tx = self.cmd_tx.as_ref().ok_or(LocalPtyError::SessionClosed)?;
        tx.send(SessionCmd::Data(bytes))
            .await
            .map_err(|_| LocalPtyError::SessionClosed)
    }

    /// Resize the PTY to `cols` × `rows`. The control thread calls
    /// `master.resize`; full-screen programs (vi/less/top) then repaint
    /// at the correct geometry.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), LocalPtyError> {
        let tx = self.cmd_tx.as_ref().ok_or(LocalPtyError::SessionClosed)?;
        tx.send(SessionCmd::Resize { cols, rows })
            .await
            .map_err(|_| LocalPtyError::SessionClosed)
    }

    /// Graceful close: kill the shell (the reaper's `wait()` returns and
    /// flips `closed`; dropping the command sender ends the control loop,
    /// which drops the master so the reader hits EOF), then join all three
    /// threads.
    ///
    /// Bounded: killing forces the blocking loops to return promptly, but
    /// the join is still capped at 2s so a wedged thread can never turn
    /// close into a hang.
    pub async fn close(mut self) -> Result<(), LocalPtyError> {
        // Recover from a poisoned lock (`into_inner`) rather than silently
        // skipping the kill — this is the last line of defense against an
        // orphaned shell, so it must run even if a prior holder panicked.
        {
            let mut k = self.killer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = k.kill();
        }
        drop(self.cmd_tx.take());

        let reader = self.reader_handle.take();
        let reaper = self.reaper_handle.take();
        let control = self.control_handle.take();
        let join = tokio::task::spawn_blocking(move || {
            // Control first (drops the master → the reader hits EOF), then the
            // reaper (child killed → wait returns), then the reader.
            if let Some(h) = control {
                let _ = h.join();
            }
            if let Some(h) = reaper {
                let _ = h.join();
            }
            if let Some(h) = reader {
                let _ = h.join();
            }
        });
        if tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .is_err()
        {
            warn!("local close: background threads did not join within 2s");
        }
        Ok(())
    }
}

#[async_trait]
impl TerminalSession for Session {
    fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    async fn send_input(&self, bytes: Bytes) -> Result<(), String> {
        Session::send_input(self, bytes)
            .await
            .map_err(|e| e.to_string())
    }

    fn ended_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    fn scrollback(&self) -> Arc<ScrollbackRing> {
        Arc::clone(&self.scrollback)
    }

    fn vendor(&self) -> Vendor {
        self.meta.vendor.clone()
    }

    fn opened_at(&self) -> time::OffsetDateTime {
        self.meta.opened_at
    }

    fn transport_label(&self) -> &'static str {
        "local"
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Belt-and-braces: if dropped without close(), kill the shell so
        // it doesn't orphan and the reader thread's blocking read returns
        // EOF. The thread handles detach on drop. Recover a poisoned lock so
        // a panic elsewhere can't leave the shell running.
        let mut k = self.killer.lock().unwrap_or_else(|e| e.into_inner());
        let _ = k.kill();
    }
}

// ---------------------------------------------------------------------
// Background threads (blocking std::io — NOT tokio tasks)
// ---------------------------------------------------------------------

fn reader_loop(
    mut reader: Box<dyn Read + Send>,
    scrollback: Arc<ScrollbackRing>,
    output_tx: broadcast::Sender<Bytes>,
    program: String,
) {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                debug!(program = %program, "local reader: EOF (shell exited)");
                break;
            }
            Ok(n) => {
                let chunk = Bytes::copy_from_slice(&buf[..n]);
                scrollback.push(&chunk);
                // `send` errors only with zero subscribers — fine, the
                // bytes are in scrollback and a late subscriber reads the
                // snapshot on attach.
                let _ = output_tx.send(chunk);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Not necessarily an error: on Linux a PTY master read after
                // the shell exits returns EIO (not `Ok(0)` like macOS), so
                // this is the NORMAL exit path there — log at debug to avoid
                // warning on every clean shell exit. The session still closes
                // correctly below (the exit code is reaped, `closed_tx` fires).
                debug!(program = %program, ?e, "local reader: read ended");
                break;
            }
        }
    }
    // Close-detection lives in the REAPER (`reaper_loop`, via `child.wait()`):
    // Windows ConPTY may never EOF this read when the child exits, so the reader
    // can't own the close signal. It just drains output until EOF — on Unix when
    // the child exits, and on every OS when close() drops the master.
}

/// Owns the child; blocks on `child.wait()` and, the moment the shell exits (on
/// its own or via the killer on close()), reaps the exit code and flips the
/// level-triggered `closed` + edge-triggered `ended`. This is the SOLE
/// close-detector — `child.wait()` waits on the process, not the PTY, so it is
/// reliable on every OS (unlike the reader's EOF, which Windows ConPTY withholds
/// past child exit).
fn reaper_loop(
    mut child: Box<dyn Child + Send + Sync>,
    ended: Arc<Notify>,
    closed_tx: watch::Sender<bool>,
    exit_code: Arc<Mutex<Option<i32>>>,
    program: String,
) {
    if let Ok(status) = child.wait() {
        let code = status.exit_code() as i32;
        if let Ok(mut slot) = exit_code.lock() {
            *slot = Some(code);
        }
    }
    debug!(program = %program, "local reaper: shell exited");
    // Level-triggered flip first (a bridge that checks late still sees `true`);
    // the Notify stays for `TerminalSession`.
    closed_tx.send_replace(true);
    ended.notify_waiters();
}

fn control_loop(
    master: Box<dyn MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    mut cmd_rx: mpsc::Receiver<SessionCmd>,
    program: String,
) {
    // `blocking_recv` is legal here: this runs on a plain OS thread, not
    // inside the tokio runtime.
    while let Some(cmd) = cmd_rx.blocking_recv() {
        match cmd {
            SessionCmd::Data(bytes) => {
                if let Err(e) = writer.write_all(&bytes) {
                    error!(program = %program, ?e, "local writer: write failed");
                    break;
                }
                if let Err(e) = writer.flush() {
                    error!(program = %program, ?e, "local writer: flush failed");
                    break;
                }
            }
            SessionCmd::Resize { cols, rows } => {
                let size = PtySize {
                    rows: rows.max(1),
                    cols: cols.max(1),
                    pixel_width: 0,
                    pixel_height: 0,
                };
                if let Err(e) = master.resize(size) {
                    warn!(program = %program, ?e, "local resize failed");
                }
            }
        }
    }
    // Sender dropped (session closed): drop writer + master, closing the
    // PTY master. With the child already killed on close, the reader has
    // already seen EOF.
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-shot command that writes a marker then exits with a known
    /// code — portable across the CI matrix (sh on Unix, cmd on Windows).
    fn marker_params() -> OpenParams {
        #[cfg(not(target_os = "windows"))]
        let (program, args) = (
            "/bin/sh".to_string(),
            vec![
                "-c".to_string(),
                "printf transit-marker; exit 7".to_string(),
            ],
        );
        #[cfg(target_os = "windows")]
        let (program, args) = (
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "echo transit-marker& exit 7".to_string()],
        );
        OpenParams {
            program,
            args,
            cwd: None,
            env: Vec::new(),
            label: "test".to_string(),
            cols: 80,
            rows: 24,
        }
    }

    async fn wait_closed(session: &Session) {
        let mut closed = session.closed_rx();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !*closed.borrow() {
                if closed.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("shell should exit within 10s");
    }

    /// Poll the scrollback for `needle`. The reaper flips `closed` on child
    /// exit, but the reader drains output on a separate thread, so the final
    /// bytes may land a beat after `closed` — poll rather than read once.
    async fn wait_for_marker(session: &Session, needle: &str) {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let out = String::from_utf8_lossy(&session.scrollback.snapshot()).to_string();
                if out.contains(needle) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let out = String::from_utf8_lossy(&session.scrollback.snapshot()).to_string();
            panic!("scrollback should contain {needle:?} within 8s; got: {out:?}")
        });
    }

    // Runs on EVERY OS, headless CI included. This test wedged on Windows
    // under portable-pty 0.9.0 — its ConPTY flags added
    // PSUEDOCONSOLE_INHERIT_CURSOR, which makes conhost emit ESC[6n at
    // startup and BLOCK all console I/O until a terminal replies (nothing
    // replies in a test, or in Transit's pipeline — the v4.4.0 Windows
    // smoke-test failure). The crate is pinned to 0.8.x, which doesn't pass
    // that flag, so a headless spawn runs/exits/reaps fine. If this test
    // times out on Windows again, check the portable-pty version FIRST.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_reads_output_and_reaps_exit_code() {
        let session = Session::open(marker_params()).expect("open local pty");
        assert_eq!(session.meta().vendor, Vendor::LocalShell);
        assert_eq!(session.meta().label, "test");

        wait_closed(&session).await;

        wait_for_marker(&session, "transit-marker").await;
        assert_eq!(session.exit_code(), Some(7), "exit code should be captured");

        session.close().await.expect("close");
    }

    /// Interactive-shell round-trip: spawn a REAL interactive shell (no
    /// `-c` / `/c` one-shot), type a command through the input path, and
    /// expect its echo/output back — the exact "tab opens, cursor blinks,
    /// keyboard does nothing" failure shape from the v4.4.0 Windows smoke
    /// test. Then `exit` and expect close-detection + reaping. This is the
    /// closest CI analog to a human using the Terminal surface.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interactive_shell_echoes_input_and_exits() {
        #[cfg(not(target_os = "windows"))]
        let (program, args) = ("/bin/sh".to_string(), Vec::new());
        #[cfg(target_os = "windows")]
        let (program, args) = ("cmd.exe".to_string(), Vec::new());
        let params = OpenParams {
            program,
            args,
            cwd: None,
            env: Vec::new(),
            label: "interactive".to_string(),
            cols: 80,
            rows: 24,
        };
        let session = Session::open(params).expect("open interactive shell");

        // Give the shell a beat to start; early bytes would just sit in the
        // PTY input buffer anyway, but this keeps the transcript readable.
        tokio::time::sleep(Duration::from_millis(500)).await;
        session
            .send_input(Bytes::from_static(b"echo transit-echo-probe\r"))
            .await
            .expect("send echo command");
        // The PTY echo of the typed line AND the command's own output both
        // carry the marker — either proves the input path end-to-end.
        wait_for_marker(&session, "transit-echo-probe").await;

        session
            .send_input(Bytes::from_static(b"exit\r"))
            .await
            .expect("send exit");
        wait_closed(&session).await;
        session.close().await.expect("close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn open_rejects_unresolvable_program() {
        let mut p = marker_params();
        p.program = "/no/such/transit-shell-xyzzy".to_string();
        p.args = Vec::new();
        assert!(
            Session::open(p).is_err(),
            "spawning a nonexistent program must fail"
        );
    }
}
