//! `Session` — PTY channel + bidirectional bytes + scrollback fanout.
//!
//! Open a session channel on top of an authenticated [`Connection`],
//! request a PTY + shell, and spawn two background tasks:
//!
//! - **Reader** — drives the russh `ChannelReadHalf`, pushes incoming
//!   bytes into [`ScrollbackRing`], and broadcasts to subscribers.
//! - **Writer** — owns the russh `ChannelWriteHalf`, processes
//!   keystroke / resize / close commands serialized through a single
//!   `mpsc` channel.
//!
//! The split-ownership model means resize and keystrokes don't race
//! for the channel: every server-bound operation goes through the
//! writer task in FIFO order.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use russh::{client::Msg, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tokio::time::timeout;
use tracing::{debug, error, warn};
use transit_core::inventory::Vendor;
use transit_core::session::TerminalSession;

use crate::connection::Connection;
use crate::error::SshError;
use crate::scrollback::ScrollbackRing;

/// Default request timeout for PTY allocation and shell start. The
/// vEX cold-start can take several seconds; we don't want to hang
/// forever if the device never replies.
pub const SESSION_OPEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Default broadcast channel size. Holds bursts of unprocessed bytes
/// for the slowest live subscriber. Large enough that the frontend
/// can lag a few hundred ms without dropping data; small enough that
/// a stalled subscriber pushes back via `RecvError::Lagged` instead
/// of buffering forever.
pub const OUTPUT_CHANNEL_SIZE: usize = 256;

/// Default keystroke channel size. Generous because pasting a long
/// command should not block on a slow writer.
pub const INPUT_CHANNEL_SIZE: usize = 256;

/// Per-session metadata. Cheap to clone — the strings are short and
/// the `OffsetDateTime` is `Copy`.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub term: String,
    /// Vendor of the connected device, sourced from inventory at
    /// connect time. Drives the post-auth paging-init step (see
    /// [`paging_init_for`]) and is read by Phase 6's
    /// `transit_app::ApprovalDispatcher` when adjudicating
    /// `propose_command` against the per-vendor `PolicyEngine`.
    pub vendor: Vendor,
    pub opened_at: time::OffsetDateTime,
}

/// Bytes the session sends to the device immediately after the shell
/// is up, to disable per-page output pagination. Pagination breaks
/// Phase 6's quiescence-based output capture — the agent waits for
/// silence, but a `---(more)---` prompt is silent waiting for input.
///
/// Per-vendor incantation:
///   - Cisco IOS / IOS-XE / NX-OS / Arista EOS — `terminal length 0`.
///     The CLI defaults to a 24-line `--More--` prompt.
///   - Junos — `set cli screen-length 0`. Paginates `show route`,
///     `show configuration`, etc. with `---(more X%)---`.
///   - PAN-OS — `set cli pager off`.
///   - Linux / UniFi / Unknown — nothing. A shell is a shell; we only
///     emit bytes for vendors we know are safe.
fn paging_init_for(vendor: &Vendor) -> Option<&'static [u8]> {
    match vendor {
        Vendor::CiscoIos
        | Vendor::CiscoIosXe
        | Vendor::CiscoIosXr
        | Vendor::NxOs
        | Vendor::AristaEos => Some(b"terminal length 0\n"),
        Vendor::Junos => Some(b"set cli screen-length 0\n"),
        Vendor::PanOs => Some(b"set cli pager off\n"),
        // Custom vendors have no known pager-disable incantation; the
        // command-capture quiescence heuristic tolerates pagination
        // (it just risks a `--More--` stall the user can scroll past).
        // LocalShell never reaches an SSH session (it's a local PTY, and
        // the agent is blind to it), but the match must be exhaustive —
        // and like Linux it has no network-CLI pager to disable.
        //
        // UniFi's CLI is a busybox shell, so it belongs with Linux here:
        // there is no `terminal length 0` equivalent, and sending a
        // network-CLI incantation into a shell would just echo an error
        // as the session's first line.
        Vendor::Linux
        | Vendor::UniFi
        | Vendor::LocalShell
        | Vendor::Unknown
        | Vendor::Custom(_) => None,
    }
}

/// Silence that suggests the device has stopped talking. Short enough
/// that a fast CLI is armed within half a second, long enough not to
/// fire in the gap between two bursts of a multi-part banner.
const PAGING_INIT_QUIET: Duration = Duration::from_millis(400);

/// Hard ceiling on waiting for a prompt. On expiry we send the init
/// anyway: a device that never prints a recognizable prompt must end up
/// no worse off than before this wait existed.
const PAGING_INIT_MAX_WAIT: Duration = Duration::from_secs(5);

/// How much trailing output to keep while looking for a prompt. A prompt
/// is short; this only has to survive the last line.
const PROMPT_TAIL_BYTES: usize = 256;

/// Whether the trailing output looks like a CLI prompt — loose about
/// vendor shapes (`>`, `#`, `$`, `%`) and biased toward false NEGATIVES,
/// because a missed prompt only costs us a wait we bound anyway, while a
/// false positive puts us back to firing into a device that isn't
/// listening.
///
/// Deliberately duplicated from `transit_app::agent_dispatch`'s sibling
/// helper rather than shared: the dependency runs app → ssh, so this
/// crate cannot reach that one, and hoisting it into `transit_core` to
/// dedupe would edit a Rule-3 file for a heuristic. If a third caller
/// ever appears, hoist it then.
fn tail_looks_like_prompt(tail: &[u8]) -> bool {
    let text = String::from_utf8_lossy(tail);
    let Some(last) = text.lines().rev().find(|l| !l.trim().is_empty()) else {
        return false;
    };
    let t = last.trim_end();
    t.len() <= 120 && (t.ends_with('>') || t.ends_with('#') || t.ends_with('$') || t.ends_with('%'))
}

/// Wait until the device's CLI looks ready to read input.
///
/// **Why this exists.** A live SSH shell channel is not a live CLI. We
/// used to queue the paging-init bytes the instant `request_shell` was
/// acknowledged, which works on gear whose CLI is already reading by
/// then — and silently fails on gear that is not. Arista EOS runs its
/// CLI as a separate process on a Fedora userland: it takes visibly
/// longer to present a prompt and DISCARDS anything typed before it
/// appears rather than buffering it. So `terminal length 0` was sent,
/// echoed into scrollback (making it look like it had run), and thrown
/// away — every session, on every EOS box. Reported by a customer
/// 2026-09-02 and reproduced in the lab on 192.0.2.190.
///
/// `transit_console`'s module docs already called this out for serial
/// ("no reliable post-auth checkpoint"); the finding is that SSH has the
/// same problem, just rarely enough to hide.
///
/// **Readiness signal.** Quiescence *plus* a prompt-shaped tail. Silence
/// alone is not enough — a device pausing mid-banner is also silent,
/// which is precisely the window we were firing into. Bounded by
/// `PAGING_INIT_MAX_WAIT` so an unrecognized prompt degrades to the old
/// behavior instead of dropping the init entirely.
async fn await_cli_ready(mut rx: broadcast::Receiver<Bytes>) {
    let deadline = tokio::time::Instant::now() + PAGING_INIT_MAX_WAIT;
    let mut tail: Vec<u8> = Vec::with_capacity(PROMPT_TAIL_BYTES * 2);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            debug!("paging init: no prompt seen within the cap, sending anyway");
            return;
        }
        match timeout(PAGING_INIT_QUIET.min(remaining), rx.recv()).await {
            Ok(Ok(bytes)) => {
                tail.extend_from_slice(&bytes);
                if tail.len() > PROMPT_TAIL_BYTES {
                    let cut = tail.len() - PROMPT_TAIL_BYTES;
                    tail.drain(..cut);
                }
            }
            // A lagged subscriber means output outran us; the tail we
            // hold is no longer the true tail, so drop it and keep
            // waiting for the next quiet moment.
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => tail.clear(),
            // Session gone. The send that follows is a harmless no-op.
            Ok(Err(broadcast::error::RecvError::Closed)) => return,
            Err(_) => {
                if tail_looks_like_prompt(&tail) {
                    return;
                }
                // Quiet but no prompt: still starting up. Keep waiting.
            }
        }
    }
}

/// Live PTY session. Drop or [`close`] to tear down the channel and
/// kill the background tasks.
///
/// [`close`]: Session::close
pub struct Session {
    /// 32K lines / 4 MiB rolling buffer. Read by the frontend at
    /// session attach (Phase 2c) and the agent's `read_scrollback`
    /// tool (Phase 5a).
    pub scrollback: Arc<ScrollbackRing>,
    /// Internal command channel. Wrapped in `Option` so [`close`]
    /// can `take()` and drop the sender (forcing the writer's
    /// `recv` to return None) without conflicting with the Drop
    /// impl. Methods that take `&self` borrow via `as_ref()`.
    ///
    /// [`close`]: Session::close
    cmd_tx: Option<mpsc::Sender<SessionCmd>>,
    /// Output broadcast. Use [`Self::subscribe`] to get a receiver.
    output_tx: broadcast::Sender<Bytes>,
    /// Fires when the reader task exits — i.e., the remote closed
    /// the channel (Eof / Close ChannelMsg) or the russh stream
    /// went away. Kept for the `TerminalSession::ended_notify`
    /// surface; new consumers should prefer [`Self::closed_rx`] —
    /// `Notify` is edge-triggered, so a notification fired before
    /// (or between) `notified()` registrations is lost forever.
    ended: Arc<Notify>,
    /// Level-triggered twin of `ended`: flips to `true` when the
    /// reader task exits and STAYS true, so a subscriber that checks
    /// late (e.g. the IPC output bridge task scheduled after the
    /// remote already closed) still observes the close. Receivers
    /// also observe sender-drop (reader task aborted) as a close.
    closed_rx: watch::Receiver<bool>,
    meta: SessionMeta,
    reader_handle: Option<tokio::task::JoinHandle<()>>,
    writer_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug)]
enum SessionCmd {
    Data(Bytes),
    Resize { cols: u16, rows: u16 },
    Close,
}

impl Session {
    /// Open a PTY shell on `connection`. `term` is forwarded to the
    /// server (typically `"xterm-256color"`). `cols` / `rows` are
    /// the initial window size; the caller calls [`Self::resize`]
    /// afterwards if the UI dimensions change. `vendor` is sourced
    /// from inventory at connect time — it drives the post-auth
    /// paging-init step (Cisco vendors get `terminal length 0`, so the
    /// first agent-driven `propose_command` quiescence capture sees no
    /// `--More--` markers). Those bytes are sent from a spawned task
    /// once the device's CLI looks ready, NOT before this returns — see
    /// [`await_cli_ready`] for why the difference matters.
    pub async fn open(
        connection: &Connection,
        term: &str,
        cols: u16,
        rows: u16,
        vendor: Vendor,
    ) -> Result<Self, SshError> {
        let channel = timeout(SESSION_OPEN_TIMEOUT, connection.open_session_channel())
            .await
            .map_err(|_| SshError::Timeout {
                host: connection.target().0.into(),
                port: connection.target().1,
            })?
            .map_err(|e| SshError::Other {
                detail: format!("channel_open_session: {e}"),
            })?;

        let (read_half, write_half) = channel.split();

        let scrollback = Arc::new(ScrollbackRing::new());
        let (output_tx, _) = broadcast::channel(OUTPUT_CHANNEL_SIZE);

        // Subscribe BEFORE the reader spawns, so the readiness waiter
        // cannot miss a banner that arrives while we are still setting
        // up. Only taken when there are init bytes to send.
        let paging_init = paging_init_for(&vendor);
        let paging_rx = paging_init.map(|_| output_tx.subscribe());
        let (cmd_tx, cmd_rx) = mpsc::channel(INPUT_CHANNEL_SIZE);
        let ended = Arc::new(Notify::new());
        let (closed_tx, closed_rx) = watch::channel(false);

        let scrollback_for_reader = Arc::clone(&scrollback);
        let output_for_reader = output_tx.clone();
        let ended_for_reader = Arc::clone(&ended);
        let reader_handle = tokio::spawn(reader_loop(
            read_half,
            scrollback_for_reader,
            output_for_reader,
            ended_for_reader,
            closed_tx,
        ));

        // request_pty / request_shell move into the writer task so
        // the `&write_half` borrows live entirely inside that task's
        // future. Holding them across awaits in Session::open trips
        // "Send is not general enough" because the channel-half's
        // auto-Sync derivation is sensitive to higher-ranked
        // lifetimes when composed inside a tauri::command future.
        // The setup_done oneshot lets `open` propagate the
        // PTY-allocation failure synchronously instead of leaking
        // a half-initialized session.
        let (setup_tx, setup_rx) = tokio::sync::oneshot::channel();
        let writer_handle = tokio::spawn(writer_loop(
            write_half,
            term.to_string(),
            cols,
            rows,
            connection.forward_agent(),
            setup_tx,
            cmd_rx,
        ));

        timeout(SESSION_OPEN_TIMEOUT, setup_rx)
            .await
            .map_err(|_| SshError::Timeout {
                host: connection.target().0.into(),
                port: connection.target().1,
            })?
            .map_err(|_| SshError::Other {
                detail: "writer task dropped before setup completed".into(),
            })??;

        // Queue the paging-init bytes (if any) before returning. The
        // writer task is already running and parked on `cmd_rx.recv()`
        // — sending the SessionCmd::Data straight in lands it ahead of
        // any user keystroke that arrives once `Session::open`'s
        // caller starts driving the session. Sending init bytes via
        // `cmd_tx` (rather than directly through the channel half)
        // means they appear in scrollback like any other input,
        // so the user sees what
        // we sent.
        if let (Some(init_bytes), Some(rx)) = (paging_init, paging_rx) {
            // Spawned, NOT awaited: `open` must stay snappy, and the
            // wait below can run to several seconds on slow-booting gear.
            // The device cannot read input before its prompt appears
            // anyway, so deferring makes interleaving with a user
            // keystroke less likely than sending eagerly did, not more.
            //
            // Best-effort send: if the writer task died in the meantime,
            // drop the init silently rather than surfacing an error that
            // would mask a more useful diagnostic from the next operation.
            let init_tx = cmd_tx.clone();
            tokio::spawn(async move {
                await_cli_ready(rx).await;
                let _ = init_tx
                    .send(SessionCmd::Data(Bytes::from_static(init_bytes)))
                    .await;
            });
        }

        let (host, port) = connection.target();
        let meta = SessionMeta {
            host: host.to_string(),
            port,
            username: connection.username().to_string(),
            term: term.to_string(),
            vendor,
            opened_at: time::OffsetDateTime::now_utc(),
        };

        Ok(Self {
            scrollback,
            cmd_tx: Some(cmd_tx),
            output_tx,
            ended,
            closed_rx,
            meta,
            reader_handle: Some(reader_handle),
            writer_handle: Some(writer_handle),
        })
    }

    pub fn meta(&self) -> &SessionMeta {
        &self.meta
    }

    /// Subscribe to the live PTY-output stream. Each subscriber gets
    /// every byte produced after the subscription was created.
    /// History before subscription is in [`Self::scrollback`].
    pub fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    /// Handle to the "session ended" signal. Fires when the reader
    /// task exits because the remote closed the channel. Multiple
    /// callers can `notified().await` on the returned `Arc<Notify>`.
    ///
    /// Edge-triggered — a notification fired before the caller's
    /// `notified()` registration is lost. Prefer [`Self::closed_rx`]
    /// unless the `TerminalSession` trait shape forces `Notify`.
    pub fn ended_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    /// Level-triggered "session ended" signal: the receiver reads
    /// `true` once the reader task has exited, no matter when the
    /// caller looks. `changed().await` wakes on the flip; a receiver
    /// error (sender dropped — reader task aborted) also means the
    /// session is gone. This is what the IPC output bridge consumes;
    /// see `transit_app::ssh::spawn_output_bridge`.
    pub fn closed_rx(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    /// Send keystrokes / paste bytes to the remote shell.
    pub async fn send_input(&self, bytes: Bytes) -> Result<(), SshError> {
        let tx = self.cmd_tx.as_ref().ok_or_else(|| SshError::Other {
            detail: "session is closed".into(),
        })?;
        tx.send(SessionCmd::Data(bytes))
            .await
            .map_err(|_| SshError::Other {
                detail: "session writer task has stopped".into(),
            })
    }

    /// Inform the server that the terminal window resized. Idempotent
    /// — sending the same dimensions twice is harmless.
    pub async fn resize(&self, cols: u16, rows: u16) -> Result<(), SshError> {
        let tx = self.cmd_tx.as_ref().ok_or_else(|| SshError::Other {
            detail: "session is closed".into(),
        })?;
        tx.send(SessionCmd::Resize { cols, rows })
            .await
            .map_err(|_| SshError::Other {
                detail: "session writer task has stopped".into(),
            })
    }

    /// Graceful close: send EOF, wait for the writer task to drain,
    /// then abort the reader task. Errors from the writer are logged
    /// but not surfaced — close should always succeed from the
    /// caller's perspective.
    ///
    /// Bounded: a wedged writer (full cmd channel, transport that
    /// never completes a write) must not turn close into a hang.
    /// `try_send` skips the Close marker if the channel is full —
    /// dropping the sender ends the writer's `recv` loop anyway —
    /// and the join is capped at 2s before the task is aborted.
    pub async fn close(mut self) -> Result<(), SshError> {
        if let Some(tx) = self.cmd_tx.take() {
            let _ = tx.try_send(SessionCmd::Close);
            // Drop the sender so the writer's `recv` returns None
            // after the (possibly skipped) Close command.
            drop(tx);
        }
        if let Some(mut h) = self.writer_handle.take() {
            if timeout(Duration::from_secs(2), &mut h).await.is_err() {
                warn!("session close: writer task did not drain within 2s; aborting");
                h.abort();
            }
        }
        if let Some(h) = self.reader_handle.take() {
            h.abort();
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
        "ssh"
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Belt-and-braces: even if the user mem::drops Session
        // without calling close(), abort both tasks so they don't
        // outlive the russh session handle (which would leak).
        if let Some(h) = self.reader_handle.take() {
            h.abort();
        }
        if let Some(h) = self.writer_handle.take() {
            h.abort();
        }
    }
}

// ---------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------

async fn reader_loop(
    mut read_half: ChannelReadHalf,
    scrollback: Arc<ScrollbackRing>,
    output_tx: broadcast::Sender<Bytes>,
    ended: Arc<Notify>,
    closed_tx: watch::Sender<bool>,
) {
    while let Some(msg) = read_half.wait().await {
        match dispatch(msg) {
            Dispatch::Bytes(data) => {
                scrollback.push(&data);
                // `send` errors only when there are zero subscribers,
                // which is fine — the bytes still made it into
                // scrollback. Frontend (re)subscribes get the full
                // history via the snapshot path.
                let _ = output_tx.send(data);
            }
            Dispatch::Close => {
                debug!("session reader: server signalled EOF/close");
                break;
            }
            Dispatch::ExitStatus(code) => {
                debug!(?code, "session reader: server reported exit status");
            }
            Dispatch::Ignore => {}
        }
    }
    // Signal subscribers (the IPC output bridge) that the remote
    // closed. Bytes pushed before this point are already in the
    // broadcast queue, so subscribers see them in order before the
    // signal fires. The watch flip is level-triggered (a bridge that
    // checks late still sees `true`); the Notify stays for the
    // `TerminalSession::ended_notify` surface.
    closed_tx.send_replace(true);
    ended.notify_waiters();
}

async fn writer_loop(
    write_half: ChannelWriteHalf<Msg>,
    term: String,
    cols: u16,
    rows: u16,
    forward_agent: bool,
    setup_tx: tokio::sync::oneshot::Sender<Result<(), SshError>>,
    mut cmd_rx: mpsc::Receiver<SessionCmd>,
) {
    // v6.5.0 — agent forwarding is requested BEFORE the PTY/shell, and
    // the ordering is load-bearing: sshd injects SSH_AUTH_SOCK into the
    // session environment only when `auth-agent-req@openssh.com`
    // arrives before the shell starts. The SUCCESS/FAILURE reply is
    // deliberately not awaited — the reader task's dispatch already
    // swallows it (like the pty/shell replies), and a server that
    // refuses forwarding must still yield a working shell.
    if forward_agent {
        if let Err(e) = write_half.agent_forward(true).await {
            let _ = setup_tx.send(Err(SshError::Other {
                detail: format!("agent_forward request: {e}"),
            }));
            return;
        }
    }

    // Allocate PTY + start shell. Both errors go back to Session::open
    // via the setup oneshot; if either fails the task exits without
    // entering the command loop.
    if let Err(e) = write_half
        .request_pty(true, &term, cols as u32, rows as u32, 0, 0, &[])
        .await
    {
        let _ = setup_tx.send(Err(SshError::Other {
            detail: format!("request_pty: {e}"),
        }));
        return;
    }
    if let Err(e) = write_half.request_shell(true).await {
        let _ = setup_tx.send(Err(SshError::Other {
            detail: format!("request_shell: {e}"),
        }));
        return;
    }
    if setup_tx.send(Ok(())).is_err() {
        // Caller already dropped — bail.
        return;
    }

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            SessionCmd::Data(bytes) => {
                // `&bytes[..]` implements tokio::io::AsyncRead via
                // tokio's blanket impl on byte slices.
                let mut slice = &bytes[..];
                if let Err(e) = write_half.data(&mut slice).await {
                    error!(?e, "session writer: channel.data failed");
                    break;
                }
            }
            SessionCmd::Resize { cols, rows } => {
                if let Err(e) = write_half
                    .window_change(cols as u32, rows as u32, 0, 0)
                    .await
                {
                    warn!(?e, "session writer: window_change failed");
                }
            }
            SessionCmd::Close => {
                let _ = write_half.eof().await;
                break;
            }
        }
    }
}

#[derive(Debug)]
enum Dispatch {
    Bytes(Bytes),
    Close,
    ExitStatus(u32),
    Ignore,
}

fn dispatch(msg: ChannelMsg) -> Dispatch {
    match msg {
        ChannelMsg::Data { data } => Dispatch::Bytes(data),
        // Standard SSH stderr ext code is 1 (SSH_EXTENDED_DATA_STDERR).
        // We fold stderr into the same scrollback / fanout — for an
        // interactive shell, stderr is part of the user-visible
        // terminal stream.
        ChannelMsg::ExtendedData { data, .. } => Dispatch::Bytes(data),
        ChannelMsg::Eof | ChannelMsg::Close => Dispatch::Close,
        ChannelMsg::ExitStatus { exit_status } => Dispatch::ExitStatus(exit_status),
        _ => Dispatch::Ignore,
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn dispatch_data_returns_bytes() {
        let msg = ChannelMsg::Data {
            data: Bytes::from_static(b"hello"),
        };
        let d = dispatch(msg);
        match d {
            Dispatch::Bytes(b) => assert_eq!(&b[..], b"hello"),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_extended_data_returns_bytes() {
        let msg = ChannelMsg::ExtendedData {
            data: Bytes::from_static(b"err"),
            ext: 1,
        };
        let d = dispatch(msg);
        match d {
            Dispatch::Bytes(b) => assert_eq!(&b[..], b"err"),
            other => panic!("expected Bytes (stderr folded into stream), got {other:?}"),
        }
    }

    #[test]
    fn dispatch_eof_returns_close() {
        assert!(matches!(dispatch(ChannelMsg::Eof), Dispatch::Close));
    }

    #[test]
    fn dispatch_close_returns_close() {
        assert!(matches!(dispatch(ChannelMsg::Close), Dispatch::Close));
    }

    #[test]
    fn dispatch_exit_status_returns_exit_status() {
        let d = dispatch(ChannelMsg::ExitStatus { exit_status: 0 });
        assert!(matches!(d, Dispatch::ExitStatus(0)));
    }

    #[test]
    fn dispatch_window_adjusted_is_ignored() {
        let d = dispatch(ChannelMsg::WindowAdjusted { new_size: 1024 });
        assert!(matches!(d, Dispatch::Ignore));
    }

    #[test]
    fn dispatch_failure_is_ignored() {
        let d = dispatch(ChannelMsg::Failure);
        assert!(matches!(d, Dispatch::Ignore));
    }

    #[test]
    fn paging_init_cisco_family_sends_terminal_length_zero() {
        for vendor in [
            Vendor::CiscoIos,
            Vendor::CiscoIosXe,
            Vendor::NxOs,
            Vendor::AristaEos,
        ] {
            assert_eq!(
                paging_init_for(&vendor),
                Some(b"terminal length 0\n".as_slice()),
                "vendor {} should disable paging",
                vendor.as_str()
            );
        }
    }

    #[test]
    fn paging_init_junos_sends_set_cli_screen_length_zero() {
        // `show route`, `show configuration`, and similar Junos
        // commands paginate with `---(more X%)---`, which makes the
        // agent's quiescence-based capture stall waiting for silence
        // that never comes.
        assert_eq!(
            paging_init_for(&Vendor::Junos),
            Some(b"set cli screen-length 0\n".as_slice()),
        );
    }

    // -----------------------------------------------------------------
    // CLI-readiness gate for the paging init (user bug, 2026-09-02).
    // -----------------------------------------------------------------

    #[test]
    fn prompt_tail_recognizes_vendor_prompt_shapes() {
        for p in [
            "switch>",
            "switch#",
            "arista-lab#",
            "user@host$",
            "admin@fw%",
            "leaf1(config)#",
        ] {
            assert!(
                tail_looks_like_prompt(p.as_bytes()),
                "{p} should look like a prompt"
            );
        }
    }

    #[test]
    fn prompt_tail_rejects_banners_and_data() {
        // Empty / whitespace, a banner line, and a long data line that
        // happens to end in '>' must all read as "not ready".
        assert!(!tail_looks_like_prompt(b""));
        assert!(!tail_looks_like_prompt(b"   \n \n"));
        assert!(!tail_looks_like_prompt(
            b"Last login: Tue Sep  2 09:14:02 2026 from 10.0.0.5"
        ));
        let long = format!("{}>", "x".repeat(200));
        assert!(!tail_looks_like_prompt(long.as_bytes()));
    }

    #[test]
    fn prompt_tail_ignores_trailing_blank_lines() {
        // A prompt followed by a newline is the normal shape off the
        // wire — the search walks back to the last non-empty line.
        assert!(tail_looks_like_prompt(b"switch#\n"));
        assert!(tail_looks_like_prompt(b"switch#\r\n\r\n"));
    }

    #[tokio::test(start_paused = true)]
    async fn ready_waits_for_the_prompt_not_merely_for_silence() {
        // THE REGRESSION. Arista EOS goes quiet mid-startup before its
        // CLI is reading; firing into that gap is what silently dropped
        // `terminal length 0` on every EOS session. Silence alone must
        // NOT be read as readiness.
        let (tx, rx) = broadcast::channel(16);
        let waiter = tokio::spawn(await_cli_ready(rx));

        // A banner, then a long quiet gap with no prompt in sight.
        tx.send(Bytes::from_static(b"Arista Networks EOS\n"))
            .unwrap();
        tokio::time::sleep(PAGING_INIT_QUIET * 3).await;
        assert!(
            !waiter.is_finished(),
            "silence without a prompt must not arm the init"
        );

        // Prompt arrives; after one quiet period we are ready.
        tx.send(Bytes::from_static(b"lab-arista#")).unwrap();
        tokio::time::sleep(PAGING_INIT_QUIET * 2).await;
        assert!(
            waiter.is_finished(),
            "a quiet, prompt-tailed device is ready"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_gives_up_at_the_cap_so_an_odd_prompt_still_gets_the_init() {
        // A device whose prompt we cannot recognize must end up no worse
        // than before this wait existed: send anyway at the ceiling.
        let (tx, rx) = broadcast::channel(16);
        let waiter = tokio::spawn(await_cli_ready(rx));
        tx.send(Bytes::from_static(b"weird-cli:: ")).unwrap();

        tokio::time::sleep(PAGING_INIT_MAX_WAIT / 2).await;
        assert!(
            !waiter.is_finished(),
            "should still be waiting before the cap"
        );

        tokio::time::sleep(PAGING_INIT_MAX_WAIT).await;
        assert!(waiter.is_finished(), "cap must release the init");
    }

    #[tokio::test(start_paused = true)]
    async fn ready_returns_immediately_when_the_session_dies() {
        // Dropping the sender closes the channel; the waiter must not
        // sit until the cap for a session that is already gone.
        let (tx, rx) = broadcast::channel::<Bytes>(16);
        let waiter = tokio::spawn(await_cli_ready(rx));
        drop(tx);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(waiter.is_finished(), "a closed channel ends the wait");
    }

    #[tokio::test(start_paused = true)]
    async fn ready_tolerates_a_lagged_subscriber() {
        // More output than the channel holds: the waiter drops its stale
        // tail and keeps waiting rather than treating garbage as a
        // prompt or bailing out.
        let (tx, rx) = broadcast::channel(2);
        let waiter = tokio::spawn(await_cli_ready(rx));
        for _ in 0..8 {
            tx.send(Bytes::from_static(b"scrolling banner line\n"))
                .unwrap();
        }
        tokio::time::sleep(PAGING_INIT_QUIET * 2).await;
        assert!(
            !waiter.is_finished(),
            "lag must not be mistaken for readiness"
        );

        tx.send(Bytes::from_static(b"lab-arista#")).unwrap();
        tokio::time::sleep(PAGING_INIT_QUIET * 2).await;
        assert!(waiter.is_finished());
    }

    #[test]
    fn paging_init_unknown_sends_nothing() {
        // We only emit init bytes for vendors we know are safe; a
        // future vendor that lands as `Unknown` until its policy
        // file is added gets no init.
        assert_eq!(paging_init_for(&Vendor::Unknown), None);
    }
}
