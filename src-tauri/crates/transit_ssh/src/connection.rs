//! `Connection` — TCP socket + russh client handshake + auth.
//!
//! Lifecycle:
//!
//! 1. Resolve TCP socket to `host:port`.
//! 2. Run russh handshake using [`crate::client_config`] (strict
//!    cipher/KEX/MAC allowlist).
//! 3. Inside the handshake, [`ConnectHandler::check_server_key`]
//!    enforces TOFU: known fingerprint match → proceed; first-seen →
//!    surface a confirmation request to the UI and wait for the
//!    user's verdict; mismatch → surface the changed-key WARNING
//!    request (same channel, `previous_fingerprint` set) — the user
//!    explicitly replaces the pin or the connect fails with
//!    `HostKeyMismatch`.
//! 4. Authenticate based on the `SecretRef`:
//!    - `SshAgent` → open an [`SshAgentSession`] and use russh's
//!      `authenticate_publickey_with`.
//!    - `Keyring` / `Op` / `Env` → resolve the value and call
//!      `authenticate_password`, falling back to keyboard-interactive
//!      (answering the prompts with the same secret) when the server
//!      rejects `password` but offers KBI — ESXi and other
//!      `PasswordAuthentication no` hosts.
//!    - `SshKey` → defer to Phase 2a.1, return a clear error.
//! 5. After successful auth, persist any pin the user confirmed
//!    during step 3 — a first-seen insert or an approved-rotation
//!    replace (only NOW — a confirmed dialog followed by a failed
//!    auth must not poison or rewrite the known-hosts file).
//!
//! `Connection` then exposes the inner russh handle for Task #66
//! to open a PTY channel.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::DisconnectReason;
use russh::keys::ssh_key::Algorithm;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use secrecy::{ExposeSecret, SecretString};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::{mpsc, watch, Mutex};
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;

/// Newtype wrapper that asserts the connect actor's future is `Send`.
///
/// **The true story (security review 2026-06-09, D-9a)**: the actor
/// future spawned in [`connect_inner`] is genuinely `Send` — every
/// value it captures or borrows across an `.await`
/// (`russh::client::Handle<ConnectHandler>`, `Fingerprint`,
/// `Algorithm`, the `Arc`s) is `Send + Sync`, machine-checked by the
/// `const` assertion below. rustc nonetheless rejects a plain
/// `tokio::spawn` of it with "implementation of `Send` is not
/// general enough … implemented for `&'0 Fingerprint`, for some
/// specific lifetime `'0`" — a known higher-ranked-lifetime
/// inference limitation where a borrow held across an await gets
/// quantified over an artificial universal lifetime instead of the
/// concrete one. (Verified again at this pin: deleting the wrapper
/// reproduces the diagnostic verbatim.)
///
/// The wrapper opts the ONE spawn site out of that broken inference
/// path. It cannot make a genuinely non-`Send` future `Send` safely
/// — soundness rests entirely on the asserted bounds below. A
/// russh/tokio upgrade that breaks any of them fails the `const`
/// assertion at compile time, not UB at runtime.
///
/// Adding a new use of this wrapper requires a security-audit
/// skill pass.
struct AssumeSendFuture<F>(F);

// Compile-time proof backing the SAFETY argument: every type the
// actor future captures (or borrows across an await — `&T: Send`
// for any lifetime whenever `T: Sync`) is Send + Sync.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<russh::client::Handle<ConnectHandler>>();
    assert_send_sync::<Fingerprint>();
    assert_send_sync::<Algorithm>();
    assert_send_sync::<PendingPinWrite>();
    assert_send_sync::<HostKeyStore>();
    assert_send_sync::<SecretRegistry>();
    assert_send_sync::<SecretRef>();
    assert_send_sync::<watch::Sender<bool>>();
    // The actor future spawned at the AssumeSendFuture site below ALSO
    // captures the command-channel receiver and the ready-signal sender.
    // These transitively pull in the third-party russh types
    // (`russh::Channel<Msg>`, `russh::Error`, reachable through
    // `ConnCmd`) plus `SshError` — the captures most likely to lose
    // `Send`/`Sync` across a russh/tokio upgrade. Asserting them here is
    // what makes the guard cover the WHOLE capture set (previously it
    // omitted these, so an upstream change could have become silent UB
    // rather than a compile error).
    assert_send_sync::<tokio::sync::mpsc::Receiver<ConnCmd>>();
    assert_send_sync::<tokio::sync::oneshot::Sender<Result<(), SshError>>>();
};

// SAFETY: the wrapped future's captures are all Send + Sync
// (machine-checked just above); the impl papers over a rustc
// higher-ranked-lifetime inference limitation, not a real auto-trait
// violation. See the type-level docstring.
#[allow(unsafe_code)]
unsafe impl<F> Send for AssumeSendFuture<F> {}

impl<F: Future> Future for AssumeSendFuture<F> {
    type Output = F::Output;

    #[allow(unsafe_code)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: pin projection — we never move `self.0`. The wrapper
        // contains only the inner future and adds no other state.
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll(cx)
    }
}

use crate::ciphers::{client_config, legacy_client_config};
use crate::error::SshError;
use crate::host_key::{Fingerprint, HostKeyStore, PinTier};

/// Default cap on the entire connect → handshake → auth flow.
/// Long enough that a slow vEX cold-start completes; short enough
/// that a black-holed remote IP doesn't hang the UI.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------
// Pause-aware connect deadline
// ---------------------------------------------------------------------

/// Shared "user interaction pending" flag for one connect attempt.
///
/// The connect deadline must bound *network* silence, not the user's
/// reading speed. Exactly two awaits in the connect flow park on a
/// human — the TOFU verdict wait in
/// [`ConnectHandler::check_server_key`] and the secret-backend
/// resolve in [`authenticate`] (1Password unlock / Touch ID) — and
/// both raise this flag for their duration so
/// [`deadline_with_interaction_pause`] re-arms instead of returning
/// a spurious `SshError::Timeout` at the user.
type InteractionPauseFlag = Arc<watch::Sender<bool>>;

/// RAII setter for [`InteractionPauseFlag`]. `enter` flips the flag
/// up; `Drop` flips it back down on every exit path (`?`, early
/// return, panic unwind), so the flag can never be left dangling
/// true after the user-facing await resolves.
struct InteractionPauseGuard {
    flag: InteractionPauseFlag,
}

impl InteractionPauseGuard {
    fn enter(flag: &InteractionPauseFlag) -> Self {
        flag.send_replace(true);
        Self {
            flag: Arc::clone(flag),
        }
    }
}

impl Drop for InteractionPauseGuard {
    fn drop(&mut self) {
        self.flag.send_replace(false);
    }
}

/// Race `fut` against a `cap` deadline that tolerates user
/// interaction. The timeout clock measures **network-silent** time
/// only: while the pause flag is up (a TOFU dialog or secret prompt is
/// open) the clock is stopped entirely, so the user gets unlimited
/// thinking time; each time the flag drops, a fresh `cap` runs for the
/// network phase that follows. With the flag down, the cap elapsing
/// returns `None` (timeout).
///
/// We stop-the-clock rather than re-arm it on expiry on purpose: a
/// re-armed deadline can land on the exact instant the future makes its
/// final progress, and `tokio::select!` breaks that tie randomly —
/// which surfaced as a flaky `interaction_pause_extends_deadline_past_cap`
/// on slower CI runners. Reacting to flag *transitions* (not polling the
/// flag value at an expiry instant) removes the tie. `borrow_and_update`
/// marks the current value seen so the next `changed()` only fires on a
/// real transition.
///
/// Built on `tokio::time` only, so tests drive it deterministically
/// with `tokio::time::pause()` / `start_paused`.
async fn deadline_with_interaction_pause<F: Future>(
    cap: Duration,
    mut pause_rx: watch::Receiver<bool>,
    fut: F,
) -> Option<F::Output> {
    tokio::pin!(fut);
    loop {
        if *pause_rx.borrow_and_update() {
            // Interaction in progress — the timeout clock is stopped.
            // Wait for the future to finish or the flag to drop.
            tokio::select! {
                biased;
                out = &mut fut => return Some(out),
                changed = pause_rx.changed() => {
                    // Sender gone (flag frozen up): don't spin — let the
                    // future run to completion.
                    if changed.is_err() {
                        return Some((&mut fut).await);
                    }
                    continue;
                }
            }
        } else {
            // Network-silent phase — a fresh `cap` is running.
            tokio::select! {
                biased;
                out = &mut fut => return Some(out),
                changed = pause_rx.changed() => {
                    // Sender gone (flag frozen down): fall back to a plain
                    // capped wait.
                    if changed.is_err() {
                        return tokio::time::timeout(cap, &mut fut).await.ok();
                    }
                    // Interaction started — loop back to the stopped-clock
                    // branch without counting this against the budget.
                    continue;
                }
                _ = tokio::time::sleep(cap) => {
                    // Re-check the flag: if it rose at this instant, the
                    // silence was the user's; keep waiting.
                    if *pause_rx.borrow() {
                        continue;
                    }
                    return None;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// Sent to the frontend when a host key needs a user verdict —
/// first contact (TOFU) or a changed key. The UI renders a
/// confirmation dialog (the loud changed-key WARNING variant when
/// `previous_fingerprint` is set) and replies via `responder`.
pub struct HostKeyConfirmRequest {
    /// The inventory device this prompt is about. Load-bearing for the
    /// dialog: two sites whose gateways are both `192.168.1.1` are
    /// exactly the case device-scoped pins exist for, and "192.168.1.1"
    /// alone would not tell the user which one they are trusting.
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub algorithm: String,
    /// `Some(pinned)` when this host already has a pinned fingerprint
    /// that does NOT match `fingerprint` — the key CHANGED since last
    /// connect (re-image, RMA, firmware re-key … or a MITM). The UI
    /// must render the warning variant and demand explicit
    /// verification; a `true` verdict replaces the pin (persisted
    /// only after auth succeeds). `None` = first contact.
    pub previous_fingerprint: Option<String>,
    pub responder: oneshot::Sender<bool>,
}

/// One `keyboard-interactive` prompt as the SERVER wrote it (RFC 4256).
///
/// ⚠️ `text` is attacker-controlled in the threat model: whoever runs the
/// host chooses it. It has already passed [`sanitize_server_text`] by the
/// time it leaves this crate, but the UI must still render it as
/// *quoted foreign text*, never as Transit's own copy — a host that sends
/// `"Enter your Anthropic API key:"` is the attack. Threat-model T46.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbiPrompt {
    /// Server-authored prompt text, sanitized.
    pub text: String,
    /// RFC 4256 `echo` flag: `false` = mask the input (a password),
    /// `true` = show it (a menu selection, an account name). Honor it;
    /// masking a menu choice is as wrong as echoing a password.
    pub echo: bool,
}

/// Sent to the frontend when the server wants a human to answer an
/// interactive auth challenge (`SecretRef::Prompt`). The UI renders the
/// prompts and replies on `responder` with one answer per prompt, in
/// order, or `None` to abandon the attempt.
///
/// Nothing here is persisted: the answers are moved into the auth attempt
/// and dropped at its scope exit. See threat-model T46.
pub struct KbiPromptRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Server-authored challenge name, sanitized. Often empty.
    pub name: String,
    /// Server-authored instruction block, sanitized. Often empty.
    pub instruction: String,
    /// TRANSIT-authored explanation, empty for a real server challenge.
    ///
    /// Kept separate from `name`/`instruction` on purpose: the dialog
    /// renders those under a "Message from the server" heading, and the
    /// T46.1 provenance guarantee is that server text can never pass for
    /// Transit's own copy. The password fallback needs to explain ITSELF
    /// ("this device doesn't offer keyboard-interactive"), which is the
    /// opposite direction — Transit's words must not appear to be the
    /// server's either.
    pub notice: String,
    pub prompts: Vec<KbiPrompt>,
    /// `Some(answers)` — one per prompt, same order. `None` — the user
    /// cancelled; the auth attempt fails cleanly rather than hanging.
    pub responder: oneshot::Sender<Option<Vec<SecretString>>>,
}

/// Longest server-authored auth string we will relay to the UI.
///
/// RFC 4256 puts no bound on these fields. The cap is deliberately
/// generous enough for a real MOTD-style instruction block but small
/// enough that a hostile host cannot push a wall of text designed to
/// scroll our own dialog chrome out of view (T46.1).
const MAX_SERVER_TEXT: usize = 512;

/// Upper bound on `keyboard-interactive` rounds for ONE auth attempt.
///
/// RFC 4256 lets a server issue `InfoRequest`s indefinitely. Without a
/// bound, a misbehaving or hostile host could loop the exchange forever —
/// and on the interactive path that means re-prompting the human forever.
/// Shared by both KBI drivers so the two can't drift apart.
const MAX_KBI_ROUNDS: usize = 16;

/// Upper bound on prompts in ONE `keyboard-interactive` round.
///
/// RFC 4256 encodes `num-prompts` as a uint32, so a hostile or broken
/// server can ask for an arbitrary number of fields in a single round —
/// which on the interactive path becomes an arbitrary number of rendered
/// inputs in a modal the user cannot dismiss without answering. Real
/// challenges use one to three (password; password + token; PAM menu).
/// Refuse beyond this rather than relay it (T46.1).
const MAX_KBI_PROMPTS: usize = 8;

/// Input bundle for [`Connection::connect`]. Bundled into a struct
/// rather than a 7-arg function so callers don't reorder positional
/// arguments by mistake.
pub struct ConnectParams {
    /// Inventory id of the device being connected to. Scopes the host-key
    /// pin (see [`HostKeyStore::lookup`]) and names the device in the TOFU
    /// dialog and in host-key errors. For a jump hop this is the HOP's own
    /// device id, so every leg of a chain pins independently.
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub secret_ref: SecretRef,
    pub auth: Arc<SecretRegistry>,
    pub host_keys: Arc<HostKeyStore>,
    /// UI-side TOFU confirmation channel. The connection layer
    /// sends a [`HostKeyConfirmRequest`] on first-seen and waits for
    /// the user's verdict on the request's `responder` oneshot.
    pub confirm_tx: mpsc::Sender<HostKeyConfirmRequest>,
    /// UI-side interactive-auth channel, used ONLY by
    /// [`SecretRef::Prompt`]. The connection layer sends a
    /// [`KbiPromptRequest`] for each round of the server's
    /// `keyboard-interactive` conversation and waits for the human's
    /// answers on the request's `responder` oneshot.
    ///
    /// Separate from `confirm_tx` on purpose: a host-key verdict is a
    /// boolean about a fingerprint, an auth answer is a credential. They
    /// have different payload sensitivity and different UI, so they get
    /// different channels rather than one union type.
    pub kbi_tx: mpsc::Sender<KbiPromptRequest>,
    /// Optional override for the connect timeout. Defaults to
    /// [`CONNECT_TIMEOUT`].
    pub timeout: Option<Duration>,
    /// When true, negotiate with [`crate::ciphers::legacy_client_config`]
    /// (which includes SHA1 KEX/MAC, CBC ciphers, and ssh-rsa
    /// host-key signatures) instead of the strict floor. Set ONLY
    /// after the user has explicitly opted in via the weak-crypto
    /// warning dialog; never default to true.
    pub allow_weak_crypto: bool,
    /// Established connection to a JUMP HOST to tunnel through
    /// (v6.5.0, T52). `None` = direct TCP. When `Some`, the transport
    /// opens a fresh `direct-tcpip` channel on it to `(host, port)`
    /// and runs the full SSH handshake over that byte pipe — host-key
    /// verification and auth for the target stay end-to-end, the jump
    /// only ever forwards ciphertext. The returned [`Connection`]
    /// keeps this `Arc` alive for exactly its own lifetime (`_via`),
    /// so a live session's tunnel can't be dropped out from under it,
    /// and drop order is structural: the dependent connection's actor
    /// aborts before the jump is released. A FRESH channel is opened
    /// per connect attempt, so the weak-crypto retry ladder works
    /// through tunnels unchanged.
    pub via: Option<Arc<Connection>>,
    /// Per-device SSH agent forwarding opt-in (v6.5.0, T53). When
    /// true, PTY sessions request `auth-agent-req@openssh.com` before
    /// the shell and the handler accepts the server's agent channels,
    /// pumping them to the LOCAL primary agent. When false (the only
    /// sane default — never default to true), inbound agent channels
    /// are explicitly rejected: russh's stock handler would ACCEPT
    /// them, so the override is load-bearing hardening even for
    /// devices that never request forwarding.
    pub forward_agent: bool,
}

/// Authenticated russh client.
///
/// **Why an actor**: moving the `Handle` into a dedicated tokio task
/// at construction time and exposing only mpsc/oneshot channels to
/// callers keeps the `tauri::command` futures trivially `Send`.
/// (Historically this was justified as "`Handle` is `!Sync`" — under
/// the pinned russh 0.61 / tokio that's false; `Handle` is
/// `Send + Sync`, machine-checked next to [`AssumeSendFuture`]. The
/// real culprit is a rustc higher-ranked-lifetime inference
/// limitation on borrows held across awaits — see the wrapper's
/// docstring — and the actor keeps that wart contained to one spawn
/// site instead of every command.)
pub struct Connection {
    cmd_tx: tokio::sync::mpsc::Sender<ConnCmd>,
    target: (String, u16),
    username: String,
    actor: Option<tokio::task::JoinHandle<()>>,
    /// The jump-host connection carrying this one, if any (v6.5.0).
    /// Held so ownership follows dependency: this connection's `Drop`
    /// aborts its own actor FIRST (field order — `actor` teardown runs
    /// in `Drop::drop`, before fields drop), and only then releases
    /// the jump. The guaranteed property is the ORDER (the jump Arc
    /// cannot be freed while a dependent `Connection` exists); `abort`
    /// is a cancellation REQUEST, so only the graceful path
    /// (`Session::close`) is promised a still-live tunnel to drain
    /// over — a plain drop's SSH-level goodbye is best-effort, which
    /// costs at most an unclean-close log line on the device. Chains
    /// compose transitively — each hop owns its predecessor, so parking
    /// the final `Connection` in a `SessionEntry` keeps the whole chain
    /// alive with no extra bookkeeping at the app layer.
    _via: Option<Arc<Connection>>,
    /// Connect-time agent-forwarding opt-in, read by `Session::open`
    /// to decide whether to send `auth-agent-req@openssh.com`. Stored
    /// here (not passed to `Session::open`) so the request side and
    /// the handler's accept side can never disagree.
    forward_agent: bool,
}

enum ConnCmd {
    OpenSession {
        reply:
            tokio::sync::oneshot::Sender<Result<russh::Channel<russh::client::Msg>, russh::Error>>,
    },
    /// v6.5.0 — open a `direct-tcpip` channel to a jump target. The
    /// channel leaves the actor by value exactly like `OpenSession`;
    /// every tunneled byte then flows outside the actor task. Covered
    /// by the existing `assert_send_sync::<Receiver<ConnCmd>>` proof.
    OpenDirectTcpip {
        host: String,
        port: u32,
        reply:
            tokio::sync::oneshot::Sender<Result<russh::Channel<russh::client::Msg>, russh::Error>>,
    },
}

impl Connection {
    pub async fn connect(params: ConnectParams) -> Result<Self, SshError> {
        let cap = params.timeout.unwrap_or(CONNECT_TIMEOUT);
        // Clone before `params` moves into `connect_inner` so a
        // timeout names the real target instead of "unknown":0.
        let host = params.host.clone();
        let port = params.port;
        // Pause-aware deadline: the TOFU dialog and the secret-
        // backend prompt raise the flag for exactly their awaits, so
        // a careful user can't burn the network budget by reading.
        let (pause_tx, pause_rx) = watch::channel(false);
        let pause: InteractionPauseFlag = Arc::new(pause_tx);
        match deadline_with_interaction_pause(cap, pause_rx, connect_inner(params, pause)).await {
            Some(result) => result,
            None => Err(SshError::Timeout { host, port }),
        }
    }

    pub fn target(&self) -> (&str, u16) {
        (&self.target.0, self.target.1)
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// Connect-time agent-forwarding opt-in (v6.5.0). Read by
    /// [`crate::Session::open`] to decide whether the PTY channel
    /// requests `auth-agent-req@openssh.com` before the shell.
    pub(crate) fn forward_agent(&self) -> bool {
        self.forward_agent
    }

    /// Open a `direct-tcpip` channel to `(target_host, target_port)`
    /// and hand it back as a plain byte stream — the jump-host tunnel
    /// (v6.5.0, T52). The SSH handshake for the TARGET runs over the
    /// returned stream via `connect_stream`, so the jump only ever
    /// carries ciphertext. `impl Trait` keeps russh types off the
    /// public surface (the `open_subsystem_stream` discipline).
    ///
    /// Failure maps to [`SshError::JumpTunnelRefused`] naming both
    /// ends: the usual cause is the jump's sshd refusing the open
    /// (`AllowTcpForwarding no` → administratively prohibited) or the
    /// target being unreachable FROM the jump.
    pub async fn open_direct_tcpip(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static, SshError>
    {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let refused = |detail: String| SshError::JumpTunnelRefused {
            jump_host: self.target.0.clone(),
            jump_port: self.target.1,
            target_host: target_host.to_string(),
            target_port,
            detail,
        };
        self.cmd_tx
            .send(ConnCmd::OpenDirectTcpip {
                host: target_host.to_string(),
                port: u32::from(target_port),
                reply,
            })
            .await
            .map_err(|_| refused("the jump connection is no longer alive".to_string()))?;
        let channel = rx
            .await
            .map_err(|_| refused("the jump connection closed mid-request".to_string()))?
            .map_err(|e| refused(e.to_string()))?;
        Ok(channel.into_stream())
    }

    /// Open a session-mode russh channel by sending a command to
    /// the actor task that owns the russh handle. Used by
    /// [`crate::Session::open`].
    pub(crate) async fn open_session_channel(
        &self,
    ) -> Result<russh::Channel<russh::client::Msg>, russh::Error> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::OpenSession { reply })
            .await
            .map_err(|_| russh::Error::SendError)?;
        rx.await.map_err(|_| russh::Error::SendError)?
    }

    /// Open a session channel, start the named SSH **subsystem** on it,
    /// and hand the channel back as a plain byte stream.
    ///
    /// The v5.0.0 Files pane's seam (`name = "sftp"`;
    /// the files pane sftp design notes (not included in this repository)). `transit_files` is
    /// transport-agnostic — it consumes any
    /// `AsyncRead + AsyncWrite + Unpin + Send + 'static` — so the
    /// `impl Trait` return keeps russh types out of this crate's public
    /// surface, the same discipline [`crate::Session`] follows with the
    /// channel halves.
    ///
    /// A subsystem channel IS a session channel, so the connect actor
    /// needs no new [`ConnCmd`]: the channel leaves the actor by value
    /// exactly as it does for a PTY, and every subsequent SFTP byte
    /// moves over the returned stream — zero SFTP work happens inside
    /// the actor task.
    ///
    /// **Why we wait for the channel-request reply.** russh's
    /// `request_subsystem` only *queues* the request; the server's
    /// verdict arrives later as `ChannelMsg::Success` / `Failure`.
    /// Without the wait, gear with no SFTP server (newer Junos before
    /// `set system services ssh sftp-server`) would surface as an
    /// opaque EOF halfway through the SFTP INIT handshake instead of a
    /// named, actionable [`SshError::SubsystemUnavailable`]. Draining
    /// pre-reply messages is safe for SFTP specifically: the protocol is
    /// client-speaks-first (we send `SSH_FXP_INIT`), so the server has
    /// nothing to say before it confirms the subsystem.
    pub async fn open_subsystem_stream(
        &self,
        name: &str,
    ) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static, SshError>
    {
        use crate::session::SESSION_OPEN_TIMEOUT;
        use russh::ChannelMsg;

        let (host, port) = (self.target.0.clone(), self.target.1);
        let unavailable = |detail: String| SshError::SubsystemUnavailable {
            host: host.clone(),
            port,
            name: name.to_string(),
            detail,
        };

        let mut channel = tokio::time::timeout(SESSION_OPEN_TIMEOUT, self.open_session_channel())
            .await
            .map_err(|_| SshError::Timeout {
                host: host.clone(),
                port,
            })?
            .map_err(|e| unavailable(format!("channel_open_session: {e}")))?;

        channel
            .request_subsystem(true, name)
            .await
            .map_err(|e| unavailable(format!("subsystem request failed to send: {e}")))?;

        // `None` = the channel ended without a verdict; `Some(false)` =
        // an explicit refusal (or an immediate Eof/Close, which some
        // servers send instead of `Failure`).
        let verdict = tokio::time::timeout(SESSION_OPEN_TIMEOUT, async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Success => return Some(true),
                    ChannelMsg::Failure | ChannelMsg::Eof | ChannelMsg::Close => {
                        return Some(false)
                    }
                    // Window adjustments / other bookkeeping can precede
                    // the reply; keep waiting.
                    _ => continue,
                }
            }
            None
        })
        .await
        .map_err(|_| SshError::Timeout {
            host: host.clone(),
            port,
        })?;

        match verdict {
            Some(true) => {
                tracing::debug!(%host, port, subsystem = %name, "subsystem started");
                Ok(channel.into_stream())
            }
            Some(false) => Err(unavailable(
                "the device refused the subsystem request".to_string(),
            )),
            None => Err(unavailable(
                "the device closed the channel without replying".to_string(),
            )),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(h) = self.actor.take() {
            h.abort();
        }
    }
}

async fn handle_actor_loop(
    handle: russh::client::Handle<ConnectHandler>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<ConnCmd>,
) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            ConnCmd::OpenSession { reply } => {
                let res = handle.channel_open_session().await;
                let _ = reply.send(res);
            }
            ConnCmd::OpenDirectTcpip { host, port, reply } => {
                // Conventional originator values — sshd logs them but
                // applies no policy to them; the tunnel is attributed
                // to the authenticated user, not this tuple.
                let res = handle
                    .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
                    .await;
                let _ = reply.send(res);
            }
        }
    }
    // `handle` drops here, closing the SSH session.
    drop(handle);
}

async fn connect_inner(
    params: ConnectParams,
    interaction_pause: InteractionPauseFlag,
) -> Result<Connection, SshError> {
    let host = params.host.clone();
    let port = params.port;

    match params.via.clone() {
        None => {
            let stream = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| SshError::Network {
                    host: host.clone(),
                    port,
                    source: e,
                })?;

            // Disable Nagle — interactive shells benefit from immediate
            // dispatch of single keystrokes. TCP-only: on the jump path
            // this is the jump's OWN socket's business, already set by
            // its own connect.
            let _ = stream.set_nodelay(true);

            connect_over_stream(stream, params, interaction_pause).await
        }
        Some(jump) => {
            // A fresh channel per attempt — the weak-crypto retry
            // ladder calls `Connection::connect` again with the same
            // `via`, and a failed handshake consumes its channel.
            let stream = jump.open_direct_tcpip(&host, port).await?;
            connect_over_stream(stream, params, interaction_pause).await
        }
    }
}

/// The transport-agnostic core of [`connect_inner`]: everything after
/// the byte pipe exists — handshake, host-key verification, auth actor
/// spawn. Generic rather than boxed because `connect_stream` wants one
/// concrete `AsyncRead + AsyncWrite` type; exactly two instantiations
/// exist (TCP and the jump tunnel's channel stream).
async fn connect_over_stream<R>(
    stream: R,
    params: ConnectParams,
    interaction_pause: InteractionPauseFlag,
) -> Result<Connection, SshError>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let host = params.host.clone();
    let port = params.port;
    let device_id = params.device_id.clone();

    let host_keys_for_handler = Arc::clone(&params.host_keys);
    let confirm_tx_for_handler = params.confirm_tx.clone();
    let handler = ConnectHandler {
        device_id: device_id.clone(),
        host: host.clone(),
        port,
        host_keys: host_keys_for_handler,
        confirm_tx: confirm_tx_for_handler,
        confirmed_pin: Arc::new(Mutex::new(None)),
        captured_error: Arc::new(Mutex::new(None)),
        interaction_pause: Arc::clone(&interaction_pause),
        forward_agent: params.forward_agent,
        agent_pumps: Arc::new(tokio::sync::Semaphore::new(
            crate::agent_forward::MAX_AGENT_PUMPS,
        )),
    };
    let confirmed_pin_slot = Arc::clone(&handler.confirmed_pin);
    let captured_error = Arc::clone(&handler.captured_error);

    let config = Arc::new(if params.allow_weak_crypto {
        legacy_client_config()
    } else {
        client_config()
    });
    let handle = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| {
            // HandlerError wraps russh::Error transparently; unwrap
            // for classification. Future handler-specific errors
            // would need their own arm here.
            let HandlerError::Russh(russh_err) = e;
            classify_handshake_error(russh_err, &device_id, &host, port, &captured_error)
        })?;

    // Move the handle into a spawned actor task whose future is
    // `'static + Send` — callers (the `tauri::command` layer) only
    // ever touch `Send + Sync` channels. The task does
    // authentication + first-seen host-key persist as Phase 1,
    // signals Ready on a oneshot, then enters the command loop for
    // `open_session_channel`.
    let username_for_actor = params.username.clone();
    let secret_ref_for_actor = params.secret_ref.clone();
    let auth_for_actor = Arc::clone(&params.auth);
    // `bool` is Copy — captured for the SshKey RSA-hash gate (a server
    // that only accepts SHA-1 ssh-rsa rides the same opt-in as a SHA-1
    // cipher); `params` is still used below for `username`.
    let allow_weak_for_actor = params.allow_weak_crypto;
    let host_keys_for_actor = Arc::clone(&params.host_keys);
    let host_for_actor = host.clone();
    let confirmed_pin_for_actor = Arc::clone(&confirmed_pin_slot);
    let device_for_actor = device_id.clone();
    let pause_for_actor = Arc::clone(&interaction_pause);
    // Interactive auth needs to tell the user WHICH host is asking, so
    // the target rides along with the channel (T46.1 — the dialog must
    // attribute server-authored prompt text to a specific host:port).
    let kbi_tx_for_actor = params.kbi_tx.clone();
    let host_for_auth = host.clone();

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ConnCmd>(8);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), SshError>>();

    let actor = tokio::spawn(AssumeSendFuture(async move {
        // Phase 1: authenticate. `handle` moves in by value and
        // out by value, so no `&Handle` borrow lives across the
        // boundary between authenticate and the next phase.
        let handle = match authenticate(
            handle,
            username_for_actor,
            secret_ref_for_actor,
            auth_for_actor,
            pause_for_actor,
            allow_weak_for_actor,
            AuthTarget {
                host: host_for_auth,
                port,
            },
            kbi_tx_for_actor,
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };

        // Phase 2: persist any pending known-hosts write AFTER auth
        // succeeds — a first-seen insert, an approved-rotation replace,
        // or adoption of a pre-scoping legacy pin. A confirmed dialog
        // followed by a failed auth must not poison (or rewrite)
        // known_hosts.toml, and neither must a failed auth let a server
        // that merely presented the right key claim another device's
        // inherited pin.
        let pending = confirmed_pin_for_actor.lock().await.take();
        if let Some(pin) = pending {
            let persisted = match pin.action {
                PinAction::Replace => {
                    host_keys_for_actor
                        .replace(
                            &device_for_actor,
                            &host_for_actor,
                            port,
                            &pin.fingerprint,
                            &pin.algorithm,
                        )
                        .await
                }
                PinAction::Insert => {
                    host_keys_for_actor
                        .insert(
                            &device_for_actor,
                            &host_for_actor,
                            port,
                            &pin.fingerprint,
                            &pin.algorithm,
                        )
                        .await
                }
                PinAction::AdoptLegacy => {
                    host_keys_for_actor
                        .adopt_legacy(&device_for_actor, &host_for_actor, port)
                        .await
                }
            };
            match persisted {
                Ok(()) => {}
                Err(SshError::KnownHostsConflict { .. }) => {
                    // Race on the insert path: another connect
                    // already wrote the same pin. Defensive — drop
                    // and continue. (`replace`/`adopt_legacy` never conflict.)
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            }
        }

        // Phase 3: command loop.
        let _ = ready_tx.send(Ok(()));
        handle_actor_loop(handle, cmd_rx).await;
    }));

    // Wait for the actor to finish auth + persist (or fail).
    match ready_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(SshError::Other {
                detail: "connect actor task dropped before signaling ready".into(),
            })
        }
    }

    Ok(Connection {
        cmd_tx,
        target: (host, port),
        username: params.username,
        actor: Some(actor),
        _via: params.via,
        forward_agent: params.forward_agent,
    })
}

/// Which host the auth attempt is against. Only interactive auth needs
/// it (to attribute prompts in the UI), but it is a plain value type so
/// the signature stays readable.
pub(crate) struct AuthTarget {
    pub host: String,
    pub port: u16,
}

#[allow(clippy::too_many_arguments)]
async fn authenticate(
    mut handle: russh::client::Handle<ConnectHandler>,
    username: String,
    secret_ref: SecretRef,
    auth: Arc<SecretRegistry>,
    interaction_pause: InteractionPauseFlag,
    allow_weak_crypto: bool,
    target: AuthTarget,
    kbi_tx: mpsc::Sender<KbiPromptRequest>,
) -> Result<russh::client::Handle<ConnectHandler>, SshError> {
    use russh::client::AuthResult;

    // Log the METHOD, never the credential (§10: the fact, not the value).
    // This is the line whose absence made a 2026-09-11 support ticket
    // un-diagnosable from a customer's diagnostic log: russh reports the
    // auth exchange at `debug!`, and the diagnostic file sink is clamped
    // to `info`, so nothing about authentication reached the log at all.
    tracing::info!(
        user = %username,
        host = %target.host,
        port = target.port,
        method = secret_ref.method_name(),
        "authenticating"
    );

    let result = match &secret_ref {
        SecretRef::SshAgent { .. } => {
            let session = auth
                .open_ssh_agent_session(&secret_ref)
                .await
                .map_err(|e| SshError::AuthFailed {
                    user: username.clone(),
                    detail: e.to_string(),
                })?;
            let pubkey = session.public_key().clone();
            let mut agent = session.into_inner();
            handle
                .authenticate_publickey_with(username.clone(), pubkey, None, &mut agent)
                .await
                .map_err(|e| SshError::AuthFailed {
                    user: username.clone(),
                    detail: format!("agent signing failed: {e:?}"),
                })?
        }
        SecretRef::Keyring { .. } | SecretRef::Op { .. } | SecretRef::Env { .. } => {
            let pw = {
                // Backend resolution can park on the user (1Password
                // unlock prompt, Touch ID). Pause the connect
                // deadline for exactly this await; the guard's Drop
                // releases it on success and on `?` alike.
                let _pause = InteractionPauseGuard::enter(&interaction_pause);
                auth.resolve_value(&secret_ref)
                    .await
                    .map_err(|e| SshError::AuthFailed {
                        user: username.clone(),
                        detail: e.to_string(),
                    })?
            };
            // expose_secret only here, scope-bounded. The &str view
            // does not outlive this match arm. The driver tries the
            // `password` method, then falls back to keyboard-interactive
            // with the same secret when the server rejects password but
            // offers KBI — ESXi and other `PasswordAuthentication no`
            // hosts — mirroring OpenSSH's method ordering.
            authenticate_password_with_kbi_fallback(&mut handle, &username, pw.expose_secret())
                .await?
        }
        SecretRef::SshKey { .. } => {
            // Load + decode the on-disk key (and its optional keychain
            // passphrase) IN transit_auth — transit_ssh never sees raw
            // key or passphrase bytes, only a sign-ready handle.
            let key = {
                // Decoding + a keychain passphrase read can park on the
                // user (Touch ID); pause the connect deadline for exactly
                // this await, like the password arm.
                let _pause = InteractionPauseGuard::enter(&interaction_pause);
                auth.load_ssh_key(&secret_ref)
                    .await
                    .map_err(|e| SshError::AuthFailed {
                        user: username.clone(),
                        detail: e.to_string(),
                    })?
            };
            // RSA needs an explicit signature hash; ed25519/ecdsa ignore
            // it. A SHA-1-only server rides the weak-crypto opt-in — and so
            // does a SILENT one (pre-RFC-8308 gear advertises nothing), since
            // that silence is the norm on exactly the legacy devices where
            // rsa-sha2-* is unknown (field bug, lab IOS-XE 2026-09-03).
            let choice = rsa_hash_for(&mut handle, &key, allow_weak_crypto, &username).await?;
            let (hash, best_effort_guess) = match choice {
                RsaHash::Use(hash) => (hash, false),
                RsaHash::BestEffortSha512 => (Some(HashAlg::Sha512), true),
            };
            let result = handle
                .authenticate_publickey(
                    username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| SshError::AuthFailed {
                    user: username.clone(),
                    detail: format!("key auth failed: {e:?}"),
                })?;
            // The SHA-512 guess against a silent server is best-effort.
            // Decide the failure disposition:
            let failed = matches!(result, AuthResult::Failure { .. });
            let publickey_still_offered = matches!(
                &result,
                AuthResult::Failure { remaining_methods, .. }
                    if remaining_methods.contains(&russh::MethodKind::PublicKey)
            );
            if weak_signature_opt_in_applies(best_effort_guess, failed, publickey_still_offered) {
                // Silent server rejected rsa-sha2-512 but STILL offers
                // public-key: it wants the legacy SHA-1 ssh-rsa signature.
                // Route to the per-device weak-crypto opt-in — the caller
                // retries with allow_weak_crypto=true, which signs ssh-rsa.
                // Never a silent SHA-1 downgrade (T20).
                return Err(SshError::WeakSignatureRequired {
                    user: username,
                    host: target.host.clone(),
                    port: target.port,
                });
            }
            if best_effort_guess && failed {
                // Rejected AND no further public-key method — the opt-in
                // retry would be pointless, so no prompt is coming. Name the
                // real remedies instead of referencing a prompt.
                return Err(SshError::AuthFailed {
                    user: username,
                    detail: "server rejected the RSA key signed with rsa-sha2-512 and offers no \
                             further public-key method. Verify the key is installed for this \
                             user, or that the device accepts rsa-sha2 or ssh-rsa signatures \
                             (or use an ed25519 key)."
                        .into(),
                });
            }
            result
        }
        SecretRef::EncryptedFile { .. } => {
            return Err(SshError::AuthFailed {
                user: username.clone(),
                detail: "the EncryptedFile backend lands in a later phase; use an \
                         ssh_key file, the SSH agent (1Password works), or a password \
                         backend (keyring, op, env) for now."
                    .into(),
            });
        }
        // Interactive auth. Nothing is resolved from `auth` — there is no
        // stored credential — so `SecretRegistry` is never consulted on
        // this path (T46 / the interactive keyboard auth design notes (not included in this repository)).
        SecretRef::Prompt => {
            authenticate_interactive(&mut handle, &username, &target, &kbi_tx, &interaction_pause)
                .await?
        }
    };

    match result {
        AuthResult::Success => Ok(handle),
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => Err(SshError::AuthFailed {
            user: username,
            detail: describe_auth_failure(&remaining_methods, partial_success),
        }),
    }
}

/// Turn a server's `USERAUTH_FAILURE` into something a network engineer
/// can act on.
///
/// This used to render the raw `MethodSet([PublicKey, Password])` debug
/// formatting straight into the UI. A user hit it for three devices in
/// a row (2026-09-11) and reasonably concluded the fault was Transit's:
/// the string names no cause, no remedy, and looks like an internal error.
/// The method list IS the diagnosis — it is the server stating what it
/// will still accept — so say that in words.
fn describe_auth_failure(remaining: &russh::MethodSet, partial_success: bool) -> String {
    let names: Vec<&str> = remaining
        .iter()
        .map(|m| match m {
            russh::MethodKind::Password => "password",
            russh::MethodKind::PublicKey => "public key",
            russh::MethodKind::KeyboardInteractive => "keyboard-interactive",
            russh::MethodKind::HostBased => "host-based",
            russh::MethodKind::GssapiWithMic => "GSSAPI (Kerberos)",
            russh::MethodKind::None => "none",
        })
        .collect();

    if partial_success {
        return format!(
            "the server accepted that factor but wants another ({}). Multi-step \
             authentication beyond one interactive exchange isn't supported yet.",
            names.join(", ")
        );
    }

    if names.is_empty() {
        return "the server rejected the credential and offered no other \
                authentication method."
            .into();
    }

    format!(
        "the server rejected the credential. It will still accept: {}. \
         If that list doesn't include the method this profile uses, change the \
         device's authentication profile to match — a device offering only \
         public key needs an SSH key or agent profile, not a password.",
        names.join(", ")
    )
}

/// The RSA signature-hash decision for `authenticate_publickey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaHash {
    /// Sign with this — `Some(rsa-sha2-*)`, or `None` for the legacy SHA-1
    /// `ssh-rsa` (only ever chosen under the weak-crypto opt-in).
    Use(Option<HashAlg>),
    /// The server advertised nothing and the user has NOT opted into weak
    /// crypto: try the strongest hash, but remember it was a guess so an
    /// auth failure can explain itself instead of dying opaque.
    BestEffortSha512,
}

/// Choose the RSA signature hash for `authenticate_publickey`;
/// `Use(None)`-hash for non-RSA keys (russh ignores it). Queries the
/// server's `server-sig-algs` (RFC 8308) and delegates the decision to
/// [`choose_rsa_hash`]; a transport error reading it is treated as
/// "server said nothing".
async fn rsa_hash_for(
    handle: &mut russh::client::Handle<ConnectHandler>,
    key: &PrivateKey,
    allow_weak_crypto: bool,
    username: &str,
) -> Result<RsaHash, SshError> {
    if !matches!(key.algorithm(), Algorithm::Rsa { .. }) {
        return Ok(RsaHash::Use(None));
    }
    let advertised = handle.best_supported_rsa_hash().await.unwrap_or(None);
    choose_rsa_hash(advertised, allow_weak_crypto, username)
}

/// Pure decision core, pinned by unit tests. Three server signals:
///
/// - Advertised an `rsa-sha2-*` hash → use the best one.
/// - Advertised ONLY the legacy SHA-1 `ssh-rsa` → treated like a SHA-1
///   cipher: requires the explicit weak-crypto opt-in, never a silent
///   downgrade (T20).
/// - Advertised NOTHING → the load-bearing case: pre-RFC-8308 network
///   gear (old IOS-XE and friends) never sends `server-sig-algs`, and
///   that same gear is where `rsa-sha2-*` is unknown. With the opt-in
///   already granted, sign SHA-1 — OpenSSH's conservative assumption
///   for a silent server — because guessing rsa-sha2-512 is a signature
///   the device provably cannot verify (field bug, 2026-09-03: lab
///   IOS-XE rejected the key Transit signed with SHA-512 while the same
///   key worked from OpenSSH). Without the opt-in, still never SHA-1:
///   best-effort SHA-512, marked as a guess for the error path.
fn choose_rsa_hash(
    advertised: Option<Option<HashAlg>>,
    allow_weak_crypto: bool,
    username: &str,
) -> Result<RsaHash, SshError> {
    match advertised {
        Some(Some(hash)) => Ok(RsaHash::Use(Some(hash))),
        Some(None) => {
            // Server supports RSA but only the legacy SHA-1 `ssh-rsa`.
            if allow_weak_crypto {
                Ok(RsaHash::Use(None)) // None ⇒ russh signs with ssh-rsa (SHA-1).
            } else {
                Err(SshError::AuthFailed {
                    user: username.to_string(),
                    detail: "this device only accepts the legacy SHA-1 `ssh-rsa` signature for \
                             RSA keys. Reconnect and allow weak crypto when prompted, or use an \
                             ed25519 key."
                        .into(),
                })
            }
        }
        None => {
            if allow_weak_crypto {
                Ok(RsaHash::Use(None))
            } else {
                Ok(RsaHash::BestEffortSha512)
            }
        }
    }
}

/// Whether a best-effort RSA auth failure against a SILENT server (one
/// that advertised no `server-sig-algs`) should surface the weak-crypto
/// opt-in for the signature, rather than failing outright. True only when
/// all three hold: we signed the best-effort SHA-512 guess
/// (`best_effort_guess`), the server rejected it (`failed`), and it still
/// offers public-key auth (`publickey_still_offered`) so a retry signed
/// with `ssh-rsa` can actually be attempted. The opt-in itself still gates
/// the SHA-1 signature (T20) — this only decides whether to ASK.
fn weak_signature_opt_in_applies(
    best_effort_guess: bool,
    failed: bool,
    publickey_still_offered: bool,
) -> bool {
    best_effort_guess && failed && publickey_still_offered
}

/// True when the server's post-failure method list offers
/// `keyboard-interactive` — the signal that a password-style KBI
/// fallback is worth attempting. ESXi's posture: the SSH `password`
/// method is absent, `keyboard-interactive` present.
fn server_offers_kbi(remaining: &russh::MethodSet) -> bool {
    remaining.contains(&russh::MethodKind::KeyboardInteractive)
}

/// Build the responses for a password-style keyboard-interactive
/// challenge: answer every prompt with the single password we hold.
///
/// A typical ESXi/PAM exchange is one non-echo `Password:` prompt. A
/// zero-prompt `InfoRequest` (informational/banner-only) yields an
/// empty response vec, which the KBI spec requires. We deliberately
/// fill *every* prompt — including any `echo = true` field — with the
/// password rather than guessing per-field: holding only one secret, a
/// genuine multi-prompt MFA challenge can't be satisfied anyway, so we
/// answer what we can and let the server reject it.
fn kbi_password_responses(prompts: &[russh::client::Prompt], password: &str) -> Vec<String> {
    prompts.iter().map(|_| password.to_owned()).collect()
}

/// Decide whether a refused `keyboard-interactive` attempt should be
/// retried as a plain `password` prompt, and do it.
///
/// **Why this exists.** `SecretRef::Prompt` ("Ask me each time") shipped
/// as keyboard-interactive ONLY, because its design premise was relaying a
/// server-driven challenge — an OTP, a PAM account menu. But most people
/// reach for it because a policy forbids storing the credential, and plenty
/// of network gear offers `password` without offering
/// `keyboard-interactive` at all. Those users got an immediate auth failure
/// with no prompt and no way forward (user report, 2026-09-11: the same
/// error against a switch, a FortiGate and a Ubiquiti switch).
///
/// This is the mirror of [`authenticate_password_with_kbi_fallback`], which
/// has always let a STORED password fall back to KBI for ESXi-style hosts
/// that only accept the interactive method. The reverse leg was simply
/// never built.
///
/// **Why it is conditional.** Falling back on *any* KBI failure would be
/// wrong in three ways, so all three are guarded:
///
/// - `prompted` — if the user was already asked and the server rejected
///   what they typed, that is a WRONG CREDENTIAL, not a missing method.
///   Re-prompting would ask the same question twice and burn a second auth
///   attempt; gear with `MaxAuthTries` set low disconnects when the budget
///   runs out (the same ceiling that forces bulk launches to be sequential).
/// - `remaining_methods` — the server tells us what can still continue. If
///   `password` is not in it, prompting would collect a credential we
///   already know will be refused.
/// - `partial_success` — KBI succeeded as one leg of a multi-factor
///   sequence. That is progress, not a refusal; restarting as `password`
///   would throw the completed factor away.
///
/// **Security.** T46's guarantee is that nothing is stored, and that is
/// untouched: the answer lives for one auth attempt and is dropped. Sending
/// it via the `password` method rather than as a KBI response is the same
/// credential, over the same encrypted channel, to the same server.
#[allow(clippy::too_many_arguments)]
async fn interactive_password_fallback(
    handle: &mut russh::client::Handle<ConnectHandler>,
    username: &str,
    target: &AuthTarget,
    kbi_tx: &mpsc::Sender<KbiPromptRequest>,
    interaction_pause: &InteractionPauseFlag,
    remaining_methods: russh::MethodSet,
    partial_success: bool,
    prompted: bool,
) -> Result<russh::client::AuthResult, SshError> {
    use russh::client::AuthResult;

    let refused = !prompted;
    let password_offered = remaining_methods
        .iter()
        .any(|m| matches!(m, russh::MethodKind::Password));

    if !(refused && password_offered && !partial_success) {
        tracing::info!(
            %username,
            host = %target.host,
            prompted,
            password_offered,
            partial_success,
            "interactive auth failed; password fallback not applicable"
        );
        return Ok(AuthResult::Failure {
            remaining_methods,
            partial_success,
        });
    }

    tracing::info!(
        %username,
        host = %target.host,
        "server refused keyboard-interactive; falling back to the password method"
    );

    // One masked field, labelled by Transit rather than the server — the
    // server said nothing here, and the dialog must not imply otherwise.
    let (responder, answer_rx) = oneshot::channel();
    let request = KbiPromptRequest {
        host: target.host.clone(),
        port: target.port,
        username: username.to_owned(),
        name: String::new(),
        instruction: String::new(),
        notice: format!(
            "{} does not offer keyboard-interactive login, so Transit is asking for the \
             password directly. It is used once for this connection and not stored.",
            target.host
        ),
        prompts: vec![KbiPrompt {
            text: "Password:".to_owned(),
            echo: false,
        }],
        responder,
    };

    if kbi_tx.send(request).await.is_err() {
        return Err(SshError::AuthFailed {
            user: username.to_owned(),
            detail: "interactive authentication is unavailable in this context".into(),
        });
    }

    let answers = {
        let _pause = InteractionPauseGuard::enter(interaction_pause);
        answer_rx.await
    };
    let answers = match answers {
        Ok(None) | Err(_) => {
            return Err(SshError::AuthFailed {
                user: username.to_owned(),
                detail: "interactive authentication was cancelled".into(),
            })
        }
        Ok(Some(a)) => a,
    };
    let [password] = answers.as_slice() else {
        return Err(SshError::AuthFailed {
            user: username.to_owned(),
            detail: format!(
                "password prompt expected 1 answer but got {}",
                answers.len()
            ),
        });
    };

    handle
        .authenticate_password(username, password.expose_secret())
        .await
        .map_err(|e| SshError::Other {
            detail: format!("password auth runtime error: {e}"),
        })
}

/// Drive `keyboard-interactive` with a HUMAN answering each round.
///
/// The distinction from [`authenticate_password_with_kbi_fallback`] is the
/// whole feature: that function replies to every prompt with one stored
/// secret (which is why an OTP challenge or a PSMP account menu cannot
/// work); this one relays the server's actual prompts to the UI and sends
/// back what the user typed. Nothing is stored, before or after.
///
/// Secret handling: answers arrive as `SecretString`, are exposed exactly
/// once at the `respond` call, and the `Vec` is dropped at the end of each
/// round. They are never logged, never put in an error string, and never
/// returned to the caller.
async fn authenticate_interactive(
    handle: &mut russh::client::Handle<ConnectHandler>,
    username: &str,
    target: &AuthTarget,
    kbi_tx: &mpsc::Sender<KbiPromptRequest>,
    interaction_pause: &InteractionPauseFlag,
) -> Result<russh::client::AuthResult, SshError> {
    use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};

    // Whether the server ever actually ASKED us something. This is the
    // discriminator for the password fallback below: a failure BEFORE any
    // prompt means the server refused the METHOD; a failure AFTER one
    // means the human's answer was wrong. Those need opposite handling and
    // are otherwise indistinguishable from outside this function.
    let mut prompted = false;

    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await
        .map_err(|e| SshError::Other {
            detail: format!("keyboard-interactive auth runtime error: {e}"),
        })?;

    for _ in 0..MAX_KBI_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return interactive_password_fallback(
                    handle,
                    username,
                    target,
                    kbi_tx,
                    interaction_pause,
                    remaining_methods,
                    partial_success,
                    prompted,
                )
                .await
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                // A server may send an InfoRequest with NO prompts purely
                // to display text (RFC 4256 §3.3). There is nothing to
                // ask a human, so answer with an empty vec and continue —
                // bouncing it to the UI would show an un-answerable
                // dialog.
                if prompts.is_empty() {
                    response = handle
                        .authenticate_keyboard_interactive_respond(Vec::new())
                        .await
                        .map_err(|e| SshError::Other {
                            detail: format!("keyboard-interactive auth runtime error: {e}"),
                        })?;
                    continue;
                }

                // Refuse an absurd challenge instead of relaying it into
                // an undismissable modal (T46.1).
                if prompts.len() > MAX_KBI_PROMPTS {
                    return Err(SshError::AuthFailed {
                        user: username.to_owned(),
                        detail: format!(
                            "server asked for {} fields in one interactive round (max {MAX_KBI_PROMPTS})",
                            prompts.len()
                        ),
                    });
                }

                let (responder, answer_rx) = oneshot::channel();
                let request = KbiPromptRequest {
                    host: target.host.clone(),
                    port: target.port,
                    username: username.to_owned(),
                    name: sanitize_server_prompt(&name),
                    instruction: sanitize_server_prompt(&instructions),
                    notice: String::new(),
                    prompts: prompts
                        .iter()
                        .map(|p| KbiPrompt {
                            text: sanitize_server_prompt(&p.prompt),
                            echo: p.echo,
                        })
                        .collect(),
                    responder,
                };
                let expected = request.prompts.len();
                prompted = true;

                if kbi_tx.send(request).await.is_err() {
                    // No UI listening (headless, or the app is shutting
                    // down). Fail the attempt rather than hang.
                    return Err(SshError::AuthFailed {
                        user: username.to_owned(),
                        detail: "interactive authentication is unavailable in this context".into(),
                    });
                }

                // The user is now typing. Pause the connect deadline for
                // exactly this await — same contract as the TOFU prompt
                // and the 1Password-unlock pause; the guard's Drop
                // releases it on every path out.
                let answers = {
                    let _pause = InteractionPauseGuard::enter(interaction_pause);
                    answer_rx.await
                };

                let answers = match answers {
                    // Cancelled, or the responder was dropped (dialog
                    // closed, chat/app teardown). Either way this is a
                    // clean auth failure, never a hang.
                    Ok(None) | Err(_) => {
                        return Err(SshError::AuthFailed {
                            user: username.to_owned(),
                            detail: "interactive authentication was cancelled".into(),
                        })
                    }
                    Ok(Some(a)) => a,
                };

                // The UI must return exactly one answer per prompt, in
                // order — russh maps them positionally, so a length
                // mismatch would silently answer the WRONG prompt (e.g.
                // send the password where the server asked for an OTP).
                // Refuse instead.
                if answers.len() != expected {
                    return Err(SshError::AuthFailed {
                        user: username.to_owned(),
                        detail: format!(
                            "interactive auth expected {expected} answer(s) but got {}",
                            answers.len()
                        ),
                    });
                }

                let exposed: Vec<String> = answers
                    .iter()
                    .map(|s| s.expose_secret().to_owned())
                    .collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(exposed)
                    .await
                    .map_err(|e| SshError::Other {
                        detail: format!("keyboard-interactive auth runtime error: {e}"),
                    })?;
                // `answers` and `exposed` drop here, at the end of the
                // round. Nothing carries into the next iteration.
            }
        }
    }

    Err(SshError::AuthFailed {
        user: username.to_owned(),
        detail: format!(
            "server issued more than {MAX_KBI_ROUNDS} interactive auth rounds without a verdict"
        ),
    })
}

/// Authenticate with the SSH `password` method, falling back to
/// `keyboard-interactive` (answering the server's prompts with the same
/// secret) when the server rejects `password` but offers KBI.
///
/// This mirrors OpenSSH's default `PreferredAuthentications` ordering —
/// and is why `ssh root@<esxi>` succeeds where a bare password attempt
/// is refused: ESXi (and any host that disables `PasswordAuthentication`
/// and enables `KbdInteractiveAuthentication`) does not implement the SSH
/// `password` method, only `keyboard-interactive`.
///
/// `password` is borrowed for the duration of this call and never
/// stored; the caller's `expose_secret()` borrow ends at its scope
/// exit, preserving the transit_ssh secret-handling floor — no secret
/// outlives the auth attempt.
async fn authenticate_password_with_kbi_fallback(
    handle: &mut russh::client::Handle<ConnectHandler>,
    username: &str,
    password: &str,
) -> Result<russh::client::AuthResult, SshError> {
    use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};

    // 1. Standard `password` method first.
    let remaining = match handle
        .authenticate_password(username, password)
        .await
        .map_err(|e| SshError::Other {
            detail: format!("password auth runtime error: {e}"),
        })? {
        AuthResult::Success => return Ok(AuthResult::Success),
        AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
    };

    // 2. Only fall back when the server actually offers KBI; otherwise
    //    report the original password failure unchanged.
    if !server_offers_kbi(&remaining) {
        return Ok(AuthResult::Failure {
            remaining_methods: remaining,
            partial_success: false,
        });
    }

    tracing::debug!(
        user = %username,
        "password method refused; attempting keyboard-interactive fallback"
    );

    // 3. KBI exchange: answer each InfoRequest's prompts with the
    //    password. Bounded so a misbehaving/hostile server that keeps
    //    issuing prompts can't loop the auth forever.
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None::<String>)
        .await
        .map_err(|e| SshError::Other {
            detail: format!("keyboard-interactive auth runtime error: {e}"),
        })?;

    for _ in 0..MAX_KBI_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => {
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                })
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = kbi_password_responses(&prompts, password);
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| SshError::Other {
                        detail: format!("keyboard-interactive auth runtime error: {e}"),
                    })?;
            }
        }
    }

    Err(SshError::AuthFailed {
        user: username.to_owned(),
        detail: "keyboard-interactive exchange did not converge (server kept prompting)".into(),
    })
}

/// Map a russh handshake error to an SshError, consulting any
/// host-key-flow error the handler captured (mismatch / rejected)
/// since russh just returns `UnknownKey`/`KeyChanged` without our
/// classified context.
fn classify_handshake_error(
    e: russh::Error,
    device_id: &str,
    host: &str,
    port: u16,
    captured: &Mutex<Option<SshError>>,
) -> SshError {
    if let Some(captured) = captured.try_lock().ok().and_then(|mut g| g.take()) {
        return captured;
    }
    match e {
        russh::Error::IO(io) => SshError::Network {
            host: host.into(),
            port,
            source: io,
        },
        russh::Error::ConnectionTimeout
        | russh::Error::Elapsed(_)
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout => SshError::Timeout {
            host: host.into(),
            port,
        },
        russh::Error::NoCommonAlgo { kind, ours, theirs } => {
            // `theirs` is the server's advertised list for the slot
            // that didn't converge. We surface it structurally so the
            // weak-crypto dialog can render it; `detail` keeps the
            // log-friendly one-liner for CLI / tracing paths.
            let offered: Vec<String> = theirs.iter().map(|n| n.to_string()).collect();
            let kind_name = format!("{kind:?}");
            SshError::CipherUnsupported {
                host: host.into(),
                port,
                kind: kind_name.clone(),
                offered: offered.clone(),
                detail: format!("no common {kind_name}: ours={ours:?}, theirs={offered:?}"),
            }
        }
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => {
            // Should have been pre-classified by the handler; if we
            // got here without a captured error, surface a generic
            // host-key error.
            SshError::HostKeyRejected {
                device_id: device_id.into(),
                host: host.into(),
                port,
            }
        }
        // The server dropped the handshake (or sent an unexpected
        // packet) before russh could read its KEXINIT into a structured
        // `NoCommonAlgo`. Legacy gear does exactly this when it can't
        // agree on our strict algorithms: Cisco SG300/SG500 → `KexInit`,
        // FS.com switches → `Disconnect`. It also happens MID-kex — a
        // GEX-only server that can't satisfy the client's group-size
        // request disconnects after negotiation, same russh error. All
        // land pre-auth, so we classify them as weak-crypto candidates
        // and let the connect flow offer the (mandatory-consent) legacy
        // opt-in. The captured-error check above still wins first, so
        // (a) a host-key mismatch that surfaces as a disconnect is NOT
        // reclassified here, and (b) when the server sent a real
        // SSH_MSG_DISCONNECT, `ConnectHandler::disconnected` already
        // captured a richer HandshakeInterrupted carrying the server's
        // own reason text — the arms below are the fallback for silent
        // drops (TCP close, no DISCONNECT payload).
        russh::Error::KexInit => SshError::HandshakeInterrupted {
            host: host.into(),
            port,
            detail: "key exchange init failed".into(),
        },
        russh::Error::Disconnect => SshError::HandshakeInterrupted {
            host: host.into(),
            port,
            detail: "server disconnected during handshake".into(),
        },
        // russh could not parse a handshake field as ASCII/UTF-8 — almost
        // always a KEXINIT name-list (RFC 4253 requires US-ASCII, russh
        // decodes it as a strict UTF-8 String). A firmware-level defect in
        // the device's SSH stack; happens before algorithm selection, so
        // it is NOT a weak-crypto candidate and the legacy opt-in cannot
        // help. Classified into an actionable message instead of leaking
        // the raw `SshEncoding: character encoding invalid`.
        russh::Error::SshEncoding(_) => SshError::HandshakeEncoding {
            host: host.into(),
            port,
        },
        other => SshError::Other {
            detail: format!("ssh handshake: {other}"),
        },
    }
}

// ---------------------------------------------------------------------
// Handler — runs inside russh's handshake task
// ---------------------------------------------------------------------

/// What the post-auth phase should write to the known-hosts store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinAction {
    /// First contact, user clicked Trust → [`HostKeyStore::insert`].
    Insert,
    /// Changed key, user verified and approved → [`HostKeyStore::replace`].
    Replace,
    /// A pre-scoping `(host, port)` entry matched and the fingerprint was
    /// correct → [`HostKeyStore::adopt_legacy`]. **No user interaction
    /// happened**: this is a silent connect that also takes ownership of
    /// the inherited pin, so a second device at the same address gets a
    /// clean first-contact prompt instead of inheriting this device's trust.
    AdoptLegacy,
}

/// A host-key store write awaiting post-auth persistence.
///
/// One carrier for all three actions rather than a parallel channel per
/// action, so the "never write before auth succeeds" rule (T11 mitigation 5)
/// stays expressed in exactly one place — the actor's phase 2.
struct PendingPinWrite {
    fingerprint: Fingerprint,
    algorithm: Algorithm,
    action: PinAction,
}

/// russh client handler. Captures the host-key flow's outcome so the
/// outer `connect_inner` can surface a classified `SshError` even
/// when russh's own error path collapses it to `UnknownKey`.
pub(crate) struct ConnectHandler {
    device_id: String,
    host: String,
    port: u16,
    host_keys: Arc<HostKeyStore>,
    confirm_tx: mpsc::Sender<HostKeyConfirmRequest>,
    /// Set when there is a store write to make once auth succeeds — user
    /// trust, an approved replacement, or a legacy-pin adoption. Drained by
    /// `connect_inner` AFTER successful auth — never before, so a failed
    /// auth doesn't poison (or rewrite) the known-hosts file.
    confirmed_pin: Arc<Mutex<Option<PendingPinWrite>>>,
    /// Pre-classified error captured during handshake.
    /// `connect_inner` reads this when russh returns its own opaque
    /// `UnknownKey`/`KeyChanged`.
    captured_error: Arc<Mutex<Option<SshError>>>,
    /// Connect-deadline pause flag — raised for the duration of a
    /// host-key verdict wait (first-seen TOFU or changed-key warning)
    /// so the user can read the fingerprint dialog without racing the
    /// connect timeout.
    interaction_pause: InteractionPauseFlag,
    /// Connect-time agent-forwarding opt-in (v6.5.0, T53). Fixes the
    /// accept/reject verdict for the connection's lifetime — flag
    /// flips in the inventory affect NEW connects only.
    forward_agent: bool,
    /// Bounds concurrent agent-forward pump tasks so a hostile server
    /// can't fd-exhaust us by spraying `auth-agent@openssh.com` opens.
    agent_pumps: Arc<tokio::sync::Semaphore>,
}

impl ConnectHandler {
    /// Ask the user for a host-key verdict — the plain TOFU prompt
    /// when `previous` is `None`, the changed-key WARNING dialog when
    /// the host already has a (different) pinned fingerprint. On
    /// trust the pin is parked in `confirmed_pin` for post-auth
    /// persistence; on decline the classified error is captured for
    /// `classify_handshake_error`. Returns the verdict for
    /// `check_server_key` to hand to russh.
    async fn confirm_with_user(
        &self,
        fp: Fingerprint,
        algorithm: Algorithm,
        previous: Option<Fingerprint>,
    ) -> bool {
        // The verdict wait parks on the user reading the dialog.
        // Pause the connect deadline for exactly this stretch; the
        // guard's Drop releases it on every branch exit.
        let _pause = InteractionPauseGuard::enter(&self.interaction_pause);
        let (tx, rx) = oneshot::channel();
        let req = HostKeyConfirmRequest {
            device_id: self.device_id.clone(),
            host: self.host.clone(),
            port: self.port,
            fingerprint: fp.to_string(),
            algorithm: algorithm.as_str().to_string(),
            previous_fingerprint: previous.as_ref().map(|p| p.to_string()),
            responder: tx,
        };
        if self.confirm_tx.send(req).await.is_err() {
            *self.captured_error.lock().await = Some(SshError::Other {
                detail: "host-key confirm channel closed before request was delivered".into(),
            });
            return false;
        }
        match rx.await {
            Ok(true) => {
                *self.confirmed_pin.lock().await = Some(PendingPinWrite {
                    fingerprint: fp,
                    algorithm,
                    action: if previous.is_some() {
                        PinAction::Replace
                    } else {
                        PinAction::Insert
                    },
                });
                true
            }
            Ok(false) => {
                *self.captured_error.lock().await = Some(match previous {
                    // Declining a changed key keeps the mismatch
                    // evidence (both fingerprints + the store path)
                    // in the surfaced error.
                    Some(known) => SshError::HostKeyMismatch {
                        device_id: self.device_id.clone(),
                        host: self.host.clone(),
                        port: self.port,
                        expected: known.to_string(),
                        got: fp.to_string(),
                        known_hosts: self.host_keys.path().into(),
                    },
                    None => SshError::HostKeyRejected {
                        device_id: self.device_id.clone(),
                        host: self.host.clone(),
                        port: self.port,
                    },
                });
                false
            }
            Err(_) => {
                *self.captured_error.lock().await = Some(SshError::Other {
                    detail: "host-key responder dropped without answering".into(),
                });
                false
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandlerError {
    #[error(transparent)]
    Russh(#[from] russh::Error),
}

impl russh::client::Handler for ConnectHandler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Transit verifies host KEYS by pinning them (TOFU, T11). Both
        // client configs offer no host-certificate algorithms, so a
        // conforming server cannot negotiate one; if a certificate
        // arrives anyway, refuse it. russh treats a certificate as
        // REPLACING the key check, and the key inside it is not one the
        // user was ever asked to trust — so it gets no TOFU prompt and no
        // pin, only a clear error.
        let server_public_key = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => {
                *self.captured_error.lock().await = Some(SshError::Other {
                    detail: "the server presented an SSH host certificate; Transit verifies \
                             pinned host keys only and does not accept host certificates"
                        .into(),
                });
                return Ok(false);
            }
        };
        let fp = Fingerprint::sha256(server_public_key.key_data());
        let algo = server_public_key.algorithm();

        match self
            .host_keys
            .lookup(&self.device_id, &self.host, self.port)
            .await
        {
            Ok(Some(known)) => {
                if known.fingerprint == fp {
                    // A legacy (pre-scoping) entry matched: the trust is
                    // real, but it is recorded against the ADDRESS, so any
                    // other device at the same address would inherit it.
                    // Park an adoption so this device takes ownership once
                    // auth succeeds — silently, with no dialog, because
                    // nothing about the user's trust has changed.
                    if known.tier == PinTier::Legacy {
                        *self.confirmed_pin.lock().await = Some(PendingPinWrite {
                            fingerprint: fp,
                            algorithm: algo,
                            action: PinAction::AdoptLegacy,
                        });
                    }
                    Ok(true)
                } else {
                    // Pinned fingerprint doesn't match: the key
                    // CHANGED. Surface the warning dialog carrying
                    // both fingerprints; the user may explicitly
                    // replace the pin (persisted post-auth) or
                    // decline (→ HostKeyMismatch).
                    Ok(self
                        .confirm_with_user(fp, algo, Some(known.fingerprint))
                        .await)
                }
            }
            Ok(None) => Ok(self.confirm_with_user(fp, algo, None).await),
            Err(e) => {
                *self.captured_error.lock().await = Some(e);
                Ok(false)
            }
        }
    }

    /// Capture the server's `SSH_MSG_DISCONNECT` payload (reason code
    /// and human-readable message) so `classify_handshake_error` can
    /// surface the server's OWN words instead of a bare "server
    /// disconnected during handshake". Legacy stacks that refuse the
    /// handshake (no algorithm overlap, unsatisfiable GEX request)
    /// often name the failing slot here — the only diagnostic a
    /// lazy-KEXINIT server ever emits, and the difference between a
    /// one-screenshot triage and a multi-release guessing game
    /// (v2.3.0 → v2.3.3). Guarded on an empty slot so a host-key-flow
    /// classification captured in `check_server_key` is never
    /// clobbered — `classify_captured_error_wins_over_disconnect`
    /// stays true with this method in play.
    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                let mut slot = self.captured_error.lock().await;
                if slot.is_none() {
                    let msg = sanitize_server_text(&info.message);
                    let detail = if msg.is_empty() {
                        format!(
                            "server sent SSH disconnect ({:?}) with no message",
                            info.reason_code
                        )
                    } else {
                        format!(
                            "server sent SSH disconnect ({:?}): \"{msg}\"",
                            info.reason_code
                        )
                    };
                    *slot = Some(SshError::HandshakeInterrupted {
                        host: self.host.clone(),
                        port: self.port,
                        detail,
                    });
                }
                Ok(())
            }
            // Mirror russh's default impl: error-shaped disconnects
            // propagate so the run loop surfaces the underlying error.
            DisconnectReason::Error(e) => Err(e),
        }
    }

    /// The server wants to open an `auth-agent@openssh.com` channel
    /// back at us (v6.5.0, T53). russh's DEFAULT impl ACCEPTS these —
    /// overriding to reject-unless-opted-in is load-bearing hardening
    /// independent of the forwarding feature: an unsolicited accept
    /// hands a hostile server a live channel it was never entitled to
    /// (today nothing pumps it, but the posture is wrong).
    ///
    /// When enabled, the verdict + agent dial are DEFERRED to a
    /// spawned task: this callback runs on the session event loop, so
    /// a stalled dial here would freeze keystrokes for the whole
    /// connection (and russh's Windows named-pipe dial can retry
    /// ERROR_PIPE_BUSY unboundedly). Deferring is protocol-legal —
    /// the server parks on the channel-open reply.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        if !self.forward_agent {
            tracing::warn!(
                host = %self.host,
                port = self.port,
                "server attempted SSH agent forwarding while it is disabled for this device; rejecting"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match Arc::clone(&self.agent_pumps).try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(crate::agent_forward::handle_inbound_channel(
                    channel,
                    reply,
                    permit,
                    self.host.clone(),
                    self.port,
                ));
            }
            Err(_) => {
                tracing::warn!(
                    host = %self.host,
                    port = self.port,
                    max = crate::agent_forward::MAX_AGENT_PUMPS,
                    "agent-forward channel flood: pump cap reached, rejecting"
                );
                reply
                    .reject(russh::ChannelOpenFailure::ResourceShortage)
                    .await;
            }
        }
        Ok(())
    }

    // ---- Blanket reject for every OTHER server-initiated channel type
    // (adversarial-review finding, v6.5.0). russh's defaults ACCEPT all
    // of these, allocating a live channel nothing in Transit services —
    // an unbounded-channel resource surface for a hostile server, and
    // the same wrong posture the agent-forward override fixes. Transit
    // never requests remote forwards, X11, or server-initiated sessions,
    // so every one of these opens is unsolicited by construction.
    // (`should_accept_unknown_server_channel` already defaults false.)

    async fn server_channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited server-opened 'session' channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited X11 channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited forwarded-tcpip channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        _socket_path: &str,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited forwarded-streamlocal channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited server-opened direct-tcpip channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: russh::Channel<russh::client::Msg>,
        _socket_path: &str,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(host = %self.host, port = self.port, "rejecting unsolicited direct-streamlocal channel");
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }
}

/// Shared core for every server-authored string that reaches our UI.
///
/// Keep printable ASCII + space, drop everything else (control
/// characters, ANSI escapes, non-ASCII) rather than trying to escape it,
/// then cap. Control characters are the load-bearing removal: CR,
/// backspace and ANSI escapes let a host overwrite or recolor what we
/// drew, and a NUL can truncate a string crossing a C boundary.
///
/// `keep_layout` additionally preserves newline and tab — wanted for a
/// multi-line auth instruction block, NOT wanted for a one-line error.
fn sanitize_server_text_inner(raw: &str, max: usize, keep_layout: bool) -> String {
    raw.chars()
        .filter(|c| {
            c.is_ascii_graphic() || *c == ' ' || (keep_layout && (*c == '\n' || *c == '\t'))
        })
        .take(max)
        .collect()
}

/// Server-supplied disconnect text is attacker-influenceable pre-auth
/// input headed for the UI and logs.
fn sanitize_server_text(raw: &str) -> String {
    sanitize_server_text_inner(raw, 160, false)
}

/// Server-authored `keyboard-interactive` text (challenge name,
/// instruction block, prompt labels) headed for the auth dialog.
///
/// Same filter as the disconnect path, but multi-line — real instruction
/// blocks use newlines for layout — and a larger cap. Sanitizing is only
/// half the mitigation: the UI must also render this as clearly-foreign,
/// host-attributed text (T46.1).
fn sanitize_server_prompt(raw: &str) -> String {
    sanitize_server_text_inner(raw, MAX_SERVER_TEXT, true)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use russh::client::Handler as _;
    use russh::keys::ssh_key::PublicKey;

    const TEST_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeWGarXFCkY8zX2GTR2H7M311S6iLXWv7AyA9AN5Tgu \
         transit-host-key-test";
    const TEST_FINGERPRINT: &str = "SHA256:TB9yfs7U9suPXvdMryrKA/UG1ZJrp3DXaZWulMipLoM";

    fn fixture_pubkey() -> PublicKey {
        PublicKey::from_openssh(TEST_PUBKEY).expect("test pubkey parses")
    }

    async fn empty_store() -> Arc<HostKeyStore> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        // Leak the tempdir so the store path stays valid for the
        // test body; tempdirs only matter at creation time here.
        std::mem::forget(dir);
        Arc::new(HostKeyStore::open(path).await.unwrap())
    }

    /// Inventory id the handler fixtures connect as. Distinct from the
    /// host string so a test that confuses the two fails loudly.
    const TEST_DEVICE: &str = "dev-test";

    fn make_handler(
        host_keys: Arc<HostKeyStore>,
        confirm_tx: mpsc::Sender<HostKeyConfirmRequest>,
    ) -> ConnectHandler {
        ConnectHandler {
            device_id: TEST_DEVICE.into(),
            host: "test-host".into(),
            port: 22,
            host_keys,
            confirm_tx,
            confirmed_pin: Arc::new(Mutex::new(None)),
            captured_error: Arc::new(Mutex::new(None)),
            interaction_pause: Arc::new(watch::channel(false).0),
            forward_agent: false,
            agent_pumps: Arc::new(tokio::sync::Semaphore::new(
                crate::agent_forward::MAX_AGENT_PUMPS,
            )),
        }
    }

    #[test]
    fn auth_failure_message_names_the_methods_in_words() {
        use russh::{MethodKind, MethodSet};

        // The customer-reported shape: a device offering password and
        // public key, reached with a keyboard-interactive-only profile.
        let m = MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password][..]);
        let msg = describe_auth_failure(&m, false);
        assert!(msg.contains("public key"), "{msg}");
        assert!(msg.contains("password"), "{msg}");
        assert!(
            !msg.contains("MethodSet"),
            "must not leak Rust debug formatting at a user: {msg}"
        );
        assert!(
            msg.contains("authentication profile"),
            "should point at the remedy: {msg}"
        );
    }

    #[test]
    fn auth_failure_message_handles_partial_success_and_an_empty_set() {
        use russh::{MethodKind, MethodSet};

        let partial = describe_auth_failure(
            &MethodSet::from(&[MethodKind::KeyboardInteractive][..]),
            true,
        );
        assert!(
            partial.contains("another"),
            "partial success is a second factor, not a rejection: {partial}"
        );

        let empty = describe_auth_failure(&MethodSet::from(&[][..]), false);
        assert!(empty.contains("no other"), "{empty}");
    }

    #[tokio::test]
    async fn check_server_key_accepts_known_match() {
        let store = empty_store().await;
        let pk = fixture_pubkey();
        let fp = Fingerprint::sha256(pk.key_data());
        store
            .insert(TEST_DEVICE, "test-host", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&pk.clone().into()).await.unwrap();
        assert!(ok, "matching pinned fingerprint should be accepted");
        assert!(h.captured_error.lock().await.is_none());
        assert!(
            h.confirmed_pin.lock().await.is_none(),
            "no new pin to record"
        );
    }

    /// A host CERTIFICATE is refused outright (russh 0.63+): no TOFU
    /// prompt, no pin, a captured error — even when the certificate's
    /// inner key is the one already pinned for this device. The configs
    /// never offer certificate algorithms (`ciphers::
    /// neither_config_offers_host_certificates`); this is the backstop if
    /// one arrives anyway.
    #[tokio::test]
    async fn check_server_key_refuses_host_certificate() {
        use russh::keys::ssh_key::certificate::{Builder, CertType};
        use russh::keys::ssh_key::private::Ed25519Keypair;

        let host = PrivateKey::from(Ed25519Keypair::from_seed(&[7u8; 32]));
        let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[9u8; 32]));
        let mut builder =
            Builder::new([0u8; 16], host.public_key().key_data().clone(), 0, u64::MAX).unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("test-host").unwrap();
        let cert = builder.sign(&ca).unwrap();

        // Pin the cert's inner key: refusal must not depend on a mismatch.
        let store = empty_store().await;
        let fp = Fingerprint::sha256(host.public_key().key_data());
        store
            .insert(TEST_DEVICE, "test-host", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&cert.into()).await.unwrap();

        assert!(!ok, "a host certificate must be refused");
        assert!(rx.try_recv().is_err(), "no TOFU prompt for a certificate");
        assert!(
            h.confirmed_pin.lock().await.is_none(),
            "nothing may be pinned from a certificate"
        );
        let captured = h.captured_error.lock().await;
        match captured.as_ref() {
            Some(SshError::Other { detail }) => {
                assert!(detail.contains("host certificate"), "{detail}")
            }
            other => panic!("expected a captured refusal, got {other:?}"),
        }
    }

    /// A pre-scoping `known_hosts.toml`: the entry has no `scope` key, so
    /// any device at that `(host, port)` inherits it.
    async fn store_with_legacy_pin(fp: &Fingerprint) -> (Arc<HostKeyStore>, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.toml");
        std::fs::write(
            &path,
            format!(
                "version = 1\n\n[[host]]\nhost = \"test-host\"\nport = 22\n\
                 fingerprint = \"{fp}\"\nalgorithm = \"ssh-ed25519\"\n\
                 first_seen = \"2026-05-08T00:00:00Z\"\n"
            ),
        )
        .unwrap();
        std::mem::forget(dir);
        let store = Arc::new(HostKeyStore::open(&path).await.unwrap());
        (store, path)
    }

    #[tokio::test]
    async fn legacy_pin_match_is_silent_and_parks_an_adoption() {
        // A device connecting against an inherited pre-scoping pin must
        // see NO dialog — the trust is already established, nothing about
        // it has changed. What it does gain is a parked adoption, so the
        // pin stops being inheritable by the next device at that address.
        let pk = fixture_pubkey();
        let fp = Fingerprint::sha256(pk.key_data());
        let (store, _path) = store_with_legacy_pin(&fp).await;

        // A channel with NO receiver: if the handler tried to prompt, the
        // send would fail and the connect would be rejected.
        let (tx, rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        drop(rx);

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&pk.clone().into()).await.unwrap();
        assert!(ok, "an inherited pin that matches must connect silently");
        assert!(
            h.captured_error.lock().await.is_none(),
            "no prompt was attempted"
        );

        let pin = h
            .confirmed_pin
            .lock()
            .await
            .take()
            .expect("adoption parked for post-auth");
        assert_eq!(pin.action, PinAction::AdoptLegacy);

        // Still unadopted on disk — phase 2 has not run.
        assert_eq!(
            store
                .lookup("someone-else", "test-host", 22)
                .await
                .unwrap()
                .expect("still inheritable")
                .tier,
            PinTier::Legacy,
            "adoption must not touch the store before auth succeeds"
        );
    }

    #[tokio::test]
    async fn scoped_pin_match_parks_nothing() {
        // The steady state after adoption: a scoped hit is a plain silent
        // match with no store write pending.
        let pk = fixture_pubkey();
        let fp = Fingerprint::sha256(pk.key_data());
        let store = empty_store().await;
        store
            .insert(TEST_DEVICE, "test-host", 22, &fp, &Algorithm::Ed25519)
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);
        assert!(h.check_server_key(&pk.clone().into()).await.unwrap());
        assert!(
            h.confirmed_pin.lock().await.is_none(),
            "a scoped match has nothing to write"
        );
    }

    #[tokio::test]
    async fn legacy_pin_mismatch_still_warns() {
        // Inheriting a pin must not weaken the changed-key path: a legacy
        // entry whose fingerprint does NOT match is still a mismatch, and
        // still surfaces the warning dialog with both fingerprints.
        let wrong: Fingerprint = WRONG_FINGERPRINT.parse().unwrap();
        let (store, _path) = store_with_legacy_pin(&wrong).await;

        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let pk = fixture_pubkey();
        let handle = tokio::spawn(async move {
            let req = rx.recv().await.expect("warning dialog raised");
            assert_eq!(
                req.previous_fingerprint.as_deref(),
                Some(WRONG_FINGERPRINT),
                "the inherited pin is the one shown as previous"
            );
            assert_eq!(req.device_id, TEST_DEVICE);
            let _ = req.responder.send(false);
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&pk.clone().into()).await.unwrap();
        handle.await.unwrap();
        assert!(!ok, "declining a changed key rejects the connect");
        assert!(matches!(
            h.captured_error.lock().await.take(),
            Some(SshError::HostKeyMismatch { .. })
        ));
    }

    /// All-zeros stand-in for a stale pin, used by the changed-key
    /// tests to force the mismatch branch.
    const WRONG_FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    async fn store_with_wrong_pin() -> Arc<HostKeyStore> {
        let store = empty_store().await;
        let wrong: Fingerprint = WRONG_FINGERPRINT.parse().expect("valid mock fingerprint");
        store
            .insert(TEST_DEVICE, "test-host", 22, &wrong, &Algorithm::Ed25519)
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn check_server_key_changed_key_user_declines() {
        let store = store_with_wrong_pin().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            // The changed-key request carries BOTH fingerprints so
            // the dialog can render them side by side.
            assert_eq!(req.previous_fingerprint.as_deref(), Some(WRONG_FINGERPRINT));
            assert_eq!(req.fingerprint, TEST_FINGERPRINT);
            req.responder.send(false).unwrap();
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(!ok, "declined key change must reject");
        let captured = h.captured_error.lock().await.take();
        match captured {
            Some(SshError::HostKeyMismatch { expected, got, .. }) => {
                assert_eq!(expected, WRONG_FINGERPRINT);
                assert_eq!(got, TEST_FINGERPRINT);
            }
            other => panic!("expected HostKeyMismatch, got {other:?}"),
        }
        assert!(
            h.confirmed_pin.lock().await.is_none(),
            "no pin parked after decline"
        );
        // The stale pin is untouched.
        let pinned = store
            .lookup(TEST_DEVICE, "test-host", 22)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pinned.fingerprint.to_string(), WRONG_FINGERPRINT);
    }

    #[tokio::test]
    async fn check_server_key_changed_key_user_replaces() {
        let store = store_with_wrong_pin().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            assert_eq!(req.previous_fingerprint.as_deref(), Some(WRONG_FINGERPRINT));
            req.responder.send(true).unwrap();
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(ok, "approved key change must accept");
        assert!(h.captured_error.lock().await.is_none());
        let pin = h
            .confirmed_pin
            .lock()
            .await
            .take()
            .expect("pin parked for post-auth persistence");
        assert_eq!(
            pin.action,
            PinAction::Replace,
            "changed-key accept must route to replace, not insert"
        );
        assert_eq!(pin.fingerprint.to_string(), TEST_FINGERPRINT);
        // Nothing persisted yet — that happens only after auth
        // succeeds (connect_inner Phase 2).
        let pinned = store
            .lookup(TEST_DEVICE, "test-host", 22)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pinned.fingerprint.to_string(),
            WRONG_FINGERPRINT,
            "approval alone must not touch the store"
        );
    }

    #[tokio::test]
    async fn check_server_key_changed_key_dropped_responder_rejects() {
        let store = store_with_wrong_pin().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            // Simulates the UI going away without choosing.
            drop(req.responder);
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(!ok);
        let captured = h.captured_error.lock().await.take();
        assert!(matches!(captured, Some(SshError::Other { .. })));
        assert!(h.confirmed_pin.lock().await.is_none());
        let pinned = store
            .lookup(TEST_DEVICE, "test-host", 22)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pinned.fingerprint.to_string(),
            WRONG_FINGERPRINT,
            "pin untouched"
        );
    }

    #[tokio::test]
    async fn check_server_key_first_seen_user_confirms() {
        let store = empty_store().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        // Spawn the responder side: confirm immediately.
        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            assert_eq!(req.fingerprint, TEST_FINGERPRINT);
            assert_eq!(req.algorithm, "ssh-ed25519");
            assert!(
                req.previous_fingerprint.is_none(),
                "first contact must not render as a changed key"
            );
            req.responder.send(true).unwrap();
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(ok, "user trust should accept");
        let pin = h
            .confirmed_pin
            .lock()
            .await
            .take()
            .expect("first-seen pin should be recorded");
        assert_eq!(
            pin.action,
            PinAction::Insert,
            "first contact routes to insert"
        );
    }

    #[tokio::test]
    async fn check_server_key_first_seen_user_cancels() {
        let store = empty_store().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            req.responder.send(false).unwrap();
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(!ok, "user cancel should reject");
        let captured = h.captured_error.lock().await.take();
        assert!(
            matches!(captured, Some(SshError::HostKeyRejected { .. })),
            "expected HostKeyRejected, got {captured:?}"
        );
        assert!(
            h.confirmed_pin.lock().await.is_none(),
            "no pin should be recorded after cancel"
        );
    }

    #[tokio::test]
    async fn check_server_key_handles_dropped_responder() {
        let store = empty_store().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            // Drop the responder without sending — simulates UI
            // closing the dialog without choosing.
            drop(req.responder);
        });

        let mut h = make_handler(Arc::clone(&store), tx);
        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();

        assert!(!ok);
        let captured = h.captured_error.lock().await.take();
        assert!(matches!(captured, Some(SshError::Other { .. })));
    }

    #[test]
    fn classify_no_common_algo_to_cipher_unsupported() {
        let captured = Mutex::new(None);
        let err = classify_handshake_error(
            russh::Error::NoCommonAlgo {
                kind: russh::AlgorithmKind::Cipher,
                ours: vec!["chacha20-poly1305@openssh.com".into()],
                theirs: vec!["3des-cbc".into()],
            },
            "dev-h",
            "h",
            22,
            &captured,
        );
        assert!(matches!(err, SshError::CipherUnsupported { .. }));
    }

    #[test]
    fn classify_kex_init_to_handshake_interrupted() {
        // Cisco SG300/SG500 (OpenSSH_5.9p1.RL): server offers only
        // SHA1 KEX, drops the strict handshake, russh reports KexInit.
        // Must classify as HandshakeInterrupted so the connect flow
        // offers the legacy opt-in instead of a dead-end error.
        let captured = Mutex::new(None);
        let err = classify_handshake_error(russh::Error::KexInit, "dev-h", "h", 22, &captured);
        assert!(matches!(err, SshError::HandshakeInterrupted { .. }));
    }

    #[test]
    fn classify_disconnect_to_handshake_interrupted() {
        // FS.com S5500: server offers only ssh-rsa/ssh-dss host keys,
        // sends SSH_MSG_DISCONNECT on the strict handshake → russh
        // Disconnect. Same weak-crypto-candidate classification.
        let captured = Mutex::new(None);
        let err = classify_handshake_error(russh::Error::Disconnect, "dev-h", "h", 22, &captured);
        assert!(matches!(err, SshError::HandshakeInterrupted { .. }));
    }

    #[tokio::test]
    async fn classify_captured_error_wins_over_disconnect() {
        // A host-key mismatch that ALSO surfaces as a server disconnect
        // must stay HostKeyMismatch — never be downgraded into a
        // weak-crypto opt-in prompt. The captured-error check precedes
        // the KexInit/Disconnect arms.
        let captured = Mutex::new(Some(SshError::HostKeyMismatch {
            device_id: "dev-h".into(),
            host: "h".into(),
            port: 22,
            expected: "SHA256:abc".into(),
            got: "SHA256:def".into(),
            known_hosts: std::path::Path::new("/tmp/known_hosts.toml").into(),
        }));
        let err = classify_handshake_error(russh::Error::Disconnect, "dev-h", "h", 22, &captured);
        assert!(matches!(err, SshError::HostKeyMismatch { .. }));
    }

    /// End-to-end contract for the disconnect-reason diagnostic: the
    /// handler captures the server's SSH_MSG_DISCONNECT words, and the
    /// classifier surfaces that capture instead of the generic
    /// "server disconnected during handshake".
    #[tokio::test]
    async fn disconnected_capture_reaches_classification() {
        let store = empty_store().await;
        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);

        h.disconnected(DisconnectReason::ReceivedDisconnect(
            russh::client::RemoteDisconnectInfo {
                reason_code: russh::Disconnect::KeyExchangeFailed,
                message: "no matching key exchange method".into(),
                lang_tag: String::new(),
            },
        ))
        .await
        .expect("received-disconnect capture returns Ok");

        let err = classify_handshake_error(
            russh::Error::Disconnect,
            "dev-h",
            "h",
            22,
            &h.captured_error,
        );
        match err {
            SshError::HandshakeInterrupted { detail, .. } => {
                assert!(
                    detail.contains("no matching key exchange method"),
                    "server's own words surface in the detail: {detail}"
                );
                assert!(
                    detail.contains("KeyExchangeFailed"),
                    "reason code surfaces in the detail: {detail}"
                );
            }
            other => panic!("expected HandshakeInterrupted, got {other:?}"),
        }
    }

    /// A prior classification (host-key mismatch) is never clobbered
    /// by a later server disconnect — the companion invariant to
    /// `classify_captured_error_wins_over_disconnect`.
    #[tokio::test]
    async fn disconnected_does_not_clobber_prior_classification() {
        let store = empty_store().await;
        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);
        *h.captured_error.lock().await = Some(SshError::HostKeyMismatch {
            device_id: "dev-h".into(),
            host: "h".into(),
            port: 22,
            expected: "SHA256:abc".into(),
            got: "SHA256:def".into(),
            known_hosts: std::path::Path::new("/tmp/known_hosts.toml").into(),
        });

        h.disconnected(DisconnectReason::ReceivedDisconnect(
            russh::client::RemoteDisconnectInfo {
                reason_code: russh::Disconnect::ByApplication,
                message: "goodbye".into(),
                lang_tag: String::new(),
            },
        ))
        .await
        .unwrap();

        let captured = h.captured_error.lock().await.take();
        assert!(
            matches!(captured, Some(SshError::HostKeyMismatch { .. })),
            "mismatch classification survives a trailing disconnect"
        );
    }

    /// Error-shaped disconnects propagate unchanged (mirrors russh's
    /// default impl) — only real SSH_MSG_DISCONNECT payloads capture.
    #[tokio::test]
    async fn disconnected_error_reason_propagates() {
        let store = empty_store().await;
        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);

        let result = h
            .disconnected(DisconnectReason::Error(HandlerError::Russh(
                russh::Error::Disconnect,
            )))
            .await;
        assert!(result.is_err(), "error-shaped disconnect must propagate");
        assert!(
            h.captured_error.lock().await.is_none(),
            "no capture for error-shaped disconnects"
        );
    }

    /// The server's disconnect text is pre-auth, attacker-influenceable
    /// input: control characters / ANSI escapes are dropped and the
    /// length is capped before it can reach the UI or logs.
    #[tokio::test]
    async fn disconnected_sanitizes_and_caps_server_text() {
        let store = empty_store().await;
        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);

        let hostile = format!("bad\x1b[31mness\r\nhere{}", "x".repeat(500));
        h.disconnected(DisconnectReason::ReceivedDisconnect(
            russh::client::RemoteDisconnectInfo {
                reason_code: russh::Disconnect::ProtocolError,
                message: hostile,
                lang_tag: String::new(),
            },
        ))
        .await
        .unwrap();

        let captured = h.captured_error.lock().await.take();
        let Some(SshError::HandshakeInterrupted { detail, .. }) = captured else {
            panic!("expected HandshakeInterrupted capture");
        };
        assert!(
            !detail.chars().any(|c| c.is_control()),
            "control characters stripped: {detail:?}"
        );
        assert!(detail.contains("bad[31mnesshere"), "printables kept");
        // 160-char cap on the server text (plus our fixed framing).
        assert!(detail.len() < 240, "capped: len = {}", detail.len());
    }

    // -----------------------------------------------------------------
    // Interactive auth (v6.1.0) — server-authored prompt text is the
    // boundary. Threat-model T46.1.
    // -----------------------------------------------------------------

    /// The prompt sanitizer keeps layout (a real instruction block is
    /// multi-line) while still stripping the characters that let a host
    /// redraw or recolor our dialog.
    #[test]
    fn prompt_sanitizer_keeps_layout_but_strips_control_chars() {
        let hostile = "Line one\nLine two\tcol\r\x1b[31mRED\x07\u{0}";
        let clean = sanitize_server_prompt(hostile);

        assert!(clean.contains('\n'), "newlines survive: {clean:?}");
        assert!(clean.contains('\t'), "tabs survive: {clean:?}");
        assert!(
            !clean
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "no other control chars: {clean:?}"
        );
        // The ESC byte is gone; its printable tail is inert text.
        assert!(!clean.contains('\x1b'), "ESC stripped: {clean:?}");
        assert!(
            !clean.contains('\r'),
            "CR stripped (it can overwrite a line)"
        );
        assert!(!clean.contains('\u{0}'), "NUL stripped");
    }

    /// A hostile host cannot push a wall of text to scroll our own
    /// dialog chrome out of view.
    #[test]
    fn prompt_sanitizer_caps_length() {
        let flood = "A".repeat(MAX_SERVER_TEXT * 4);
        assert_eq!(
            sanitize_server_prompt(&flood).chars().count(),
            MAX_SERVER_TEXT
        );
    }

    /// The disconnect-path sanitizer keeps its ORIGINAL one-line
    /// behavior — sharing an inner helper must not have widened it.
    #[test]
    fn disconnect_sanitizer_still_strips_newlines_and_caps_at_160() {
        let raw = "first\nsecond\tthird";
        let clean = sanitize_server_text(raw);
        assert!(!clean.contains('\n'), "one-line: {clean:?}");
        assert!(!clean.contains('\t'), "one-line: {clean:?}");
        assert_eq!(sanitize_server_text(&"A".repeat(400)).len(), 160);
    }

    /// Non-ASCII is dropped rather than passed through — the UI contract
    /// is printable ASCII, so a multi-byte payload can't smuggle
    /// look-alike glyphs into a dialog the user is about to trust.
    #[test]
    fn prompt_sanitizer_drops_non_ascii() {
        let clean = sanitize_server_prompt("Пароль: аdmin\u{202E}gnp.txt");
        assert!(clean.is_ascii(), "ascii only: {clean:?}");
        // The RTL-override that could reverse displayed text is gone.
        assert!(!clean.contains('\u{202E}'));
    }

    /// An empty disconnect message still produces a useful detail.
    #[tokio::test]
    async fn disconnected_empty_message_notes_absence() {
        let store = empty_store().await;
        let (tx, _rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        let mut h = make_handler(Arc::clone(&store), tx);

        h.disconnected(DisconnectReason::ReceivedDisconnect(
            russh::client::RemoteDisconnectInfo {
                reason_code: russh::Disconnect::KeyExchangeFailed,
                message: String::new(),
                lang_tag: String::new(),
            },
        ))
        .await
        .unwrap();

        let captured = h.captured_error.lock().await.take();
        let Some(SshError::HandshakeInterrupted { detail, .. }) = captured else {
            panic!("expected HandshakeInterrupted capture");
        };
        assert!(
            detail.contains("with no message"),
            "absence is stated, not an empty quote: {detail}"
        );
    }

    #[test]
    fn classify_ssh_encoding_to_handshake_encoding() {
        // FS S5500-48T8SP on one firmware build sends a KEXINIT
        // name-list with a non-ASCII byte; russh's strict UTF-8 decode
        // aborts with SshEncoding. Must classify into the actionable
        // HandshakeEncoding message, not the opaque catch-all.
        let captured = Mutex::new(None);
        let err = classify_handshake_error(
            russh::Error::SshEncoding(russh::keys::ssh_encoding::Error::CharacterEncoding),
            "dev-h",
            "h",
            22,
            &captured,
        );
        assert!(matches!(err, SshError::HandshakeEncoding { .. }));
        // The rendered message guides toward a firmware update and never
        // leaks the raw russh/ssh-encoding enum text.
        let msg = err.to_string();
        assert!(msg.contains("firmware"), "actionable guidance: {msg}");
        assert!(
            !msg.contains("character encoding invalid"),
            "raw ssh-encoding text must not leak: {msg}"
        );
    }

    #[tokio::test]
    async fn classify_captured_error_wins_over_ssh_encoding() {
        // A host-key mismatch captured in the handler must not be
        // reclassified as a malformed-handshake encoding error.
        let captured = Mutex::new(Some(SshError::HostKeyRejected {
            device_id: "dev-h".into(),
            host: "h".into(),
            port: 22,
        }));
        let err = classify_handshake_error(
            russh::Error::SshEncoding(russh::keys::ssh_encoding::Error::CharacterEncoding),
            "dev-h",
            "h",
            22,
            &captured,
        );
        assert!(matches!(err, SshError::HostKeyRejected { .. }));
    }

    #[test]
    fn classify_io_error_to_network() {
        let captured = Mutex::new(None);
        let err = classify_handshake_error(
            russh::Error::IO(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused",
            )),
            "dev-h",
            "h",
            22,
            &captured,
        );
        assert!(matches!(err, SshError::Network { .. }));
    }

    #[test]
    fn classify_timeout_to_timeout() {
        let captured = Mutex::new(None);
        let err =
            classify_handshake_error(russh::Error::ConnectionTimeout, "dev-h", "h", 22, &captured);
        assert!(matches!(err, SshError::Timeout { .. }));
    }

    #[tokio::test]
    async fn classify_consults_captured_error_first() {
        let captured = Mutex::new(Some(SshError::HostKeyMismatch {
            device_id: "dev-h".into(),
            host: "h".into(),
            port: 22,
            expected: "SHA256:abc".into(),
            got: "SHA256:def".into(),
            known_hosts: std::path::Path::new("/tmp/known_hosts.toml").into(),
        }));
        // russh would report the same situation as UnknownKey;
        // ours wins.
        let err = classify_handshake_error(russh::Error::UnknownKey, "dev-h", "h", 22, &captured);
        assert!(matches!(err, SshError::HostKeyMismatch { .. }));
    }

    // ---- Pause-aware connect deadline ---------------------------------

    /// A host-key verdict delayed well beyond the cap must not time
    /// the connect out while the pause flag is up. Paused clock —
    /// tokio auto-advances to the next timer when all tasks idle, so
    /// the simulated 90s of user thinking completes instantly and
    /// deterministically.
    #[tokio::test(start_paused = true)]
    async fn interaction_pause_extends_deadline_past_cap() {
        let cap = Duration::from_secs(30);
        let (pause_tx, pause_rx) = watch::channel(false);
        let flag: InteractionPauseFlag = Arc::new(pause_tx);

        let fut = {
            let flag = Arc::clone(&flag);
            async move {
                // Simulate check_server_key's verdict wait: pause
                // up, user thinks for 3x the cap, pause down.
                let pause = InteractionPauseGuard::enter(&flag);
                tokio::time::sleep(Duration::from_secs(90)).await;
                drop(pause);
                // Post-verdict work (rest of handshake) inside the
                // re-armed budget.
                tokio::time::sleep(Duration::from_secs(1)).await;
                42u32
            }
        };

        let out = deadline_with_interaction_pause(cap, pause_rx, fut).await;
        assert_eq!(out, Some(42), "paused connect must complete, not time out");
    }

    /// A silent network (no pause flag) still times out at the cap.
    #[tokio::test(start_paused = true)]
    async fn silent_connect_times_out_at_cap() {
        let cap = Duration::from_secs(30);
        let (pause_tx, pause_rx) = watch::channel(false);
        // Keep the sender alive so the flag stays a live `false`.
        let _flag: InteractionPauseFlag = Arc::new(pause_tx);

        let started = tokio::time::Instant::now();
        let out =
            deadline_with_interaction_pause(cap, pause_rx, std::future::pending::<()>()).await;
        assert!(out.is_none(), "silent connect must time out");
        assert_eq!(
            started.elapsed(),
            cap,
            "timeout must fire at the cap, not later"
        );
    }

    /// A pause that ends, followed by genuine network silence, still
    /// times out — at the cap measured from when interaction ended, not
    /// from connect start. Pins the post-interaction budget and the
    /// boundary that broke CI: an interaction whose length is a multiple
    /// of the cap no longer ties with the deadline instant.
    #[tokio::test(start_paused = true)]
    async fn silent_after_interaction_still_times_out() {
        let cap = Duration::from_secs(30);
        let (pause_tx, pause_rx) = watch::channel(false);
        let flag: InteractionPauseFlag = Arc::new(pause_tx);

        let started = tokio::time::Instant::now();
        let fut = {
            let flag = Arc::clone(&flag);
            async move {
                // 10s of interaction (uncounted), then the network goes
                // silent forever.
                let pause = InteractionPauseGuard::enter(&flag);
                tokio::time::sleep(Duration::from_secs(10)).await;
                drop(pause);
                std::future::pending::<u32>().await
            }
        };

        let out = deadline_with_interaction_pause(cap, pause_rx, fut).await;
        assert!(out.is_none(), "post-interaction silence must time out");
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(10) + cap,
            "cap runs from the end of interaction, not from connect start"
        );
    }

    /// The TOFU verdict wait must raise the pause flag for its
    /// duration and release it after — that's what makes the
    /// deadline user-proof end to end.
    #[tokio::test]
    async fn check_server_key_first_seen_raises_pause_flag_during_wait() {
        let store = empty_store().await;
        let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(1);

        let mut h = make_handler(Arc::clone(&store), tx);
        let pause_rx = h.interaction_pause.subscribe();

        let responder_task = tokio::spawn(async move {
            let req = rx.recv().await.unwrap();
            // While the dialog is "open", the flag must be up.
            assert!(
                *pause_rx.borrow(),
                "pause flag must be raised while the TOFU verdict is pending"
            );
            req.responder.send(true).unwrap();
        });

        let ok = h.check_server_key(&fixture_pubkey().into()).await.unwrap();
        responder_task.await.unwrap();
        assert!(ok);
        assert!(
            !*h.interaction_pause.borrow(),
            "pause flag must drop once the verdict resolves"
        );
    }

    /// A timed-out connect names the real target — not the historical
    /// `"unknown":0` placeholder.
    #[tokio::test]
    async fn connect_timeout_names_the_real_target() {
        // A listener that accepts and then never speaks SSH: the
        // handshake stalls until the connect deadline fires.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let _sock = listener.accept().await;
            std::future::pending::<()>().await
        });

        let (confirm_tx, _confirm_rx) = mpsc::channel::<HostKeyConfirmRequest>(1);
        // Never exercised here: this test authenticates with a stored
        // credential, so the interactive path is not reached.
        let (kbi_tx, _kbi_rx) = mpsc::channel::<KbiPromptRequest>(1);
        let result = Connection::connect(ConnectParams {
            device_id: TEST_DEVICE.into(),
            host: "127.0.0.1".into(),
            port,
            username: "tester".into(),
            secret_ref: SecretRef::Env {
                var: "TRANSIT_TEST_NO_SUCH_SECRET".into(),
            },
            auth: Arc::new(SecretRegistry::standard()),
            host_keys: empty_store().await,
            confirm_tx,
            kbi_tx,
            timeout: Some(Duration::from_millis(250)),
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        })
        .await;

        // (`Connection` isn't Debug, so no expect_err.)
        let err = match result {
            Ok(_) => panic!("handshake against a mute server must time out"),
            Err(e) => e,
        };
        match err {
            SshError::Timeout { host, port: p } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(p, port);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        hold.abort();
    }

    // ---- Keyboard-interactive fallback helpers ------------------------

    #[test]
    fn kbi_responses_answer_single_prompt_with_password() {
        let prompts = vec![russh::client::Prompt {
            prompt: "Password: ".into(),
            echo: false,
        }];
        assert_eq!(
            kbi_password_responses(&prompts, "hunter2"),
            vec!["hunter2".to_string()]
        );
    }

    #[test]
    fn kbi_responses_empty_for_zero_prompts() {
        // A banner-only InfoRequest carries no prompts; the KBI spec
        // requires an empty response vector in reply.
        assert_eq!(kbi_password_responses(&[], "hunter2"), Vec::<String>::new());
    }

    #[test]
    fn kbi_responses_fill_every_prompt() {
        let prompts = vec![
            russh::client::Prompt {
                prompt: "Password: ".into(),
                echo: false,
            },
            russh::client::Prompt {
                prompt: "Token: ".into(),
                echo: true,
            },
        ];
        assert_eq!(
            kbi_password_responses(&prompts, "pw"),
            vec!["pw".to_string(), "pw".to_string()]
        );
    }

    #[test]
    fn server_offers_kbi_detects_method_presence() {
        use russh::{MethodKind, MethodSet};
        let offered =
            MethodSet::from(&[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..]);
        let not_offered = MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password][..]);
        assert!(server_offers_kbi(&offered));
        assert!(!server_offers_kbi(&not_offered));
    }

    /// The v5.0.0 subsystem error must be *actionable*: the failure mode it
    /// describes (a device with SSH but no SFTP server) is fixed on the
    /// device, so the message has to name the subsystem, the target, and the
    /// Junos knob — that text is the whole remedy the user gets.
    #[test]
    fn subsystem_unavailable_names_the_subsystem_and_the_remedy() {
        let err = SshError::SubsystemUnavailable {
            host: "192.0.2.35".into(),
            port: 22,
            name: "sftp".into(),
            detail: "the device refused the subsystem request".into(),
        };
        let text = err.to_string();
        assert!(text.contains("192.0.2.35:22"), "{text}");
        assert!(text.contains("'sftp'"), "{text}");
        assert!(
            text.contains("the device refused the subsystem request"),
            "{text}"
        );
        assert!(
            text.contains("set system services ssh sftp-server"),
            "the Junos remedy must be spelled out: {text}"
        );
        // It must NOT read like a weak-crypto or auth problem — those have
        // their own variants and their own dialogs.
        assert!(!text.contains("weak crypto"), "{text}");
        assert!(!text.contains("authentication"), "{text}");
    }

    // ---- choose_rsa_hash: RSA signature flavor vs server-sig-algs (T20) ----

    #[test]
    fn rsa_hash_advertised_sha2_is_used_regardless_of_opt_in() {
        for opt_in in [false, true] {
            assert_eq!(
                choose_rsa_hash(Some(Some(HashAlg::Sha512)), opt_in, "alice").unwrap(),
                RsaHash::Use(Some(HashAlg::Sha512)),
            );
            assert_eq!(
                choose_rsa_hash(Some(Some(HashAlg::Sha256)), opt_in, "alice").unwrap(),
                RsaHash::Use(Some(HashAlg::Sha256)),
            );
        }
    }

    #[test]
    fn rsa_hash_advertised_sha1_only_requires_the_opt_in() {
        assert_eq!(
            choose_rsa_hash(Some(None), true, "alice").unwrap(),
            RsaHash::Use(None),
        );
        let err = choose_rsa_hash(Some(None), false, "alice").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("allow weak crypto"), "{text}");
    }

    // The field bug (2026-09-03): old IOS-XE never sends `server-sig-algs`
    // and cannot verify rsa-sha2-512. The weak-crypto opt-in was already
    // granted (its SHA-1-only KEX forced the modal before auth ran), so
    // the signature must ride the same opt-in — SHA-1 `ssh-rsa`, OpenSSH's
    // assumption for a silent server — not a guess the device rejects.
    #[test]
    fn rsa_hash_silent_server_with_opt_in_signs_sha1() {
        assert_eq!(
            choose_rsa_hash(None, true, "alice").unwrap(),
            RsaHash::Use(None),
        );
    }

    // No opt-in ⇒ never a silent SHA-1 downgrade (T20). Strongest hash as
    // best-effort, flagged as a guess so the auth-failure path can point
    // at the opt-in instead of surfacing an opaque rejection.
    #[test]
    fn rsa_hash_silent_server_without_opt_in_stays_best_effort_sha512() {
        assert_eq!(
            choose_rsa_hash(None, false, "alice").unwrap(),
            RsaHash::BestEffortSha512,
        );
    }

    // ---- weak_signature_opt_in_applies: when to surface the modal (T20) ----
    //
    // The field case (IOS-XE 17.x, lab C9300 at 192.0.2.56): modern KEX so
    // no KEX-triggered prompt, silent server-sig-algs, rejects rsa-sha2-512,
    // still offers publickey → we ASK (then retry signs ssh-rsa on consent).

    #[test]
    fn weak_signature_opt_in_only_when_best_effort_failed_and_pubkey_remains() {
        // The one true case: best-effort guess, rejected, publickey remains.
        assert!(weak_signature_opt_in_applies(true, true, true));
    }

    #[test]
    fn weak_signature_opt_in_refused_when_not_a_best_effort_guess() {
        // The server advertised a hash (or we're already opted in) — a plain
        // rejection, never the signature opt-in.
        assert!(!weak_signature_opt_in_applies(false, true, true));
    }

    #[test]
    fn weak_signature_opt_in_refused_when_auth_did_not_fail() {
        assert!(!weak_signature_opt_in_applies(true, false, true));
    }

    #[test]
    fn weak_signature_opt_in_refused_when_pubkey_no_longer_offered() {
        // Retrying with ssh-rsa would be pointless if the server won't take
        // another public key — fail cleanly instead of a dead-end prompt.
        assert!(!weak_signature_opt_in_applies(true, true, false));
    }
}
