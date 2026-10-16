//! SSH IPC commands and shared session state.
//!
//! Six commands:
//! - `connect_device(device_id)` → session id. May emit a
//!   `host-key:confirm` event mid-flight; the frontend replies via
//!   `verify_host_key`.
//! - `disconnect_session(session_id)` — graceful close.
//! - `list_open_sessions()` → metadata for active sessions.
//! - `send_input(session_id, data_b64)` — base64-encoded keystroke
//!   bytes.
//! - `resize_pty(session_id, cols, rows)`.
//! - `verify_host_key(host, port, trust)` — frontend reply to a
//!   `host-key:confirm` event.
//!
//! Three event families:
//! - `pty:{session_id}:output` — base64-encoded PTY bytes.
//! - `pty:{session_id}:closed` — emitted when the channel ends.
//! - `host-key:confirm` — host-key prompt: first-contact TOFU, or the
//!   changed-key warning when the payload carries
//!   `previous_fingerprint` (the stale pin).
//!
//! Per Rule 1: no command returns a credential. `send_input` accepts
//! raw keystroke bytes (which may *contain* credentials when the user
//! types a password into a remote shell prompt — but those bytes
//! never round-trip back to the frontend, only forward to the PTY).

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use transit_core::inventory::SecretRef;
use transit_ssh::{
    ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, KbiPromptRequest, Session,
    SshError,
};
use uuid::Uuid;

use crate::commands::{AppState, InventoryState};

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

const TOFU_CHANNEL_SIZE: usize = 8;

/// Keyed by DEVICE id since v6.5.7, not `(host, port)`: two devices can
/// legitimately share an address, and routing a verdict by address would
/// hand one device's Trust click to the other's prompt.
type PendingTofu = Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>;
/// Pending interactive-auth prompts keyed `(host, port)`.
///
/// `None` on the oneshot = the user cancelled. The map holds a SENDER,
/// never a credential — answers travel straight from the IPC handler into
/// the waiting auth attempt and are never stored here (T46.3).
type PendingKbi = Arc<Mutex<HashMap<(String, u16), oneshot::Sender<Option<Vec<SecretString>>>>>>;
type PendingWeakCrypto = Arc<Mutex<HashMap<(String, u16), oneshot::Sender<WeakCryptoVerdict>>>>;

/// Verdict the frontend returns on a weak-crypto warning dialog.
/// `accept=false` aborts the connect; `accept=true` retries with
/// the legacy cipher allowlist. `remember=true` additionally
/// persists `allow_weak_crypto=true` to the device's inventory
/// record so future connects skip the prompt.
#[derive(Debug, Clone, Copy)]
pub struct WeakCryptoVerdict {
    accept: bool,
    remember: bool,
}

pub struct SshState {
    pub sessions: Mutex<HashMap<String, SessionEntry>>,
    pub host_keys: Arc<HostKeyStore>,
    /// Pending host-key confirmations (first-contact TOFU or
    /// changed-key warning) keyed by `(host, port)`. The
    /// connection-layer handler sent a `host-key:confirm` event;
    /// `verify_host_key` looks up the responder and sends the verdict.
    pub pending_tofu: PendingTofu,
    /// Pending weak-crypto confirmations keyed by `(host, port)`.
    /// Mirror of `pending_tofu`. The connect flow emits a
    /// `weak-crypto:confirm` event when the strict allowlist rejected
    /// the server; `weak_crypto_decision` looks up the responder and
    /// sends the user's verdict.
    pub pending_weak_crypto: PendingWeakCrypto,
    /// Pending interactive-auth prompts keyed by `(host, port)`.
    /// Mirror of `pending_tofu`. The connect flow emits `auth:kbi:request`;
    /// `submit_kbi_answers` / `cancel_kbi` look up the responder.
    ///
    /// Single-slot per target, exactly like the other two prompt maps —
    /// which is the same reason bulk "Launch all" must stay sequential,
    /// and why prompt-auth devices are held back from it entirely.
    pub pending_kbi: PendingKbi,
}

pub struct SessionEntry {
    pub session: Arc<Session>,
    /// The inventory id of the device this session connects to —
    /// the connection name the user chose ("R1"). Stashed at the
    /// app layer (transit_ssh stays inventory-free; same pattern as
    /// `ConsoleSessionEntry.label`) so the agent's
    /// `list_open_sessions` surfaces the name users reference in
    /// chat instead of a host:port stand-in.
    pub device_id: String,
    /// Bridge task that subscribes to the session's broadcast and
    /// emits `pty:{id}:output` events. Aborted on disconnect.
    pub bridge: tokio::task::JoinHandle<()>,
    /// The Connection's russh Handle is held here so it isn't
    /// dropped — dropping it kills the SSH session immediately.
    /// The bridge keeps it alive until close.
    pub _connection: Arc<Connection>,
}

impl SshState {
    pub async fn new() -> Result<Self, String> {
        let path = HostKeyStore::default_path().map_err(|e| e.to_string())?;
        let store = HostKeyStore::open(path).await.map_err(|e| e.to_string())?;
        Ok(Self {
            sessions: Mutex::new(HashMap::new()),
            host_keys: Arc::new(store),
            pending_tofu: Arc::new(Mutex::new(HashMap::new())),
            pending_weak_crypto: Arc::new(Mutex::new(HashMap::new())),
            pending_kbi: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

// ---------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
pub struct SessionMetaWire {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// RFC3339 timestamp.
    pub opened_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct HostKeyConfirmPayload {
    /// Which inventory device this prompt is about. The dialog renders it:
    /// with device-scoped pins two sites can both be at 192.168.1.1,
    /// and the address alone no longer identifies what is being trusted.
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub algorithm: String,
    /// `Some(pinned)` when the host's key CHANGED since last connect —
    /// the frontend renders the loud changed-key warning variant
    /// (both fingerprints, verify checkbox, destructive Replace)
    /// instead of the first-contact TOFU prompt.
    pub previous_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PtyOutputPayload {
    pub session_id: String,
    /// Base64-no-pad encoded bytes. Frontend decodes before passing
    /// to xterm.js (Phase 2c) or text rendering (Phase 2b).
    pub data_b64: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PtyClosedPayload {
    pub session_id: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyHostKeyArgs {
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub trust: bool,
}

/// `weak-crypto:confirm` event payload. `kind` is the negotiation
/// slot that didn't converge (`Kex`, `Cipher`, `Mac`, `Key`);
/// `offered` is the server's advertised list for that slot. The
/// dialog renders both so the user knows what's being negotiated
/// down to.
#[derive(Debug, Serialize, Clone)]
pub struct WeakCryptoConfirmPayload {
    pub host: String,
    pub port: u16,
    pub device_id: String,
    pub kind: String,
    pub offered: Vec<String>,
}

/// One prompt in an interactive-auth challenge, as it goes to the UI.
///
/// `text` is SERVER-AUTHORED (already sanitized in `transit_ssh`). The
/// dialog must render it as quoted, host-attributed foreign text — never
/// as Transit's own copy. Threat-model T46.1.
#[derive(Debug, Serialize, Clone)]
pub struct KbiPromptWire {
    pub text: String,
    /// RFC 4256 echo flag. `false` → mask the field.
    pub echo: bool,
}

/// Payload of `auth:kbi:request`. Carries NO credential — it is the
/// question, never the answer.
#[derive(Debug, Serialize, Clone)]
pub struct KbiPromptPayload {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub name: String,
    pub instruction: String,
    /// Transit-authored explanation; empty for a real server challenge.
    /// Rendered OUTSIDE the "Message from the server" block (T46.1).
    pub notice: String,
    pub prompts: Vec<KbiPromptWire>,
}

/// Frontend → backend answers for an `auth:kbi:request`.
///
/// ⚠️ **This is the second command in the app that accepts a secret**
/// (Rule 1; the other is `enroll_secret`). It is write-only: nothing is
/// returned, nothing is persisted, nothing is logged. The `Vec<String>`
/// is converted to `SecretString` the moment it lands and moved into the
/// waiting auth attempt.
#[derive(Deserialize)]
pub struct SubmitKbiAnswersArgs {
    pub host: String,
    pub port: u16,
    pub answers: Vec<String>,
}

// Hand-written so a derived `Debug` can never print `answers`.
impl std::fmt::Debug for SubmitKbiAnswersArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubmitKbiAnswersArgs")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "answers",
                &format_args!("[{} redacted]", self.answers.len()),
            )
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct CancelKbiArgs {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct WeakCryptoDecisionArgs {
    pub host: String,
    pub port: u16,
    pub accept: bool,
    pub remember: bool,
}

// ---------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------

/// Connect to a device. Allocates a session UUID, opens a `Connection`
/// + `Session`, spawns the output-bridge task, and returns the id.
///
/// During the handshake, if the host key is unknown, this command
/// will emit a `host-key:confirm` event and block until the frontend
/// answers via `verify_host_key`.
#[tauri::command]
pub async fn connect_device(
    app: AppHandle,
    state: State<'_, AppState>,
    device_id: String,
) -> Result<String, String> {
    // The russh handshake + Session::open sequence captures
    // borrows whose Sync derivation rustc can't pin to a
    // higher-ranked lifetime when the future is composed
    // inside the tauri::command macro. Sidestep by handing the
    // entire flow to `tauri::async_runtime::spawn` and bridging
    // the result via a oneshot. The spawned future's Send bound
    // is `'static`, not "for any lifetime", which the compiler
    // accepts.
    let secrets = Arc::clone(&state.secrets);
    let ssh = Arc::clone(&state.ssh);
    let params = lookup_connect_params(&state, &device_id).await?;
    let (tx, rx) = oneshot::channel();
    tauri::async_runtime::spawn(async move {
        let result = do_connect(app, secrets, ssh, device_id, params).await;
        let _ = tx.send(result);
    });
    rx.await.map_err(|_| "connect task panicked".to_string())?
}

// Private indirection between `connect_device` (`tauri::command`) and
// `do_connect_inner` (the actual russh + Session::open flow). The
// boxed future sidesteps the `tauri::command` macro's HRT
// auto-Send analysis.
fn do_connect(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    device_id: String,
    params: ResolvedConnectParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>> {
    Box::pin(do_connect_inner(app, secrets, ssh, device_id, params))
}

async fn do_connect_inner(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    device_id: String,
    params: ResolvedConnectParams,
) -> Result<String, String> {
    let (connection, vendor) = establish_connection_chain(
        app.clone(),
        secrets,
        Arc::clone(&ssh),
        device_id.clone(),
        params,
    )
    .await?;

    let connection = Arc::new(connection);
    let session = Session::open(&connection, "xterm-256color", 80, 24, vendor)
        .await
        .map_err(|e| e.to_string())?;
    let session = Arc::new(session);

    let session_id = Uuid::new_v4().to_string();
    let bridge = spawn_output_bridge(
        app.clone(),
        session.subscribe(),
        session.closed_rx(),
        session_id.clone(),
    );

    {
        let mut guard = ssh.sessions.lock().await;
        guard.insert(
            session_id.clone(),
            SessionEntry {
                session: Arc::clone(&session),
                device_id,
                bridge,
                _connection: connection,
            },
        );
    }

    Ok(session_id)
}

/// Authenticate an SSH connection to a device: strict handshake, the
/// weak-crypto classify → opt-in → legacy-retry ladder, host-key TOFU and
/// the changed-key modal, and all four auth backends. Everything up to (but
/// not including) the choice of channel type.
///
/// Extracted from `do_connect_inner` in v5.0.0 so the Files pane's
/// `files_connect` behaves byte-for-byte like a terminal connect until the
/// channel type diverges (plan §4). Both callers share the ONE
/// `SshState.pending_tofu` / `pending_weak_crypto` responder-map pair, so
/// `verify_host_key` / `weak_crypto_decision` serve both surfaces
/// unchanged. Those maps are single-slot keyed `(host, port)`, which is why
/// Files launches — like bulk SSH connects — must stay strictly sequential.
///
/// Returns the device's `Vendor` alongside the connection because the
/// caller may need it (the PTY path uses it for paging init; the Files path
/// ignores it — SFTP has no vendor-specific behavior).
pub(crate) async fn establish_connection(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    device_id: String,
    params: ResolvedConnectParams,
    via: Option<Arc<Connection>>,
) -> Result<(Connection, transit_core::inventory::Vendor), String> {
    let ResolvedConnectParams {
        host,
        port,
        username,
        secret_ref,
        vendor,
        allow_weak_crypto: initial_allow_weak,
        forward_agent,
        // Single-hop primitive by design: hops are the CHAIN wrapper's
        // business (`establish_connection_chain`), which feeds them
        // back through here one at a time via `via`.
        jump_chain: _,
    } = params;

    // First attempt — strict by default, legacy upfront only if the
    // device's inventory record already opted in.
    let attempt = try_connect(
        app.clone(),
        Arc::clone(&ssh),
        Arc::clone(&secrets),
        device_id.to_string(),
        host.clone(),
        port,
        username.clone(),
        secret_ref.clone(),
        initial_allow_weak,
        via.clone(),
        forward_agent,
    )
    .await;

    let connection = match attempt {
        Ok(c) => c,
        Err(err) if !initial_allow_weak => {
            // v6.5.0 adversarial-review finding: through a TUNNEL, a
            // jump-side channel teardown mid-handshake surfaces as
            // russh `Disconnect` → `HandshakeInterrupted` attributed to
            // the TARGET — the same shape legacy gear produces — so a
            // transient jump flake could bait the weak-crypto dialog
            // and, via "remember", a PERSISTENT crypto downgrade of the
            // target. Before offering any opt-in on a jumped connect,
            // retry STRICT once on a fresh direct-tcpip channel: a
            // flake heals (no prompt), genuine legacy gear fails the
            // same way twice and proceeds to the prompt as usual.
            let err = if via.is_some() && matches!(err, SshError::HandshakeInterrupted { .. }) {
                match try_connect(
                    app.clone(),
                    Arc::clone(&ssh),
                    Arc::clone(&secrets),
                    device_id.to_string(),
                    host.clone(),
                    port,
                    username.clone(),
                    secret_ref.clone(),
                    initial_allow_weak,
                    via.clone(),
                    forward_agent,
                )
                .await
                {
                    Ok(c) => return Ok((c, vendor)),
                    Err(second) => second,
                }
            } else {
                err
            };
            // A strict handshake can fail two ways that a legacy
            // (SHA1 KEX / CBC / ssh-rsa) negotiation might fix:
            //   1. `CipherUnsupported` — russh parsed the server's
            //      KEXINIT and found no common algorithm, so we have a
            //      structured `kind` + `offered` list to render.
            //   2. `HandshakeInterrupted` — the server dropped the
            //      handshake before advertising a list (russh `KexInit`
            //      / `Disconnect`). Legacy gear (Cisco SG300/SG500,
            //      FS.com switches) does this instead of replying with
            //      its weak list. There is no `offered` list, so the
            //      dialog renders a generic "handshake" slot.
            // Both route to the SAME per-device opt-in — weak crypto is
            // NEVER auto-granted; the modal is mandatory (T20). Every
            // other error (auth, host-key, network, timeout) returns
            // as-is with no prompt. If the user opts in and the legacy
            // retry ALSO fails, that error surfaces — so a genuinely
            // non-crypto interruption (ACL drop, TCP reset) isn't masked
            // as "weak crypto".
            let prompt = match &err {
                SshError::CipherUnsupported {
                    kind,
                    offered,
                    detail,
                    ..
                } => {
                    tracing::warn!(%host, port, %kind, ?offered, "{detail}");
                    Some((kind.clone(), offered.clone()))
                }
                SshError::HandshakeInterrupted { detail, .. } => {
                    tracing::warn!(%host, port, "strict handshake interrupted: {detail}");
                    Some(("handshake".to_string(), Vec::new()))
                }
                // v6.5.5 — the user-auth analogue: a modern-KEX device (so
                // no KEX-triggered prompt) that is silent on server-sig-algs
                // and only accepts the legacy SHA-1 ssh-rsa KEY signature.
                // Same per-device opt-in; on accept the retry signs ssh-rsa
                // (choose_rsa_hash under allow_weak_crypto). The `offered`
                // slot names the signature the device will take.
                SshError::WeakSignatureRequired { .. } => {
                    tracing::warn!(
                        %host, port,
                        "device requires the legacy SHA-1 ssh-rsa key signature"
                    );
                    Some((
                        "RSA key signature".to_string(),
                        vec!["ssh-rsa (SHA-1)".to_string()],
                    ))
                }
                _ => None,
            };
            let Some((kind, offered)) = prompt else {
                return Err(err.to_string());
            };
            // The dialog emits a `weak-crypto:confirm` event with the
            // offered list (empty for an interrupted handshake);
            // `weak_crypto_decision` IPC replies via oneshot.
            let verdict = await_weak_crypto_decision(
                &app,
                Arc::clone(&ssh),
                device_id.clone(),
                host.clone(),
                port,
                kind,
                offered,
            )
            .await?;
            if !verdict.accept {
                return Err(format!(
                    "user declined to allow weak crypto for {host}:{port}"
                ));
            }
            if verdict.remember {
                if let Err(e) = persist_allow_weak_crypto(&app, &device_id).await {
                    // Best-effort — log and continue, the connect
                    // should still proceed even if the toml write
                    // is delayed.
                    tracing::warn!(?e, %device_id, "failed to persist allow_weak_crypto");
                }
            }
            try_connect(
                app.clone(),
                Arc::clone(&ssh),
                Arc::clone(&secrets),
                device_id.to_string(),
                host.clone(),
                port,
                username.clone(),
                secret_ref,
                true,
                // A fresh direct-tcpip channel per attempt — the failed
                // strict handshake consumed the previous one.
                via,
                forward_agent,
            )
            .await
            .map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };

    Ok((connection, vendor))
}

/// v6.5.0 — establish a device's FULL connect path: every jump hop in
/// `params.jump_chain` (outermost first), then the target over the last
/// hop's tunnel. Each hop is a complete [`establish_connection`] — its
/// own TOFU prompt, KBI, weak-crypto ladder, and (on "remember") its own
/// persisted opt-in — which also keeps the single-slot `(host, port)`
/// responder maps safe: hops are strictly sequential by construction.
///
/// Ownership needs no bookkeeping here: each hop's `Connection` moves
/// into the NEXT hop's `via`, and transit_ssh parks it in that
/// connection's `_via`, so the returned target `Connection` transitively
/// owns the whole chain and tears down in dependency order.
///
/// Hop failures are prefixed with the hop's device id so a chain failure
/// is attributable at a glance; target-leg failures surface as-is (a
/// tunnel refusal already names both ends via `JumpTunnelRefused`).
pub(crate) async fn establish_connection_chain(
    app: AppHandle,
    secrets: Arc<transit_auth::SecretRegistry>,
    ssh: Arc<SshState>,
    device_id: String,
    mut params: ResolvedConnectParams,
) -> Result<(Connection, transit_core::inventory::Vendor), String> {
    let mut via: Option<Arc<Connection>> = None;
    for hop in std::mem::take(&mut params.jump_chain) {
        let hop_label = format!("{} ({}:{})", hop.device_id, hop.host, hop.port);
        let hop_params = ResolvedConnectParams {
            host: hop.host,
            port: hop.port,
            username: hop.username,
            secret_ref: hop.secret_ref,
            // A jump leg never opens a PTY: vendor is unused (paging
            // init and the policy gate key off the SESSION's vendor,
            // and no session is ever opened on a hop connection).
            vendor: transit_core::inventory::Vendor::Unknown,
            allow_weak_crypto: hop.allow_weak_crypto,
            forward_agent: false,
            jump_chain: Vec::new(),
        };
        let (conn, _) = establish_connection(
            app.clone(),
            Arc::clone(&secrets),
            Arc::clone(&ssh),
            hop.device_id,
            hop_params,
            via,
        )
        .await
        .map_err(|e| format!("via jump host {hop_label}: {e}"))?;
        via = Some(Arc::new(conn));
    }
    establish_connection(app, secrets, ssh, device_id, params, via).await
}

/// Graceful disconnect. Aborts the output bridge, sends EOF to the
/// channel, and removes the session from the map.
///
/// Phase 7b: falls through to `ConsoleState.sessions` if the id
/// isn't an SSH session, so the frontend's standard tab-close flow
/// works for both transports.
#[tauri::command]
pub async fn disconnect_session(
    state: State<'_, AppState>,
    console_state: State<'_, Arc<crate::console::ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: String,
) -> Result<(), String> {
    let entry = state.ssh.sessions.lock().await.remove(&session_id);
    if let Some(entry) = entry {
        entry.bridge.abort();
        match Arc::try_unwrap(entry.session) {
            Ok(session) => session.close().await.map_err(|e| e.to_string())?,
            Err(_) => {
                tracing::warn!(
                    "session {session_id} had outstanding Arc references at disconnect; \
                     relying on Drop to clean up"
                );
            }
        }
        return Ok(());
    }

    // Not an SSH session — try the console table.
    let console_entry = console_state.sessions.lock().await.remove(&session_id);
    if let Some(entry) = console_entry {
        entry.bridge.abort();
        match Arc::try_unwrap(entry.session) {
            Ok(session) => session.close().await.map_err(|e| e.to_string())?,
            Err(_) => {
                tracing::warn!(
                    "console session {session_id} had outstanding Arc references at \
                     disconnect; relying on Drop to clean up"
                );
            }
        }
        return Ok(());
    }

    // Not a console session — try the local-shell table.
    let local_entry = local_state.sessions.lock().await.remove(&session_id);
    if let Some(entry) = local_entry {
        entry.bridge.abort();
        match Arc::try_unwrap(entry.session) {
            Ok(session) => session.close().await.map_err(|e| e.to_string())?,
            Err(_) => {
                tracing::warn!(
                    "local session {session_id} had outstanding Arc references at \
                     disconnect; relying on Drop to clean up"
                );
            }
        }
        return Ok(());
    }

    Err(format!("session {session_id} not found"))
}

#[tauri::command]
pub async fn list_open_sessions(
    state: State<'_, AppState>,
) -> Result<Vec<SessionMetaWire>, String> {
    let guard = state.ssh.sessions.lock().await;
    let mut out = Vec::with_capacity(guard.len());
    for (id, entry) in guard.iter() {
        let m = entry.session.meta();
        let opened_at = m
            .opened_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        out.push(SessionMetaWire {
            session_id: id.clone(),
            host: m.host.clone(),
            port: m.port,
            username: m.username.clone(),
            opened_at,
        });
    }
    Ok(out)
}

/// Forward keystrokes / paste bytes to a session's PTY.
///
/// Phase 7b: falls through to `ConsoleState.sessions` if the id
/// isn't an SSH session.
#[tauri::command]
pub async fn send_input(
    state: State<'_, AppState>,
    console_state: State<'_, Arc<crate::console::ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: String,
    data_b64: String,
) -> Result<(), String> {
    let bytes = STANDARD_NO_PAD
        .decode(data_b64.as_bytes())
        .map_err(|e| format!("invalid base64 input: {e}"))?;

    // Clone the Arc inside the guard, drop the guard, THEN await the
    // transport — holding the global session table across a
    // transport await lets one wedged session freeze every session
    // (and `list_open_sessions`). Same pattern as
    // `SshSessionExecutor::run_command`.
    let ssh_session = {
        let guard = state.ssh.sessions.lock().await;
        guard.get(&session_id).map(|e| Arc::clone(&e.session))
    };
    if let Some(session) = ssh_session {
        return session
            .send_input(Bytes::from(bytes))
            .await
            .map_err(|e| e.to_string());
    }

    let console_session = {
        let guard = console_state.sessions.lock().await;
        guard.get(&session_id).map(|e| Arc::clone(&e.session))
    };
    if let Some(session) = console_session {
        return session
            .send_input(Bytes::from(bytes))
            .await
            .map_err(|e| e.to_string());
    }

    let local_session = {
        let guard = local_state.sessions.lock().await;
        guard.get(&session_id).map(|e| Arc::clone(&e.session))
    };
    if let Some(session) = local_session {
        return session
            .send_input(Bytes::from(bytes))
            .await
            .map_err(|e| e.to_string());
    }

    Err(format!("session {session_id} not found"))
}

/// Inform an SSH session of the new terminal window size. Console
/// sessions get a silent Ok — serial has no concept of window geometry,
/// and the frontend calls this unconditionally on every resize.
#[tauri::command]
pub async fn resize_pty(
    state: State<'_, AppState>,
    console_state: State<'_, Arc<crate::console::ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    // Clone-then-drop, same rationale as `send_input`: never hold
    // the session table across the transport await.
    let ssh_session = {
        let guard = state.ssh.sessions.lock().await;
        guard.get(&session_id).map(|e| Arc::clone(&e.session))
    };
    if let Some(session) = ssh_session {
        return session.resize(cols, rows).await.map_err(|e| e.to_string());
    }

    if console_state
        .sessions
        .lock()
        .await
        .contains_key(&session_id)
    {
        return Ok(());
    }

    // A local PTY *does* need a real resize (unlike console) — this is
    // the one shared command where the local arm does actual work.
    let local_session = {
        let guard = local_state.sessions.lock().await;
        guard.get(&session_id).map(|e| Arc::clone(&e.session))
    };
    if let Some(session) = local_session {
        return session.resize(cols, rows).await.map_err(|e| e.to_string());
    }

    Err(format!("session {session_id} not found"))
}

/// Wipe a session's scrollback ring (v1.4.0 "Clear terminal").
///
/// Backs the user-driven right-click-tab → Clear action. Resets the
/// backend `ScrollbackRing` so the agent's `read_scrollback` returns
/// only post-clear bytes; the frontend separately clears the xterm.js
/// view. Falls through to `ConsoleState.sessions` like `send_input`.
#[tauri::command]
pub async fn clear_scrollback(
    state: State<'_, AppState>,
    console_state: State<'_, Arc<crate::console::ConsoleState>>,
    local_state: State<'_, Arc<crate::local_shell::LocalPtyState>>,
    session_id: String,
) -> Result<(), String> {
    // Clone the `Arc<ScrollbackRing>` inside the guard, drop the guard,
    // THEN clear: the ring's own (sync) Mutex serializes the wipe
    // against the reader task's `push`, so we never hold the session
    // table across the clear and need no `SessionCmd`/mpsc round-trip.
    let ssh_ring = {
        let guard = state.ssh.sessions.lock().await;
        guard
            .get(&session_id)
            .map(|e| Arc::clone(&e.session.scrollback))
    };
    if let Some(ring) = ssh_ring {
        ring.clear();
        return Ok(());
    }

    let console_ring = {
        let guard = console_state.sessions.lock().await;
        guard
            .get(&session_id)
            .map(|e| Arc::clone(&e.session.scrollback))
    };
    if let Some(ring) = console_ring {
        ring.clear();
        return Ok(());
    }

    let local_ring = {
        let guard = local_state.sessions.lock().await;
        guard
            .get(&session_id)
            .map(|e| Arc::clone(&e.session.scrollback))
    };
    if let Some(ring) = local_ring {
        ring.clear();
        return Ok(());
    }

    Err(format!("session {session_id} not found"))
}

/// Reply to an in-flight `host-key:confirm` event — first-contact
/// TOFU or the changed-key warning. `trust = true` on a changed key
/// approves replacing the pin (persisted only after auth succeeds).
#[tauri::command]
pub async fn verify_host_key(
    state: State<'_, AppState>,
    args: VerifyHostKeyArgs,
) -> Result<(), String> {
    let mut pending = state.ssh.pending_tofu.lock().await;
    match pending.remove(&args.device_id) {
        Some(responder) => responder
            .send(args.trust)
            .map_err(|_| "TOFU responder already consumed".to_string()),
        None => Err(format!(
            "no pending host-key confirmation for device '{}' ({}:{})",
            args.device_id, args.host, args.port
        )),
    }
}

/// Frontend reply to an `auth:kbi:request` event — the user's answers to
/// the server's interactive auth prompts.
///
/// **Rule 1 note.** Along with `enroll_secret` this is one of only two
/// commands that accept a credential across IPC, and unlike enrollment it
/// stores nothing: the answers are wrapped in `SecretString`, handed to
/// the auth attempt that is parked on the oneshot, and dropped when that
/// attempt finishes. Nothing is written to disk, returned to the
/// frontend, or logged. See the interactive keyboard auth design notes (not included in this repository)
/// and threat-model T46.
#[tauri::command]
pub async fn submit_kbi_answers(
    state: State<'_, AppState>,
    args: SubmitKbiAnswersArgs,
) -> Result<(), String> {
    let answers: Vec<SecretString> = args.answers.into_iter().map(SecretString::from).collect();
    let mut pending = state.ssh.pending_kbi.lock().await;
    let key = (args.host.clone(), args.port);
    match pending.remove(&key) {
        Some(responder) => responder
            .send(Some(answers))
            // The auth attempt went away (timeout, app teardown). Nothing
            // to do but report it — the secret drops with the error path.
            .map_err(|_| "interactive auth responder already consumed".to_string()),
        None => Err(format!(
            "no pending interactive auth prompt for {}:{}",
            args.host, args.port
        )),
    }
}

/// Frontend reply when the user dismisses the interactive-auth dialog.
/// Fails the connect cleanly instead of leaving it parked until the
/// connect deadline expires.
#[tauri::command]
pub async fn cancel_kbi(state: State<'_, AppState>, args: CancelKbiArgs) -> Result<(), String> {
    let mut pending = state.ssh.pending_kbi.lock().await;
    let key = (args.host.clone(), args.port);
    match pending.remove(&key) {
        Some(responder) => responder
            .send(None)
            .map_err(|_| "interactive auth responder already consumed".to_string()),
        // Not an error worth surfacing: a cancel racing the attempt's own
        // teardown is normal.
        None => Ok(()),
    }
}

/// Frontend reply to a `weak-crypto:confirm` event. Mirror of
/// [`verify_host_key`]: lookup the responder keyed by (host, port)
/// and send the user's [`WeakCryptoVerdict`].
///
/// `accept=false` aborts the connect; `accept=true` retries with the
/// legacy cipher allowlist. `remember=true` additionally flips the
/// device's `allow_weak_crypto` inventory field to `Some(true)`.
#[tauri::command]
pub async fn weak_crypto_decision(
    state: State<'_, AppState>,
    args: WeakCryptoDecisionArgs,
) -> Result<(), String> {
    let mut pending = state.ssh.pending_weak_crypto.lock().await;
    let key = (args.host.clone(), args.port);
    match pending.remove(&key) {
        Some(responder) => responder
            .send(WeakCryptoVerdict {
                accept: args.accept,
                remember: args.remember,
            })
            .map_err(|_| "weak-crypto responder already consumed".to_string()),
        None => Err(format!(
            "no pending weak-crypto confirmation for {}:{}",
            args.host, args.port
        )),
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Resolved connect parameters for a device. Returned by
/// [`lookup_connect_params`]; consumed by [`connect_device`].
pub(crate) struct ResolvedConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub secret_ref: SecretRef,
    pub vendor: transit_core::inventory::Vendor,
    /// The device's persisted weak-crypto opt-in. `Some(true)`
    /// means the user has previously approved SHA1 KEX/CBC/ssh-rsa
    /// for this device; subsequent connects negotiate with the
    /// legacy allowlist upfront, no dialog.
    pub allow_weak_crypto: bool,
    /// Per-device agent-forwarding opt-in (v6.5.0, T53). Only ever
    /// true for the TARGET leg — a jump leg never opens a PTY session,
    /// so it never requests forwarding.
    pub forward_agent: bool,
    /// The device's resolved jump path, OUTERMOST FIRST (v6.5.0, T52):
    /// `[first hop from this machine, …, the device's direct jump]`.
    /// Empty = direct connect. Each hop carries its own auth; every
    /// hop gets its own TOFU, KBI, and weak-crypto ladder in
    /// [`establish_connection_chain`].
    pub jump_chain: Vec<ResolvedHop>,
}

/// One resolved jump hop — the subset of a device's connect identity a
/// tunnel leg needs (no vendor: a jump leg never opens a PTY, so
/// paging init and the policy gate never see it).
pub(crate) struct ResolvedHop {
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub secret_ref: SecretRef,
    pub allow_weak_crypto: bool,
}

/// Read a device + its auth profile out of the in-memory inventory.
/// Crate-public since v5.0.0: `files_connect` resolves a device exactly the
/// same way a terminal connect does (plan §4).
pub(crate) async fn lookup_connect_params(
    state: &State<'_, AppState>,
    device_id: &str,
) -> Result<ResolvedConnectParams, String> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => {
            let text = doc.to_string();
            toml::from_str::<transit_core::inventory::InventoryFile>(&text)
                .map_err(|e| e.to_string())?
        }
        InventoryState::Broken { reason } => return Err(reason.clone()),
    };
    let device = inv
        .devices
        .iter()
        .find(|d| d.id == device_id)
        .ok_or_else(|| format!("device '{device_id}' not found"))?;
    let auth = inv
        .auth_profiles
        .get(&device.auth)
        .ok_or_else(|| format!("auth profile '{}' not found for device", device.auth))?;

    // v6.5.0 — resolve the jump chain, walking `jump_via` outward from
    // the target and reversing so the caller connects OUTERMOST FIRST.
    // The loader already guarantees resolution/acyclicity/depth at
    // load and on every mutation; this re-check is defensive (the
    // in-memory doc is authoritative and could in principle drift),
    // so it mirrors the loader's limits rather than trusting them.
    let mut jump_chain: Vec<ResolvedHop> = Vec::new();
    let mut seen = std::collections::HashSet::from([device.id.as_str()]);
    let mut cursor = device.jump_via.as_deref();
    while let Some(jump_id) = cursor {
        if !seen.insert(jump_id) {
            return Err(format!(
                "jump-host cycle detected while resolving '{device_id}' (at '{jump_id}')"
            ));
        }
        if jump_chain.len() >= transit_core::inventory::MAX_JUMP_CHAIN {
            return Err(format!(
                "jump-host chain for '{device_id}' exceeds the maximum depth of {}",
                transit_core::inventory::MAX_JUMP_CHAIN
            ));
        }
        let hop = inv
            .devices
            .iter()
            .find(|d| d.id == jump_id)
            .ok_or_else(|| format!("jump host '{jump_id}' not found for device '{device_id}'"))?;
        let hop_auth = inv.auth_profiles.get(&hop.auth).ok_or_else(|| {
            format!(
                "auth profile '{}' not found for jump host '{jump_id}'",
                hop.auth
            )
        })?;
        jump_chain.push(ResolvedHop {
            device_id: hop.id.clone(),
            host: hop.host.clone(),
            port: hop.port,
            username: hop_auth.username.clone(),
            secret_ref: hop_auth.secret.clone(),
            allow_weak_crypto: hop.allow_weak_crypto.unwrap_or(false),
        });
        cursor = hop.jump_via.as_deref();
    }
    // Walked target → outward; connects run outward → target.
    jump_chain.reverse();

    Ok(ResolvedConnectParams {
        host: device.host.clone(),
        port: device.port,
        username: auth.username.clone(),
        secret_ref: auth.secret.clone(),
        vendor: device.vendor.clone(),
        allow_weak_crypto: device.allow_weak_crypto.unwrap_or(false),
        forward_agent: device.forward_agent.unwrap_or(false),
        jump_chain,
    })
}

/// Run one connect attempt with a fresh TOFU channel pair. Factored
/// out so the weak-crypto retry path can build a second attempt
/// after the first one's `CipherUnsupported` rejection.
#[allow(clippy::too_many_arguments)]
async fn try_connect(
    app: AppHandle,
    ssh: Arc<SshState>,
    secrets: Arc<transit_auth::SecretRegistry>,
    device_id: String,
    host: String,
    port: u16,
    username: String,
    secret_ref: SecretRef,
    allow_weak_crypto: bool,
    via: Option<Arc<Connection>>,
    forward_agent: bool,
) -> Result<Connection, SshError> {
    let (confirm_tx, confirm_rx) = mpsc::channel::<HostKeyConfirmRequest>(TOFU_CHANNEL_SIZE);
    let (kbi_tx, kbi_rx) = mpsc::channel::<KbiPromptRequest>(TOFU_CHANNEL_SIZE);
    let tofu_bridge = spawn_tofu_bridge(app.clone(), Arc::clone(&ssh.pending_tofu), confirm_rx);
    let kbi_bridge = spawn_kbi_bridge(app, Arc::clone(&ssh.pending_kbi), kbi_rx);
    let target = (host.clone(), port);
    let result = Connection::connect(ConnectParams {
        device_id,
        host,
        port,
        username,
        secret_ref,
        auth: secrets,
        host_keys: Arc::clone(&ssh.host_keys),
        confirm_tx,
        kbi_tx,
        timeout: None,
        allow_weak_crypto,
        via,
        forward_agent,
    })
    .await;
    tofu_bridge.abort();
    kbi_bridge.abort();
    // Aborting the bridge does NOT clear a responder it already parked.
    // Drop any leftover for this target so a later attempt can't be
    // answered by a dialog belonging to the attempt that just ended —
    // and so the weak-crypto retry starts from a clean slate.
    {
        let mut guard = ssh.pending_kbi.lock().await;
        guard.remove(&target);
    }
    result
}

/// Emit a `weak-crypto:confirm` event with the server's offered list
/// and wait for the frontend's verdict. Mirrors the TOFU flow: the
/// IPC handler `weak_crypto_decision` looks up the keyed responder
/// and sends the [`WeakCryptoVerdict`].
async fn await_weak_crypto_decision(
    app: &AppHandle,
    ssh: Arc<SshState>,
    device_id: String,
    host: String,
    port: u16,
    kind: String,
    offered: Vec<String>,
) -> Result<WeakCryptoVerdict, String> {
    let (tx, rx) = oneshot::channel::<WeakCryptoVerdict>();
    {
        let mut guard = ssh.pending_weak_crypto.lock().await;
        guard.insert((host.clone(), port), tx);
    }
    let payload = WeakCryptoConfirmPayload {
        host: host.clone(),
        port,
        device_id,
        kind,
        offered,
    };
    if let Err(e) = app.emit("weak-crypto:confirm", payload) {
        // Drop the responder we just inserted so we don't leak it.
        let _ = ssh.pending_weak_crypto.lock().await.remove(&(host, port));
        return Err(format!("failed to emit weak-crypto:confirm: {e}"));
    }
    rx.await
        .map_err(|_| "weak-crypto dialog dismissed without verdict".to_string())
}

/// Persist `allow_weak_crypto=true` to the device's inventory record
/// so future connects negotiate with the legacy allowlist upfront,
/// skipping the prompt.
async fn persist_allow_weak_crypto(app: &AppHandle, device_id: &str) -> Result<(), String> {
    use transit_core::inventory::mutator::{update_device, write_atomic};

    let state: State<'_, AppState> = app.state::<AppState>();
    let mut guard = state.inventory.write().await;
    let doc = match &mut *guard {
        InventoryState::Ready(doc) => doc,
        InventoryState::Broken { reason } => {
            return Err(format!(
                "inventory file is in error state — fix manually before editing in-app: {reason}"
            ));
        }
    };

    let text = doc.to_string();
    let inv: transit_core::inventory::InventoryFile =
        toml::from_str(&text).map_err(|e| e.to_string())?;
    let device = inv
        .devices
        .iter()
        .find(|d| d.id == device_id)
        .ok_or_else(|| format!("device '{device_id}' not found"))?;
    let mut updated = device.clone();
    updated.allow_weak_crypto = Some(true);

    update_device(doc, device_id, &updated).map_err(|e| e.to_string())?;
    let serialized = doc.to_string();
    write_atomic(&state.inventory_path, &serialized).map_err(|e| e.to_string())
}

/// Turn `KbiPromptRequest`s from the connection layer into
/// `auth:kbi:request` events, parking each responder in `pending_kbi`
/// keyed `(host, port)`. Exact mirror of [`spawn_tofu_bridge`].
///
/// The emitted payload carries the QUESTION only — server-authored prompt
/// text, already sanitized upstream. The answer comes back through
/// [`submit_kbi_answers`], never through this channel.
fn spawn_kbi_bridge(
    app: AppHandle,
    pending: PendingKbi,
    mut prompt_rx: mpsc::Receiver<KbiPromptRequest>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(req) = prompt_rx.recv().await {
            let payload = KbiPromptPayload {
                host: req.host.clone(),
                port: req.port,
                username: req.username.clone(),
                name: req.name.clone(),
                instruction: req.instruction.clone(),
                notice: req.notice.clone(),
                prompts: req
                    .prompts
                    .iter()
                    .map(|p| KbiPromptWire {
                        text: p.text.clone(),
                        echo: p.echo,
                    })
                    .collect(),
            };
            {
                let mut guard = pending.lock().await;
                // Replace-on-collision mirrors pending_tofu. A stale
                // responder for the same target is dropped, which makes
                // its parked auth attempt observe a cancel rather than
                // hang forever.
                guard.insert((req.host.clone(), req.port), req.responder);
            }
            if let Err(e) = app.emit("auth:kbi:request", payload) {
                tracing::error!(?e, "failed to emit auth:kbi:request");
            }
        }
    })
}

fn spawn_tofu_bridge(
    app: AppHandle,
    pending: PendingTofu,
    mut confirm_rx: mpsc::Receiver<HostKeyConfirmRequest>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(req) = confirm_rx.recv().await {
            let payload = HostKeyConfirmPayload {
                device_id: req.device_id.clone(),
                host: req.host.clone(),
                port: req.port,
                fingerprint: req.fingerprint.clone(),
                algorithm: req.algorithm.clone(),
                previous_fingerprint: req.previous_fingerprint.clone(),
            };
            {
                let mut guard = pending.lock().await;
                guard.insert(req.device_id.clone(), req.responder);
            }
            if let Err(e) = app.emit("host-key:confirm", payload) {
                tracing::error!(?e, "failed to emit host-key:confirm");
            }
        }
    })
}

/// Translate a session's broadcast output into `pty:{id}:output`
/// Tauri events. Crate-public so the console transport can reuse
/// the same event topic — the frontend's `TerminalPane` doesn't
/// care which transport produced the bytes.
///
/// `closed_rx` is the session's level-triggered "reader exited"
/// signal (`Session::closed_rx`). It used to be an edge-triggered
/// `Notify`, but the bridge recreated `notified()` every loop
/// iteration — a `notify_waiters` fired in the gap between
/// iterations (or before this task first ran) was lost forever and
/// `pty:{id}:closed` could permanently fail to emit. The watch
/// channel reads `true` whenever the bridge looks, no matter when
/// the reader exited.
pub(crate) fn spawn_output_bridge(
    app: AppHandle,
    mut rx: broadcast::Receiver<Bytes>,
    mut closed_rx: tokio::sync::watch::Receiver<bool>,
    session_id: String,
) -> tokio::task::JoinHandle<()> {
    let event_name = format!("pty:{session_id}:output");
    let closed_event = format!("pty:{session_id}:closed");
    tokio::spawn(async move {
        let emit_output = |bytes: &Bytes| {
            let payload = PtyOutputPayload {
                session_id: session_id.clone(),
                data_b64: STANDARD_NO_PAD.encode(bytes),
            };
            if let Err(e) = app.emit(&event_name, payload) {
                tracing::warn!(?e, "failed to emit pty output");
            }
        };
        // Drain whatever the reader queued before exiting, then emit
        // the closed event — Junos / IOS often write a "logout"
        // message right before closing the channel.
        let drain_and_emit_closed = |rx: &mut broadcast::Receiver<Bytes>, reason: &str| {
            while let Ok(bytes) = rx.try_recv() {
                emit_output(&bytes);
            }
            let payload = PtyClosedPayload {
                session_id: session_id.clone(),
                reason: reason.into(),
            };
            let _ = app.emit(&closed_event, payload);
        };

        // The session may have ended before this task first ran —
        // `borrow_and_update` both checks the level and marks the
        // current version seen so the in-loop `changed()` only wakes
        // on a *later* flip.
        if *closed_rx.borrow_and_update() {
            drain_and_emit_closed(&mut rx, "remote closed the channel");
            return;
        }

        // Without the closed signal the bridge would sit on
        // `rx.recv()` forever after a remote-side close, because
        // Session still holds a `broadcast::Sender`, so
        // `RecvError::Closed` never fires.
        loop {
            tokio::select! {
                biased;
                res = rx.recv() => {
                    match res {
                        Ok(bytes) => emit_output(&bytes),
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped,
                                "frontend lagged on pty output; bytes dropped \
                                 from the live stream (still in scrollback)"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Session itself dropped (typically because
                            // the user clicked Disconnect). Emit close so
                            // the frontend can finalize.
                            let payload = PtyClosedPayload {
                                session_id: session_id.clone(),
                                reason: "session torn down".into(),
                            };
                            let _ = app.emit(&closed_event, payload);
                            break;
                        }
                    }
                }
                changed = closed_rx.changed() => {
                    // Ok(()) → the reader flipped the flag; Err(_) →
                    // the reader task was aborted and the sender
                    // dropped. Either way the session is gone.
                    let _ = changed;
                    drain_and_emit_closed(&mut rx, "remote closed the channel");
                    break;
                }
            }
        }
    })
}
