//! Jump-host (`direct-tcpip` tunnel) integration tests against
//! **in-process russh servers** (v6.5.0, threat model T52) — the
//! `keyboard_interactive.rs` harness pattern: ephemeral ports,
//! throwaway ed25519 host keys, no Docker, runs in every `cargo test`.
//!
//! Topology per test: an OUTER server that authenticates and forwards
//! `direct-tcpip` opens to a real local TCP dial (the jump), and an
//! INNER password server (the target). The client connects the jump
//! directly, then connects the target with `via: Some(jump)`.

// `std::env::set_var` is `unsafe` in Rust 2024+. Each test sets
// uniquely-named vars at start; the registry reads them in-process.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use russh::server::{Auth, Handler as ServerHandler};
use tokio::sync::mpsc;
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;
use transit_ssh::{
    ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, KbiPromptRequest, PinTier,
    SshError,
};

const JUMP_PASSWORD: &str = "jump-test-password";
const TARGET_PASSWORD: &str = "target-test-password";

/// Plain password-auth server; the target of a tunnel.
struct PasswordHandler {
    expected: String,
}

impl ServerHandler for PasswordHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == self.expected {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }
}

/// Password-auth server that ALSO forwards `direct-tcpip` channel
/// opens by dialing the requested target itself — a minimal sshd with
/// `AllowTcpForwarding yes`. The `forwarding` flag models the `no`
/// case: when false the handler drops the reply handle, which
/// auto-rejects with `administratively prohibited` (exactly what a
/// locked-down sshd answers).
struct JumpHandler {
    expected: String,
    forwarding: bool,
}

impl ServerHandler for JumpHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == self.expected {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if !self.forwarding {
            // Dropping `reply` auto-rejects (administratively
            // prohibited) — the same wire behavior as a real sshd with
            // AllowTcpForwarding no.
            drop(reply);
            return Ok(());
        }
        let target = (host_to_connect.to_string(), port_to_connect as u16);
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect(target).await {
                Ok(mut tcp) => {
                    reply.accept().await;
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }
                Err(_) => {
                    reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                }
            }
        });
        Ok(())
    }
}

fn server_config() -> russh::server::Config {
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("generate ephemeral test host key");
    russh::server::Config {
        keys: vec![key],
        ..Default::default()
    }
}

/// Bind an ephemeral port and serve EVERY inbound connection with a
/// fresh handler from `make` — unlike the single-accept KBI helpers,
/// jump tests need multiple connections (the jump link + one tunneled
/// dial per connect attempt).
async fn spawn_accept_loop_server<H, F>(make: F) -> (u16, tokio::task::JoinHandle<()>)
where
    H: ServerHandler<Error = russh::Error> + Send + 'static,
    F: Fn() -> H + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server_config());
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = Arc::clone(&config);
            let handler = make();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    (port, task)
}

async fn fresh_known_hosts() -> (Arc<HostKeyStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts.toml");
    let store = HostKeyStore::open(path).await.expect("open empty store");
    (Arc::new(store), dir)
}

fn auto_trust_channel() -> mpsc::Sender<HostKeyConfirmRequest> {
    let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let _ = req.responder.send(true);
        }
    });
    tx
}

fn unused_kbi_channel() -> mpsc::Sender<KbiPromptRequest> {
    let (tx, _rx) = mpsc::channel::<KbiPromptRequest>(1);
    tx
}

fn params(
    device_id: &str,
    port: u16,
    env_var: &str,
    host_keys: &Arc<HostKeyStore>,
    via: Option<Arc<Connection>>,
) -> ConnectParams {
    ConnectParams {
        device_id: device_id.into(),
        host: "127.0.0.1".into(),
        port,
        username: "alice".into(),
        secret_ref: SecretRef::Env {
            var: env_var.into(),
        },
        auth: Arc::new(SecretRegistry::standard()),
        host_keys: Arc::clone(host_keys),
        confirm_tx: auto_trust_channel(),
        kbi_tx: unused_kbi_channel(),
        timeout: Some(Duration::from_secs(20)),
        allow_weak_crypto: false,
        via,
        forward_agent: false,
    }
}

/// The headline: connect a target THROUGH a jump; auth runs against the
/// inner server end-to-end and each leg's host-key pin lands under that
/// leg's own DEVICE id — the tunnel changes transport, never identity.
///
/// Since v6.5.7 the pin key is the device, not the address, which is what
/// makes the overlapping-RFC1918 case work: here both hops answer on
/// `127.0.0.1` and are told apart by device id alone, not by port.
/// Hard ceiling per test, so a wedge FAILS instead of hanging.
///
/// These tests have repeatedly wedged on `macos-latest` (both the v6.5.0
/// and v6.5.1 CI runs), sitting until the 50-minute job cap with only
/// "has been running for over 60 seconds" to go on. `ConnectParams.timeout`
/// cannot bound it: `deadline_with_interaction_pause` stops the clock
/// entirely while the interaction-pause flag is up, so a stall inside a
/// host-key prompt window is unbounded by design. This converts that into a
/// fast, named failure — and if it fires in CI it tells us which test, which
/// is strictly more than a hang tells us.
const TEST_DEADLINE: Duration = Duration::from_secs(60);

async fn with_deadline<F>(name: &str, fut: F)
where
    F: std::future::Future<Output = ()>,
{
    if tokio::time::timeout(TEST_DEADLINE, fut).await.is_err() {
        panic!(
            "{name} did not finish within {TEST_DEADLINE:?} — the jump tunnel wedged. \
             Normal runtime is ~1s; see transit_ssh::connection::deadline_with_interaction_pause."
        );
    }
}

// 4 workers, not the KBI harness's 2: this file runs an outer (jump)
// server accept loop + session, a spawned copy_bidirectional forwarder,
// an inner (target) server accept loop + session, and the client
// Connection actor — roughly seven interdependent tasks with
// three-party round-trips, against KBI's one server and two parties.
// A macos-latest runner has 3 cores, and cargo runs these three tests
// concurrently. Do not "align" this back to 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_through_jump_authenticates_and_pins_target_identity() {
    with_deadline(
        "connect_through_jump_authenticates_and_pins_target_identity",
        connect_through_jump_authenticates_and_pins_target_identity_inner(),
    )
    .await;
}

async fn connect_through_jump_authenticates_and_pins_target_identity_inner() {
    let (target_port, target_srv) = spawn_accept_loop_server(|| PasswordHandler {
        expected: TARGET_PASSWORD.into(),
    })
    .await;
    let (jump_port, jump_srv) = spawn_accept_loop_server(|| JumpHandler {
        expected: JUMP_PASSWORD.into(),
        forwarding: true,
    })
    .await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // SAFETY: unique var names, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_JUMP_PW_1", JUMP_PASSWORD) };
    unsafe { std::env::set_var("TRANSIT_TEST_TARGET_PW_1", TARGET_PASSWORD) };

    let jump = Connection::connect(params(
        "dev-jump",
        jump_port,
        "TRANSIT_TEST_JUMP_PW_1",
        &host_keys,
        None,
    ))
    .await
    .expect("jump connects directly");
    let jump = Arc::new(jump);

    let target = Connection::connect(params(
        "dev-target",
        target_port,
        "TRANSIT_TEST_TARGET_PW_1",
        &host_keys,
        Some(Arc::clone(&jump)),
    ))
    .await
    .expect("target connects through the tunnel");

    // Pins landed under each hop's own DEVICE, and each is independent.
    // Note both lookups pass the same host — the device id is what tells
    // them apart, which is precisely the overlapping-address property.
    let jump_pin = host_keys
        .lookup("dev-jump", "127.0.0.1", jump_port)
        .await
        .expect("store readable")
        .expect("jump pin recorded under the jump's device id");
    let target_pin = host_keys
        .lookup("dev-target", "127.0.0.1", target_port)
        .await
        .expect("store readable")
        .expect("target pin recorded under the TARGET's device id");
    assert_eq!(jump_pin.tier, PinTier::Scoped);
    assert_eq!(target_pin.tier, PinTier::Scoped);

    // The decisive assertion: asking for one device's pin at the OTHER's
    // address still returns that device's own pin, never the neighbour's.
    // Before device scoping these two shared a slot.
    assert_ne!(
        jump_pin.fingerprint.to_string(),
        target_pin.fingerprint.to_string(),
        "two servers on 127.0.0.1 must hold independent pins"
    );
    // And the connection reports the TARGET's identity.
    assert_eq!(target.target(), ("127.0.0.1", target_port));

    drop(target);
    drop(jump);
    jump_srv.abort();
    target_srv.abort();
}

/// A jump whose sshd refuses TCP forwarding surfaces the dedicated,
/// both-ends-named error — not a generic network failure.
// 4 workers, not the KBI harness's 2: this file runs an outer (jump)
// server accept loop + session, a spawned copy_bidirectional forwarder,
// an inner (target) server accept loop + session, and the client
// Connection actor — roughly seven interdependent tasks with
// three-party round-trips, against KBI's one server and two parties.
// A macos-latest runner has 3 cores, and cargo runs these three tests
// concurrently. Do not "align" this back to 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_refusing_tunnel_surfaces_jump_tunnel_refused() {
    with_deadline(
        "jump_refusing_tunnel_surfaces_jump_tunnel_refused",
        jump_refusing_tunnel_surfaces_jump_tunnel_refused_inner(),
    )
    .await;
}

async fn jump_refusing_tunnel_surfaces_jump_tunnel_refused_inner() {
    let (jump_port, jump_srv) = spawn_accept_loop_server(|| JumpHandler {
        expected: JUMP_PASSWORD.into(),
        forwarding: false,
    })
    .await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_JUMP_PW_2", JUMP_PASSWORD) };

    let jump = Connection::connect(params(
        "dev-jump",
        jump_port,
        "TRANSIT_TEST_JUMP_PW_2",
        &host_keys,
        None,
    ))
    .await
    .expect("jump connects directly");
    let jump = Arc::new(jump);

    let err = match Connection::connect(params(
        "dev-target",
        9,
        "TRANSIT_TEST_JUMP_PW_2",
        &host_keys,
        Some(jump),
    ))
    .await
    {
        Ok(_) => panic!("tunnel to a refusing jump must fail"),
        Err(e) => e,
    };
    match err {
        SshError::JumpTunnelRefused {
            jump_host,
            jump_port: jp,
            target_host,
            target_port,
            ..
        } => {
            assert_eq!(jump_host, "127.0.0.1");
            assert_eq!(jp, jump_port);
            assert_eq!(target_host, "127.0.0.1");
            assert_eq!(target_port, 9);
        }
        other => panic!("expected JumpTunnelRefused, got {other:?}"),
    }
    jump_srv.abort();
}

/// A failed attempt through the jump must not poison it: the next
/// attempt gets a FRESH `direct-tcpip` channel and succeeds. This is
/// the transport property the app-side weak-crypto retry ladder relies
/// on when its strict attempt dies mid-handshake.
// 4 workers, not the KBI harness's 2: this file runs an outer (jump)
// server accept loop + session, a spawned copy_bidirectional forwarder,
// an inner (target) server accept loop + session, and the client
// Connection actor — roughly seven interdependent tasks with
// three-party round-trips, against KBI's one server and two parties.
// A macos-latest runner has 3 cores, and cargo runs these three tests
// concurrently. Do not "align" this back to 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_attempt_then_retry_gets_a_fresh_tunnel() {
    with_deadline(
        "failed_attempt_then_retry_gets_a_fresh_tunnel",
        failed_attempt_then_retry_gets_a_fresh_tunnel_inner(),
    )
    .await;
}

async fn failed_attempt_then_retry_gets_a_fresh_tunnel_inner() {
    let (target_port, target_srv) = spawn_accept_loop_server(|| PasswordHandler {
        expected: TARGET_PASSWORD.into(),
    })
    .await;
    let (jump_port, jump_srv) = spawn_accept_loop_server(|| JumpHandler {
        expected: JUMP_PASSWORD.into(),
        forwarding: true,
    })
    .await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // SAFETY: unique var names, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_JUMP_PW_3", JUMP_PASSWORD) };
    unsafe { std::env::set_var("TRANSIT_TEST_TARGET_PW_3", TARGET_PASSWORD) };
    unsafe { std::env::set_var("TRANSIT_TEST_WRONG_PW_3", "not-the-password") };

    let jump = Connection::connect(params(
        "dev-jump",
        jump_port,
        "TRANSIT_TEST_JUMP_PW_3",
        &host_keys,
        None,
    ))
    .await
    .expect("jump connects directly");
    let jump = Arc::new(jump);

    // (`Connection` isn't Debug, so match the error arm only.)
    match Connection::connect(params(
        "dev-target",
        target_port,
        "TRANSIT_TEST_WRONG_PW_3",
        &host_keys,
        Some(Arc::clone(&jump)),
    ))
    .await
    {
        Ok(_) => panic!("wrong password must fail through the tunnel"),
        Err(SshError::AuthFailed { .. }) => {}
        Err(other) => panic!("expected AuthFailed through the tunnel, got {other:?}"),
    }

    Connection::connect(params(
        "dev-target",
        target_port,
        "TRANSIT_TEST_TARGET_PW_3",
        &host_keys,
        Some(Arc::clone(&jump)),
    ))
    .await
    .expect("retry over a fresh tunnel channel succeeds");

    jump_srv.abort();
    target_srv.abort();
}
