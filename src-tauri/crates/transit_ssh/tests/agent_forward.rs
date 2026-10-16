//! SSH agent-forwarding integration tests against an **in-process
//! russh server** (v6.5.0, threat model T53). Three pins:
//!
//! 1. Disabled ⇒ the server's `auth-agent@openssh.com` open is
//!    REJECTED with `administratively prohibited` — the hardening pin
//!    (russh's stock client handler would have ACCEPTED it).
//! 2. Enabled ⇒ the request precedes the shell (sshd only injects
//!    `SSH_AUTH_SOCK` when it does) and one full agent round-trip
//!    transits the pump to a fake local agent.
//! 3. Enabled but the local agent is unreachable ⇒ the open is
//!    rejected with `connect failed`, never accepted-then-EOFed.
//!
//! Tests 2 and 3 mutate the process-wide `SSH_AUTH_SOCK`, so they
//! serialize on a shared lock and are unix-only (on Windows the dial
//! ignores the env var and would find a real named pipe on dev boxes).

// `std::env::set_var` is `unsafe` in Rust 2024+; mutation is
// serialized behind ENV_LOCK below.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use russh::server::{Auth, Handler as ServerHandler};
use tokio::sync::{mpsc, Mutex};
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;
use transit_ssh::{
    ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, KbiPromptRequest,
};

const PASSWORD: &str = "agent-fwd-test-password";

/// Serializes SSH_AUTH_SOCK mutation across tests in this binary —
/// unlike the KBI tests' uniquely-named vars, this name is fixed by
/// the protocol. Unix-only like its two consumers, or Windows clippy
/// (-D warnings) flags it dead.
#[cfg(unix)]
static ENV_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

/// Password server that records the ORDER of channel requests and
/// signals when auth has completed (so the test knows when
/// `channel_open_agent` is protocol-legal).
struct RecordingHandler {
    /// Written by the request hooks on every platform; READ only by the
    /// unix-gated round-trip test (the ordering pin), so Windows clippy
    /// sees a never-read field without the allow.
    #[cfg_attr(not(unix), allow(dead_code))]
    requests: Arc<Mutex<Vec<&'static str>>>,
}

impl ServerHandler for RecordingHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // The server default drop-rejects; a PTY session needs accept.
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        self.requests.lock().await.push("agent");
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.requests.lock().await.push("shell");
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

struct TestServer {
    port: u16,
    /// The server-side handle for opening channels TOWARD the client.
    /// (Tests await `Connection::connect` first, so auth has already
    /// completed by the time anyone opens a channel through this.)
    handle_rx: tokio::sync::oneshot::Receiver<russh::server::Handle>,
    #[cfg_attr(not(unix), allow(dead_code))]
    requests: Arc<Mutex<Vec<&'static str>>>,
    task: tokio::task::JoinHandle<()>,
}

/// Accept ONE connection and expose the running session's handle so
/// the test can drive server-initiated channel opens.
async fn spawn_recording_server() -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (handle_tx, handle_rx) = tokio::sync::oneshot::channel();
    let handler = RecordingHandler {
        requests: Arc::clone(&requests),
    };
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        if let Ok(session) =
            russh::server::run_stream(Arc::new(server_config()), stream, handler).await
        {
            let _ = handle_tx.send(session.handle());
            let _ = session.await;
        }
    });
    TestServer {
        port,
        handle_rx,
        requests,
        task,
    }
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
    port: u16,
    env_var: &str,
    host_keys: &Arc<HostKeyStore>,
    forward_agent: bool,
) -> ConnectParams {
    ConnectParams {
        device_id: "dev-under-test".into(),
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
        via: None,
        forward_agent,
    }
}

/// The hardening pin: with forwarding OFF (the default for every
/// device), a server-initiated agent channel is refused with the
/// policy reason code. A dial failure would read `ConnectFailed`, so
/// the code also proves WHICH branch ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_rejects_unsolicited_agent_channel() {
    let srv = spawn_recording_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_AGENTFWD_PW_1", PASSWORD) };

    let conn = Connection::connect(params(
        srv.port,
        "TRANSIT_TEST_AGENTFWD_PW_1",
        &host_keys,
        false,
    ))
    .await
    .expect("connect succeeds");

    let handle = srv.handle_rx.await.expect("server handle");
    let err = match tokio::time::timeout(Duration::from_secs(10), handle.channel_open_agent()).await
    {
        Ok(Ok(_)) => panic!("agent channel must be rejected while forwarding is disabled"),
        Ok(Err(e)) => e,
        Err(_) => panic!("server never received a channel-open verdict"),
    };
    match err {
        russh::Error::ChannelOpenFailure(reason) => {
            assert_eq!(
                reason,
                russh::ChannelOpenFailure::AdministrativelyProhibited
            );
        }
        other => panic!("expected ChannelOpenFailure, got {other:?}"),
    }

    drop(conn);
    srv.task.abort();
}

/// Full happy path (unix): request ordering + one agent round-trip
/// through the pump to a fake `SSH_AUTH_SOCK` agent.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_pumps_agent_round_trip() {
    let _env = ENV_LOCK.lock().await;

    // Fake agent: a unix socket answering SSH_AGENTC_REQUEST_IDENTITIES
    // ([len=1, type=11]) with an empty IDENTITIES_ANSWER
    // ([len=5, type=12, count=0]).
    let agent_dir = tempfile::tempdir().unwrap();
    let sock_path = agent_dir.path().join("fake-agent.sock");
    let agent_listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let agent_task = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = agent_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut req = [0u8; 5];
                if conn.read_exact(&mut req).await.is_ok() {
                    assert_eq!(req, [0, 0, 0, 1, 11], "expected REQUEST_IDENTITIES");
                    let _ = conn.write_all(&[0, 0, 0, 5, 12, 0, 0, 0, 0]).await;
                    let _ = conn.flush().await;
                }
            });
        }
    });
    // SAFETY: serialized behind ENV_LOCK; restored by the next locker.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &sock_path) };

    let srv = spawn_recording_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_AGENTFWD_PW_2", PASSWORD) };

    let conn = Connection::connect(params(
        srv.port,
        "TRANSIT_TEST_AGENTFWD_PW_2",
        &host_keys,
        true,
    ))
    .await
    .expect("connect succeeds");
    let conn = Arc::new(conn);

    // A real PTY session — this is what sends auth-agent-req.
    let session = transit_ssh::Session::open(
        &conn,
        "xterm-256color",
        80,
        24,
        transit_core::inventory::Vendor::Unknown,
    )
    .await
    .expect("session opens");

    // Ordering pin: the agent request must precede the shell request,
    // or sshd never exports SSH_AUTH_SOCK into the session. The client
    // sends channel requests fire-and-forget, so poll until the server
    // has processed the shell request before asserting order.
    let order_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let reqs = srv.requests.lock().await;
            if reqs.contains(&"shell") {
                let agent_pos = reqs.iter().position(|r| *r == "agent");
                let shell_pos = reqs.iter().position(|r| *r == "shell");
                assert!(
                    matches!((agent_pos, shell_pos), (Some(a), Some(s)) if a < s),
                    "agent request must precede shell request, got {reqs:?}"
                );
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < order_deadline,
            "server never saw the shell request"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Server opens the agent channel and runs one round-trip.
    let handle = srv.handle_rx.await.expect("server handle");
    let channel = tokio::time::timeout(Duration::from_secs(10), handle.channel_open_agent())
        .await
        .expect("verdict within timeout")
        .expect("agent channel accepted while forwarding is enabled");
    channel
        .data(&[0u8, 0, 0, 1, 11][..])
        .await
        .expect("send REQUEST_IDENTITIES");

    let mut answer: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut channel = channel;
    while answer.len() < 9 {
        let msg = tokio::time::timeout_at(deadline, channel.wait())
            .await
            .expect("agent reply within timeout");
        match msg {
            Some(russh::ChannelMsg::Data { data }) => answer.extend_from_slice(&data),
            Some(_) => continue,
            None => panic!("channel closed before the agent reply arrived"),
        }
    }
    assert_eq!(
        answer,
        vec![0, 0, 0, 5, 12, 0, 0, 0, 0],
        "empty IDENTITIES_ANSWER transits the pump back to the server"
    );

    drop(session);
    drop(conn);
    srv.task.abort();
    agent_task.abort();
}

/// Blanket channel posture (adversarial-review finding): EVERY other
/// server-initiated channel type is rejected too — russh's defaults
/// would accept them, handing a hostile server unbounded live channels
/// nothing in Transit services. Pinned via forwarded-tcpip and
/// server-opened session as representatives of the six overrides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsolicited_non_agent_channels_are_rejected() {
    let srv = spawn_recording_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_AGENTFWD_PW_4", PASSWORD) };

    // Forwarding ON — proving these channel types are refused even on a
    // connection that opted into agent forwarding.
    let conn = Connection::connect(params(
        srv.port,
        "TRANSIT_TEST_AGENTFWD_PW_4",
        &host_keys,
        true,
    ))
    .await
    .expect("connect succeeds");

    let handle = srv.handle_rx.await.expect("server handle");

    let fwd = tokio::time::timeout(
        Duration::from_secs(10),
        handle.channel_open_forwarded_tcpip("victim.example", 443, "10.0.0.1", 51000),
    )
    .await
    .expect("verdict within timeout");
    match fwd {
        Ok(_) => panic!("forwarded-tcpip must be rejected — Transit never requests forwards"),
        Err(russh::Error::ChannelOpenFailure(reason)) => {
            assert_eq!(
                reason,
                russh::ChannelOpenFailure::AdministrativelyProhibited
            );
        }
        Err(other) => panic!("expected ChannelOpenFailure, got {other:?}"),
    }

    let sess = tokio::time::timeout(Duration::from_secs(10), handle.channel_open_session())
        .await
        .expect("verdict within timeout");
    match sess {
        Ok(_) => panic!("server-opened session channels must be rejected"),
        Err(russh::Error::ChannelOpenFailure(reason)) => {
            assert_eq!(
                reason,
                russh::ChannelOpenFailure::AdministrativelyProhibited
            );
        }
        Err(other) => panic!("expected ChannelOpenFailure, got {other:?}"),
    }

    drop(conn);
    srv.task.abort();
}

/// Enabled but the agent is gone: the open must be REJECTED (connect
/// failed), never accepted and then EOFed mid-protocol.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_but_agent_unreachable_rejects() {
    let _env = ENV_LOCK.lock().await;
    // SAFETY: serialized behind ENV_LOCK.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", "/nonexistent/transit-test-agent.sock") };

    let srv = spawn_recording_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_AGENTFWD_PW_3", PASSWORD) };

    let conn = Connection::connect(params(
        srv.port,
        "TRANSIT_TEST_AGENTFWD_PW_3",
        &host_keys,
        true,
    ))
    .await
    .expect("connect succeeds");

    let handle = srv.handle_rx.await.expect("server handle");
    let err = match tokio::time::timeout(Duration::from_secs(10), handle.channel_open_agent()).await
    {
        Ok(Ok(_)) => panic!("agent channel must be rejected when the local agent is unreachable"),
        Ok(Err(e)) => e,
        Err(_) => panic!("server never received a channel-open verdict"),
    };
    match err {
        russh::Error::ChannelOpenFailure(reason) => {
            assert_eq!(reason, russh::ChannelOpenFailure::ConnectFailed);
        }
        other => panic!("expected ChannelOpenFailure, got {other:?}"),
    }

    drop(conn);
    srv.task.abort();
}
