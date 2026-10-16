//! End-to-end integration tests against a real OpenSSH server in
//! Docker. Gated behind `--features docker-tests` so local dev
//! doesn't require Docker; CI's Linux runner flips it on.
//!
//! Bring-up: a `compose.yml` fixture starts
//! `linuxserver/openssh-server` on `127.0.0.1:2222` with a known
//! username + password. Each test grabs the compose lifecycle via
//! the `Fixture` RAII guard. Tests run sequentially (cargo defaults
//! to per-test threads but the docker container is a shared
//! resource — `--test-threads=1` is set in CI).
//!
//! macOS / Windows runners skip these via the cfg gate; Linux CI
//! has Docker available out of the box.

#![cfg(feature = "docker-tests")]
// `std::env::set_var` is `unsafe` in Rust 2024+. The test file is
// single-threaded by construction (the docker fixture is a shared
// resource; CI runs `--test-threads=1`), so the API soundness
// requirement is met.
#![allow(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;
use transit_ssh::{
    ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, KbiPromptRequest, Session,
    SshError,
};

/// Inventory id the fixtures connect as. Pins are scoped per device
/// (v6.5.7), so the store is addressed by this, not by TEST_HOST.
const TEST_DEVICE: &str = "dev-docker";
const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 2222;
const TEST_USER: &str = "testuser";
const TEST_PASSWORD_VAR: &str = "TRANSIT_TEST_OPENSSH_PASSWORD";
const TEST_PASSWORD: &str = "transit-test-password-123";

/// RAII docker-compose lifecycle. The first construction runs
/// `docker compose up -d` and waits for the health check; drop runs
/// `docker compose down`. Tests share one fixture across all cases
/// via a static OnceCell so the slow image-pull happens once.
struct Fixture;

impl Fixture {
    async fn start() -> Self {
        let compose = compose_path();
        let status = Command::new("docker")
            .args(["compose", "-f"])
            .arg(&compose)
            .args(["up", "-d", "--wait"])
            .status()
            .await
            .expect("docker compose up failed to spawn");
        assert!(status.success(), "docker compose up returned {status}");
        Self
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // `docker compose down` is sync-fire-and-forget; we don't
        // block test exit on it. CI tears down the runner anyway.
        let compose = compose_path();
        let _ = std::process::Command::new("docker")
            .args(["compose", "-f"])
            .arg(&compose)
            .args(["down", "-v"])
            .status();
    }
}

fn compose_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("openssh")
        .join("compose.yml")
}

/// Throwaway `HostKeyStore` rooted at a tempdir; each test gets its
/// own so first-seen + mismatch flows are independent.
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

/// These tests all authenticate with a STORED credential, so the
/// interactive (v6.1.0 `SecretRef::Prompt`) path is never entered. A live
/// sender with a dropped receiver is the honest stand-in: if a refactor
/// ever routed stored auth through the interactive driver, the send would
/// fail loudly instead of the test quietly changing meaning.
fn unused_kbi_channel() -> mpsc::Sender<KbiPromptRequest> {
    let (tx, _rx) = mpsc::channel::<KbiPromptRequest>(1);
    tx
}

fn registry() -> Arc<SecretRegistry> {
    Arc::new(SecretRegistry::standard())
}

fn password_secret_ref() -> SecretRef {
    // SAFETY: single-threaded test setup; we own the env var.
    unsafe { std::env::set_var(TEST_PASSWORD_VAR, TEST_PASSWORD) };
    SecretRef::Env {
        var: TEST_PASSWORD_VAR.into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_with_password_succeeds_and_runs_remote_command() {
    let _fx = Fixture::start().await;

    let (host_keys, _tmp) = fresh_known_hosts().await;
    let confirm_tx = auto_trust_channel();

    let connection = timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: TEST_DEVICE.into(),
            host: TEST_HOST.into(),
            port: TEST_PORT,
            username: TEST_USER.into(),
            secret_ref: password_secret_ref(),
            auth: registry(),
            host_keys: Arc::clone(&host_keys),
            confirm_tx,
            kbi_tx: unused_kbi_channel(),
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    // OpenSSH-on-Linux harness is vendor-agnostic; `Unknown` skips
    // the paging-init step so the round-trip assertion below sees
    // only the `echo TRANSIT_OK` echo, not vendor init bytes.
    let session = Session::open(
        &connection,
        "xterm-256color",
        80,
        24,
        transit_core::inventory::Vendor::Unknown,
    )
    .await
    .expect("session open failed");

    // Send `echo TRANSIT_OK\r` and wait for the echoed bytes.
    let mut rx = session.subscribe();
    session
        .send_input(Bytes::from_static(b"echo TRANSIT_OK\r"))
        .await
        .expect("send_input failed");

    let mut acc = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Ok(b)) => {
                acc.extend_from_slice(&b);
                if String::from_utf8_lossy(&acc).contains("TRANSIT_OK") {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }

    let text = String::from_utf8_lossy(&acc);
    assert!(
        text.contains("TRANSIT_OK"),
        "expected `TRANSIT_OK` in PTY output, got: {text:?}"
    );

    session.close().await.expect("session close failed");

    // Known_hosts must now contain the pinned fingerprint.
    let stored = host_keys
        .lookup(TEST_DEVICE, TEST_HOST, TEST_PORT)
        .await
        .expect("lookup failed");
    assert!(
        stored.is_some(),
        "host_keys should have pinned the fingerprint after first-seen-trust"
    );
}

/// Stale pin planted by [`store_with_stale_pin`] to force the
/// changed-key flow on the next connect.
const BOGUS_FP: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Shared setup for the changed-key tests: first connect auto-trusts
/// and pins the server's real fingerprint, then the on-disk entry is
/// rewritten to [`BOGUS_FP`] to simulate a re-keyed device. Returns
/// the reopened store and the real fingerprint for later assertions.
async fn store_with_stale_pin() -> (Arc<HostKeyStore>, tempfile::TempDir, String) {
    let (host_keys, tmp) = fresh_known_hosts().await;
    let confirm_tx = auto_trust_channel();
    Connection::connect(ConnectParams {
        device_id: TEST_DEVICE.into(),
        host: TEST_HOST.into(),
        port: TEST_PORT,
        username: TEST_USER.into(),
        secret_ref: password_secret_ref(),
        auth: registry(),
        host_keys: Arc::clone(&host_keys),
        confirm_tx,
        kbi_tx: unused_kbi_channel(),
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await
    .expect("first connect failed");

    let real_fp = host_keys
        .lookup(TEST_DEVICE, TEST_HOST, TEST_PORT)
        .await
        .expect("lookup pinned fingerprint")
        .expect("first connect should have pinned")
        .fingerprint
        .to_string();

    // Rewrite the on-disk fingerprint to simulate a key change.
    let path = host_keys.path().to_path_buf();
    let original = std::fs::read_to_string(&path).expect("read known_hosts");
    let corrupted = original
        .lines()
        .map(|l| {
            if l.starts_with("fingerprint = ") {
                format!("fingerprint = \"{BOGUS_FP}\"")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, corrupted).expect("write corrupted known_hosts");

    // Reload the store to pick up the corruption.
    let store = Arc::new(HostKeyStore::open(path).await.expect("reopen store"));
    (store, tmp, real_fp)
}

/// Reply channel for the changed-key prompt: asserts every request
/// carries the stale pin as `previous_fingerprint`, then answers
/// with `verdict`.
fn changed_key_channel(verdict: bool) -> mpsc::Sender<HostKeyConfirmRequest> {
    let (tx, mut rx) = mpsc::channel::<HostKeyConfirmRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            assert_eq!(
                req.previous_fingerprint.as_deref(),
                Some(BOGUS_FP),
                "changed-key prompt must carry the pinned fingerprint"
            );
            let _ = req.responder.send(verdict);
        }
    });
    tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_key_change_declined_fails_with_mismatch() {
    let _fx = Fixture::start().await;
    let (host_keys, _tmp, _real_fp) = store_with_stale_pin().await;

    let res = Connection::connect(ConnectParams {
        device_id: TEST_DEVICE.into(),
        host: TEST_HOST.into(),
        port: TEST_PORT,
        username: TEST_USER.into(),
        secret_ref: password_secret_ref(),
        auth: registry(),
        host_keys: Arc::clone(&host_keys),
        confirm_tx: changed_key_channel(false),
        kbi_tx: unused_kbi_channel(),
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await;

    assert!(
        matches!(res, Err(SshError::HostKeyMismatch { .. })),
        "expected HostKeyMismatch, got {}",
        res.as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Ok(_)".into())
    );

    // Declining must leave the (stale) pin untouched.
    let pinned = host_keys
        .lookup(TEST_DEVICE, TEST_HOST, TEST_PORT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pinned.fingerprint.to_string(),
        BOGUS_FP,
        "pin untouched after decline"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_key_change_approved_replaces_pin_after_auth() {
    let _fx = Fixture::start().await;
    let (host_keys, _tmp, real_fp) = store_with_stale_pin().await;

    let connection = Connection::connect(ConnectParams {
        device_id: TEST_DEVICE.into(),
        host: TEST_HOST.into(),
        port: TEST_PORT,
        username: TEST_USER.into(),
        secret_ref: password_secret_ref(),
        auth: registry(),
        host_keys: Arc::clone(&host_keys),
        confirm_tx: changed_key_channel(true),
        kbi_tx: unused_kbi_channel(),
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await
    .expect("approved rotation should connect");
    drop(connection);

    let pinned = host_keys
        .lookup(TEST_DEVICE, TEST_HOST, TEST_PORT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pinned.fingerprint.to_string(),
        real_fp,
        "pin replaced with the server's real fingerprint after auth"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_key_change_approved_but_failed_auth_keeps_stale_pin() {
    let _fx = Fixture::start().await;
    let (host_keys, _tmp, _real_fp) = store_with_stale_pin().await;

    // Wrong password: even an APPROVED replacement must not persist
    // when auth fails — an attacker who can present a key but can't
    // authenticate cannot displace the pin.
    // SAFETY: single-threaded test setup; we own the env var.
    unsafe { std::env::set_var("TRANSIT_TEST_BAD_PASSWORD", "definitely-not-the-password") };
    let res = Connection::connect(ConnectParams {
        device_id: TEST_DEVICE.into(),
        host: TEST_HOST.into(),
        port: TEST_PORT,
        username: TEST_USER.into(),
        secret_ref: SecretRef::Env {
            var: "TRANSIT_TEST_BAD_PASSWORD".into(),
        },
        auth: registry(),
        host_keys: Arc::clone(&host_keys),
        confirm_tx: changed_key_channel(true),
        kbi_tx: unused_kbi_channel(),
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await;

    assert!(
        matches!(res, Err(SshError::AuthFailed { .. })),
        "expected AuthFailed, got {}",
        res.as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Ok(_)".into())
    );

    let pinned = host_keys
        .lookup(TEST_DEVICE, TEST_HOST, TEST_PORT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pinned.fingerprint.to_string(),
        BOGUS_FP,
        "failed auth must not rewrite the pin"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_password() {
    let _fx = Fixture::start().await;

    let (host_keys, _tmp) = fresh_known_hosts().await;
    let confirm_tx = auto_trust_channel();

    // Plant a deliberately-wrong password.
    // SAFETY: single-threaded test setup; we own the env var.
    unsafe { std::env::set_var("TRANSIT_TEST_BAD_PASSWORD", "definitely-not-the-password") };
    let secret_ref = SecretRef::Env {
        var: "TRANSIT_TEST_BAD_PASSWORD".into(),
    };

    let res = Connection::connect(ConnectParams {
        device_id: TEST_DEVICE.into(),
        host: TEST_HOST.into(),
        port: TEST_PORT,
        username: TEST_USER.into(),
        secret_ref,
        auth: registry(),
        host_keys,
        confirm_tx,
        kbi_tx: unused_kbi_channel(),
        timeout: None,
        allow_weak_crypto: false,
        via: None,
        forward_agent: false,
    })
    .await;

    assert!(
        matches!(res, Err(SshError::AuthFailed { .. })),
        "expected AuthFailed, got {}",
        res.as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Ok(_)".into())
    );
}
