//! End-to-end test of the keyboard-interactive auth fallback, against
//! an **in-process russh server** that models VMware ESXi: it refuses
//! the SSH `password` method (pointing the client at
//! `keyboard-interactive`) and accepts the password only through the KBI
//! prompt/response exchange. Proves that `transit_ssh::Connection::connect`
//! — which leads with the `password` method — transparently falls back to
//! KBI and authenticates, the exact failure ESXi 7.x exposed.
//!
//! No Docker: deterministic, cross-platform, runs in every `cargo test`
//! (unlike `dockerized_openssh.rs`, which is gated behind `docker-tests`).

// `std::env::set_var` is `unsafe` in Rust 2024+. Each test sets one
// uniquely-named var at start; the registry reads it in-process.
#![allow(unsafe_code)]

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::server::{Auth, Handler as ServerHandler, Response};
use russh::{MethodKind, MethodSet};
use tokio::sync::mpsc;
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;
use transit_ssh::{
    ConnectParams, Connection, HostKeyConfirmRequest, HostKeyStore, KbiPromptRequest, SshError,
};

const EXPECTED_PASSWORD: &str = "esxi-test-password";

/// A russh server handler that behaves like ESXi's sshd: the SSH
/// `password` method is refused (with a pointer to keyboard-interactive),
/// and the password is accepted only via the KBI prompt/response exchange.
struct EsxiLikeHandler {
    expected_password: String,
}

impl ServerHandler for EsxiLikeHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        // ESXi doesn't implement the `password` method — refuse it and
        // tell the client to proceed with keyboard-interactive.
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: false,
        })
    }

    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        let expected = self.expected_password.clone();
        async move {
            match response {
                // First call: issue a single non-echo "Password:" prompt.
                None => Ok(Auth::Partial {
                    name: Cow::Borrowed(""),
                    instructions: Cow::Borrowed(""),
                    prompts: Cow::Owned(vec![(Cow::Borrowed("Password: "), false)]),
                }),
                // The client's answer: accept iff it equals the password.
                Some(mut resp) => {
                    let answer = resp.next();
                    if answer.as_deref() == Some(expected.as_bytes()) {
                        Ok(Auth::Accept)
                    } else {
                        Ok(Auth::reject())
                    }
                }
            }
        }
    }
}

fn server_config() -> russh::server::Config {
    // Generate a throwaway ed25519 host key per run (mirrors russh's own
    // tests), so no private key is committed to the repo.
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("generate ephemeral test host key");
    russh::server::Config {
        keys: vec![key],
        ..Default::default()
    }
}

/// Bind an ephemeral port, accept one connection, and drive an
/// ESXi-like server on it. Returns the port + the server task handle
/// (abort it at test end).
async fn spawn_esxi_like_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let handler = EsxiLikeHandler {
            expected_password: EXPECTED_PASSWORD.into(),
        };
        if let Ok(session) =
            russh::server::run_stream(Arc::new(server_config()), stream, handler).await
        {
            // Drive the session until the client disconnects.
            let _ = session.await;
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

/// These two tests authenticate with a STORED credential, so the
/// interactive path is never entered. A live sender with a dropped
/// receiver is the honest stand-in: if a refactor ever routed stored
/// auth through the interactive driver, the send would fail and the
/// test would break loudly instead of silently changing meaning.
fn unused_kbi_channel() -> mpsc::Sender<KbiPromptRequest> {
    let (tx, _rx) = mpsc::channel::<KbiPromptRequest>(1);
    tx
}

// ---------------------------------------------------------------------
// The MIRROR case (user report 2026-09-11): a host that offers
// `password` but NOT `keyboard-interactive`, reached with the
// "Ask me each time" (`SecretRef::Prompt`) profile.
// ---------------------------------------------------------------------

const PW_ONLY_PASSWORD: &str = "password-only-test-pw";

/// The exact inverse of [`EsxiLikeHandler`]: `keyboard-interactive` is
/// refused outright (pointing at `password`), and only the `password`
/// method is accepted. This is how a lot of network gear ships — the
/// shape that made "Ask me each time" unusable before the fallback.
struct PasswordOnlyHandler {
    expected_password: String,
}

impl ServerHandler for PasswordOnlyHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        if password == self.expected_password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        // Refuse the METHOD without ever issuing a prompt, naming
        // `password` as what can continue — precisely the
        // `MethodSet([PublicKey, Password])` the user saw.
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(
                &[MethodKind::PublicKey, MethodKind::Password][..],
            )),
            partial_success: false,
        })
    }
}

async fn spawn_password_only_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let handler = PasswordOnlyHandler {
            expected_password: PW_ONLY_PASSWORD.into(),
        };
        if let Ok(session) =
            russh::server::run_stream(Arc::new(server_config()), stream, handler).await
        {
            let _ = session.await;
        }
    });
    (port, task)
}

/// A KBI channel that answers the FIRST prompt with `answer` and records
/// what it was asked, so a test can assert the dialog it would have shown.
fn recording_kbi_channel(
    answer: &'static str,
) -> (
    mpsc::Sender<KbiPromptRequest>,
    Arc<tokio::sync::Mutex<Vec<KbiPromptRequest>>>,
) {
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let seen_for_task = Arc::clone(&seen);
    let (tx, mut rx) = mpsc::channel::<KbiPromptRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let responder = req.responder;
            let n = req.prompts.len();
            // Store everything except the responder for assertions.
            seen_for_task.lock().await.push(KbiPromptRequest {
                host: req.host,
                port: req.port,
                username: req.username,
                name: req.name,
                instruction: req.instruction,
                notice: req.notice,
                prompts: req.prompts,
                responder: tokio::sync::oneshot::channel().0,
            });
            let answers = (0..n)
                .map(|_| secrecy::SecretString::from(answer.to_owned()))
                .collect();
            let _ = responder.send(Some(answers));
        }
    });
    (tx, seen)
}

/// THE headline for this batch: "Ask me each time" against a host that
/// refuses keyboard-interactive now prompts for a password and
/// authenticates, instead of failing immediately with a raw method set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompt_profile_falls_back_to_password_when_kbi_is_refused() {
    let (port, server) = spawn_password_only_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    let (kbi_tx, seen) = recording_kbi_channel(PW_ONLY_PASSWORD);

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "admin".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys: Arc::clone(&host_keys),
            confirm_tx: auto_trust_channel(),
            kbi_tx,
            timeout: Some(Duration::from_secs(15)),
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect must not hang");

    assert!(
        result.is_ok(),
        "password fallback should authenticate, got {:?}",
        result.err()
    );

    // The user saw exactly one masked field, and the copy is Transit's own
    // — the server issued no prompt text here, so the dialog must not
    // imply it did.
    let seen = seen.lock().await;
    assert_eq!(seen.len(), 1, "exactly one prompt round");
    assert_eq!(seen[0].prompts.len(), 1);
    assert!(!seen[0].prompts[0].echo, "a password field must be masked");
    assert!(
        seen[0].notice.contains("keyboard-interactive"),
        "the dialog should say why it is asking: {:?}",
        seen[0].notice
    );
    // And it must land in the TRANSIT-authored channel, never the
    // server-authored one — the dialog renders `instruction` under a
    // "Message from the server" heading (T46.1).
    assert!(
        seen[0].instruction.is_empty() && seen[0].name.is_empty(),
        "Transit's own copy must not occupy the server-authored fields"
    );

    server.abort();
}

/// The guard that keeps the fallback from being a double-prompt: when the
/// server DID ask and the human's answer was wrong, that is a bad
/// credential, not a missing method. Re-prompting would ask the same
/// question twice and burn a second auth attempt against gear whose
/// `MaxAuthTries` budget is small.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_interactive_answer_does_not_trigger_a_second_prompt() {
    let (port, server) = spawn_esxi_like_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    let (kbi_tx, seen) = recording_kbi_channel("the-wrong-password");

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "root".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys: Arc::clone(&host_keys),
            confirm_tx: auto_trust_channel(),
            kbi_tx,
            timeout: Some(Duration::from_secs(15)),
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect must not hang");

    assert!(result.is_err(), "a wrong password must not authenticate");

    // The decisive assertion: the ESXi server DOES offer KBI and did
    // prompt, so the failure is a rejected credential. Exactly one round.
    let seen = seen.lock().await;
    assert_eq!(
        seen.len(),
        1,
        "a rejected credential must not be retried as a password prompt"
    );

    server.abort();
}

/// The headline: a client leading with `password` against a host that
/// only accepts keyboard-interactive still authenticates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyboard_interactive_fallback_succeeds() {
    let (port, server) = spawn_esxi_like_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_KBI_GOOD", EXPECTED_PASSWORD) };

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "root".into(),
            secret_ref: SecretRef::Env {
                var: "TRANSIT_TEST_KBI_GOOD".into(),
            },
            auth: Arc::new(SecretRegistry::standard()),
            host_keys: Arc::clone(&host_keys),
            confirm_tx: auto_trust_channel(),
            kbi_tx: unused_kbi_channel(),
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out");

    // `Connection` isn't Debug, so unwrap by hand.
    let connection = match result {
        Ok(c) => c,
        Err(e) => panic!("expected KBI fallback to authenticate, got: {e}"),
    };

    // Auth succeeded → the first-seen host key must now be pinned.
    let pinned = host_keys
        .lookup("dev-under-test", "127.0.0.1", port)
        .await
        .expect("lookup");
    assert!(pinned.is_some(), "fingerprint should pin after success");

    drop(connection);
    server.abort();
}

/// A wrong password over the same KBI exchange must fail cleanly — the
/// fallback authenticates, it doesn't blindly accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyboard_interactive_wrong_password_fails() {
    let (port, server) = spawn_esxi_like_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // SAFETY: unique var name, set once at the start of this test.
    unsafe { std::env::set_var("TRANSIT_TEST_KBI_BAD", "not-the-password") };

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "root".into(),
            secret_ref: SecretRef::Env {
                var: "TRANSIT_TEST_KBI_BAD".into(),
            },
            auth: Arc::new(SecretRegistry::standard()),
            host_keys,
            confirm_tx: auto_trust_channel(),
            kbi_tx: unused_kbi_channel(),
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out");

    match result {
        Err(SshError::AuthFailed { .. }) => {}
        Ok(_) => panic!("wrong KBI password must not authenticate"),
        Err(other) => panic!("expected AuthFailed, got: {other}"),
    }

    server.abort();
}

// =====================================================================
// Interactive auth (v6.1.0) — a HUMAN answers the prompts.
//
// The distinction under test: the stored-credential driver above replies
// to every prompt with one secret, which is exactly why MFA cannot work.
// These exercise `SecretRef::Prompt`, where each round's real prompts are
// relayed and answered individually.
// =====================================================================

const MFA_PASSWORD: &str = "stage-one-password";
const MFA_OTP: &str = "654321";

/// A server that models an MFA'd host / PAM proxy: round one asks for a
/// password AND a one-time code in a single two-prompt challenge, with
/// mixed echo flags (the OTP field echoes, the password does not).
struct MfaHandler {
    round: usize,
}

impl ServerHandler for MfaHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: false,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => {
                self.round += 1;
                Ok(Auth::Partial {
                    name: Cow::Borrowed("Two-factor authentication"),
                    instructions: Cow::Borrowed("Enter your password, then your token code."),
                    prompts: Cow::Owned(vec![
                        (Cow::Borrowed("Password: "), false),
                        (Cow::Borrowed("Token code: "), true),
                    ]),
                })
            }
            Some(mut resp) => {
                let pw = resp.next().map(|b| b.to_vec());
                let otp = resp.next().map(|b| b.to_vec());
                // Both must be correct AND in the right order — this is
                // what catches a driver that answers positionally wrong
                // or reuses one answer for every prompt.
                if pw.as_deref() == Some(MFA_PASSWORD.as_bytes())
                    && otp.as_deref() == Some(MFA_OTP.as_bytes())
                {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
        }
    }
}

async fn spawn_mfa_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        if let Ok(session) =
            russh::server::run_stream(Arc::new(server_config()), stream, MfaHandler { round: 0 })
                .await
        {
            let _ = session.await;
        }
    });
    (port, task)
}

/// Stand in for the UI: answer each relayed prompt from a canned map
/// keyed on the prompt TEXT, and record what was asked so the test can
/// assert the server's own wording and echo flags survived the trip.
type AskedPrompts = Arc<std::sync::Mutex<Vec<(String, bool)>>>;

fn scripted_kbi_channel(
    answers: Vec<&'static str>,
    asked: AskedPrompts,
) -> mpsc::Sender<KbiPromptRequest> {
    let (tx, mut rx) = mpsc::channel::<KbiPromptRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            {
                let mut g = asked.lock().unwrap();
                for p in &req.prompts {
                    g.push((p.text.clone(), p.echo));
                }
            }
            let reply: Vec<secrecy::SecretString> = answers
                .iter()
                .map(|a| secrecy::SecretString::from(a.to_string()))
                .collect();
            let _ = req.responder.send(Some(reply));
        }
    });
    tx
}

/// The headline for interactive auth: a two-prompt MFA challenge that a
/// single stored password could never satisfy now authenticates, with
/// each answer landing on the prompt it belongs to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_auth_answers_each_prompt_individually() {
    let (port, server) = spawn_mfa_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    let asked: AskedPrompts = Arc::new(std::sync::Mutex::new(Vec::new()));

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "operator".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys: Arc::clone(&host_keys),
            confirm_tx: auto_trust_channel(),
            kbi_tx: scripted_kbi_channel(vec![MFA_PASSWORD, MFA_OTP], Arc::clone(&asked)),
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out");

    let connection = match result {
        Ok(c) => c,
        Err(e) => panic!("expected interactive auth to succeed, got: {e}"),
    };

    // The server's own prompt text and echo flags reached the UI layer
    // intact — masking is driven by the server's flag, not a guess.
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2, "both prompts relayed: {asked:?}");
    assert!(asked[0].0.starts_with("Password:"), "{asked:?}");
    assert!(!asked[0].1, "password prompt must not echo");
    assert!(asked[1].0.starts_with("Token code:"), "{asked:?}");
    assert!(asked[1].1, "token prompt echoes");

    drop(connection);
    server.abort();
}

/// Cancelling the dialog fails the connect cleanly and promptly — it
/// must not hang until the connect deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_auth_cancel_fails_cleanly() {
    let (port, server) = spawn_mfa_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    let (kbi_tx, mut kbi_rx) = mpsc::channel::<KbiPromptRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = kbi_rx.recv().await {
            // The user dismissed the dialog.
            let _ = req.responder.send(None);
        }
    });

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "operator".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys,
            confirm_tx: auto_trust_channel(),
            kbi_tx,
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("cancel must not hang the connect");

    match result {
        Err(SshError::AuthFailed { detail, .. }) => {
            assert!(
                detail.contains("cancelled"),
                "detail names the cause: {detail}"
            );
        }
        Ok(_) => panic!("a cancelled prompt must not authenticate"),
        Err(other) => panic!("expected AuthFailed, got: {other}"),
    }

    server.abort();
}

/// A dropped responder (dialog window closed, app teardown) is the same
/// clean failure as an explicit cancel — never a hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_auth_dropped_responder_fails_cleanly() {
    let (port, server) = spawn_mfa_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;

    let (kbi_tx, mut kbi_rx) = mpsc::channel::<KbiPromptRequest>(4);
    tokio::spawn(async move {
        while let Some(req) = kbi_rx.recv().await {
            drop(req.responder);
        }
    });

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "operator".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys,
            confirm_tx: auto_trust_channel(),
            kbi_tx,
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("a dropped responder must not hang the connect");

    assert!(
        matches!(result, Err(SshError::AuthFailed { .. })),
        "dropped responder is a clean auth failure"
    );

    server.abort();
}

/// The wrong NUMBER of answers must be refused, not sent. russh maps
/// answers to prompts positionally, so a short/long vec would silently
/// answer the wrong prompt — e.g. send the password where the server
/// asked for the OTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_auth_refuses_answer_count_mismatch() {
    let (port, server) = spawn_mfa_server().await;
    let (host_keys, _tmp) = fresh_known_hosts().await;
    let asked: AskedPrompts = Arc::new(std::sync::Mutex::new(Vec::new()));

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "operator".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys,
            confirm_tx: auto_trust_channel(),
            // Server asks two; UI returns one.
            kbi_tx: scripted_kbi_channel(vec![MFA_PASSWORD], asked),
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out");

    match result {
        Err(SshError::AuthFailed { detail, .. }) => {
            assert!(
                detail.contains("expected 2 answer"),
                "detail names the mismatch: {detail}"
            );
        }
        Ok(_) => panic!("an answer-count mismatch must not authenticate"),
        Err(other) => panic!("expected AuthFailed, got: {other}"),
    }

    server.abort();
}

/// A server that asks for an absurd number of fields in one round. Real
/// challenges use one to three; relaying hundreds would render hundreds
/// of inputs in a modal the user cannot dismiss without answering.
struct PromptFloodHandler;

impl ServerHandler for PromptFloodHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: false,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(
                (0..64)
                    .map(|i| (Cow::Owned(format!("Field {i}: ")), false))
                    .collect(),
            ),
        })
    }
}

/// The flood is refused at the transport boundary — it never reaches a
/// responder, so the UI is never asked to render it (T46.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactive_auth_refuses_a_prompt_flood() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        if let Ok(session) =
            russh::server::run_stream(Arc::new(server_config()), stream, PromptFloodHandler).await
        {
            let _ = session.await;
        }
    });
    let (host_keys, _tmp) = fresh_known_hosts().await;

    // If anything DID reach the UI channel this would answer it; the
    // point of the test is that nothing does.
    let (kbi_tx, mut kbi_rx) = mpsc::channel::<KbiPromptRequest>(4);
    let relayed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let relayed_probe = Arc::clone(&relayed);
    tokio::spawn(async move {
        while let Some(req) = kbi_rx.recv().await {
            relayed_probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = req.responder.send(None);
        }
    });

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Connection::connect(ConnectParams {
            device_id: "dev-under-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "operator".into(),
            secret_ref: SecretRef::Prompt,
            auth: Arc::new(SecretRegistry::standard()),
            host_keys,
            confirm_tx: auto_trust_channel(),
            kbi_tx,
            timeout: None,
            allow_weak_crypto: false,
            via: None,
            forward_agent: false,
        }),
    )
    .await
    .expect("connect timed out");

    match result {
        Err(SshError::AuthFailed { detail, .. }) => {
            assert!(
                detail.contains("fields in one interactive round"),
                "{detail}"
            );
        }
        Ok(_) => panic!("a prompt flood must not authenticate"),
        Err(other) => panic!("expected AuthFailed, got: {other}"),
    }
    assert_eq!(
        relayed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the flood must be refused BEFORE it reaches the UI"
    );

    server.abort();
}
