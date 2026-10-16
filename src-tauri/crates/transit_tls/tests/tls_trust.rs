//! Strict-TLS trust-anchor behavior against a local TLS server that
//! presents an untrusted (self-signed) certificate — the deterministic,
//! hermetic half of threat-model T27 (`T_TLS_INSPECTION`) verification.
//!
//! What this PROVES (in CI, no network, no keychain mutation): both trust
//! modes still fully VALIDATE the chain — neither the OS-store default
//! (Strict OFF) nor webpki-only (Strict ON) accepts an untrusted
//! certificate, so a request never reaches the server.
//!
//! What it deliberately does NOT prove (needs a real OS keychain entry):
//! that Strict OFF *accepts* a CA that IS installed in the OS store. That
//! asymmetry is inherent — CI has no inspection CA installed, so every
//! cert here is untrusted in both modes.

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

/// Stand up a TCP+TLS listener on localhost presenting a freshly minted
/// self-signed cert for "localhost". Returns the bound port.
async fn spawn_untrusted_tls_server() -> u16 {
    let key_pair = rcgen::KeyPair::generate().expect("generate keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config with single cert");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind localhost");
    let port = listener.local_addr().expect("local addr").port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });

    port
}

async fn get_error_for(strict: bool, port: u16) -> reqwest::Error {
    let client = transit_tls::build_http_client(strict);
    client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .expect_err("untrusted cert must fail the request")
}

fn assert_is_handshake_failure(err: &reqwest::Error) {
    // A TLS-trust failure surfaces as a connect-phase error with a
    // certificate message somewhere in the source chain — never as an
    // HTTP status (which would mean the handshake SUCCEEDED).
    assert!(err.status().is_none(), "got an HTTP status: {err:?}");
    let chain = format!("{err:?}").to_ascii_lowercase();
    assert!(
        chain.contains("certificate") || chain.contains("unknownissuer") || chain.contains("tls"),
        "expected a TLS/certificate failure, got: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_mode_rejects_untrusted_cert() {
    let port = spawn_untrusted_tls_server().await;
    let err = get_error_for(true, port).await;
    assert_is_handshake_failure(&err);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn os_store_mode_still_rejects_untrusted_cert() {
    // Strict OFF (OS-store / platform-verifier) still VALIDATES: a
    // self-signed cert that isn't in the CI keychain is rejected too.
    // Proves the default is "trust the OS store", never "accept everything".
    let port = spawn_untrusted_tls_server().await;
    let err = get_error_for(false, port).await;
    assert_is_handshake_failure(&err);
}
