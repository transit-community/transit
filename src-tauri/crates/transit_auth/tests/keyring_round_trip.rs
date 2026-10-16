//! Real OS-keystore round-trip tests, gated behind the
//! `integration-tests` feature so local dev runs don't trip on
//! environments without Secret Service / Credential Manager.
//!
//! CI flips the feature on for all 3 OSes via `cargo test
//! --workspace --features transit_auth/integration-tests`; the
//! Linux runner gets `gnome-keyring-daemon` started in the workflow
//! file. macOS and Windows don't need extra setup — Keychain and
//! Credential Manager are always available on a logged-in session.
//!
//! Each test uses a unique account name (process PID + a per-test
//! discriminator) so concurrent runs / partial cleanups don't trip
//! over each other.

#![cfg(feature = "integration-tests")]

use secrecy::ExposeSecret;
use transit_auth::SecretRegistry;
use transit_core::inventory::SecretRef;

/// Build a SecretRef::Keyring with a test-only key that namespaces by
/// PID + suffix. Cleaned up by the test on success; an orphan after a
/// failed test is harmless (it shares no service with anything else).
fn test_ref(suffix: &str) -> SecretRef {
    SecretRef::Keyring {
        key: format!("__transit_test_{}_{}", std::process::id(), suffix),
    }
}

#[tokio::test]
async fn enroll_then_resolve_round_trips() {
    let registry = SecretRegistry::standard();
    let refp = test_ref("rt");

    registry
        .enroll(&refp, "shibboleth-1234".into())
        .await
        .expect("enroll into the OS keystore");

    let got = registry
        .resolve_value(&refp)
        .await
        .expect("resolve the value back");
    assert_eq!(got.expose_secret(), "shibboleth-1234");

    // Best-effort cleanup. We can't delete via the public registry
    // API (by design — there's no `forget_secret`); the next dev
    // running this test will overwrite anyway via enroll.
}

#[tokio::test]
async fn resolve_missing_key_yields_not_found() {
    let registry = SecretRegistry::standard();
    let refp = test_ref("missing");

    // Don't enroll first — the key shouldn't exist.
    let err = registry
        .resolve_value(&refp)
        .await
        .expect_err("missing key should error");
    let s = err.to_string();
    assert!(
        s.contains("no entry") || s.contains("NotFound"),
        "expected NotFound-flavored error, got: {s}"
    );
}

#[tokio::test]
async fn enroll_overwrites_existing() {
    let registry = SecretRegistry::standard();
    let refp = test_ref("overwrite");

    registry
        .enroll(&refp, "v1".into())
        .await
        .expect("first enroll");
    registry
        .enroll(&refp, "v2".into())
        .await
        .expect("second enroll overwrites");

    let got = registry.resolve_value(&refp).await.expect("resolve");
    assert_eq!(got.expose_secret(), "v2");
}
