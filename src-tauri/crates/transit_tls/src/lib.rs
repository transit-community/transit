//! Centralized TLS trust configuration for every outbound HTTPS client
//! Transit builds — the direct AI-provider clients (Anthropic / OpenAI),
//! the BYOM self-hosted endpoint clients, and the API-controller REST
//! transport.
//!
//! **Security-load-bearing.** The trust-anchor choice is made in exactly
//! one place so it cannot drift per-crate. A regression here could
//! silently relax verification for the request that carries the user's
//! provider key.
//!
//! The control is the `[network] strict_tls` setting (resolved by the
//! Tauri shell and threaded in as `strict`):
//!
//! - **`strict = false` (default)** — trust the OS/platform certificate
//!   store via [`rustls_platform_verifier`]. The OS store holds the
//!   public web-PKI roots *and* any privately-installed CA (a corporate
//!   TLS-inspection cert pushed into the macOS keychain / Windows store),
//!   so connections on an inspected enterprise network validate and work.
//! - **`strict = true`** — trust *only* the bundled [`webpki_roots`]
//!   (Mozilla public set); the OS store is ignored. A privately-installed
//!   inspection root isn't in that set, so the provider connection is
//!   rejected — the user has deliberately refused MITM'd traffic.
//!
//! This is a swap of the *trust-anchor source*, never a relaxation of
//! verification: both paths fully validate the presented chain. There is
//! no `danger_accept_invalid_certs` path here or anywhere. See
//! `docs/security/threat-model.md` T27 (`T_TLS_INSPECTION`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::{BuilderVerifierExt, Verifier as PlatformVerifier};
use sha2::{Digest, Sha256};

/// TCP/TLS connection-setup budget for every request (bounds the
/// handshake, not the body). Lives here so every client built shares it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the reqwest client used for direct AI-provider traffic.
///
/// `strict` selects the trust-anchor source (see the module docs). The
/// builder is otherwise fixed: a versioned user-agent, a 10 s connect
/// timeout, `redirect::none()` and no proxy. The last two are security
/// properties: the request carries the user's provider key in a header,
/// and a 3xx (or an ambient `HTTP_PROXY`) must never re-route it to a
/// host the user did not configure. Neither provider redirects API routes.
pub fn build_http_client(strict: bool) -> Client {
    let tls = if strict {
        strict_webpki_config()
    } else {
        os_store_config()
    };

    Client::builder()
        .user_agent(concat!("transit-community/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        // Never follow redirects: the request carries the provider key;
        // a 307/308 would re-send it to the redirect target.
        .redirect(reqwest::redirect::Policy::none())
        // Never honor an ambient HTTP(S)_PROXY: a proxy is an egress
        // channel for the key (threat-model T35 reasoning, applied to
        // provider traffic).
        .no_proxy()
        // Override reqwest's default (bundled-webpki) roots with our
        // explicitly-chosen trust anchors.
        .use_preconfigured_tls(tls)
        .build()
        .expect("reqwest client with preconfigured rustls must build")
}

/// An explicit aws-lc-rs crypto provider, matching reqwest's own rustls
/// backend. Passed via `builder_with_provider` (rather than relying on
/// the process-default) so building a `ClientConfig` never depends on a
/// `CryptoProvider::install_default` having run first — this crate
/// installs no global provider.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// `strict = false`: delegate chain verification to the OS/platform
/// store (public roots **plus** any privately-installed CA).
fn os_store_config() -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_platform_verifier()
        .expect("platform certificate verifier is available")
        .with_no_client_auth()
}

/// OS-store trust config for the BYOM local/self-hosted endpoint
/// clients in `transit_agent` (`llm/transport.rs`). Same posture as
/// `strict = false` — full chain verification delegated to the platform
/// store — so an enterprise's internal CA on a self-hosted vLLM/Ollama
/// endpoint validates. Exists so TLS trust selection stays centralized
/// in this one module instead of being duplicated per-crate. Never a
/// verification relaxation.
pub fn os_store_tls_config() -> ClientConfig {
    os_store_config()
}

/// `strict = true`: trust ONLY the bundled Mozilla web-PKI roots. A
/// privately-installed inspection CA is absent here, so an inspected
/// connection fails the handshake — the intended refusal.
fn strict_webpki_config() -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Walk a reqwest *send* failure's error chain looking for a rustls
/// certificate-validation failure (`rustls::Error::InvalidCertificate`,
/// raised by either the webpki or the platform verifier). Callers map a
/// `true` to an actionable "TLS certificate not trusted" error so the
/// "behind a TLS-inspection proxy" case is recoverable in the UI (Settings
/// → Network → Strict TLS), not an opaque transport error. See T27.
///
/// reqwest / hyper wrap the rustls error several layers deep, and
/// crucially it sits *inside* one or more `std::io::Error`s — which do
/// NOT forward `source()` to their inner error. So at each node we both
/// follow `source()` and, for an `io::Error`, descend the `get_ref()`
/// chain. Structural (downcast), not Display-string matching, so it
/// survives dependency upgrades.
pub fn is_tls_trust_error(err: &reqwest::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if is_rustls_cert_error(e) {
            return true;
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            let mut inner = io.get_ref();
            while let Some(i) = inner {
                if is_rustls_cert_error_ss(i) {
                    return true;
                }
                inner = i
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::get_ref);
            }
        }
        current = e.source();
    }
    false
}

fn is_rustls_cert_error(e: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        e.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::InvalidCertificate(_))
    )
}

/// Same check for the `Send + Sync` trait object that
/// `std::io::Error::get_ref` yields — written separately so we don't
/// depend on trait upcasting.
fn is_rustls_cert_error_ss(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    matches!(
        e.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::InvalidCertificate(_))
    )
}

// ---------------------------------------------------------------------------
// Self-signed API-controller cert pinning (threat-model T40, T_API_SELF_SIGNED)
//
// On-prem controllers (Cisco ACI/APIC, Catalyst SD-WAN vManage, FortiManager/
// Analyzer, Juniper Apstra) present a SELF-SIGNED management cert by default,
// so the strict OS-trust path above rejects them and the request never leaves
// the machine. Instead of a blanket `danger_accept_invalid_certs` (never used
// here — §9), the user does the SSH-known-hosts dance: Transit shows the leaf
// cert's SHA-256, the user VERIFIES + accepts it, and the fingerprint is pinned
// per-controller. `PinAwareVerifier` then trusts that host IFF it presents
// exactly that leaf again.
//
// Security shape (the whole point):
//   * The OS/platform store is consulted FIRST and unchanged — a publicly- or
//     enterprise-CA-trusted controller validates normally, no pin involved.
//   * A pin is a FALLBACK consulted ONLY after the chain is REJECTED, and it
//     accepts ONLY an exact leaf SHA-256 match for that exact host.
//   * An unpinned untrusted cert, or a pinned host presenting a DIFFERENT
//     cert, is NEVER accepted — the real chain error is re-raised. A changed
//     fingerprint hard-fails (re-surfacing the warning), exactly like an SSH
//     host-key change.
// ---------------------------------------------------------------------------

/// host (lowercased, no port) → pinned leaf-cert SHA-256. Shared with the
/// `transit_api` controller client, which inserts a controller's pin before a
/// send so the handshake verifier can find it.
pub type PinStore = Arc<RwLock<HashMap<String, [u8; 32]>>>;

/// host (lowercased) → SHA-256 of the most recent cert this client REJECTED
/// for that host (chain-untrusted AND not pinned). The untrusted-cert dialog
/// reads it to show the fingerprint the user must verify before pinning.
/// Recording the fingerprint of a cert we did NOT trust grants nothing.
pub type LastRejectedStore = Arc<RwLock<HashMap<String, [u8; 32]>>>;

/// SHA-256 over a leaf cert's DER bytes — the fingerprint shown to the user
/// and stored as the pin. Stable for a given cert, distinct across certs.
pub fn cert_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    let digest = Sha256::digest(cert.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lowercase host key for the pin map: DNS name verbatim, IP as its canonical
/// string. `None` for other `ServerName` variants → treated as "no pin", i.e.
/// re-raise the chain error (fail closed).
fn server_name_host(name: &ServerName<'_>) -> Option<String> {
    match name {
        ServerName::DnsName(d) => Some(d.as_ref().to_ascii_lowercase()),
        ServerName::IpAddress(ip) => Some(std::net::IpAddr::from(*ip).to_string()),
        _ => None,
    }
}

/// Whether the user has pinned `host` to exactly `leaf_sha256`. Factored out so
/// the security-critical predicate is unit-testable without a live handshake.
/// Consulted ONLY after the platform store has already REJECTED the chain; a
/// `false` result means the chain error stands (no unpinned/mismatched cert is
/// ever accepted). An unnameable host (`None`) is never a match (fail closed).
fn is_pinned_match(
    host: Option<&str>,
    leaf_sha256: [u8; 32],
    pins: &HashMap<String, [u8; 32]>,
) -> bool {
    matches!(host.and_then(|h| pins.get(h)), Some(pin) if *pin == leaf_sha256)
}

/// A [`ServerCertVerifier`] that delegates the full chain check to the OS/
/// platform store and, ONLY on rejection, falls back to a user-pinned leaf
/// SHA-256 (see the module comment above). Signature verification is always
/// the platform verifier's — pinning changes trust anchoring, never the
/// handshake crypto.
#[derive(Debug)]
struct PinAwareVerifier {
    inner: PlatformVerifier,
    pins: PinStore,
    /// Where a rejected leaf's fingerprint is recorded (per host) so the UI can
    /// offer TOFU trust. Written only on the reject path; never consulted for
    /// trust decisions.
    rejected: LastRejectedStore,
}

impl ServerCertVerifier for PinAwareVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(chain_err) => {
                let host = server_name_host(server_name);
                let leaf = cert_sha256(end_entity);
                let matched = {
                    let pins = self
                        .pins
                        .read()
                        .map_err(|_| rustls::Error::General("cert pin store poisoned".into()))?;
                    is_pinned_match(host.as_deref(), leaf, &pins)
                };
                if matched {
                    return Ok(ServerCertVerified::assertion());
                }
                // Rejected. Record the leaf fingerprint (per host) so the
                // untrusted-cert dialog can surface it for out-of-band
                // verification, then re-raise the real chain error — nothing
                // untrusted is accepted here.
                if let Some(h) = host {
                    if let Ok(mut rej) = self.rejected.write() {
                        rej.insert(h, leaf);
                    }
                }
                Err(chain_err)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// OS-store trust config that ADDITIONALLY honors user-pinned self-signed
/// controller certs from `pins` (see [`PinAwareVerifier`]). Identical public-
/// and enterprise-CA behavior to [`os_store_tls_config`]; the pins are a
/// per-host fallback the user explicitly established after verifying a
/// fingerprint. Used by the `transit_api` controller client only; provider
/// traffic stays on [`build_http_client`] (no pins).
pub fn pinned_os_store_tls_config(pins: PinStore, rejected: LastRejectedStore) -> ClientConfig {
    let inner = PlatformVerifier::new(crypto_provider())
        .expect("platform certificate verifier is available");
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        // `dangerous()` is rustls's name for "install a custom verifier"; this
        // is NOT `danger_accept_invalid_certs`. The verifier fully validates
        // via the platform store and only ADDS an exact-pin fallback.
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinAwareVerifier {
            inner,
            pins,
            rejected,
        }))
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the highest-risk regression: a crypto-provider mismatch or
    /// a bad `builder_with_provider` chain would panic inside
    /// `build_http_client`. Both trust modes must construct cleanly.
    #[test]
    fn both_trust_modes_build() {
        let _strict = build_http_client(true);
        let _os = build_http_client(false);
    }

    /// The Strict-ON anchor set must be the bundled public roots and
    /// non-empty — an empty set would reject every connection, masking a
    /// broken `webpki-roots` dependency as "strict working".
    #[test]
    fn webpki_root_set_is_nonempty() {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        assert!(!roots.is_empty(), "bundled webpki root set is empty");
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn cert_sha256_is_stable_and_distinct() {
        let a = CertificateDer::from(vec![1u8, 2, 3, 4]);
        let b = CertificateDer::from(vec![1u8, 2, 3, 5]);
        assert_eq!(
            cert_sha256(&a),
            cert_sha256(&a),
            "same DER → same fingerprint"
        );
        assert_ne!(
            cert_sha256(&a),
            cert_sha256(&b),
            "different DER → different"
        );
    }

    /// The security-critical branch: the pin fallback accepts ONLY an exact
    /// host + exact fingerprint, and re-raises the real chain error otherwise.
    #[test]
    fn is_pinned_match_only_true_for_exact_host_and_fingerprint() {
        let leaf = [7u8; 32];
        let mut pins: HashMap<String, [u8; 32]> = HashMap::new();

        // No pin for the host → not a match (an unpinned untrusted cert is refused).
        assert!(!is_pinned_match(Some("apic.lab"), leaf, &pins));

        // Pinned to a DIFFERENT fingerprint → not a match (a changed cert hard-fails).
        pins.insert("apic.lab".into(), [9u8; 32]);
        assert!(!is_pinned_match(Some("apic.lab"), leaf, &pins));

        // Unnameable host (None) → not a match even though a pin exists.
        assert!(!is_pinned_match(None, leaf, &pins));

        // Exact host + exact fingerprint → match.
        pins.insert("apic.lab".into(), leaf);
        assert!(is_pinned_match(Some("apic.lab"), leaf, &pins));

        // A pin for a DIFFERENT host never leaks to this one.
        assert!(!is_pinned_match(Some("other.lab"), leaf, &pins));
    }

    #[test]
    fn pinned_tls_config_builds() {
        let pins: PinStore = Arc::new(RwLock::new(HashMap::new()));
        let rejected: LastRejectedStore = Arc::new(RwLock::new(HashMap::new()));
        let _cfg = pinned_os_store_tls_config(pins, rejected);
    }

    /// End-to-end verifier coverage (v4.3.0 adversarial review): drive the real
    /// `verify_server_cert` trait method — not just the pure predicate — through
    /// a self-signed leaf the platform store rejects, exercising the accept-via-
    /// pin, reject-and-record, and cross-host paths.
    #[test]
    fn verify_server_cert_accepts_only_the_pinned_self_signed_leaf() {
        use rustls::pki_types::{ServerName, UnixTime};
        use std::time::Duration;

        let ck = rcgen::generate_simple_self_signed(vec!["apic.lab".to_string()]).unwrap();
        let der: CertificateDer<'static> = ck.cert.der().clone();
        let fp = cert_sha256(&der);
        let name = ServerName::try_from("apic.lab").unwrap();
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000));
        let mk = |pins: HashMap<String, [u8; 32]>| PinAwareVerifier {
            inner: PlatformVerifier::new(crypto_provider()).expect("platform verifier"),
            pins: Arc::new(RwLock::new(pins)),
            rejected: Arc::new(RwLock::new(HashMap::new())),
        };

        // No pin → rejected (platform store rejects a self-signed leaf), and the
        // fingerprint is recorded for the untrusted-cert dialog.
        let v = mk(HashMap::new());
        assert!(v.verify_server_cert(&der, &[], &name, &[], now).is_err());
        assert_eq!(
            v.rejected.read().unwrap().get("apic.lab").copied(),
            Some(fp)
        );

        // Exact pin for the exact host → accepted.
        let v = mk(HashMap::from([("apic.lab".to_string(), fp)]));
        assert!(v.verify_server_cert(&der, &[], &name, &[], now).is_ok());

        // Wrong fingerprint → rejected.
        let v = mk(HashMap::from([("apic.lab".to_string(), [0u8; 32])]));
        assert!(v.verify_server_cert(&der, &[], &name, &[], now).is_err());

        // Right fingerprint, WRONG host → rejected (no cross-host reuse).
        let v = mk(HashMap::from([("other.lab".to_string(), fp)]));
        assert!(v.verify_server_cert(&der, &[], &name, &[], now).is_err());
    }
}
