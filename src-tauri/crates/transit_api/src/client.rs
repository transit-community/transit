//! The hardened HTTP client for API-session traffic.
//!
//! Built exactly like every other Transit HTTP client (cloud +
//! BYOM-local): a versioned user-agent, the centralized OS-trust TLS
//! config (`transit_tls`), **never** honoring `HTTP_PROXY`
//! (`no_proxy`) and **never** following redirects
//! (`redirect::Policy::none()` — a rogue 3xx must not re-ship the
//! injected key or the response elsewhere).
//!
//! The client is pure transport: callers hand it an ALREADY-CONFINED
//! URL ([`Endpoint::confine`](crate::Endpoint::confine) or the
//! [`gate`](crate::gate) produced it), so host-pinning has already
//! happened. The client's added responsibilities are (1) injecting the
//! `X-API-KEY` header from the resolved secret while stripping any
//! caller-supplied auth header, and (2) bounding the response — a hard
//! byte cap plus a total-time deadline — so a malicious or slow
//! controller cannot exhaust memory or hang the app.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use url::Url;

use crate::auth::AppliedAuth;
use crate::endpoint::Endpoint;
use crate::error::ApiError;

/// TCP/TLS connection-setup budget. Bounds the handshake, not the body.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request budget (connect + send + body read). Bounds a slow /
/// trickling controller from hanging the caller. Applied via an explicit
/// `tokio::time::timeout` around the whole fetch — a client-level
/// `.timeout()` does not reliably bound a manually-drained body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on the response body we buffer, so an oversized / malicious
/// controller response cannot exhaust memory. The agent path caps its
/// *view* further downstream (`cap_head_tail`); this caps the *buffer*.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Response-header caps for the human Postman view. A pathological
/// controller cannot bloat the IPC payload / UI: at most this many
/// (name, value) pairs, each value truncated to [`MAX_HEADER_VALUE_LEN`].
const MAX_RESPONSE_HEADERS: usize = 100;
const MAX_HEADER_VALUE_LEN: usize = 4 * 1024;

/// Hardened reqwest client for API-session requests. Clone-cheap
/// (reqwest `Client` is internally reference-counted and pools
/// connections); one per process is plenty.
#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    /// host → a user-pinned self-signed leaf SHA-256, consulted by the TLS
    /// verifier (`transit_tls::PinAwareVerifier`). A controller's
    /// stored pin is inserted (via [`trust_pin`](Self::trust_pin)) before a
    /// send to that host, so an on-prem self-signed controller the user
    /// verified connects while an unpinned one still hard-fails.
    pins: transit_tls::PinStore,
    /// host → SHA-256 of the last cert we REJECTED for it (untrusted + not
    /// pinned). Read by the untrusted-cert dialog to show the fingerprint the
    /// user must verify before pinning. Never a trust input.
    rejected: transit_tls::LastRejectedStore,
}

/// A completed API response, decoded for the caller.
///
/// `body` is the response text (JSON, usually), read with a hard byte
/// cap ([`MAX_BODY_BYTES`]); `truncated` is true if the cap was hit. The
/// AGENT path redacts `body` before it reaches the LLM; the HUMAN path
/// renders it verbatim (their own device's data).
///
/// `headers` is the response header set (name, value) in wire order, for
/// the HUMAN Postman view only — capped at [`MAX_RESPONSE_HEADERS`] pairs
/// and per-value length. The agent's tool output is built from `body`
/// alone, so headers never cross the redaction boundary to the LLM
/// (a `Set-Cookie` session token stays out of the model's context).
///
/// `Debug` is hand-written to print only the *length* of `body` and the
/// header *count*, never their content — both are raw device output,
/// which §10 forbids logging.
#[derive(Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
    pub truncated: bool,
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for ApiResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("truncated", &self.truncated)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// The fixed cloud host of the Site Manager / connector-proxy surfaces. The
/// operator never types it, so a connect failure there is never a port
/// mistake — it must not attract the 8443 hint.
const CLOUD_HOST: &str = "api.ui.com";

/// How a connect attempt failed at the socket level. Only these two shapes
/// earn an actionable hint; everything else (TLS rejection, DNS, protocol)
/// keeps its own error, which already says what went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectFailure {
    /// The peer actively refused (RST) — nothing bound to that port.
    Refused,
    /// No answer at all — a filtered/dropped port.
    TimedOut,
    /// Anything else. Never hinted.
    Other,
}

/// Walk an error's `source` chain to the `std::io::Error` underneath (reqwest →
/// hyper → io) and classify it. Split from [`socket_failure`] so it is testable
/// without a `reqwest::Error` (which cannot be constructed outside reqwest).
///
/// A rustls cert rejection reaches this as `InvalidData`/`Other`, NOT
/// `ConnectionRefused`/`TimedOut` — which is exactly why the cert-pin TOFU flow
/// (T40) is untouched by the hint.
fn io_failure_kind(err: &(dyn std::error::Error + 'static)) -> ConnectFailure {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::ConnectionRefused => ConnectFailure::Refused,
                std::io::ErrorKind::TimedOut => ConnectFailure::TimedOut,
                _ => ConnectFailure::Other,
            };
        }
        cur = e.source();
    }
    ConnectFailure::Other
}

/// Classify a `reqwest` send failure. Our own `CONNECT_TIMEOUT` fires without
/// an `io::Error` in the chain, so fall back to reqwest's own flags — but
/// require `is_connect()` so a slow-but-listening controller (response-header
/// timeout) is never mistaken for a wrong port.
fn socket_failure(err: &reqwest::Error) -> ConnectFailure {
    match io_failure_kind(err) {
        ConnectFailure::Other if err.is_connect() && err.is_timeout() => ConnectFailure::TimedOut,
        other => other,
    }
}

/// The actionable "did you mean :8443?" error, or `None` to keep the raw
/// transport error. Pure + total, so every guard is unit-tested below.
///
/// Guards, all of which must hold:
/// - no explicit port — an operator who typed `:9443` gets their own error,
///   never our second-guess (`Url::port()` is `None` for the scheme default);
/// - https — the http relaxation is generic/dev-only, where 443 means nothing;
/// - not the fixed cloud host — the operator didn't choose it;
/// - the socket was refused or silently dropped.
fn default_port_hint(url: &Url, failure: ConnectFailure) -> Option<ApiError> {
    if url.scheme() != "https" || url.port().is_some() {
        return None;
    }
    let host = url.host_str()?;
    if host.eq_ignore_ascii_case(CLOUD_HOST) {
        return None;
    }
    match failure {
        ConnectFailure::Refused => Some(ApiError::DefaultPortRefused {
            host: host.to_string(),
        }),
        ConnectFailure::TimedOut => Some(ApiError::DefaultPortTimeout {
            host: host.to_string(),
        }),
        ConnectFailure::Other => None,
    }
}

impl ApiClient {
    pub fn new() -> Self {
        let pins = transit_tls::PinStore::default();
        let rejected = transit_tls::LastRejectedStore::default();
        let http = Client::builder()
            .user_agent(concat!("transit-app/", env!("CARGO_PKG_VERSION")))
            // "local" / device bytes must not transit a corporate proxy,
            // and a rogue redirect must never re-ship the injected key.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            // Full OS-store chain verification (honors enterprise CAs) PLUS a
            // fallback to user-verified pins for self-signed on-prem
            // controllers — never `danger_accept_invalid_certs` (§9 /
            // PinAwareVerifier). `pins` is empty until the user trusts one.
            .use_preconfigured_tls(transit_tls::pinned_os_store_tls_config(
                pins.clone(),
                rejected.clone(),
            ))
            .build()
            .expect("reqwest client with static config cannot fail to build");
        Self {
            http,
            pins,
            rejected,
        }
    }

    /// Record that `host` is trusted to present exactly `sha256` — a
    /// self-signed controller cert the user verified + accepted in the
    /// untrusted-cert dialog. Idempotent; a re-verified different fingerprint
    /// overwrites. The key is lowercased to match the TLS `ServerName`. This
    /// is the ONLY way a self-signed host becomes reachable — no blanket
    /// bypass exists.
    pub fn trust_pin(&self, host: &str, sha256: [u8; 32]) {
        let key = host.to_ascii_lowercase();
        if let Ok(mut pins) = self.pins.write() {
            pins.insert(key.clone(), sha256);
        }
        // Clear any recorded rejection for this host so a later UNRELATED
        // transport error (controller briefly down) can't resurface a stale
        // "untrusted certificate" dialog for a host the user already trusted
        // (v4.3.0 adversarial review). A genuine cert change re-records on the
        // next handshake, so this loses nothing.
        if let Ok(mut rejected) = self.rejected.write() {
            rejected.remove(&key);
        }
    }

    /// The SHA-256 of the last cert REJECTED for `host` (untrusted + unpinned),
    /// if any — the fingerprint the untrusted-cert dialog shows for the user to
    /// verify before pinning. `None` if nothing was rejected for this host.
    pub fn pending_cert(&self, host: &str) -> Option<[u8; 32]> {
        self.rejected
            .read()
            .ok()
            .and_then(|r| r.get(&host.to_ascii_lowercase()).copied())
    }

    /// Convenience for the AGENT path: a GET with no caller headers. The
    /// [`gate`](crate::gate) only ever yields a URL to GET, and routing
    /// the agent through this method (instead of [`send`](Self::send)
    /// with a caller-chosen `Method`) makes it structurally impossible
    /// for the agent path to issue a non-GET request.
    pub async fn get(&self, url: Url, auth: &AppliedAuth) -> Result<ApiResponse, ApiError> {
        self.send(Method::GET, url, &HeaderMap::new(), None, auth)
            .await
    }

    /// The agent GET path, carrying caller-supplied headers — used to replay
    /// the session auth header the HUMAN established on a login-flow
    /// controller (ACI cookie, vManage JSESSIONID, Apstra AuthToken), which is
    /// not a keychain-backed [`AppliedAuth`] and so cannot be injected.
    ///
    /// `Method::GET` is still hardcoded, exactly as in [`get`](Self::get): the
    /// agent path remains structurally incapable of a non-GET request. Only
    /// the header map opens up, and `send` still injects `auth` LAST, so a
    /// caller-supplied header can never displace the real credential.
    /// `headers` are `(name, value)` pairs, parsed here (CRLF / control
    /// chars refused) so the transport's header types stay inside this crate.
    pub async fn get_with_headers(
        &self,
        url: Url,
        headers: &[(String, String)],
        auth: &AppliedAuth,
    ) -> Result<ApiResponse, ApiError> {
        let header_map = Self::build_header_map(headers)?;
        self.send(Method::GET, url, &header_map, None, auth).await
    }

    /// The HUMAN (Postman) send path. Confines `path` to `endpoint`
    /// (host-pin — the human cannot choose the host either), accepts ANY
    /// method (ungated, exactly like typing at the SSH terminal), injects
    /// the key, and sends. The response is returned RAW — redaction is the
    /// agent boundary, never applied to what the operator sees of their
    /// own controller. `method` + each header name/value are parsed here;
    /// an invalid one is refused before any request is sent.
    pub async fn send_human(
        &self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        auth: &AppliedAuth,
    ) -> Result<ApiResponse, ApiError> {
        let url = endpoint.confine(path)?;
        let method = Method::from_bytes(method.trim().as_bytes())
            .map_err(|_| ApiError::InvalidMethod(method.to_string()))?;
        let header_map = Self::build_header_map(headers)?;
        self.send(method, url, &header_map, body, auth).await
    }

    /// Parse caller (human) headers into a [`HeaderMap`], refusing any
    /// invalid name/value (CRLF, control chars) before a request is built.
    /// Uses `append`, not `insert`: a Postman user may set the same header
    /// twice (e.g. two `Accept`) and both must be sent. The injected
    /// `X-API-KEY` is unaffected — [`send`](Self::send) strips every caller
    /// `x-api-key` (case-insensitive) before injecting its own.
    fn build_header_map(headers: &[(String, String)]) -> Result<HeaderMap, ApiError> {
        const SENSITIVE: [&str; 4] = ["cookie", "authorization", "authtoken", "x-auth-token"];
        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            let hn = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ApiError::InvalidHeader(name.clone()))?;
            let mut hv =
                HeaderValue::from_str(value).map_err(|_| ApiError::InvalidHeader(name.clone()))?;
            // Mirror `AppliedAuth::apply`: keep a credential out of the HTTP/2
            // HPACK index and out of any `Debug` of the request.
            if SENSITIVE.iter().any(|s| name.eq_ignore_ascii_case(s)) {
                hv.set_sensitive(true);
            }
            header_map.append(hn, hv);
        }
        Ok(header_map)
    }

    /// Send one request to an ALREADY-CONFINED `url` (the caller pinned
    /// the host via [`Endpoint::confine`](crate::Endpoint::confine) or
    /// the [`gate`](crate::gate)).
    ///
    /// `extra_headers` are caller-supplied (e.g. human Postman headers);
    /// any `x-api-key` among them is dropped — this method is the sole
    /// authority for that header. `key` is injected as `X-API-KEY`,
    /// marked sensitive, and never placed in the URL or logged. The
    /// response body is byte-capped and the whole request is bounded by
    /// [`REQUEST_TIMEOUT`].
    pub async fn send(
        &self,
        method: Method,
        url: Url,
        extra_headers: &HeaderMap,
        body: Option<Vec<u8>>,
        auth: &AppliedAuth,
    ) -> Result<ApiResponse, ApiError> {
        let mut headers = extra_headers.clone();
        // A caller may not supply the auth header — we own it. Strip any
        // caller-supplied copy of the header this scheme owns (`remove` is
        // case-insensitive; HeaderMap normalizes names), then inject our own
        // sensitive value. `AppliedAuth::None` owns nothing → a public API
        // sends no auth, and a human's manual `Authorization` is left intact.
        if let Some(owned) = auth.owned_header() {
            headers.remove(&owned);
        }
        auth.apply(&mut headers)?;

        // Kept for error classification only — `url` moves into the request.
        let hint_url = url.clone();
        let mut req = self.http.request(method, url).headers(headers);
        if let Some(b) = body {
            req = req.body(b);
        }

        // Wrap the whole send + bounded body read in one deadline so a
        // slow / trickling controller cannot hang the caller, and cap the
        // buffered bytes so an oversized body cannot exhaust memory.
        let fetch = async {
            // Only the CONNECT phase earns the port hint. A failure mid-body
            // (below) means we connected fine, so it stays a plain transport
            // error — suggesting a different port there would be wrong.
            let mut resp = req.send().await.map_err(|e| {
                default_port_hint(&hint_url, socket_failure(&e)).unwrap_or(ApiError::Transport(e))
            })?;
            let status = resp.status().as_u16();
            // Snapshot the response headers (HUMAN view only) before the body
            // stream is consumed. Capped in count + per-value length so a
            // pathological controller can't bloat the IPC payload / UI.
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .take(MAX_RESPONSE_HEADERS)
                .map(|(name, value)| {
                    let mut v = String::from_utf8_lossy(value.as_bytes()).into_owned();
                    if v.len() > MAX_HEADER_VALUE_LEN {
                        // Truncate on a char boundary — from_utf8_lossy yields
                        // valid UTF-8, but the byte cap may land mid-codepoint.
                        let mut end = MAX_HEADER_VALUE_LEN;
                        while !v.is_char_boundary(end) {
                            end -= 1;
                        }
                        v.truncate(end);
                        v.push('…');
                    }
                    (name.as_str().to_string(), v)
                })
                .collect();
            let mut buf: Vec<u8> = Vec::new();
            let mut truncated = false;
            while let Some(chunk) = resp.chunk().await? {
                let remaining = MAX_BODY_BYTES.saturating_sub(buf.len());
                if chunk.len() > remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok::<(u16, Vec<(String, String)>, Vec<u8>, bool), ApiError>((
                status, headers, buf, truncated,
            ))
        };

        let (status, headers, buf, truncated) = tokio::time::timeout(REQUEST_TIMEOUT, fetch)
            .await
            .map_err(|_| ApiError::Timeout)??;

        let body = String::from_utf8_lossy(&buf).into_owned();
        Ok(ApiResponse {
            status,
            body,
            truncated,
            headers,
        })
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use wiremock::matchers::{header, method as match_method, path as match_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The historic UniFi X-API-KEY auth, for tests exercising the send path
    /// with a key. (Scheme dispatch itself is unit-tested in `auth`.)
    fn key_auth(k: &str) -> AppliedAuth {
        AppliedAuth::api_key("x-api-key", "", SecretString::from(k.to_string())).unwrap()
    }

    #[test]
    fn client_builds() {
        // A crypto-provider mismatch in the preconfigured-TLS path would
        // panic here rather than at first request.
        let _c = ApiClient::new();
    }

    // ---- default-port hint (":443 refused → did you mean :8443?") ----------
    //
    // The hint is pure + total, so every guard is tested here. The socket
    // classification is tested through a synthetic error chain because a
    // `reqwest::Error` cannot be constructed outside reqwest.

    /// One link in an error chain, mimicking reqwest → hyper → io nesting.
    #[derive(Debug)]
    struct Wrap(Box<dyn std::error::Error + Send + Sync + 'static>);

    impl std::fmt::Display for Wrap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }

    impl std::error::Error for Wrap {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    fn chain(kind: std::io::ErrorKind) -> Wrap {
        // Two levels deep, so a walker that only checks the top layer fails.
        Wrap(Box::new(Wrap(Box::new(std::io::Error::new(kind, "boom")))))
    }

    #[test]
    fn io_failure_kind_walks_the_chain_to_the_socket_error() {
        assert_eq!(
            io_failure_kind(&chain(std::io::ErrorKind::ConnectionRefused)),
            ConnectFailure::Refused
        );
        assert_eq!(
            io_failure_kind(&chain(std::io::ErrorKind::TimedOut)),
            ConnectFailure::TimedOut
        );
    }

    #[test]
    fn io_failure_kind_does_not_claim_tls_or_dns_failures() {
        // REGRESSION GUARD (T40): a rustls cert rejection reaches us as
        // InvalidData. If it ever classified as Refused/TimedOut, a
        // self-signed controller would get "did you mean :8443?" instead of
        // the cert-pin TOFU dialog — the exact wrong answer.
        for kind in [
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::NotFound,
        ] {
            assert_eq!(
                io_failure_kind(&chain(kind)),
                ConnectFailure::Other,
                "{kind:?} must not earn a port hint"
            );
        }
        // No io::Error anywhere in the chain → Other, not a panic.
        assert_eq!(
            io_failure_kind(&Wrap(Box::new(ApiError::InvalidKey))),
            ConnectFailure::Other
        );
    }

    #[test]
    fn hint_suggests_8443_when_the_implicit_port_is_refused() {
        let url = Url::parse("https://unifi.example.com/proxy/network/integration/v1/").unwrap();
        let err = default_port_hint(&url, ConnectFailure::Refused).expect("should hint");
        assert!(
            matches!(&err, ApiError::DefaultPortRefused { host } if host == "unifi.example.com")
        );
        let msg = err.to_string();
        assert!(msg.contains("unifi.example.com:8443"), "{msg}");
        // Must not trip the frontend's cert-dialog regex
        // (/transport error|error sending request|certificate/i), or a plain
        // wrong-port mistake would detour through the untrusted-cert path.
        assert!(!msg.to_lowercase().contains("transport error"), "{msg}");
        assert!(!msg.to_lowercase().contains("certificate"), "{msg}");
        assert!(
            !msg.to_lowercase().contains("error sending request"),
            "{msg}"
        );
    }

    #[test]
    fn hint_timeout_names_both_the_port_and_the_firewall_cause() {
        let url = Url::parse("https://unifi.example.com/").unwrap();
        let msg = default_port_hint(&url, ConnectFailure::TimedOut)
            .expect("should hint")
            .to_string();
        assert!(msg.contains("unifi.example.com:8443"), "{msg}");
        assert!(msg.contains("security group"), "{msg}");
    }

    #[test]
    fn hint_never_second_guesses_an_explicit_port() {
        // The operator typed a port — their choice stands, whatever happens.
        for base in [
            "https://unifi.example.com:8443/",
            "https://unifi.example.com:9443/",
            "https://10.0.0.1:8443/",
        ] {
            let url = Url::parse(base).unwrap();
            assert!(
                default_port_hint(&url, ConnectFailure::Refused).is_none(),
                "{base} carries an explicit port"
            );
        }
    }

    #[test]
    fn hint_declines_for_the_fixed_cloud_host() {
        // Site Manager + connector-proxy hosts aren't operator-chosen, so 8443
        // is never the answer there.
        for base in [
            "https://api.ui.com/v1/hosts",
            "https://API.UI.COM/v1/connector/consoles/x/",
        ] {
            let url = Url::parse(base).unwrap();
            assert!(
                default_port_hint(&url, ConnectFailure::Refused).is_none(),
                "{base} is the cloud host"
            );
        }
    }

    #[test]
    fn hint_declines_for_http_and_for_unclassified_failures() {
        // http is the generic/dev relaxation — 443 carries no convention.
        let http = Url::parse("http://localhost/api/").unwrap();
        assert!(default_port_hint(&http, ConnectFailure::Refused).is_none());
        // A TLS/DNS/protocol failure keeps its own (more accurate) error.
        let https = Url::parse("https://unifi.example.com/").unwrap();
        assert!(default_port_hint(&https, ConnectFailure::Other).is_none());
    }

    #[tokio::test]
    async fn send_injects_api_key_and_returns_body() {
        let server = MockServer::start().await;
        Mock::given(match_method("GET"))
            .and(match_path("/v1/hosts"))
            .and(header("x-api-key", "SECRET-123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":["ok"]}"#))
            .mount(&server)
            .await;

        let client = ApiClient::new();
        let url = Url::parse(&format!("{}/v1/hosts", server.uri())).unwrap();
        let auth = key_auth("SECRET-123");

        let resp = client
            .send(Method::GET, url, &HeaderMap::new(), None, &auth)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("ok"), "body was: {}", resp.body);
        assert!(!resp.truncated, "a tiny body must not be truncated");
    }

    #[tokio::test]
    async fn get_helper_issues_a_get() {
        let server = MockServer::start().await;
        Mock::given(match_method("GET"))
            .and(match_path("/v1/sites"))
            .and(header("x-api-key", "K"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;

        let client = ApiClient::new();
        let url = Url::parse(&format!("{}/v1/sites", server.uri())).unwrap();
        let auth = key_auth("K");

        let resp = client.get(url, &auth).await.expect("GET should succeed");
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn caller_supplied_api_key_header_cannot_override_the_injected_one() {
        let server = MockServer::start().await;
        Mock::given(match_method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = ApiClient::new();
        let url = Url::parse(&format!("{}/v1/hosts", server.uri())).unwrap();
        let auth = key_auth("REAL-KEY");

        let mut extra = HeaderMap::new();
        // Attempt to smuggle a different key.
        extra.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("FAKE-KEY"),
        );

        client
            .send(Method::GET, url, &extra, None, &auth)
            .await
            .expect("request should succeed");

        let reqs = server
            .received_requests()
            .await
            .expect("wiremock records requests");
        assert_eq!(reqs.len(), 1);
        let sent: Vec<String> = reqs[0]
            .headers
            .get_all("x-api-key")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            sent,
            vec!["REAL-KEY".to_string()],
            "exactly the injected key must be sent, never the caller's"
        );
    }

    /// `Debug` must never print the raw body (device data / §10).
    #[test]
    fn debug_elides_body_content() {
        let resp = ApiResponse {
            status: 200,
            body: "super-secret-wifi-psk".to_string(),
            truncated: false,
            headers: vec![("set-cookie".to_string(), "session=super-secret".to_string())],
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("super-secret-wifi-psk"), "body leaked: {dbg}");
        assert!(!dbg.contains("super-secret"), "header value leaked: {dbg}");
        assert!(dbg.contains("body_len"), "should report length: {dbg}");
        assert!(
            dbg.contains("header_count"),
            "should report header count: {dbg}"
        );
    }

    #[tokio::test]
    async fn send_human_rejects_invalid_method() {
        let ep = crate::Endpoint::network_local("10.0.0.1").unwrap();
        let auth = key_auth("K");
        let err = ApiClient::new()
            .send_human(&ep, "BAD METHOD", "sites", &[], None, &auth)
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidMethod(_)), "{err:?}");
    }

    #[tokio::test]
    async fn send_human_rejects_invalid_header() {
        let ep = crate::Endpoint::network_local("10.0.0.1").unwrap();
        let auth = key_auth("K");
        let err = ApiClient::new()
            .send_human(
                &ep,
                "GET",
                "sites",
                &[("bad name".to_string(), "v".to_string())],
                None,
                &auth,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidHeader(_)), "{err:?}");
    }

    #[tokio::test]
    async fn send_human_confines_path_before_sending() {
        // An encoded-traversal path is refused by confine before any send.
        let ep = crate::Endpoint::network_local("10.0.0.1").unwrap();
        let auth = key_auth("K");
        let err = ApiClient::new()
            .send_human(&ep, "GET", "..%2f..%2fadmin", &[], None, &auth)
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::PathEscape { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn send_human_rejects_crlf_in_header_value() {
        // Header-VALUE injection (distinct from the invalid-NAME case):
        // a CRLF-bearing value must be refused before any request is sent,
        // so a caller can't smuggle a second header line.
        let ep = crate::Endpoint::network_local("10.0.0.1").unwrap();
        let auth = key_auth("K");
        let err = ApiClient::new()
            .send_human(
                &ep,
                "GET",
                "sites",
                &[("X-Test".to_string(), "a\r\nEvil: 1".to_string())],
                None,
                &auth,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidHeader(_)), "{err:?}");
    }

    #[test]
    fn build_header_map_preserves_duplicates_and_rejects_bad() {
        // Duplicate header names are both kept (append, not insert).
        let map = ApiClient::build_header_map(&[
            ("Accept".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/plain".to_string()),
        ])
        .unwrap();
        let accepts: Vec<String> = map
            .get_all("accept")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(accepts, vec!["application/json", "text/plain"]);

        // A bad NAME and a CRLF-bearing VALUE both refuse.
        assert!(matches!(
            ApiClient::build_header_map(&[("bad name".to_string(), "v".to_string())]),
            Err(ApiError::InvalidHeader(_))
        ));
        assert!(matches!(
            ApiClient::build_header_map(&[("X-Test".to_string(), "a\r\nEvil: 1".to_string())]),
            Err(ApiError::InvalidHeader(_))
        ));
    }
}
