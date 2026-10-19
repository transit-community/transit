//! Failure modes for the API transport.
//!
//! None of these variants ever carry the API key: `InvalidKey` is
//! reported without the value, and `Transport` wraps a `reqwest::Error`
//! whose `Display` only ever names the URL (the key rides in a header,
//! never the URL, and is marked sensitive).

use thiserror::Error;

/// Errors returned by [`Endpoint`](crate::Endpoint) construction /
/// confinement and by [`ApiClient::send`](crate::ApiClient::send).
#[derive(Debug, Error)]
pub enum ApiError {
    /// The stored controller config could not be turned into a valid
    /// base URL (bad host, non-https, missing trailing slash, …).
    #[error("invalid API endpoint: {0}")]
    InvalidEndpoint(String),

    /// The caller-supplied request path is not a valid URL reference.
    #[error("request path `{path}` is not a valid URL reference: {source}")]
    InvalidPath {
        path: String,
        #[source]
        source: url::ParseError,
    },

    /// The resolved request would leave the endpoint's origin
    /// (scheme + host + port) — an absolute URL or protocol-relative
    /// path tried to repoint the request at another host.
    #[error("request escapes the controller host (endpoint {expected}, resolved {got})")]
    HostEscape { expected: String, got: String },

    /// The resolved request path climbed above the endpoint's API base
    /// path (an absolute path or `..` traversal).
    #[error("request path escapes the controller's API base `{base}`")]
    PathEscape { base: String },

    /// The caller supplied an HTTP method that is not a valid token
    /// (human request path only — the agent path is GET-locked).
    #[error("invalid HTTP method `{0}`")]
    InvalidMethod(String),

    /// A caller-supplied request header name or value was not valid.
    #[error("invalid request header `{0}`")]
    InvalidHeader(String),

    /// The API key contained bytes that are not valid in an HTTP header
    /// value. Reported WITHOUT the key.
    #[error("the API key is not a valid HTTP header value")]
    InvalidKey,

    /// The request exceeded the total time budget (connect + send + body
    /// read). Guards against a slow / trickling controller hanging the app.
    #[error("API request timed out")]
    Timeout,

    /// Nothing accepted a connection on the implicit https port (443) of an
    /// operator-chosen controller host. Overwhelmingly this means the port was
    /// omitted from the controller host and the management API is on 8443 —
    /// the single most common self-hosted-controller setup mistake, and
    /// indistinguishable from "wrong host" in the raw transport error.
    ///
    /// Only ever raised when NO port was given (an explicit port is the
    /// operator's decision and is never second-guessed) and never for the
    /// fixed-host cloud surfaces. See `client::default_port_hint`.
    #[error(
        "nothing is listening on {host}:443 — did you mean {host}:8443? \
         Self-hosted controllers commonly serve their API on 8443 (UniFi \
         Network Application, Cisco vManage); UniFi OS consoles use 443. \
         Add the port to the controller host."
    )]
    DefaultPortRefused { host: String },

    /// Same shape as [`DefaultPortRefused`](Self::DefaultPortRefused), but the
    /// connection was silently dropped rather than refused — a filtered port
    /// (cloud NSG / security group / firewall) as opposed to nothing bound.
    /// Both causes are worth naming: the raw error is just "operation timed
    /// out", which tells the operator nothing about which of the two it is.
    #[error(
        "no response from {host}:443 — if the controller serves its API on \
         8443, add the port to the controller host ({host}:8443). Otherwise \
         this machine cannot reach {host}:443 — check the firewall / cloud \
         security group / VPN. Transit connects directly and ignores any \
         HTTP proxy."
    )]
    DefaultPortTimeout { host: String },

    /// Transport-level failure (connect/TLS/read). Never carries the key.
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
}
