//! Transport policy + hardened HTTP client construction for the BYOM
//! local/self-hosted endpoint clients (`ollama.rs`, `openai_compat.rs`).
//!
//! One module owns the URL rules (threat-model T35) so the config
//! layer (transit_app) and the clients validate with the SAME
//! predicates and can't drift:
//!
//! - [`loopback_violation`] — the zero-config `[local_models]` Ollama
//!   path: **loopback only**, http or https.
//! - [`transport_violation`] — custom endpoints: plain http only to
//!   loopback (cleartext must never leave the machine); any other host
//!   requires https, chain-verified against the **OS trust store** so
//!   enterprise-internal CAs on self-hosted vLLM/Ollama work.
//!
//! Client hardening shared by every local-endpoint request: never
//! honor `HTTP_PROXY` (`no_proxy` — "local" bytes must not transit a
//! corporate proxy), never follow redirects (`Policy::none()` — a
//! rogue listener must not 307 conversation bytes off-box;
//! wiremock-pinned in `ollama.rs`), and a short connect timeout so a
//! dead port can't eat the agent loop's per-round stream budget. TLS
//! trust for https endpoints comes from
//! `transit_tls::os_store_tls_config` — trust-anchor
//! selection stays centralized in that §9 module.

use std::time::Duration;

/// `None` when `base_url` is a loopback http(s) URL; otherwise the
/// user-facing refusal reason. Guards the zero-config Ollama path —
/// enforced at the config layer AND re-checked in the client (defense
/// in depth; T35).
pub fn loopback_violation(base_url: &str) -> Option<String> {
    let url = match reqwest::Url::parse(base_url) {
        Ok(u) => u,
        Err(e) => return Some(format!("invalid Ollama base URL `{base_url}`: {e}")),
    };
    if !matches!(url.scheme(), "http" | "https") {
        return Some(format!(
            "refusing Ollama base URL `{base_url}` — only http/https URLs are supported"
        ));
    }
    if url_host_is_loopback(&url) {
        None
    } else {
        Some(format!(
            "refusing non-loopback Ollama base URL `{base_url}` — the built-in Ollama \
             integration is loopback-only (add a custom endpoint for a remote server)"
        ))
    }
}

/// `None` when `base_url` satisfies the CUSTOM-endpoint transport
/// rules (T35): https → any host (OS-store verified); http → loopback
/// host only; anything else refused.
pub fn transport_violation(base_url: &str) -> Option<String> {
    let url = match reqwest::Url::parse(base_url) {
        Ok(u) => u,
        Err(e) => return Some(format!("invalid endpoint URL `{base_url}`: {e}")),
    };
    match url.scheme() {
        "https" => None,
        "http" if url_host_is_loopback(&url) => None,
        "http" => Some(format!(
            "refusing plain-HTTP endpoint `{base_url}` on a non-loopback host — device \
             output would cross the network unencrypted; use https (the OS trust store, \
             including enterprise CAs, is honored)"
        )),
        _ => Some(format!(
            "refusing endpoint `{base_url}` — only http (loopback) or https URLs are supported"
        )),
    }
}

/// Loopback = 127.0.0.0/8, `::1`, or the literal `localhost`.
fn url_host_is_loopback(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        // IPv6 host_str carries brackets (`[::1]`).
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

/// The one reqwest builder for local-endpoint traffic (module docs).
/// `total_timeout` is set only for short probe calls — streaming
/// completions stay untimed (the agent loop's `stream_timeout` owns
/// that guard, same division of labor as the cloud client).
pub(crate) fn hardened_client(
    os_trust_tls: bool,
    total_timeout: Option<Duration>,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2));
    if os_trust_tls {
        builder = builder.use_preconfigured_tls(transit_tls::os_store_tls_config());
    }
    if let Some(t) = total_timeout {
        builder = builder.timeout(t);
    }
    builder
        .build()
        .expect("reqwest client with static config cannot fail to build")
}

/// Hardened client for a caller-validated endpoint URL: https
/// endpoints get the OS-store trust config; loopback-http endpoints a
/// plain client (no TLS handshake ever happens). Callers MUST have
/// passed the URL through [`transport_violation`] /
/// [`loopback_violation`] first — this only selects TLS plumbing.
///
/// TLS selection keys on the PARSED, lowercased scheme (not a raw
/// `starts_with`) so it agrees with the validation predicates: a
/// `HTTPS://…` URL validates as https and must get the OS-store
/// config too. Unparseable → treat as non-https (plain client);
/// validation already rejected it, so no request is actually sent.
pub fn endpoint_http_client(base_url: &str, total_timeout: Option<Duration>) -> reqwest::Client {
    let is_https = reqwest::Url::parse(base_url)
        .map(|u| u.scheme().eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    hardened_client(is_https, total_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_violation_accepts_loopback_forms_only() {
        for ok in [
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://[::1]:11434",
            "https://127.0.0.1",
            "http://127.0.0.2:11434", // whole 127/8 block is loopback
        ] {
            assert!(loopback_violation(ok).is_none(), "{ok} should be allowed");
        }
        for bad in [
            "http://192.168.1.5:11434",
            "http://ollama.example.com:11434",
            "http://127.0.0.1.evil.com:11434",
            "ftp://127.0.0.1:11434",
            "not a url",
        ] {
            assert!(loopback_violation(bad).is_some(), "{bad} should be refused");
        }
    }

    #[test]
    fn transport_violation_requires_https_off_loopback() {
        for ok in [
            "http://127.0.0.1:1234/v1",
            "http://localhost:11434",
            "https://vllm.lab.internal:8000/v1",
            "https://10.20.30.40:8443",
            "https://127.0.0.1:8443",
        ] {
            assert!(transport_violation(ok).is_none(), "{ok} should be allowed");
        }
        for (bad, needle) in [
            ("http://192.168.1.50:11434", "unencrypted"),
            ("http://vllm.lab.internal:8000/v1", "unencrypted"),
            ("http://127.0.0.1.evil.com:11434", "unencrypted"),
            ("ws://127.0.0.1:1234", "only http"),
            ("not a url", "invalid"),
        ] {
            let msg = transport_violation(bad).expect(bad);
            assert!(msg.contains(needle), "{bad}: {msg}");
        }
    }

    /// Both client flavors must construct cleanly — a crypto-provider
    /// mismatch inside the preconfigured-TLS path would panic here
    /// rather than at first use.
    #[test]
    fn both_client_flavors_build() {
        let _plain = hardened_client(false, None);
        let _tls = hardened_client(true, Some(Duration::from_secs(5)));
        let _by_scheme_http = endpoint_http_client("http://127.0.0.1:11434", None);
        let _by_scheme_https = endpoint_http_client("https://vllm.lab.internal:8000", None);
    }
}
