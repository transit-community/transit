//! Endpoint construction + the host-pinning confinement check.
//!
//! An [`Endpoint`] is a *fixed* base URL — the only host a session's
//! requests can ever reach. Callers supply a relative path;
//! [`Endpoint::confine`] joins it to the base and refuses anything that
//! resolves off-origin or above the API path prefix. This is the one
//! guarantee shared by BOTH the human and agent paths: the
//! host is never caller-chosen, so a crafted path cannot reach an
//! internal service (SSRF) or ship the injected key to a foreign host.

use url::{Origin, Url};

use crate::error::ApiError;

/// Which UniFi API surface an endpoint addresses. Selects how the fixed
/// base URL is built; once constructed, all kinds are treated
/// uniformly by [`Endpoint::confine`] and the [`gate`](crate::gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// UniFi Site Manager cloud API (`https://api.ui.com`). Account-wide
    /// inventory / health; public-CA TLS (no self-signed handling).
    SiteManager,
    /// A local / self-hosted controller's Network Integration API
    /// (`https://<host>/proxy/network/integration/v1/`). Self-signed
    /// TLS is the norm here; cert-pin TOFU lands in Phase 3, so until
    /// then this kind only succeeds against a controller whose cert the
    /// OS trust store already validates.
    NetworkLocal,
    /// The cloud connector-proxy that tunnels a console's Network API
    /// through `api.ui.com` (public-CA TLS, no inbound firewall).
    ConnectorProxy,
    /// A user-supplied generic REST base (any vendor; no bundled
    /// collection). The caller provides the FULL base URL. This is the one
    /// kind that permits `http` — for local / dev testing, UI-warned — and
    /// carries no fixed host; every request is still host-pinned + confined
    /// under the base by [`Endpoint::confine`], and the host is never
    /// agent-chosen (the operator set it when adding the controller).
    Generic,
}

/// A fully-resolved API endpoint: the fixed base URL every request in a
/// session is confined to. Build via [`Endpoint::site_manager`] /
/// [`Endpoint::network_local`] / [`Endpoint::connector_proxy`]; the
/// stored controller config supplies the host / console id.
#[derive(Debug, Clone)]
pub struct Endpoint {
    kind: EndpointKind,
    /// Base URL, GUARANTEED https and to end in `/` so a relative
    /// `join` resolves *under* it and the path-prefix pin has a clean
    /// segment boundary.
    api_base: Url,
}

const SITE_MANAGER_BASE: &str = "https://api.ui.com/";
const NETWORK_PATH: &str = "/proxy/network/integration/v1/";

impl Endpoint {
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }

    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    /// UniFi Site Manager cloud. The host is fixed (`api.ui.com`); the
    /// caller supplies nothing to validate. The base path is `/`, so any
    /// path on `api.ui.com` is in-base — that host is entirely API, and
    /// GET-only (for the agent) is the real read-only floor.
    pub fn site_manager() -> Self {
        let api_base = Url::parse(SITE_MANAGER_BASE).expect("SITE_MANAGER_BASE is a valid URL");
        debug_assert!(api_base.path().ends_with('/'));
        Self {
            kind: EndpointKind::SiteManager,
            api_base,
        }
    }

    /// A local / self-hosted controller addressed by `host` (`host` or
    /// `host:port`, NO scheme, NO path). https is forced.
    ///
    /// The host charset is ALLOWLISTED up front (letters, digits, and
    /// `.`, `-`, `:`, `[`, `]` for hostnames / `:port` / bracketed
    /// IPv6), so newline / CR / tab, spaces, and Unicode label
    /// separators (e.g. the ideographic full stop U+3002, which IDNA
    /// maps to `.`) are refused BEFORE the URL parser can strip or remap
    /// them into a different host — closing the "validated value ≠
    /// connected host" gap. The parse result is then re-checked so no
    /// userinfo / path / query slipped in.
    pub fn network_local(host: &str) -> Result<Self, ApiError> {
        let host = host.trim();
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        {
            return Err(ApiError::InvalidEndpoint(format!(
                "invalid controller host `{host}`"
            )));
        }
        let mut url = Url::parse(&format!("https://{host}")).map_err(|e| {
            ApiError::InvalidEndpoint(format!("invalid controller host `{host}`: {e}"))
        })?;
        // The parser must have read `host` as a bare authority. If any
        // of these are non-default, the input smuggled URL structure.
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.path() != "/"
        {
            return Err(ApiError::InvalidEndpoint(format!(
                "invalid controller host `{host}`"
            )));
        }
        url.set_path(NETWORK_PATH);
        Self::finish(EndpointKind::NetworkLocal, url)
    }

    /// The cloud connector-proxy for a specific console id. The id is a
    /// single path segment; it is restricted to `[A-Za-z0-9-]` so it
    /// cannot inject additional segments or dot-segments.
    pub fn connector_proxy(console_id: &str) -> Result<Self, ApiError> {
        let id = console_id.trim();
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ApiError::InvalidEndpoint(format!(
                "invalid console id `{console_id}`"
            )));
        }
        let url = Url::parse(&format!(
            "https://api.ui.com/v1/connector/consoles/{id}{NETWORK_PATH}"
        ))
        .map_err(|e| ApiError::InvalidEndpoint(format!("invalid connector base: {e}")))?;
        Self::finish(EndpointKind::ConnectorProxy, url)
    }

    /// A user-supplied generic REST base for any vendor (e.g.
    /// `https://swapi.dev/api`). Unlike the UniFi kinds the caller gives the
    /// FULL base URL (scheme + host [+ path]); `http` is permitted (the one
    /// relaxation of the https floor — for local / dev testing, the UI warns
    /// and warns harder when auth carries a secret). Every other invariant
    /// still holds — a host, NO embedded credentials (those belong in the
    /// auth scheme, and a URL password would bypass the sensitive-header
    /// path), trailing-slash-confined — and the host is never agent-chosen
    /// (the gate confines every request under this base).
    pub fn generic(base_url: &str) -> Result<Self, ApiError> {
        let raw = base_url.trim();
        let mut url = Url::parse(raw)
            .map_err(|e| ApiError::InvalidEndpoint(format!("invalid base URL `{raw}`: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ApiError::InvalidEndpoint(format!(
                "base URL must be http or https, got `{}`",
                url.scheme()
            )));
        }
        // Reject a missing OR empty host — `https:///path` parses to an
        // empty authority (Some("")) for special schemes, which `is_none()`
        // alone would miss.
        if matches!(url.host_str(), None | Some("")) {
            return Err(ApiError::InvalidEndpoint("base URL has no host".into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ApiError::InvalidEndpoint(
                "base URL must not embed credentials (use the auth scheme)".into(),
            ));
        }
        // The base is a prefix, not a request: drop any query/fragment, and
        // guarantee a trailing slash so a relative join resolves UNDER it.
        url.set_query(None);
        url.set_fragment(None);
        if !url.path().ends_with('/') {
            let with_slash = format!("{}/", url.path());
            url.set_path(&with_slash);
        }
        Self::finish(EndpointKind::Generic, url)
    }

    /// Validate the constructed base URL's load-bearing invariants:
    /// https (or http for the `Generic` kind only), a host is present, and
    /// the path ends in `/`.
    fn finish(kind: EndpointKind, api_base: Url) -> Result<Self, ApiError> {
        // https everywhere EXCEPT `Generic`, which permits http (local/dev
        // testing; the UI warns). `finish` is the single invariant gate, so
        // the relaxation is expressed here once, not per-constructor.
        let scheme_ok = api_base.scheme() == "https"
            || (kind == EndpointKind::Generic && api_base.scheme() == "http");
        if !scheme_ok {
            return Err(ApiError::InvalidEndpoint(format!(
                "endpoint must be https{}, got `{}`",
                if kind == EndpointKind::Generic {
                    " or http"
                } else {
                    ""
                },
                api_base.scheme()
            )));
        }
        if matches!(api_base.host_str(), None | Some("")) {
            return Err(ApiError::InvalidEndpoint("endpoint has no host".into()));
        }
        if !api_base.path().ends_with('/') {
            return Err(ApiError::InvalidEndpoint(
                "endpoint base path must end in `/`".into(),
            ));
        }
        Ok(Self { kind, api_base })
    }

    /// Resolve a caller-supplied `path` against `api_base`, refusing
    /// anything that leaves the origin, climbs above the API path
    /// prefix, or could climb once the server decodes it. **Used for
    /// BOTH human and agent requests** — the host is never caller-chosen.
    ///
    /// Three checks on the *resolved* URL:
    /// 1. same origin (scheme + host + port) — catches absolute and
    ///    protocol-relative references that would repoint the host (SSRF);
    /// 2. resolved path is at/under the base path — catches absolute
    ///    paths and literal `../` traversal (`url` normalizes those);
    /// 3. NO `%` and no `;` in the resolved path. `url` does NOT treat
    ///    `..%2f`, overlong-UTF-8 (`..%c0%af`), or a percent-encoded
    ///    unicode slash (`..／` → `%ef%bc%8f`) as dot-segments, so check (2)
    ///    passes them through intact; a controller that decodes-then-routes
    ///    (UniFi runs Java behind nginx) could then climb above the base
    ///    path. We refuse ANY percent-encoding in the PATH — an allowlist,
    ///    not a per-encoding denylist, so overlong-UTF-8 / unicode /
    ///    double-encoding are all closed at once — plus `;` matrix params.
    ///    Legitimate UniFi paths carry no `%` in the path component; the
    ///    query string is EXCLUDED (`path()` returns only the path
    ///    component), so encoded values in `?query` are unaffected.
    pub fn confine(&self, path: &str) -> Result<Url, ApiError> {
        let resolved = self
            .api_base
            .join(path)
            .map_err(|source| ApiError::InvalidPath {
                path: path.to_string(),
                source,
            })?;
        if resolved.origin() != self.api_base.origin() {
            return Err(ApiError::HostEscape {
                expected: origin_display(&self.api_base),
                got: origin_display(&resolved),
            });
        }
        if !resolved.path().starts_with(self.api_base.path()) {
            return Err(ApiError::PathEscape {
                base: self.api_base.path().to_string(),
            });
        }
        // Encoded-traversal / path-confusion defense (see the doc
        // comment): a decoding server (UniFi runs Java behind nginx) can
        // turn a percent-encoded byte in the PATH into a separator/dot and
        // climb above the base — `url` leaves `..%2f`, overlong-UTF-8
        // (`..%c0%af`), and percent-encoded unicode slashes (`..／` →
        // `%ef%bc%8f`) intact, so check (2) alone passes them. Refuse ANY
        // `%` in the resolved PATH (an allowlist, not a per-encoding
        // denylist, so overlong-UTF-8 / unicode / double-encoding are all
        // closed at once) plus `;` matrix parameters. The query string is
        // excluded — `path()` omits it — so encoded `?query` values are
        // unaffected, and legitimate UniFi paths carry no `%` in the path.
        let path_component = resolved.path();
        if path_component.contains('%') || path_component.contains(';') {
            return Err(ApiError::PathEscape {
                base: self.api_base.path().to_string(),
            });
        }
        Ok(resolved)
    }
}

fn origin_display(url: &Url) -> String {
    match url.origin() {
        Origin::Tuple(scheme, host, port) => format!("{scheme}://{host}:{port}"),
        Origin::Opaque(_) => "<opaque>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_manager_base_is_trailing_slash_https() {
        let ep = Endpoint::site_manager();
        assert_eq!(ep.api_base().as_str(), "https://api.ui.com/");
        assert!(ep.api_base().path().ends_with('/'));
        assert_eq!(ep.kind(), EndpointKind::SiteManager);
    }

    #[test]
    fn generic_https_base_gets_trailing_slash() {
        let ep = Endpoint::generic("https://swapi.dev/api").unwrap();
        assert_eq!(ep.api_base().as_str(), "https://swapi.dev/api/");
        assert_eq!(ep.kind(), EndpointKind::Generic);
        // Confines a resource path under the base, host-pinned.
        let url = ep.confine("people/1/").unwrap();
        assert_eq!(url.as_str(), "https://swapi.dev/api/people/1/");
    }

    #[test]
    fn generic_permits_http_for_local_testing() {
        // The one kind that allows http — a dev testing a loopback API.
        let ep = Endpoint::generic("http://localhost:8080").unwrap();
        assert_eq!(ep.api_base().as_str(), "http://localhost:8080/");
        assert_eq!(ep.confine("v2/things").unwrap().scheme(), "http");
    }

    #[test]
    fn generic_rejects_non_http_scheme() {
        for evil in ["ftp://h/x", "file:///etc/passwd", "data:text/plain,x"] {
            assert!(
                matches!(Endpoint::generic(evil), Err(ApiError::InvalidEndpoint(_))),
                "`{evil}` must be refused"
            );
        }
    }

    #[test]
    fn generic_rejects_embedded_credentials_and_junk() {
        // A URL-embedded password would bypass the sensitive-header path.
        assert!(Endpoint::generic("https://user:pass@api.example/").is_err());
        assert!(Endpoint::generic("https://user@api.example/").is_err());
        // Not a URL / empty.
        assert!(Endpoint::generic("not a url").is_err());
        assert!(Endpoint::generic("").is_err());
        assert!(Endpoint::generic("swapi.dev/api").is_err()); // no scheme
    }

    #[test]
    fn generic_drops_query_and_fragment_on_the_base() {
        let ep = Endpoint::generic("https://api.example/base?x=1#frag").unwrap();
        assert_eq!(ep.api_base().as_str(), "https://api.example/base/");
    }

    #[test]
    fn non_generic_kinds_still_require_https() {
        // The http relaxation is Generic-ONLY — network_local still forces https.
        let ep = Endpoint::network_local("10.0.0.1").unwrap();
        assert_eq!(ep.api_base().scheme(), "https");
    }

    #[test]
    fn network_local_builds_expected_base() {
        let ep = Endpoint::network_local("192.168.1.1").unwrap();
        assert_eq!(
            ep.api_base().as_str(),
            "https://192.168.1.1/proxy/network/integration/v1/"
        );
        // host:port is honored.
        let ep = Endpoint::network_local("udm.lan:8443").unwrap();
        assert_eq!(
            ep.api_base().as_str(),
            "https://udm.lan:8443/proxy/network/integration/v1/"
        );
        // bracketed IPv6 literal is allowed.
        let ep = Endpoint::network_local("[2001:db8::1]").unwrap();
        assert_eq!(ep.api_base().host_str(), Some("[2001:db8::1]"));
    }

    #[test]
    fn network_local_rejects_host_injection() {
        for bad in [
            "",
            "   ",
            "a/b",                // path smuggling
            "user@evil.com",      // userinfo → real host would be evil.com
            "good.com/../evil",   // path
            "good.com?x=1",       // query
            "good.com#frag",      // fragment
            "has space",          // whitespace
            "good.com\\evil.com", // backslash
            "evil\n.com",         // newline (would be stripped by the parser)
            "evil\r.com",         // carriage return
            "127.0.0.1\u{3002}x", // ideographic full stop → '.' via IDNA
            "①.example",          // non-ASCII digit → IDNA remap
        ] {
            assert!(
                Endpoint::network_local(bad).is_err(),
                "host `{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn connector_proxy_validates_console_id() {
        let ep = Endpoint::connector_proxy("70A7-41B2-console").unwrap();
        assert_eq!(
            ep.api_base().as_str(),
            "https://api.ui.com/v1/connector/consoles/70A7-41B2-console/proxy/network/integration/v1/"
        );
        for bad in ["", "a/b", "a..b", "a b", "a/../b", "id#x", "id?y"] {
            assert!(
                Endpoint::connector_proxy(bad).is_err(),
                "console id `{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn confine_allows_paths_under_base() {
        let ep = Endpoint::network_local("10.0.0.1").unwrap();
        for ok in ["sites", "sites/default", "devices/abc?limit=10", "info"] {
            let url = ep
                .confine(ok)
                .unwrap_or_else(|e| panic!("`{ok}` should confine: {e}"));
            assert_eq!(url.origin(), ep.api_base().origin());
            assert!(url.path().starts_with("/proxy/network/integration/v1/"));
        }
    }

    #[test]
    fn confine_rejects_host_escapes() {
        let ep = Endpoint::network_local("10.0.0.1").unwrap();
        for evil in [
            "https://evil.example/x", // absolute URL
            "//evil.example/x",       // protocol-relative
        ] {
            let err = ep.confine(evil).unwrap_err();
            assert!(
                matches!(err, ApiError::HostEscape { .. }),
                "`{evil}` → {err:?}"
            );
        }
    }

    #[test]
    fn confine_rejects_path_escapes() {
        let ep = Endpoint::network_local("10.0.0.1").unwrap();
        for evil in [
            "/etc/passwd",       // absolute path off the prefix
            "../../../../admin", // literal traversal above the prefix
            "../v1sites",        // prefix-boundary masquerade
        ] {
            let err = ep.confine(evil).unwrap_err();
            assert!(
                matches!(err, ApiError::PathEscape { .. }),
                "`{evil}` → {err:?}"
            );
        }
    }

    #[test]
    fn confine_rejects_encoded_traversal() {
        // MEDIUM-1 class: `url` does not treat these as dot-segments, so
        // the base-path pin must reject the encoded/matrix forms outright.
        let ep = Endpoint::network_local("10.0.0.1").unwrap();
        for evil in [
            "..%2f..%2f..%2fadmin",    // encoded-slash climb
            "%2e%2e%2fadmin",          // encoded dot + slash
            "..;/..;/admin",           // matrix-parameter climb
            "sites%2f..%2f..%2fhosts", // encoded slash mid-path
            "%252e%252e%252fadmin",    // double-encoded
            // Adversarial-review additions (2026-07-30): the "reject ANY %
            // in the path" allowlist closes the overlong-UTF-8 + unicode-
            // slash climbs the old per-encoding denylist let through.
            "..%c0%afadmin",                 // 2-byte overlong-UTF-8 `/`
            "..%c0%af..%c0%af..%c0%afadmin", // repeated overlong `/`
            "..%e0%80%afadmin",              // 3-byte overlong-UTF-8 `/`
            "..／admin",                     // U+FF0F fullwidth solidus
            "..∕admin",                      // U+2215 division slash
            "..⁄admin",                      // U+2044 fraction slash
        ] {
            let err = ep.confine(evil).unwrap_err();
            assert!(
                matches!(err, ApiError::PathEscape { .. }),
                "`{evil}` must be a PathEscape, got {err:?}"
            );
        }
    }

    #[test]
    fn confine_connector_proxy_blocks_sibling_console_climb() {
        // Worst case from the review: on the deep connector-proxy base an
        // encoded-slash climb would otherwise reach `/v1/hosts` or a
        // sibling console — all on api.ui.com with the same key.
        let ep = Endpoint::connector_proxy("AAAA-BBBB-c1").unwrap();
        assert!(matches!(
            ep.confine("..%2f..%2f..%2f..%2f..%2f..%2fhosts"),
            Err(ApiError::PathEscape { .. })
        ));
        assert!(matches!(
            ep.confine("..%2f..%2fAAAA-BBBB-c2%2fproxy%2fnetwork%2fintegration%2fv1%2fsites"),
            Err(ApiError::PathEscape { .. })
        ));
    }

    #[test]
    fn confine_on_site_manager_allows_any_same_host_path_but_pins_host() {
        let ep = Endpoint::site_manager();
        // Root base ⇒ any api.ui.com path is in-base (host is all API).
        assert!(ep.confine("v1/hosts").is_ok());
        assert!(ep.confine("ea/isp-metrics/1h").is_ok());
        // …but the host is still pinned.
        assert!(matches!(
            ep.confine("//evil.example/x"),
            Err(ApiError::HostEscape { .. })
        ));
        assert!(matches!(
            ep.confine("https://evil.example/x"),
            Err(ApiError::HostEscape { .. })
        ));
    }
}
