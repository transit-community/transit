//! The **agent-only** read-only gate for API sessions.
//!
//! This is the HTTP-world analog of `transit_policy`'s command gate, but
//! far simpler and harder to get wrong: the read-only floor is a single
//! HTTP method. A GET cannot create / update / delete by REST
//! semantics, so "investigate-only" holds by construction rather than by
//! pattern-matching a command string.
//!
//! Human (Postman) requests do NOT come through here — they are ungated
//! by design (see the crate docs). Every AGENT-proposed request does.

use url::Url;

use crate::endpoint::Endpoint;

/// The verdict for an agent-proposed API call. Mirrors
/// `transit_policy::Decision`'s default-deny shape. `Allow` carries the
/// already-confined URL so the executor sends *exactly* what was
/// adjudicated — there is no gap between the check and the send.
#[derive(Debug, Clone)]
pub enum ApiDecision {
    Allow { url: Url },
    Deny { reason: String },
}

impl ApiDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, ApiDecision::Allow { .. })
    }
}

/// Adjudicate an agent-proposed API call. Two conditions, both required:
///
/// 1. `method` is GET (compared case-insensitively). This is the whole
///    investigate-only guarantee. The agent's tool has no method field
///    — GET is implicit — so this is defense-in-depth against any future
///    caller that reaches this function with something else.
/// 2. `path` [confines](Endpoint::confine) to `endpoint`: same origin,
///    at or under the API base path, with no encoded/matrix traversal.
///
/// Default-deny: anything else is [`ApiDecision::Deny`]. The deny reason
/// names the rule class (so the model can correct course) but never
/// enumerates the allowed surface.
pub fn evaluate_agent_get(endpoint: &Endpoint, method: &str, path: &str) -> ApiDecision {
    if !method.eq_ignore_ascii_case("GET") {
        return ApiDecision::Deny {
            reason: "investigate-only: the agent may issue GET requests only".to_string(),
        };
    }
    match endpoint.confine(path) {
        Ok(url) => ApiDecision::Allow { url },
        Err(e) => ApiDecision::Deny {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ep() -> Endpoint {
        Endpoint::network_local("10.0.0.1").unwrap()
    }

    #[test]
    fn get_under_prefix_is_allowed() {
        let d = evaluate_agent_get(&ep(), "GET", "sites");
        match d {
            ApiDecision::Allow { url } => {
                assert_eq!(url.path(), "/proxy/network/integration/v1/sites");
            }
            ApiDecision::Deny { reason } => panic!("expected allow, got deny: {reason}"),
        }
    }

    #[test]
    fn get_is_case_insensitive() {
        assert!(evaluate_agent_get(&ep(), "get", "sites").is_allow());
        assert!(evaluate_agent_get(&ep(), "GeT", "sites").is_allow());
    }

    #[test]
    fn non_get_methods_are_denied() {
        for m in [
            "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "",
        ] {
            let d = evaluate_agent_get(&ep(), m, "sites");
            assert!(!d.is_allow(), "method `{m}` must be denied but was allowed");
        }
    }

    #[test]
    fn get_that_escapes_the_host_is_denied() {
        assert!(!evaluate_agent_get(&ep(), "GET", "https://evil.example/x").is_allow());
        assert!(!evaluate_agent_get(&ep(), "GET", "//evil.example/x").is_allow());
        assert!(!evaluate_agent_get(&ep(), "GET", "/etc/passwd").is_allow());
        assert!(!evaluate_agent_get(&ep(), "GET", "../../../../admin").is_allow());
    }

    #[test]
    fn get_with_encoded_traversal_is_denied() {
        // The MEDIUM-1 class: `url` does not treat these as dot-segments,
        // so the gate (via `confine`) must reject them explicitly.
        for evil in [
            "..%2f..%2fadmin",
            "%2e%2e%2fadmin",
            "..;/..;/admin",
            "sites%2f..%2f..%2fhosts",
        ] {
            assert!(
                !evaluate_agent_get(&ep(), "GET", evil).is_allow(),
                "encoded-traversal `{evil}` must be denied"
            );
        }
    }

    proptest! {
        /// Same-`url`-view invariant: NOTHING but a GET whose resolved
        /// URL stays on the endpoint's origin and under its API base path
        /// may be allowed. (This asserts the properties `confine` itself
        /// checks, so it cannot by itself catch a `url`-view-vs-server
        /// divergence — the encoded-traversal corpus in
        /// `get_with_encoded_traversal_is_denied` +
        /// `endpoint::tests::confine_rejects_encoded_traversal` covers
        /// that class explicitly.)
        #[test]
        fn only_confined_gets_are_ever_allowed(
            method in "[A-Za-z]{0,8}",
            path in ".*",
        ) {
            let endpoint = ep();
            let decision = evaluate_agent_get(&endpoint, &method, &path);
            if let ApiDecision::Allow { url } = decision {
                prop_assert!(method.eq_ignore_ascii_case("GET"));
                prop_assert_eq!(url.origin(), endpoint.api_base().origin());
                prop_assert!(url.path().starts_with(endpoint.api_base().path()));
            }
        }

        /// Any non-GET method, regardless of path, is denied.
        #[test]
        fn no_non_get_ever_allowed(
            method in "[A-Za-z]{1,8}",
            path in ".*",
        ) {
            prop_assume!(!method.eq_ignore_ascii_case("GET"));
            let decision = evaluate_agent_get(&ep(), &method, &path);
            prop_assert!(!decision.is_allow());
        }
    }
}
