//! Pluggable per-request auth for API sessions.
//!
//! [`AppliedAuth`] is the RESOLVED auth for one request — built by the caller
//! (which owns `SecretRef` → `SecretString` resolution) from the controller's
//! configured scheme. `transit_api` sets the right header, marks it sensitive,
//! and NEVER logs it or places it in the URL. `None` sends no auth (a public
//! API such as swapi.dev). This generalizes the original hardcoded `X-API-KEY`
//! injection so generic vendors can use Bearer / Basic / a custom key header /
//! nothing at all — while the secret still enters only here, at the transport
//! boundary, never crossing to the agent.

use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use secrecy::{ExposeSecret, SecretString};

use crate::error::ApiError;

/// The resolved auth to apply to one outgoing request.
#[derive(Debug)]
pub enum AppliedAuth {
    /// No auth header — a public API.
    None,
    /// A custom header carrying the key value (generalizes UniFi's
    /// `X-API-KEY`; the header name is caller-chosen — `x-api-key`, `apikey`,
    /// `X-Auth-Token`, …). `value_prefix` is non-secret text prepended
    /// verbatim to the key — `"Token "` produces NetBox's
    /// `Authorization: Token <key>`; empty produces the bare key, the
    /// historic shape.
    ApiKey {
        header: HeaderName,
        value_prefix: String,
        key: SecretString,
    },
    /// `Authorization: Bearer <token>`.
    Bearer { token: SecretString },
    /// `Authorization: Basic base64(username:password)`.
    Basic {
        username: String,
        password: SecretString,
    },
}

impl AppliedAuth {
    /// Build an API-key scheme from a caller-supplied header NAME, a
    /// non-secret value prefix (may be empty), and the resolved key. Refuses
    /// an invalid header name up front.
    pub fn api_key(
        header_name: &str,
        value_prefix: &str,
        key: SecretString,
    ) -> Result<Self, ApiError> {
        let header = HeaderName::from_bytes(header_name.trim().as_bytes())
            .map_err(|_| ApiError::InvalidHeader(header_name.to_string()))?;
        Ok(AppliedAuth::ApiKey {
            header,
            value_prefix: value_prefix.to_string(),
            key,
        })
    }

    /// The header this scheme owns — so [`send`](crate::ApiClient::send) can
    /// strip any caller-supplied copy before injecting its own. `None` owns
    /// nothing (and does not strip a human's manually-set `Authorization`).
    pub(crate) fn owned_header(&self) -> Option<HeaderName> {
        match self {
            AppliedAuth::None => None,
            AppliedAuth::ApiKey { header, .. } => Some(header.clone()),
            AppliedAuth::Bearer { .. } | AppliedAuth::Basic { .. } => Some(AUTHORIZATION),
        }
    }

    /// Insert the sensitive auth value for the owned header. The caller must
    /// have already stripped any caller-supplied copy (via [`owned_header`]).
    /// A no-op for `None`.
    pub(crate) fn apply(&self, headers: &mut HeaderMap) -> Result<(), ApiError> {
        let value = match self {
            AppliedAuth::None => return Ok(()),
            AppliedAuth::ApiKey {
                key, value_prefix, ..
            } => format!("{value_prefix}{}", key.expose_secret()),
            AppliedAuth::Bearer { token } => format!("Bearer {}", token.expose_secret()),
            AppliedAuth::Basic { username, password } => {
                let creds = STANDARD.encode(format!("{username}:{}", password.expose_secret()));
                format!("Basic {creds}")
            }
        };
        let header = self
            .owned_header()
            .expect("a non-None scheme always owns a header");
        let mut hv = HeaderValue::from_str(&value).map_err(|_| ApiError::InvalidKey)?;
        hv.set_sensitive(true);
        headers.insert(header, hv);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(a: &AppliedAuth) -> HeaderMap {
        let mut h = HeaderMap::new();
        a.apply(&mut h).expect("apply");
        h
    }

    #[test]
    fn none_sets_no_header_and_owns_nothing() {
        let h = apply(&AppliedAuth::None);
        assert!(h.is_empty());
        assert!(AppliedAuth::None.owned_header().is_none());
    }

    #[test]
    fn api_key_sets_the_custom_header_marked_sensitive() {
        let a = AppliedAuth::api_key("X-Auth-Token", "", SecretString::from("SEK")).unwrap();
        let h = apply(&a);
        assert_eq!(h.get("x-auth-token").unwrap(), "SEK");
        assert!(h.get("x-auth-token").unwrap().is_sensitive());
        assert_eq!(a.owned_header().unwrap().as_str(), "x-auth-token");
    }

    #[test]
    fn api_key_empty_prefix_is_byte_identical_to_the_bare_key() {
        // The pre-value_prefix behavior: header value IS the key, nothing else.
        let a = AppliedAuth::api_key("X-API-KEY", "", SecretString::from("k3y")).unwrap();
        let h = apply(&a);
        assert_eq!(h.get("x-api-key").unwrap().as_bytes(), b"k3y");
    }

    #[test]
    fn api_key_value_prefix_prepends_verbatim_netbox_shape() {
        let a =
            AppliedAuth::api_key("Authorization", "Token ", SecretString::from("abc123")).unwrap();
        let h = apply(&a);
        assert_eq!(h.get(AUTHORIZATION).unwrap(), "Token abc123");
        assert!(h.get(AUTHORIZATION).unwrap().is_sensitive());
    }

    #[test]
    fn bearer_sets_authorization_bearer() {
        let a = AppliedAuth::Bearer {
            token: SecretString::from("tok123"),
        };
        let h = apply(&a);
        assert_eq!(h.get(AUTHORIZATION).unwrap(), "Bearer tok123");
        assert!(h.get(AUTHORIZATION).unwrap().is_sensitive());
    }

    #[test]
    fn basic_base64_encodes_user_and_password() {
        let a = AppliedAuth::Basic {
            username: "aladdin".into(),
            password: SecretString::from("opensesame"),
        };
        let h = apply(&a);
        // base64("aladdin:opensesame") == "YWxhZGRpbjpvcGVuc2VzYW1l"
        assert_eq!(
            h.get(AUTHORIZATION).unwrap(),
            "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
        );
        assert!(h.get(AUTHORIZATION).unwrap().is_sensitive());
    }

    #[test]
    fn api_key_rejects_an_invalid_header_name() {
        assert!(AppliedAuth::api_key("bad header", "", SecretString::from("k")).is_err());
        assert!(AppliedAuth::api_key("", "", SecretString::from("k")).is_err());
    }
}
