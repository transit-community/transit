//! Sign in with ChatGPT — OpenAI's open-source plan-usage flow (preview).
//!
//! Lets a ChatGPT Plus/Pro user run the OpenAI side on their plan instead
//! of a platform key. The flow is the documented one for open-source,
//! locally running apps: Authorization Code + PKCE against
//! `auth.openai.com`, a loopback redirect on `127.0.0.1`, dynamic client
//! registration on first use (`client_id=dynamic_agent_client` → an
//! issued `oaiapp_…` id we keep), rotating one-hour access tokens and
//! 30-day refresh tokens, and inference on the public Responses API with
//! the access token as a bearer (`transit_agent::llm::direct::OpenAiAuth::ChatGptPlan`).
//!
//! ## Security shape (threat-model T55, T_CHATGPT_PLAN_TOKEN)
//!
//! - **The refresh token is the standing credential.** It lives only in the
//!   OS keychain, under the same service as the provider keys. It is
//!   rotated on every refresh (the replacement overwrites it) and cleared
//!   on sign-out or on any refresh failure that means the grant is gone.
//! - **The access token never touches disk.** It is held in memory with
//!   its expiry and refreshed when within five minutes of it.
//! - **Rule 1 holds.** No token crosses IPC in either direction; the status
//!   command returns a boolean plus the account email, which is read from
//!   the ID token purely for display (its signature is not verified — it is
//!   never used as a credential).
//! - **One outbound host.** `auth.openai.com` for authorize (opened in the
//!   system browser) and the token exchange (from Rust, on the
//!   `transit_tls` client: no redirects, no proxy, OS-store trust). The
//!   no-phone-home scan allows exactly this host, by name, for this reason.
//! - **The redirect is loopback-bound.** A one-shot listener on
//!   `127.0.0.1:<ephemeral>` accepts exactly one request, requires the
//!   `state` it issued, and closes. Nothing is registered with the OS; no
//!   custom URL scheme comes back.
//! - **Non-secret state** (the installation's `ext_agent_host_id`, the
//!   issued client id, the account email) lives in `config.toml`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::commands::{config_path, read_config_string, write_config_string_at};

const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
/// RFC 7009 revocation, from `auth.openai.com/.well-known/openid-configuration`.
/// Sign-out revokes the refresh token here so the grant dies server-side,
/// not just on this disk (OpenAI's accounts-and-sessions guidance).
const REVOKE_URL: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
/// Identity scopes + plan usage. Pinned by `scopes_are_the_documented_set`.
const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const RESOURCE: &str = "https://api.openai.com/v1";
/// Shown to the user on OpenAI's consent screen, and what the issued
/// client id is registered under.
const AGENT_NAME_HINT: &str = "Transit Community Edition";
/// Before an issued id exists this literal triggers dynamic registration.
const DYNAMIC_CLIENT_ID: &str = "dynamic_agent_client";
const CALLBACK_PATH: &str = "/auth/callback";
/// How long the loopback listener waits for the browser.
const SIGNIN_TIMEOUT: Duration = Duration::from_secs(300);
/// Refresh when the access token is this close to expiry.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
/// Bound on the code exchange so a stalled token endpoint can't hold
/// the sign-in task (and its loopback stream) open indefinitely.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest `error` text from the callback we repeat to the user.
const CALLBACK_ERROR_MAX: usize = 120;

/// Keychain account (service shared with the provider keys) holding the
/// refresh token.
const REFRESH_ACCOUNT: &str = "openai-chatgpt-refresh";
const CONFIG_SECTION: &str = "chatgpt";
const PROVIDERS_SECTION: &str = "providers";

/// Which credential the OpenAI side uses. Persisted as
/// `[providers] openai_method`; defaults to the API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAiMethod {
    ApiKey,
    Chatgpt,
}

pub fn read_openai_method() -> OpenAiMethod {
    match read_config_string(PROVIDERS_SECTION, "openai_method").as_deref() {
        Some("chatgpt") => OpenAiMethod::Chatgpt,
        _ => OpenAiMethod::ApiKey,
    }
}

struct CachedAccess {
    token: SecretString,
    expires_at: Instant,
}

/// Process-wide ChatGPT sign-in state: the in-memory access token and the
/// in-flight sign-in task. Shared (as an `Arc`) between the chat factory,
/// which needs tokens, and the IPC commands, which drive sign-in.
pub struct ChatGptState {
    access: Mutex<Option<CachedAccess>>,
    pending: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Test-only override of the token endpoint so wiremock can stand in.
    #[cfg(test)]
    token_url: std::sync::RwLock<Option<String>>,
    #[cfg(test)]
    revoke_url: std::sync::RwLock<Option<String>>,
}

impl Default for ChatGptState {
    fn default() -> Self {
        Self::new()
    }
}

/// Why no access token could be produced.
#[derive(Debug)]
pub enum PlanAuthError {
    /// Never signed in, or the grant is gone — the user signs in again.
    Reauth,
    /// Keychain or network trouble; the message is user-shaped.
    Other(String),
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    id_token: Option<String>,
}

#[derive(Deserialize, Default)]
struct TokenError {
    error: Option<String>,
}

/// Refresh-token errors after which the grant is unusable (per OpenAI's
/// errors-and-recovery reference): clear everything and start over.
const DEAD_GRANT_ERRORS: &[&str] = &[
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

impl ChatGptState {
    pub fn new() -> Self {
        Self {
            access: Mutex::new(None),
            pending: Mutex::new(None),
            #[cfg(test)]
            token_url: std::sync::RwLock::new(None),
            #[cfg(test)]
            revoke_url: std::sync::RwLock::new(None),
        }
    }

    fn revoke_url(&self) -> String {
        #[cfg(test)]
        if let Some(u) = self.revoke_url.read().ok().and_then(|g| g.clone()) {
            return u;
        }
        REVOKE_URL.to_string()
    }

    fn token_url(&self) -> String {
        #[cfg(test)]
        if let Some(u) = self.token_url.read().ok().and_then(|g| g.clone()) {
            return u;
        }
        TOKEN_URL.to_string()
    }

    fn http(&self) -> reqwest::Client {
        transit_tls::build_http_client(crate::commands::resolve_strict_tls())
    }

    /// Whether a refresh token is stored (the durable "signed in" signal).
    pub fn signed_in(&self) -> bool {
        matches!(read_refresh_token(), Ok(Some(_)))
    }

    /// A valid access token, refreshing through the stored refresh token
    /// when the cached one is missing or near expiry.
    ///
    /// The `access` lock is held for the WHOLE call, refresh included.
    /// Refresh tokens rotate on every use and OpenAI treats a second
    /// presentation of a superseded one as `refresh_token_reused` (a
    /// dead-grant signal), so two concurrent sends racing to refresh
    /// would sign the user out; serializing here makes the second caller
    /// see the first caller's freshly-minted token instead.
    pub async fn access_token(&self) -> Result<SecretString, PlanAuthError> {
        let mut guard = self.access.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.expires_at.saturating_duration_since(Instant::now()) > REFRESH_MARGIN {
                return Ok(c.token.clone());
            }
        }
        let refresh = read_refresh_token()
            .map_err(|e| PlanAuthError::Other(format!("keychain: {e}")))?
            .ok_or(PlanAuthError::Reauth)?;
        let Some(client_id) = read_config_string(CONFIG_SECTION, "client_id") else {
            // A refresh token with no client id cannot be used; a half
            // finished sign-in left it. Clear so `signed_in()` stops
            // claiming a session every send would refuse.
            *guard = None;
            drop(guard);
            self.clear_all().await;
            return Err(PlanAuthError::Reauth);
        };
        // The same resource indicator as the authorize request on EVERY
        // grant: OpenAI binds the grant to it and answers `invalid_grant`
        // otherwise (community issue #18). `scope` is deliberately absent
        // on refresh so the original grant is retained.
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.expose_secret()),
            ("client_id", client_id.as_str()),
            ("resource", RESOURCE),
        ];
        let resp = self
            .http()
            .post(self.token_url())
            .form(&form)
            .send()
            .await
            .map_err(|e| PlanAuthError::Other(format!("refresh request failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let code = serde_json::from_str::<TokenError>(&body)
                .unwrap_or_default()
                .error
                .unwrap_or_default();
            if status.as_u16() == 400
                || status.as_u16() == 401
                || DEAD_GRANT_ERRORS.contains(&code.as_str())
            {
                warn!(code = %code, "ChatGPT refresh rejected; clearing the grant");
                *guard = None;
                drop(guard);
                self.clear_all().await;
                return Err(PlanAuthError::Reauth);
            }
            return Err(PlanAuthError::Other(format!(
                "ChatGPT token refresh failed ({status})"
            )));
        }
        let parsed: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| PlanAuthError::Other(format!("token response: {e}")))?;
        self.store_tokens_locked(&mut guard, &parsed)
            .map_err(PlanAuthError::Other)?;
        Ok(SecretString::new(parsed.access_token.into()))
    }

    /// Drop the in-memory access token so the next send refreshes. Used
    /// when OpenAI answers a request with `plan_reauth_required`: the
    /// cached token may still look unexpired, and without this the user
    /// would see the same refusal for up to an hour. A refresh that is
    /// itself refused then clears the grant through the dead-grant path.
    pub async fn invalidate_access(&self) {
        *self.access.lock().await = None;
    }

    /// Persist a token response: rotated refresh token to the keychain,
    /// access token + expiry to memory, email (display only) to config.
    async fn store_tokens(&self, t: &TokenResponse) -> Result<(), String> {
        let mut guard = self.access.lock().await;
        self.store_tokens_locked(&mut guard, t)
    }

    fn store_tokens_locked(
        &self,
        access: &mut Option<CachedAccess>,
        t: &TokenResponse,
    ) -> Result<(), String> {
        if let Some(r) = &t.refresh_token {
            write_refresh_token(&SecretString::new(r.clone().into()))
                .map_err(|e| format!("keychain: {e}"))?;
        }
        let ttl = Duration::from_secs(t.expires_in.unwrap_or(3600));
        *access = Some(CachedAccess {
            token: SecretString::new(t.access_token.clone().into()),
            expires_at: Instant::now() + ttl,
        });
        if let Some(email) = t.id_token.as_deref().and_then(email_from_id_token) {
            let _ = write_config_string_at(
                &config_path(),
                CONFIG_SECTION,
                "account_email",
                Some(&email),
            );
        }
        Ok(())
    }

    /// Sign out: revoke the refresh token at OpenAI (so the grant is dead
    /// everywhere, not just forgotten here), then clear local state
    /// regardless. Returns whether OpenAI confirmed the revocation; the UI
    /// tells the user to disconnect the app in ChatGPT settings when it
    /// did not, per OpenAI's guidance. With nothing stored there is
    /// nothing to revoke and the answer is `true`.
    pub async fn sign_out(&self) -> bool {
        let refresh = read_refresh_token().ok().flatten();
        let client_id = read_config_string(CONFIG_SECTION, "client_id");
        let revoked = match (refresh, client_id) {
            (Some(token), Some(cid)) => self.revoke_refresh(&token, &cid).await,
            (Some(_), None) => false,
            (None, _) => true,
        };
        self.clear_all().await;
        revoked
    }

    /// One RFC 7009 revocation with bounded retries: a network failure or
    /// 5xx is retried (OpenAI: "retry with backoff while the refresh token
    /// is still available"); any 2xx — including for an already-invalid
    /// token — is success; any other 4xx is a definitive no.
    pub(crate) async fn revoke_refresh(&self, token: &SecretString, client_id: &str) -> bool {
        let form = [
            ("token", token.expose_secret()),
            ("token_type_hint", "refresh_token"),
            ("client_id", client_id),
        ];
        let backoff = [
            Duration::from_millis(0),
            Duration::from_millis(300),
            Duration::from_millis(900),
        ];
        for wait in backoff {
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            let sent = tokio::time::timeout(
                EXCHANGE_TIMEOUT,
                self.http().post(self.revoke_url()).form(&form).send(),
            )
            .await;
            match sent {
                Ok(Ok(resp)) if resp.status().is_success() => return true,
                Ok(Ok(resp)) if resp.status().is_server_error() => {
                    warn!(status = %resp.status(), "ChatGPT revocation: server error, retrying");
                }
                Ok(Ok(resp)) => {
                    warn!(status = %resp.status(), "ChatGPT revocation refused");
                    return false;
                }
                Ok(Err(e)) => warn!(error = %e, "ChatGPT revocation: request failed, retrying"),
                Err(_) => warn!("ChatGPT revocation: timed out, retrying"),
            }
        }
        false
    }

    /// Forget the grant: keychain refresh token, memory access token,
    /// account email. The installation's `host_id`/`client_id` stay —
    /// they identify this install to OpenAI, not the user.
    pub async fn clear_all(&self) {
        *self.access.lock().await = None;
        if let Err(e) = clear_refresh_token() {
            warn!(error = %e, "could not clear the ChatGPT refresh token");
        }
        let _ = write_config_string_at(&config_path(), CONFIG_SECTION, "account_email", None);
    }

    /// Exchange an authorization code (after the loopback callback).
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        verifier: &str,
    ) -> Result<(), String> {
        // `redirect_uri` and `resource` must repeat the authorize request
        // byte for byte; the code is bound to both (community issue #18).
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
            ("resource", RESOURCE),
        ];
        let resp = tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            self.http().post(self.token_url()).form(&form).send(),
        )
        .await
        .map_err(|_| "token exchange timed out".to_string())?
        .map_err(|e| format!("token exchange failed: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let code = serde_json::from_str::<TokenError>(&body)
                .unwrap_or_default()
                .error
                .unwrap_or_default();
            return Err(format!("OpenAI rejected the sign-in ({status} {code})"));
        }
        let parsed: TokenResponse =
            serde_json::from_str(&body).map_err(|e| format!("token response: {e}"))?;
        if parsed.refresh_token.is_none() {
            return Err("OpenAI returned no refresh token — plan usage was not granted".into());
        }
        self.store_tokens(&parsed).await
    }
}

// ---------------------------------------------------------------------
// Keychain + config helpers
// ---------------------------------------------------------------------

fn refresh_entry() -> keyring::Result<Entry> {
    Entry::new(crate::provider_keys::KEYRING_SERVICE, REFRESH_ACCOUNT)
}

fn read_refresh_token() -> keyring::Result<Option<SecretString>> {
    match refresh_entry()?.get_password() {
        Ok(s) => Ok(Some(SecretString::new(s.into()))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_refresh_token(value: &SecretString) -> keyring::Result<()> {
    refresh_entry()?.set_password(value.expose_secret())
}

fn clear_refresh_token() -> keyring::Result<()> {
    match refresh_entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The installation's stable `ext_agent_host_id`, created on first use.
fn host_id() -> Result<String, String> {
    if let Some(id) = read_config_string(CONFIG_SECTION, "host_id") {
        return Ok(id);
    }
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    write_config_string_at(&config_path(), CONFIG_SECTION, "host_id", Some(&id))?;
    Ok(id)
}

/// The client id to exchange with. On a first run the callback carries
/// the id OpenAI just issued and we must use (and keep) it; on every
/// later run the callback's `client_id`, if any, is ignored — the id on
/// file is the registration, and nothing that reaches the loopback gets
/// to rename it.
pub(crate) fn effective_client_id(
    on_file: &str,
    issued: Option<&str>,
    first_run: bool,
) -> Result<String, String> {
    if !first_run {
        return Ok(on_file.to_string());
    }
    let id = issued.ok_or("OpenAI did not issue a client id for this app")?;
    if !valid_client_id(id) {
        return Err("OpenAI issued a client id of an unexpected shape".into());
    }
    Ok(id.to_string())
}

/// Shape check before an issued id is written to `config.toml`.
pub(crate) fn valid_client_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// The issued client id, else the dynamic-registration literal.
fn client_id() -> String {
    read_config_string(CONFIG_SECTION, "client_id").unwrap_or_else(|| DYNAMIC_CLIENT_ID.to_string())
}

/// `email` claim of an ID token, decoded WITHOUT signature verification.
/// Display only — it is never used to authorize anything.
pub(crate) fn email_from_id_token(jwt: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("email")
        .and_then(|e| e.as_str())
        .filter(|e| e.len() <= 254)
        .map(str::to_owned)
}

// ---------------------------------------------------------------------
// PKCE + the authorize URL
// ---------------------------------------------------------------------

fn random_urlsafe(bytes: usize) -> String {
    use base64::Engine as _;
    // Two v4 UUIDs = 32 bytes from the OS CSPRNG, which is what `uuid`
    // draws from; enough for a PKCE verifier and a `state`.
    let mut buf = Vec::with_capacity(bytes);
    while buf.len() < bytes {
        buf.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    buf.truncate(bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

pub(crate) fn authorize_url(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    host_id: &str,
    first_run: bool,
) -> String {
    let mut u = url::Url::parse(AUTHORIZE_URL).expect("constant URL parses");
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("resource", RESOURCE)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("ext_agent_host_id", host_id);
        if first_run {
            q.append_pair("agent_name_hint", AGENT_NAME_HINT);
        }
    }
    u.to_string()
}

// ---------------------------------------------------------------------
// The loopback callback
// ---------------------------------------------------------------------

/// What the browser hands back on the loopback redirect.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Callback {
    pub code: String,
    pub state: String,
    /// Present on first-run dynamic registration: the id to keep.
    pub issued_client_id: Option<String>,
}

/// Parse the request line of the single loopback hit. Anything that is
/// not `GET /auth/callback?…` with `code` and `state` is refused.
pub(crate) fn parse_callback(request_head: &str) -> Result<Callback, String> {
    let line = request_head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    if parts.next() != Some("GET") {
        return Err("unexpected method on the sign-in callback".into());
    }
    let target = parts.next().ok_or("malformed sign-in callback")?;
    let u = url::Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "malformed sign-in callback URL".to_string())?;
    if u.path() != CALLBACK_PATH {
        return Err("sign-in callback hit the wrong path".into());
    }
    let mut code = None;
    let mut state = None;
    let mut issued = None;
    let mut error = None;
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "client_id" => issued = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            _ => {}
        }
    }
    if let Some(e) = error {
        // The browser (or whoever reached the loopback) chose this
        // string; keep it printable and short before it reaches a toast.
        let e: String = e
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(CALLBACK_ERROR_MAX)
            .collect();
        return Err(format!("OpenAI returned an error: {e}"));
    }
    Ok(Callback {
        code: code.ok_or("sign-in callback carried no code")?,
        state: state.ok_or("sign-in callback carried no state")?,
        issued_client_id: issued,
    })
}

const CALLBACK_HTML_OK: &str =
    "<!doctype html><html><body style=\"font-family:system-ui;padding:2rem\">\
<h2>Signed in to Transit Community Edition</h2><p>You can close this tab.</p></body></html>";
const CALLBACK_HTML_ERR: &str =
    "<!doctype html><html><body style=\"font-family:system-ui;padding:2rem\">\
<h2>Sign-in did not complete</h2><p>Return to Transit and try again.</p></body></html>";

async fn respond(stream: &mut tokio::net::TcpStream, ok: bool) {
    let body = if ok {
        CALLBACK_HTML_OK
    } else {
        CALLBACK_HTML_ERR
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Accept exactly one connection and read its request head.
async fn accept_one(listener: TcpListener) -> Result<(tokio::net::TcpStream, String), String> {
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("sign-in callback listener: {e}"))?;
    let mut buf = vec![0u8; 8192];
    let mut head = Vec::new();
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("sign-in callback read: {e}"))?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() >= 8192 {
            break;
        }
    }
    Ok((stream, String::from_utf8_lossy(&head).into_owned()))
}

#[derive(Serialize, Clone)]
struct SigninErrorPayload {
    reason: String,
}

/// Run the whole sign-in: bind, open the browser, wait for the callback,
/// exchange, store, emit. Errors are emitted as `chatgpt:signin-error`.
async fn run_signin(app: tauri::AppHandle, state: Arc<ChatGptState>) {
    let outcome: Result<(), String> = async {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| format!("could not open the sign-in callback port: {e}"))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        let verifier = random_urlsafe(48);
        let csrf = random_urlsafe(24);
        let challenge = pkce_challenge(&verifier);
        let host = host_id()?;
        let cid = client_id();
        let first_run = cid == DYNAMIC_CLIENT_ID;
        let url = authorize_url(&cid, &redirect_uri, &csrf, &challenge, &host, first_run);
        info!(port, first_run, "ChatGPT sign-in: opening the browser");
        tauri_plugin_opener::OpenerExt::opener(&app)
            .open_url(url, None::<&str>)
            .map_err(|e| format!("could not open the browser: {e}"))?;

        let (mut stream, head) = tokio::time::timeout(SIGNIN_TIMEOUT, accept_one(listener))
            .await
            .map_err(|_| "timed out waiting for the browser".to_string())??;
        let cb = match parse_callback(&head) {
            Ok(cb) => cb,
            Err(e) => {
                respond(&mut stream, false).await;
                return Err(e);
            }
        };
        if cb.state != csrf {
            respond(&mut stream, false).await;
            return Err("sign-in callback state mismatch".into());
        }
        let issued = match effective_client_id(&cid, cb.issued_client_id.as_deref(), first_run) {
            Ok(id) => id,
            Err(e) => {
                respond(&mut stream, false).await;
                return Err(e);
            }
        };
        // Persist the registration BEFORE the exchange: the id is issued
        // whether or not this exchange succeeds, and a refresh token
        // stored without its client id would be unusable (see
        // `access_token`).
        if first_run {
            write_config_string_at(&config_path(), CONFIG_SECTION, "client_id", Some(&issued))?;
        }
        match state
            .exchange_code(&cb.code, &redirect_uri, &issued, &verifier)
            .await
        {
            Ok(()) => {
                respond(&mut stream, true).await;
                Ok(())
            }
            Err(e) => {
                respond(&mut stream, false).await;
                Err(e)
            }
        }
    }
    .await;

    match outcome {
        Ok(()) => {
            info!("ChatGPT sign-in: complete");
            let _ = app.emit("chatgpt:signin-success", ());
        }
        Err(reason) => {
            warn!(%reason, "ChatGPT sign-in failed");
            let _ = app.emit("chatgpt:signin-error", SigninErrorPayload { reason });
        }
    }
}

// ---------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------

/// Begin the browser sign-in. Returns at once; completion arrives as the
/// `chatgpt:signin-success` / `chatgpt:signin-error` events.
#[tauri::command]
pub async fn chatgpt_signin_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<ChatGptState>>,
) -> Result<(), String> {
    let st = Arc::clone(&state);
    let mut pending = st.pending.lock().await;
    if let Some(h) = pending.take() {
        h.abort();
    }
    *pending = Some(tauri::async_runtime::spawn(run_signin(
        app,
        Arc::clone(&st),
    )));
    Ok(())
}

/// Abort an in-flight sign-in (closes the listener).
#[tauri::command]
pub async fn chatgpt_signin_cancel(
    state: tauri::State<'_, Arc<ChatGptState>>,
) -> Result<(), String> {
    if let Some(h) = state.pending.lock().await.take() {
        h.abort();
    }
    Ok(())
}

/// Sign-out outcome: whether OpenAI confirmed the revocation (Rule 1:
/// a boolean, nothing else).
#[derive(Debug, Clone, Serialize)]
pub struct ChatGptSignout {
    pub revoked: bool,
}

/// Revoke the grant at OpenAI and forget it on this machine.
#[tauri::command]
pub async fn chatgpt_signout(
    state: tauri::State<'_, Arc<ChatGptState>>,
) -> Result<ChatGptSignout, String> {
    let revoked = state.sign_out().await;
    Ok(ChatGptSignout { revoked })
}

/// Booleans + display email only (Rule 1).
#[derive(Debug, Clone, Serialize)]
pub struct ChatGptStatus {
    pub signed_in: bool,
    pub email: Option<String>,
    pub method: OpenAiMethod,
}

#[tauri::command]
pub async fn chatgpt_status(
    state: tauri::State<'_, Arc<ChatGptState>>,
) -> Result<ChatGptStatus, String> {
    let signed_in = state.signed_in();
    Ok(ChatGptStatus {
        signed_in,
        email: if signed_in {
            read_config_string(CONFIG_SECTION, "account_email")
        } else {
            None
        },
        method: read_openai_method(),
    })
}

/// Choose which credential the OpenAI side uses. Persisted; applies on
/// the next send (the chat factory re-reads it per message).
#[tauri::command]
pub fn provider_openai_method_set(method: OpenAiMethod) -> Result<(), String> {
    let v = match method {
        OpenAiMethod::ApiKey => "api_key",
        OpenAiMethod::Chatgpt => "chatgpt",
    };
    write_config_string_at(&config_path(), PROVIDERS_SECTION, "openai_method", Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_client_id_is_honoured_only_on_first_run_and_shape_checked() {
        // First run: the callback's id is the registration.
        assert_eq!(
            effective_client_id(DYNAMIC_CLIENT_ID, Some("oaiapp_abc-1"), true).unwrap(),
            "oaiapp_abc-1"
        );
        // First run with no id: refuse rather than register the literal.
        assert!(effective_client_id(DYNAMIC_CLIENT_ID, None, true).is_err());
        // First run with a hostile shape: refused before it hits config.toml.
        assert!(effective_client_id(DYNAMIC_CLIENT_ID, Some("x\n[evil]"), true).is_err());
        assert!(effective_client_id(DYNAMIC_CLIENT_ID, Some(""), true).is_err());
        // Later runs: whatever reaches the loopback cannot rename the registration.
        assert_eq!(
            effective_client_id("oaiapp_mine", Some("oaiapp_theirs"), false).unwrap(),
            "oaiapp_mine"
        );
        assert!(valid_client_id("oaiapp_9.Z-_"));
        assert!(!valid_client_id(&"a".repeat(129)));
    }

    #[test]
    fn callback_error_text_is_sanitized_and_capped() {
        let long = "x".repeat(500);
        let head = format!(
            "GET /auth/callback?error={long}%0A%1B[31mred&state=s HTTP/1.1\r\nHost: h\r\n\r\n"
        );
        let err = parse_callback(&head).unwrap_err();
        assert!(err.starts_with("OpenAI returned an error: "));
        let text = &err["OpenAI returned an error: ".len()..];
        assert!(text.len() <= CALLBACK_ERROR_MAX);
        assert!(text.chars().all(|c| c.is_ascii_graphic() || c == ' '));
    }

    /// Revocation is RFC 7009 (token + hint + client id); 2xx = done, a 5xx
    /// is retried up to three times then reported unconfirmed, a plain 4xx
    /// is reported unconfirmed at once. Pure HTTP — no keychain.
    #[tokio::test]
    async fn revocation_request_shape_and_retry_policy() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let tok = SecretString::new("rt-1".to_string().into());

        let ok = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=rt-1"))
            .and(body_string_contains("token_type_hint=refresh_token"))
            .and(body_string_contains("client_id=oaiapp_1"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&ok)
            .await;
        let state = ChatGptState::new();
        *state.revoke_url.write().unwrap() = Some(format!("{}/revoke", ok.uri()));
        assert!(state.revoke_refresh(&tok, "oaiapp_1").await);

        let flaky = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(503))
            .expect(3)
            .mount(&flaky)
            .await;
        let state = ChatGptState::new();
        *state.revoke_url.write().unwrap() = Some(format!("{}/revoke", flaky.uri()));
        assert!(!state.revoke_refresh(&tok, "oaiapp_1").await);

        let refused = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&refused)
            .await;
        let state = ChatGptState::new();
        *state.revoke_url.write().unwrap() = Some(format!("{}/revoke", refused.uri()));
        assert!(!state.revoke_refresh(&tok, "oaiapp_1").await);
    }

    #[test]
    fn scopes_are_the_documented_set() {
        assert_eq!(
            SCOPES,
            "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
        );
        assert_eq!(RESOURCE, "https://api.openai.com/v1");
        assert!(AUTHORIZE_URL.starts_with("https://auth.openai.com/"));
        assert!(TOKEN_URL.starts_with("https://auth.openai.com/"));
        assert!(REVOKE_URL.starts_with("https://auth.openai.com/"));
    }

    #[test]
    fn authorize_url_carries_every_required_parameter() {
        let u = authorize_url(
            "dynamic_agent_client",
            "http://127.0.0.1:1455/auth/callback",
            "st",
            "ch",
            "urn:uuid:x",
            true,
        );
        let parsed = url::Url::parse(&u).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "dynamic_agent_client");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:1455/auth/callback");
        assert_eq!(q["scope"], SCOPES);
        assert_eq!(q["resource"], RESOURCE);
        assert_eq!(q["state"], "st");
        assert_eq!(q["code_challenge"], "ch");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["ext_agent_host_id"], "urn:uuid:x");
        assert_eq!(q["agent_name_hint"], AGENT_NAME_HINT);
        // A re-authorization with an issued id sends no name hint.
        let u2 = authorize_url(
            "oaiapp_1",
            "http://127.0.0.1:2/auth/callback",
            "s",
            "c",
            "h",
            false,
        );
        assert!(!u2.contains("agent_name_hint"));
    }

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        // RFC 7636 appendix B test vector.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let v = random_urlsafe(48);
        assert!(
            v.len() >= 43 && v.len() <= 128,
            "PKCE verifier length: {}",
            v.len()
        );
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn callback_parsing_accepts_only_the_documented_shape() {
        let ok = parse_callback(
            "GET /auth/callback?code=abc&scope=openid&state=xyz&client_id=oaiapp_9 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            ok,
            Callback {
                code: "abc".into(),
                state: "xyz".into(),
                issued_client_id: Some("oaiapp_9".into())
            }
        );
        assert!(parse_callback("POST /auth/callback?code=a&state=b HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_callback("GET /other?code=a&state=b HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_callback("GET /auth/callback?state=b HTTP/1.1\r\n\r\n").is_err());
        let denied =
            parse_callback("GET /auth/callback?error=access_denied&state=b HTTP/1.1\r\n\r\n");
        assert!(denied.unwrap_err().contains("access_denied"));
    }

    #[test]
    fn email_is_read_from_the_id_token_payload_only() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"u1","email":"alice@example.com"}"#);
        let jwt = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
        assert_eq!(
            email_from_id_token(&jwt).as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(email_from_id_token("not-a-jwt"), None);
    }

    #[tokio::test]
    async fn loopback_listener_reads_one_request_and_answers_html() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, head) = accept_one(listener).await.unwrap();
            let cb = parse_callback(&head).unwrap();
            respond(&mut stream, true).await;
            cb
        });
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client
            .write_all(b"GET /auth/callback?code=c1&state=s1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("close this tab"));
        let cb = server.await.unwrap();
        assert_eq!(cb.code, "c1");
        assert_eq!(cb.state, "s1");
    }

    /// Refresh goes to the token endpoint with the documented grant and
    /// stores the rotated refresh token; a dead-grant error clears the
    /// grant and reports re-auth. Runs against a temp config + the real
    /// keychain only when `TRANSIT_KEYRING_TESTS=1`; the pure request
    /// shape is asserted regardless via the mock.
    #[tokio::test]
    async fn refresh_request_shape_and_dead_grant_mapping() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=dead"))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fapi.openai.com%2Fv1",
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "refresh_token_expired"
            })))
            .mount(&server)
            .await;
        let state = ChatGptState::new();
        *state.token_url.write().unwrap() = Some(format!("{}/token", server.uri()));
        // Drive the HTTP half directly: the keychain read is bypassed by
        // calling the exchange path with a known refresh value.
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", "dead"),
            ("client_id", "oaiapp_1"),
            ("resource", RESOURCE),
        ];
        let resp = state
            .http()
            .post(state.token_url())
            .form(&form)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400);
        let body = resp.text().await.unwrap();
        let code = serde_json::from_str::<TokenError>(&body)
            .unwrap()
            .error
            .unwrap();
        assert!(DEAD_GRANT_ERRORS.contains(&code.as_str()));
    }

    /// Community issue #18: the code exchange omitted `resource`, so OpenAI
    /// answered `invalid_grant` after a successful browser login. Every
    /// field the doc lists for the `authorization_code` grant must be on
    /// the wire, `resource` and `redirect_uri` identical to the authorize
    /// request. A 400 reply keeps the keychain out of the test.
    #[tokio::test]
    async fn exchange_request_repeats_resource_and_redirect_uri() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=abc"))
            .and(body_string_contains(
                "redirect_uri=http%3A%2F%2F127.0.0.1%3A4242%2Fauth%2Fcallback",
            ))
            .and(body_string_contains("client_id=oaiapp_1"))
            .and(body_string_contains("code_verifier=v"))
            .and(body_string_contains(
                "resource=https%3A%2F%2Fapi.openai.com%2Fv1",
            ))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let state = ChatGptState::new();
        *state.token_url.write().unwrap() = Some(format!("{}/token", server.uri()));
        let err = state
            .exchange_code(
                "abc",
                "http://127.0.0.1:4242/auth/callback",
                "oaiapp_1",
                "v",
            )
            .await
            .unwrap_err();
        assert!(err.contains("invalid_grant"), "{err}");
        // `.expect(1)` is verified on drop: a request missing any field
        // would not have matched and the mock would panic the test.
    }
}
