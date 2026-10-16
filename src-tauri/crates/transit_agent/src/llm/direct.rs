//! Direct provider impls of `LlmClient` — the production AI path.
//!
//! `DirectAnthropic` and `DirectOpenAI` call the providers directly with
//! the user's own API key. There is no proxy, no account, no metering and
//! no entitlement: the key the user enrolled (OS keychain, write-only IPC,
//! see `transit_app::provider_keys`) is the whole of the authorization.
//!
//! ## Security shape (threat-model T_DIRECT_KEY)
//!
//! - The key is a `SecretString` for its entire life here (`Debug` renders
//!   `[REDACTED]`); it is exposed exactly once per request, into the auth
//!   header.
//! - The HTTP client comes from `transit_tls::build_http_client(strict)`:
//!   OS-store (or webpki-only) chain verification, a 10 s connect timeout,
//!   **no redirects** (a 3xx must never carry the header elsewhere) and
//!   **no ambient proxy** (`HTTP_PROXY` is an egress channel for the key).
//! - Each impl knows exactly ONE host — the constants below. The release
//!   "no-phone-home" scan verifies no other hostname is in the binary.
//!
//! ## Errors
//!
//! Non-2xx responses map to typed [`LlmError`] variants whose `Display`
//! embeds a stable marker (`provider_key_rejected`, `rate_limit_exceeded`,
//! `provider_overloaded`) so the Tauri shell can route UX after the agent
//! loop has flattened the error to a string. The error body is reduced to a
//! sanitized `error.message` snippet — never echoed whole.

use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures::stream::StreamExt;
use secrecy::{ExposeSecret, SecretString};

use crate::llm::anthropic::{build_anthropic_body, parse_anthropic_stream};
use crate::llm::openai::{build_openai_body, parse_openai_stream, plan_error_for_code};
use crate::llm::{LlmClient, LlmError, LlmRequest, LlmResult, LlmStream};

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// The Responses API — the only OpenAI endpoint that allows function tools
/// and reasoning together (see `openai.rs` module docs).
const OPENAI_URL: &str = "https://api.openai.com/v1/responses";

const ANTHROPIC_MODELS_URL: &str = "https://api.anthropic.com/v1/models";
const OPENAI_MODELS_URL: &str = "https://api.openai.com/v1/models";

/// Human-readable provider name used in error copy and the
/// `missing_provider_key` routing.
pub const ANTHROPIC: &str = "Anthropic";
pub const OPENAI: &str = "OpenAI";

/// Coarse capability tier used to group the chat picker. Derived from the
/// model id's family name — the providers publish no such field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelLevel {
    Easy,
    Medium,
    Advanced,
}

/// One selectable provider model, as discovered from the provider's own
/// model list. Metadata only — this is what crosses IPC to the picker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderModel {
    pub id: String,
    pub display_name: String,
    /// Unix seconds, when the provider reports one. Lists are sorted
    /// newest-first on this; `None` sorts last.
    pub created: Option<i64>,
    pub level: ModelLevel,
    /// Context window in tokens, when the provider reports one.
    pub context_window: Option<u32>,
}

/// Level from a model id's family name. Shared by both providers'
/// parsers so the picker groups them the same way.
fn level_for_id(id: &str) -> ModelLevel {
    let id = id.to_ascii_lowercase();
    if id.contains("haiku") || id.contains("nano") || id.contains("mini") {
        ModelLevel::Easy
    } else if id.contains("opus") || id.contains("fable") || id.contains("-pro") {
        ModelLevel::Advanced
    } else {
        ModelLevel::Medium
    }
}

fn sort_newest_first(models: &mut [ProviderModel]) {
    models.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
}

// ---------------------------------------------------------------------------
// Anthropic model list
// ---------------------------------------------------------------------------

/// Parse one page of `GET /v1/models` (Anthropic). Every entry is a chat
/// model, so there is no filtering — only mapping. Returns the models and
/// the `last_id` to continue from when `has_more` is set.
pub(crate) fn anthropic_models_from_json(
    page: &serde_json::Value,
) -> (Vec<ProviderModel>, Option<String>) {
    let mut out = Vec::new();
    for m in page
        .get("data")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
    {
        let Some(id) = m.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let display_name = m
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or(id)
            .to_string();
        let created = m
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(rfc3339_to_unix);
        let context_window = m
            .get("max_input_tokens")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok());
        out.push(ProviderModel {
            id: id.to_string(),
            display_name,
            created,
            level: level_for_id(id),
            context_window,
        });
    }
    let next = match page.get("has_more").and_then(|v| v.as_bool()) {
        Some(true) => page
            .get("last_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    };
    (out, next)
}

fn rfc3339_to_unix(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

// ---------------------------------------------------------------------------
// OpenAI model list
// ---------------------------------------------------------------------------

/// Id substrings that mark a non-chat model in OpenAI's catalogue, which
/// mixes embeddings, speech, image and moderation models into one list.
/// Heuristic by construction; a wrongly hidden model is still reachable
/// through the picker's custom-id field.
const OPENAI_EXCLUDE: &[&str] = &[
    "audio",
    "realtime",
    "tts",
    "transcribe",
    "embedding",
    "image",
    "dall-e",
    "whisper",
    "moderation",
    "search",
    "instruct",
    "computer-use",
];

fn openai_id_is_chat_family(id: &str) -> bool {
    if id.starts_with("gpt-") {
        return true;
    }
    let mut chars = id.chars();
    matches!(chars.next(), Some('o')) && matches!(chars.next(), Some(c) if c.is_ascii_digit())
}

/// `gpt-5.6-sol` → `GPT-5.6 Sol`; `o4-mini` → `O4 Mini`. Purely cosmetic:
/// the family token is upper-cased, a version token stays attached to it
/// with the hyphen, every later token is capitalized.
pub(crate) fn openai_display_name(id: &str) -> String {
    let parts: Vec<&str> = id.split('-').collect();
    let mut out = String::new();
    for (i, part) in parts.iter().enumerate() {
        let starts_digit = part.chars().next().is_some_and(|c| c.is_ascii_digit());
        let rendered = if i == 0 {
            part.to_ascii_uppercase()
        } else if starts_digit {
            (*part).to_string()
        } else {
            let mut cs = part.chars();
            match cs.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + cs.as_str(),
                None => String::new(),
            }
        };
        if i == 0 {
            out.push_str(&rendered);
        } else if i == 1 && starts_digit {
            out.push('-');
            out.push_str(&rendered);
        } else {
            out.push(' ');
            out.push_str(&rendered);
        }
    }
    out
}

/// True for a `-YYYY-MM-DD` suffix.
fn dated_snapshot_base(id: &str) -> Option<&str> {
    let (base, tail) = id.rsplit_once('-')?;
    let (base, mm) = base.rsplit_once('-')?;
    let (base, yyyy) = base.rsplit_once('-')?;
    let ok = yyyy.len() == 4
        && mm.len() == 2
        && tail.len() == 2
        && [yyyy, mm, tail]
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_digit()));
    ok.then_some(base)
}

/// Parse `GET /v1/models` (OpenAI, API-key shape: `data[]` of `id`,
/// `created`, `owned_by`, optional `shutdown_date`) into chat models only.
pub(crate) fn openai_models_from_json(
    list: &serde_json::Value,
    now_unix: i64,
) -> Vec<ProviderModel> {
    let entries: Vec<&serde_json::Value> = list
        .get("data")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
        .collect();
    let ids: std::collections::HashSet<&str> = entries
        .iter()
        .filter_map(|m| m.get("id").and_then(|v| v.as_str()))
        .collect();

    let mut out = Vec::new();
    for m in entries {
        let Some(id) = m.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let owned_by = m.get("owned_by").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(owned_by, "openai" | "system") {
            continue;
        }
        if !openai_id_is_chat_family(id) {
            continue;
        }
        let lower = id.to_ascii_lowercase();
        if OPENAI_EXCLUDE.iter().any(|x| lower.contains(x)) {
            continue;
        }
        if let Some(base) = dated_snapshot_base(id) {
            if ids.contains(base) {
                continue;
            }
        }
        if let Some(shutdown) = m.get("shutdown_date").and_then(|v| v.as_str()) {
            if let Some(ts) = rfc3339_to_unix(shutdown).or_else(|| date_to_unix(shutdown)) {
                if ts <= now_unix {
                    continue;
                }
            }
        }
        out.push(ProviderModel {
            id: id.to_string(),
            display_name: openai_display_name(id),
            created: m.get("created").and_then(|v| v.as_i64()),
            level: level_for_id(id),
            context_window: None,
        });
    }
    sort_newest_first(&mut out);
    out
}

/// `YYYY-MM-DD` (date only, as `shutdown_date` is published) → unix midnight.
fn date_to_unix(s: &str) -> Option<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    time::Date::parse(s, &fmt)
        .ok()
        .map(|d| d.midnight().assume_utc().unix_timestamp())
}

pub struct DirectAnthropic {
    http: reqwest::Client,
    api_key: SecretString,
    /// Test-only override so wiremock can stand in for the provider. In
    /// production this is never set: the host is the constant above.
    #[cfg(test)]
    base: Option<String>,
}

impl std::fmt::Debug for DirectAnthropic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectAnthropic")
            .field("api_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DirectAnthropic {
    /// `strict_tls` selects the trust-anchor source (`[network] strict_tls`,
    /// T27): `false` = OS store, `true` = bundled web-PKI roots only.
    pub fn new(api_key: SecretString, strict_tls: bool) -> Self {
        Self {
            http: transit_tls::build_http_client(strict_tls),
            api_key,
            #[cfg(test)]
            base: None,
        }
    }

    #[cfg(test)]
    fn with_base(mut self, base: &str) -> Self {
        self.base = Some(base.trim_end_matches('/').to_string());
        self
    }

    fn models_url(&self) -> String {
        #[cfg(test)]
        if let Some(b) = &self.base {
            return format!("{b}/v1/models");
        }
        ANTHROPIC_MODELS_URL.to_string()
    }

    /// The account's model catalogue, newest first. Follows pagination.
    pub async fn list_models(&self) -> LlmResult<Vec<ProviderModel>> {
        let mut all = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..10 {
            let mut req = self
                .http
                .get(self.models_url())
                .header("x-api-key", self.api_key.expose_secret())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .query(&[("limit", "100")]);
            if let Some(a) = &after {
                req = req.query(&[("after_id", a.as_str())]);
            }
            let response = req.send().await.map_err(classify_send_error)?;
            let response = check_status(ANTHROPIC, response).await?;
            let page: serde_json::Value = response
                .json()
                .await
                .map_err(|e| LlmError::Malformed(format!("models list: {e}")))?;
            let (mut models, next) = anthropic_models_from_json(&page);
            all.append(&mut models);
            match next {
                Some(id) => after = Some(id),
                None => break,
            }
        }
        sort_newest_first(&mut all);
        Ok(all)
    }
}

#[async_trait]
impl LlmClient for DirectAnthropic {
    async fn messages(&self, req: LlmRequest) -> LlmResult<LlmStream> {
        let body = build_anthropic_body(&req);
        let response = self
            .http
            .post(ANTHROPIC_URL)
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(classify_send_error)?;
        let response = check_status(ANTHROPIC, response).await?;
        let events = response.bytes_stream().eventsource();
        Ok(parse_anthropic_stream(events).boxed())
    }
}

/// How a request to OpenAI is authorized. Both are a bearer-style secret
/// in a header; they differ in what the server accepts in the body and
/// which model list it returns.
pub enum OpenAiAuth {
    /// A platform API key (`sk-…`): the full Responses API.
    ApiKey(SecretString),
    /// A Sign-in-with-ChatGPT access token: the user's plan pays, with the
    /// preview's body restrictions (see `build_openai_body`'s `plan`).
    ChatGptPlan(SecretString),
}

impl OpenAiAuth {
    fn secret(&self) -> &SecretString {
        match self {
            OpenAiAuth::ApiKey(s) | OpenAiAuth::ChatGptPlan(s) => s,
        }
    }
    fn is_plan(&self) -> bool {
        matches!(self, OpenAiAuth::ChatGptPlan(_))
    }
}

pub struct DirectOpenAI {
    http: reqwest::Client,
    auth: OpenAiAuth,
    /// Test-only override; see [`DirectAnthropic`].
    #[cfg(test)]
    base: Option<String>,
}

impl std::fmt::Debug for DirectOpenAI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectOpenAI")
            .field(
                "auth",
                &if self.auth.is_plan() {
                    "ChatGptPlan([REDACTED])"
                } else {
                    "ApiKey([REDACTED])"
                },
            )
            .finish_non_exhaustive()
    }
}

impl DirectOpenAI {
    pub fn new(auth: OpenAiAuth, strict_tls: bool) -> Self {
        Self {
            http: transit_tls::build_http_client(strict_tls),
            auth,
            #[cfg(test)]
            base: None,
        }
    }

    /// Whether this client rides a ChatGPT plan token.
    pub fn is_plan(&self) -> bool {
        self.auth.is_plan()
    }

    #[cfg(test)]
    fn with_base(mut self, base: &str) -> Self {
        self.base = Some(base.trim_end_matches('/').to_string());
        self
    }

    fn models_url(&self) -> String {
        #[cfg(test)]
        if let Some(b) = &self.base {
            return format!("{b}/v1/models");
        }
        OPENAI_MODELS_URL.to_string()
    }

    /// The account's chat models, newest first (see [`OPENAI_EXCLUDE`]).
    pub async fn list_models(&self) -> LlmResult<Vec<ProviderModel>> {
        let response = self
            .http
            .get(self.models_url())
            .bearer_auth(self.auth.secret().expose_secret())
            .send()
            .await
            .map_err(classify_send_error)?;
        let response = check_status_openai(response, self.auth.is_plan()).await?;
        let list: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LlmError::Malformed(format!("models list: {e}")))?;
        if self.auth.is_plan() {
            return Ok(openai_plan_models_from_json(&list));
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Ok(openai_models_from_json(&list, now))
    }
}

#[async_trait]
impl LlmClient for DirectOpenAI {
    async fn messages(&self, req: LlmRequest) -> LlmResult<LlmStream> {
        let body = build_openai_body(&req, self.auth.is_plan());
        let response = self
            .http
            .post(OPENAI_URL)
            .bearer_auth(self.auth.secret().expose_secret())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(classify_send_error)?;
        let response = check_status_openai(response, self.auth.is_plan()).await?;
        let events = response.bytes_stream().eventsource();
        Ok(parse_openai_stream(events).boxed())
    }
}

/// A reqwest *send* failure: a certificate-validation failure becomes the
/// actionable `TlsTrust`; everything else stays `Http`.
fn classify_send_error(err: reqwest::Error) -> LlmError {
    if transit_tls::is_tls_trust_error(&err) {
        LlmError::TlsTrust
    } else {
        LlmError::Http(err)
    }
}

/// Turn a non-2xx provider response into the typed error. 2xx passes the
/// response through untouched so the body can be streamed.
async fn check_status(
    provider: &'static str,
    response: reqwest::Response,
) -> LlmResult<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    Err(status_error(provider, status.as_u16(), &body))
}

/// OpenAI status handling: in plan mode the body's `error.code` carries
/// the plan outcome (cap, eligibility, re-auth) and takes precedence over
/// the bare status; otherwise identical to [`check_status`].
async fn check_status_openai(
    response: reqwest::Response,
    plan: bool,
) -> LlmResult<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    if plan {
        let code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        if let Some(err) = plan_error_for_code(&code, &error_message_snippet(&body)) {
            return Err(err);
        }
        // A plain 401 on the plan path means the token is dead, not that
        // "the key" is wrong — route to re-auth, not to Settings → keys.
        if status.as_u16() == 401 {
            return Err(LlmError::PlanReauthRequired);
        }
    }
    Err(status_error(OPENAI, status.as_u16(), &body))
}

/// Parse the plan-token shape of `GET /v1/models` (`models[]` of `slug`,
/// `display_name`, `visibility`); only `visibility == "list"` entries are
/// offered. No `created` is published; order is the server's.
pub(crate) fn openai_plan_models_from_json(list: &serde_json::Value) -> Vec<ProviderModel> {
    let mut out = Vec::new();
    for m in list
        .get("models")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
    {
        let Some(slug) = m.get("slug").and_then(|v| v.as_str()) else {
            continue;
        };
        if m.get("visibility").and_then(|v| v.as_str()) != Some("list") {
            continue;
        }
        let display_name = m
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| openai_display_name(slug));
        out.push(ProviderModel {
            id: slug.to_string(),
            display_name,
            created: None,
            level: level_for_id(slug),
            context_window: None,
        });
    }
    out
}

/// Pure status → error mapping, split out so it is unit-testable without
/// a live socket.
pub(crate) fn status_error(provider: &'static str, status: u16, body: &str) -> LlmError {
    match status {
        401 | 403 => LlmError::KeyRejected { provider },
        429 => LlmError::RateLimited { provider },
        // Anthropic signals overload with 529; both providers use 502/503
        // for transient upstream trouble. All are "try again shortly".
        502 | 503 | 529 => LlmError::Overloaded { provider },
        _ => LlmError::Status {
            provider,
            status,
            message: error_message_snippet(body),
        },
    }
}

/// Reduce a provider error body to a short, sanitized message. Both
/// providers wrap errors as `{"error": {"message": "..."}}`; when that
/// shape isn't present the raw body is used. Control characters are
/// stripped (no log-line injection / ANSI smuggling) and the result is
/// capped at 200 chars — an HTML error page must never flood the UI.
pub(crate) fn error_message_snippet(body: &str) -> String {
    const MAX_CHARS: usize = 200;
    let text = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.to_owned());
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_constructs_direct_clients_with_secret_keys_in_both_trust_modes() {
        let key = SecretString::new("sk-anthropic-test".to_string().into());
        let a = DirectAnthropic::new(key, false);
        let key = SecretString::new("sk-openai-test".to_string().into());
        let o = DirectOpenAI::new(OpenAiAuth::ApiKey(key), true);
        // Debug must never render the key.
        let dbg = format!("{a:?}{o:?}");
        assert!(!dbg.contains("sk-"), "key leaked via Debug: {dbg}");
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn provider_hosts_are_the_only_two() {
        assert!(ANTHROPIC_URL.starts_with("https://api.anthropic.com/"));
        assert!(ANTHROPIC_MODELS_URL.starts_with("https://api.anthropic.com/"));
        assert!(OPENAI_URL.starts_with("https://api.openai.com/"));
        assert!(OPENAI_MODELS_URL.starts_with("https://api.openai.com/"));
    }

    // ----- model discovery: pure parsers --------------------------------

    #[test]
    fn anthropic_models_map_fields_and_levels() {
        let page = serde_json::json!({
            "data": [
                {"id": "claude-opus-5-5", "display_name": "Claude Opus 5.5",
                 "created_at": "2026-09-01T00:00:00Z", "max_input_tokens": 1000000},
                {"id": "claude-sonnet-5-5", "display_name": "Claude Sonnet 5.5",
                 "created_at": "2026-08-01T00:00:00Z"},
                {"id": "claude-haiku-4-5-20251001", "display_name": "Claude Haiku 4.5",
                 "created_at": "2025-10-01T00:00:00Z"}
            ],
            "has_more": true, "last_id": "claude-haiku-4-5-20251001"
        });
        let (models, next) = anthropic_models_from_json(&page);
        assert_eq!(next.as_deref(), Some("claude-haiku-4-5-20251001"));
        assert_eq!(models.len(), 3);
        assert_eq!(models[0].display_name, "Claude Opus 5.5");
        assert_eq!(models[0].level, ModelLevel::Advanced);
        assert_eq!(models[0].context_window, Some(1_000_000));
        assert_eq!(models[0].created, Some(1_788_220_800));
        assert_eq!(models[1].level, ModelLevel::Medium);
        assert_eq!(models[2].level, ModelLevel::Easy);
        assert!(models[1].context_window.is_none());
    }

    #[test]
    fn openai_models_filter_to_chat_family() {
        let now = 1_800_000_000;
        let list = serde_json::json!({"object": "list", "data": [
            {"id": "gpt-5.6-sol", "created": 1_790_000_000, "owned_by": "system"},
            {"id": "gpt-5.6-sol-2026-09-01", "created": 1_790_000_001, "owned_by": "system"},
            {"id": "gpt-5.6-luna-2026-09-01", "created": 1_790_000_002, "owned_by": "system"},
            {"id": "o4-mini", "created": 1_780_000_000, "owned_by": "system"},
            {"id": "gpt-4o-realtime-preview", "created": 1, "owned_by": "system"},
            {"id": "gpt-4o-audio-preview", "created": 1, "owned_by": "system"},
            {"id": "text-embedding-3-large", "created": 1, "owned_by": "system"},
            {"id": "whisper-1", "created": 1, "owned_by": "openai-internal"},
            {"id": "tts-1", "created": 1, "owned_by": "openai-internal"},
            {"id": "dall-e-3", "created": 1, "owned_by": "system"},
            {"id": "omni-moderation-latest", "created": 1, "owned_by": "system"},
            {"id": "gpt-3.5-turbo-instruct", "created": 1, "owned_by": "system"},
            {"id": "computer-use-preview", "created": 1, "owned_by": "system"},
            {"id": "gpt-4.1", "created": 1_700_000_000, "owned_by": "system",
             "shutdown_date": "2026-01-01"},
            {"id": "ft:gpt-4.1:acme::abc", "created": 1, "owned_by": "user-123"},
            {"id": "gpt-5-pro", "created": 1_770_000_000, "owned_by": "system"}
        ]});
        let ids: Vec<String> = openai_models_from_json(&list, now)
            .into_iter()
            .map(|m| m.id)
            .collect();
        // Newest first; the dated Sol snapshot is folded into its bare id,
        // the dated Luna snapshot survives because no bare id exists.
        assert_eq!(
            ids,
            vec![
                "gpt-5.6-luna-2026-09-01",
                "gpt-5.6-sol",
                "o4-mini",
                "gpt-5-pro"
            ]
        );
        let models = openai_models_from_json(&list, now);
        assert_eq!(models[1].display_name, "GPT-5.6 Sol");
        assert_eq!(models[2].display_name, "O4 Mini");
        assert_eq!(models[2].level, ModelLevel::Easy);
        assert_eq!(models[3].level, ModelLevel::Advanced);
        assert_eq!(models[1].level, ModelLevel::Medium);
    }

    #[test]
    fn plan_model_list_keeps_listed_slugs_only() {
        let list = serde_json::json!({"models": [
            {"slug": "gpt-6.1-sol", "display_name": "GPT-6.1 Sol", "visibility": "list"},
            {"slug": "gpt-6.1-internal", "display_name": "x", "visibility": "hidden"},
            {"slug": "gpt-5.6-terra", "visibility": "list"}
        ]});
        let models = openai_plan_models_from_json(&list);
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gpt-6.1-sol", "gpt-5.6-terra"]);
        assert_eq!(models[0].display_name, "GPT-6.1 Sol");
        assert_eq!(models[1].display_name, "GPT-5.6 Terra");
    }

    #[tokio::test]
    async fn plan_mode_status_codes_map_to_plan_errors() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer plan-capped"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {"code": "subscription_sharing_usage_limit_exceeded", "message": "cap"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer plan-dead"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {"code": "invalid_token", "message": "expired"}
            })))
            .mount(&server)
            .await;
        let capped = DirectOpenAI::new(
            OpenAiAuth::ChatGptPlan(SecretString::new("plan-capped".to_string().into())),
            false,
        )
        .with_base(&server.uri());
        let err = capped.list_models().await.expect_err("429 must fail");
        assert!(matches!(err, LlmError::PlanCapReached), "{err}");
        let dead = DirectOpenAI::new(
            OpenAiAuth::ChatGptPlan(SecretString::new("plan-dead".to_string().into())),
            false,
        )
        .with_base(&server.uri());
        let err = dead.list_models().await.expect_err("401 must fail");
        assert!(matches!(err, LlmError::PlanReauthRequired), "{err}");
    }

    #[test]
    fn openai_display_names_are_cosmetic_only() {
        assert_eq!(openai_display_name("gpt-5.6-sol"), "GPT-5.6 Sol");
        assert_eq!(openai_display_name("gpt-5.6-terra"), "GPT-5.6 Terra");
        assert_eq!(openai_display_name("o3"), "O3");
        assert_eq!(openai_display_name("gpt-4.1-mini"), "GPT-4.1 Mini");
    }

    #[test]
    fn dated_snapshot_detection() {
        assert_eq!(
            dated_snapshot_base("gpt-5.6-sol-2026-09-01"),
            Some("gpt-5.6-sol")
        );
        assert_eq!(dated_snapshot_base("gpt-5.6-sol"), None);
        assert_eq!(dated_snapshot_base("claude-haiku-4-5-20251001"), None);
    }

    // ----- model discovery: wiremock round trips ------------------------

    #[tokio::test]
    async fn anthropic_list_models_round_trip_follows_pagination() {
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("x-api-key", "sk-ant-test"))
            .and(query_param("after_id", "claude-sonnet-5-5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"id": "claude-haiku-4-5", "display_name": "Claude Haiku 4.5",
                          "created_at": "2025-10-01T00:00:00Z"}],
                "has_more": false
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("x-api-key", "sk-ant-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"id": "claude-sonnet-5-5", "display_name": "Claude Sonnet 5.5",
                          "created_at": "2026-08-01T00:00:00Z"}],
                "has_more": true, "last_id": "claude-sonnet-5-5"
            })))
            .mount(&server)
            .await;
        let client =
            DirectAnthropic::new(SecretString::new("sk-ant-test".to_string().into()), false)
                .with_base(&server.uri());
        let models = client.list_models().await.expect("list");
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["claude-sonnet-5-5", "claude-haiku-4-5"]);
    }

    #[tokio::test]
    async fn openai_list_models_round_trip_and_401_maps_to_key_rejected() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer sk-good"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [{"id": "gpt-5.6-sol", "created": 1_790_000_000, "owned_by": "system"},
                         {"id": "tts-1", "created": 1, "owned_by": "openai-internal"}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(header("authorization", "Bearer sk-bad"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": {"message": "Incorrect API key"}})),
            )
            .mount(&server)
            .await;
        let good = DirectOpenAI::new(
            OpenAiAuth::ApiKey(SecretString::new("sk-good".to_string().into())),
            false,
        )
        .with_base(&server.uri());
        let models = good.list_models().await.expect("list");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].display_name, "GPT-5.6 Sol");

        let bad = DirectOpenAI::new(
            OpenAiAuth::ApiKey(SecretString::new("sk-bad".to_string().into())),
            false,
        )
        .with_base(&server.uri());
        let err = bad.list_models().await.expect_err("401 must fail");
        assert!(matches!(err, LlmError::KeyRejected { .. }), "{err}");
    }

    #[test]
    fn status_mapping_is_stable_and_embeds_markers() {
        let e = status_error(ANTHROPIC, 401, "");
        assert!(matches!(e, LlmError::KeyRejected { .. }));
        assert!(e.to_string().contains("provider_key_rejected"), "{e}");
        assert!(e.to_string().contains("Anthropic"), "{e}");

        let e = status_error(OPENAI, 403, "");
        assert!(matches!(e, LlmError::KeyRejected { .. }));

        let e = status_error(OPENAI, 429, "");
        assert!(e.to_string().contains("rate_limit_exceeded"), "{e}");

        for s in [502u16, 503, 529] {
            let e = status_error(ANTHROPIC, s, "");
            assert!(e.to_string().contains("provider_overloaded"), "{s}: {e}");
        }

        let e = status_error(
            ANTHROPIC,
            400,
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: too large"}}"#,
        );
        let rendered = e.to_string();
        assert!(rendered.contains("400"), "{rendered}");
        assert!(rendered.contains("max_tokens: too large"), "{rendered}");
        assert!(!rendered.contains("invalid_request_error"), "{rendered}");
    }

    #[test]
    fn error_snippet_strips_controls_and_truncates() {
        let s = error_message_snippet(&format!("bad\x1b[31mgateway\n{}", "x".repeat(500)));
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\n'));
        assert!(s.chars().count() <= 200);
        // Non-JSON body passes through (sanitized).
        assert!(s.starts_with("bad"));
        // OpenAI shape.
        let s = error_message_snippet(r#"{"error":{"message":"Incorrect API key","type":"x"}}"#);
        assert_eq!(s, "Incorrect API key");
    }
}
