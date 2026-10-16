//! Provider API-key storage + IPC commands.
//!
//! The user supplies their own Anthropic and/or OpenAI API key. It is
//! stored in the OS keychain and, at send time, read HERE (transit_app is
//! a `deny.toml` keyring wrapper; transit_agent is not) and handed to the
//! direct provider client as a `SecretString`. The key goes to exactly
//! one host — the provider's own API — over OS-verified TLS with no
//! redirects and no ambient proxy (`transit_agent::llm::direct`,
//! threat-model T_DIRECT_KEY).
//!
//! Service-name layout: `transit-ce-provider-keys` with the provider id
//! as the account. Scoped separately from `transit_auth`'s SSH-credential
//! keychain entries so the agent firewall stays clean — `transit_agent`
//! never has cause to read this surface, and a secret audit can list all
//! provider keys with one keychain query. The `-ce-` infix keeps this
//! edition's entries apart from any other Transit install on the machine.
//!
//! The keys NEVER cross the IPC boundary back to the frontend. Set is
//! write-only (the `value` flows from frontend → keychain in one
//! direction); status returns booleans only ("is a key configured for
//! anthropic / openai?"). Rule 1.

use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::warn;
use transit_agent::{DirectAnthropic, DirectOpenAI, OpenAiAuth, ProviderModel};

pub(crate) const KEYRING_SERVICE: &str = "transit-ce-provider-keys";

/// Provider id used as the keychain account name. Kept as a typed
/// enum to prevent typos creeping in across IPC + keychain reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    Openai,
}

impl Provider {
    fn account(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
        }
    }

    /// Human-readable name for error copy. Matches the constants the
    /// direct clients embed in their errors.
    pub fn display_name(self) -> &'static str {
        match self {
            Provider::Anthropic => transit_agent::llm::direct::ANTHROPIC,
            Provider::Openai => transit_agent::llm::direct::OPENAI,
        }
    }

    /// Route a (non-local) model id to its provider: any id containing
    /// `claude` is Anthropic; everything else is OpenAI. Local
    /// (`ollama:` / `endpoint:`) ids never reach this — the chat factory
    /// checks `is_local_model` first.
    pub fn for_model(model: &str) -> Self {
        if model.contains("claude") {
            Provider::Anthropic
        } else {
            Provider::Openai
        }
    }
}

/// Read the stored key for `provider`, if any. Returns `Ok(None)` when
/// no entry exists (the common "user hasn't enrolled a key" case);
/// `Ok(Some)` when a key is present; `Err` only on real keychain
/// failures (locked, denied, etc.).
pub fn read_key(provider: Provider) -> keyring::Result<Option<SecretString>> {
    let entry = Entry::new(KEYRING_SERVICE, provider.account())?;
    match entry.get_password() {
        Ok(s) => Ok(Some(SecretString::new(s.into()))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_key(provider: Provider, value: &SecretString) -> keyring::Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, provider.account())?;
    entry.set_password(value.expose_secret())
}

fn clear_key(provider: Provider) -> keyring::Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, provider.account())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Frontend-facing status — does the keychain currently hold a key
/// for each provider? Booleans only; the keys themselves never
/// flow back across IPC.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderKeysStatus {
    pub anthropic: bool,
    pub openai: bool,
}

// ---------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------

/// Store a provider key in the OS keychain. The Settings → API keys tab
/// calls this when the user clicks Save. The IPC is write-only — no
/// corresponding read command exists by design (Rule 1).
///
/// `value` arrives as a plain `String` because Tauri's command-arg
/// deserializer doesn't accept `SecretString` (no `Deserialize` impl,
/// intentional). Wrap immediately on entry and don't touch the raw
/// `String` again — same pattern as `commands::enroll_secret`.
#[tauri::command]
pub fn provider_key_set(provider: Provider, value: String) -> Result<(), String> {
    let secret = SecretString::new(value.into());
    if secret.expose_secret().trim().is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    write_key(provider, &secret).map_err(|e| {
        warn!(provider = ?provider, error = %e, "provider_key_set failed");
        e.to_string()
    })
}

/// Remove a provider key from the OS keychain. Idempotent — clearing a
/// non-existent entry is a successful no-op.
#[tauri::command]
pub fn provider_key_clear(provider: Provider) -> Result<(), String> {
    clear_key(provider).map_err(|e| {
        warn!(provider = ?provider, error = %e, "provider_key_clear failed");
        e.to_string()
    })
}

/// Report whether each provider has a key configured. Returns
/// booleans, never the keys themselves.
#[tauri::command]
pub fn provider_keys_status() -> Result<ProviderKeysStatus, String> {
    Ok(ProviderKeysStatus {
        anthropic: key_present(Provider::Anthropic),
        openai: key_present(Provider::Openai),
    })
}

/// The provider's live model catalogue for the enrolled key, newest
/// first. Metadata only crosses IPC (Rule 1); the key is read in-process
/// and sent to the provider's own host exactly as a chat request would be.
/// Strict TLS is re-resolved per call like the chat factory does.
#[tauri::command]
pub async fn provider_models_list(
    provider: Provider,
    chatgpt: tauri::State<'_, std::sync::Arc<crate::chatgpt_auth::ChatGptState>>,
) -> Result<Vec<ProviderModel>, String> {
    let strict_tls = crate::commands::resolve_strict_tls();
    // OpenAI on a ChatGPT plan lists the plan's catalogue with the plan
    // token; no key is involved.
    if provider == Provider::Openai
        && crate::chatgpt_auth::read_openai_method() == crate::chatgpt_auth::OpenAiMethod::Chatgpt
    {
        let token = chatgpt.access_token().await.map_err(|e| match e {
            crate::chatgpt_auth::PlanAuthError::Reauth => {
                "ChatGPT sign-in has expired — sign in again (plan_reauth_required)".to_string()
            }
            crate::chatgpt_auth::PlanAuthError::Other(m) => m,
        })?;
        return DirectOpenAI::new(OpenAiAuth::ChatGptPlan(token), strict_tls)
            .list_models()
            .await
            .map_err(|e| e.to_string());
    }
    let key = read_key(provider)
        .map_err(|e| {
            format!(
                "could not read the {} API key: {e}",
                provider.display_name()
            )
        })?
        .ok_or_else(|| {
            format!(
                "no {} API key configured (missing_provider_key)",
                provider.display_name()
            )
        })?;
    let models = match provider {
        Provider::Anthropic => DirectAnthropic::new(key, strict_tls).list_models().await,
        Provider::Openai => {
            DirectOpenAI::new(OpenAiAuth::ApiKey(key), strict_tls)
                .list_models()
                .await
        }
    }
    .map_err(|e| e.to_string())?;
    Ok(models)
}

fn key_present(provider: Provider) -> bool {
    match read_key(provider) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!(provider = ?provider, error = %e, "provider_keys_status read failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_account_strings_are_stable() {
        // The keychain account name is part of the storage layout —
        // changing it strands existing users' keys. Pin the strings
        // so a careless rename surfaces here.
        assert_eq!(Provider::Anthropic.account(), "anthropic");
        assert_eq!(Provider::Openai.account(), "openai");
    }

    #[test]
    fn provider_serde_round_trips_lowercase() {
        let s = serde_json::to_string(&Provider::Anthropic).unwrap();
        assert_eq!(s, "\"anthropic\"");
        let p: Provider = serde_json::from_str(&s).unwrap();
        assert_eq!(p, Provider::Anthropic);
    }

    #[test]
    fn keyring_service_constant_pinned() {
        // Same reasoning as the account-name test — pin the service
        // name so a refactor doesn't accidentally orphan stored keys.
        // The `-ce-` infix is deliberate: it keeps this edition's
        // entries apart from any other Transit install's.
        assert_eq!(KEYRING_SERVICE, "transit-ce-provider-keys");
    }

    #[test]
    fn model_routing_claude_to_anthropic_else_openai() {
        assert_eq!(Provider::for_model("claude-opus-4-7"), Provider::Anthropic);
        assert_eq!(Provider::for_model("gpt-5.6-sol"), Provider::Openai);
        assert_eq!(Provider::for_model("o1-preview"), Provider::Openai);
    }
}
