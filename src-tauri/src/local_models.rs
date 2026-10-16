//! BYOM local-models status IPC (v3.0.0 A2) — the read-only probe
//! surface behind Settings → Local models and the chat model picker.
//!
//! These are user-facing `#[tauri::command]`s, NOT agent tools: the
//! agent's tool surface stays exactly four (Rule 2), and the agent has
//! no path that reads or writes local-endpoint configuration. Per
//! Rule 1 nothing returned is a credential — names, sizes, flags.

use std::time::Duration;

use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tracing::warn;

use crate::commands::{
    resolve_local_endpoints, resolve_local_models, validate_endpoint, write_local_endpoints,
    LocalEndpoint, LocalEndpointKind, LOCAL_MODELS_MAX_ENDPOINTS,
};

/// One local model. `id` is the namespaced form the chat factory
/// routes on (`ollama:<name>`); the picker additionally filters on
/// `tools_capable` (the agent loop requires tool calling).
#[derive(Debug, Clone, Serialize)]
pub struct LocalModelEntry {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    pub tools_capable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalModelsStatus {
    pub enabled: bool,
    pub reachable: bool,
    pub base_url: String,
    pub version: Option<String>,
    /// `Some(false)` when the server predates `/api/show`
    /// capabilities (< 0.6.4) — every model would report
    /// `tools_capable: false`, so the UI should prompt an upgrade
    /// instead of showing an empty picker. `None` = unparseable.
    pub version_supported: Option<bool>,
    pub models: Vec<LocalModelEntry>,
    /// Installed `:cloud` tags — hidden from selection because they
    /// proxy inference through ollama.com (threat-model T33). Listed
    /// so Settings can say WHY they're hidden.
    pub hidden_cloud_models: Vec<String>,
    /// User-shaped reason when `reachable` is false.
    pub error: Option<String>,
    /// Config-resolution warning (e.g. a rejected non-loopback URL).
    pub warning: Option<String>,
}

/// Probe the configured loopback Ollama server. Short-circuits when
/// the feature is disabled — Transit never probes localhost ports the
/// user didn't opt into.
#[tauri::command]
pub async fn local_models_status() -> Result<LocalModelsStatus, String> {
    let resolved = resolve_local_models();
    let mut status = LocalModelsStatus {
        enabled: resolved.enabled,
        reachable: false,
        base_url: resolved.cfg.base_url.clone(),
        version: None,
        version_supported: None,
        models: Vec::new(),
        hidden_cloud_models: Vec::new(),
        error: None,
        warning: resolved.warning,
    };
    if !resolved.enabled {
        return Ok(status);
    }
    match transit_agent::llm::ollama::probe(&resolved.cfg.base_url).await {
        Ok(p) => {
            status.reachable = true;
            status.version_supported = version_at_least(
                &p.version,
                transit_agent::llm::ollama::MIN_SUPPORTED_VERSION,
            );
            status.version = Some(p.version);
            status.models = p
                .models
                .into_iter()
                .map(|m| LocalModelEntry {
                    id: format!("ollama:{}", m.name),
                    name: m.name,
                    size_bytes: m.size_bytes,
                    tools_capable: m.tools_capable,
                })
                .collect();
            status.hidden_cloud_models = p.hidden_cloud_models;
        }
        Err(e) => status.error = Some(e),
    }
    Ok(status)
}

// ---------------------------------------------------------------------
// Custom endpoints — CRUD + bearer tokens + status (BYOM A3).
//
// Bearer tokens live in the OS keychain (service `transit-local-
// endpoint`, account = endpoint id — the provider_keys.rs layout), write-only
// over IPC (Rule 1): set/clear only, status returns booleans. The
// chat factory reads them via `read_endpoint_token` in-process.
// ---------------------------------------------------------------------

const ENDPOINT_TOKEN_SERVICE: &str = "transit-ce-local-endpoint";

/// Read the stored bearer for an endpoint id. Factory-side use in the
/// chat path — the token never crosses IPC outbound.
pub fn read_endpoint_token(id: &str) -> keyring::Result<Option<SecretString>> {
    let entry = Entry::new(ENDPOINT_TOKEN_SERVICE, id)?;
    match entry.get_password() {
        Ok(s) => Ok(Some(SecretString::new(s.into()))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_endpoint_token(id: &str, value: &SecretString) -> keyring::Result<()> {
    let entry = Entry::new(ENDPOINT_TOKEN_SERVICE, id)?;
    entry.set_password(value.expose_secret())
}

fn clear_endpoint_token(id: &str) -> keyring::Result<()> {
    let entry = Entry::new(ENDPOINT_TOKEN_SERVICE, id)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

fn token_present(id: &str) -> bool {
    match read_endpoint_token(id) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            warn!(endpoint = %id, error = %e, "endpoint token read failed");
            false
        }
    }
}

/// Endpoint view for the Settings UI — the config entry plus a
/// has-token boolean. Never the token itself (Rule 1).
#[derive(Debug, Clone, Serialize)]
pub struct LocalEndpointView {
    pub id: String,
    pub name: String,
    pub kind: LocalEndpointKind,
    pub base_url: String,
    pub context_length: u32,
    pub has_token: bool,
}

#[tauri::command]
pub fn local_endpoints_list() -> Result<Vec<LocalEndpointView>, String> {
    Ok(resolve_local_endpoints()
        .into_iter()
        .map(|ep| {
            let has_token = token_present(&ep.id);
            LocalEndpointView {
                id: ep.id,
                name: ep.name,
                kind: ep.kind,
                base_url: ep.base_url,
                context_length: ep.context_length,
                has_token,
            }
        })
        .collect())
}

/// Create or replace (by id) a custom endpoint. Validation — id
/// charset, transport rules (T35), context range — happens here so a
/// bad entry is an error the Settings UI shows, never silently
/// rewritten.
#[tauri::command]
pub async fn local_endpoint_upsert(endpoint: LocalEndpoint) -> Result<(), String> {
    validate_endpoint(&endpoint)?;
    let mut list = resolve_local_endpoints();
    if let Some(slot) = list.iter_mut().find(|e| e.id == endpoint.id) {
        *slot = endpoint;
    } else {
        if list.len() >= LOCAL_MODELS_MAX_ENDPOINTS {
            return Err(format!(
                "at most {LOCAL_MODELS_MAX_ENDPOINTS} custom endpoints are supported"
            ));
        }
        list.push(endpoint);
    }
    write_local_endpoints(&list)
}

/// Delete an endpoint and (best-effort) its keychain token. Idempotent.
#[tauri::command]
pub async fn local_endpoint_delete(id: String) -> Result<(), String> {
    let mut list = resolve_local_endpoints();
    list.retain(|e| e.id != id);
    write_local_endpoints(&list)?;
    if let Err(e) = clear_endpoint_token(&id) {
        // The config row is gone either way; a stranded token is
        // unreachable (reads are keyed by configured ids) but worth a
        // trace for the keychain audit.
        warn!(endpoint = %id, error = %e, "endpoint token cleanup failed");
    }
    Ok(())
}

/// Store an endpoint bearer token in the OS keychain. Write-only —
/// there is no corresponding read IPC by design (Rule 1; mirrors
/// `provider_key_set`).
#[tauri::command]
pub fn local_endpoint_set_token(id: String, value: String) -> Result<(), String> {
    if !resolve_local_endpoints().iter().any(|e| e.id == id) {
        return Err(format!("no endpoint with id `{id}`"));
    }
    let secret = SecretString::new(value.into());
    if secret.expose_secret().trim().is_empty() {
        return Err("token cannot be empty".to_string());
    }
    write_endpoint_token(&id, &secret).map_err(|e| {
        warn!(endpoint = %id, error = %e, "local_endpoint_set_token failed");
        e.to_string()
    })
}

/// Remove an endpoint bearer token. Idempotent.
#[tauri::command]
pub fn local_endpoint_clear_token(id: String) -> Result<(), String> {
    clear_endpoint_token(&id).map_err(|e| {
        warn!(endpoint = %id, error = %e, "local_endpoint_clear_token failed");
        e.to_string()
    })
}

/// One model offered by a custom endpoint. `tools_capable` is
/// `Some(_)` for Ollama endpoints (`/api/show` capabilities) and
/// `None` for OpenAI-compat ones — that wire has no capability
/// metadata, so tool support is unverified.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointModelEntry {
    pub id: String,
    pub name: String,
    pub tools_capable: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalEndpointStatus {
    pub id: String,
    pub name: String,
    pub kind: LocalEndpointKind,
    pub reachable: bool,
    pub error: Option<String>,
    pub models: Vec<EndpointModelEntry>,
    /// `:cloud` tags on a REMOTE Ollama server still proxy inference
    /// to ollama.com from that server — hidden for the same T33
    /// reason as the loopback path.
    pub hidden_cloud_models: Vec<String>,
}

/// Probe every configured custom endpoint. Sequential (≤8 endpoints,
/// 5s cap each); errors are per-endpoint, never fatal to the list.
#[tauri::command]
pub async fn local_endpoints_status() -> Result<Vec<LocalEndpointStatus>, String> {
    let mut out = Vec::new();
    for ep in resolve_local_endpoints() {
        out.push(endpoint_status(&ep).await);
    }
    Ok(out)
}

async fn endpoint_status(ep: &LocalEndpoint) -> LocalEndpointStatus {
    let http = transit_agent::llm::endpoint_http_client(&ep.base_url, Some(Duration::from_secs(5)));
    let mut st = LocalEndpointStatus {
        id: ep.id.clone(),
        name: ep.name.clone(),
        kind: ep.kind,
        reachable: false,
        error: None,
        models: Vec::new(),
        hidden_cloud_models: Vec::new(),
    };
    match ep.kind {
        LocalEndpointKind::Ollama => {
            match transit_agent::llm::ollama::probe_with(&http, &ep.base_url).await {
                Ok(p) => {
                    st.reachable = true;
                    st.models = p
                        .models
                        .into_iter()
                        .map(|m| {
                            let id = format!("endpoint:{}/{}", ep.id, m.name);
                            EndpointModelEntry {
                                id,
                                name: m.name,
                                tools_capable: Some(m.tools_capable),
                            }
                        })
                        .collect();
                    st.hidden_cloud_models = p.hidden_cloud_models;
                }
                Err(e) => st.error = Some(e),
            }
        }
        LocalEndpointKind::OpenaiCompat => {
            let bearer = read_endpoint_token(&ep.id).ok().flatten();
            match transit_agent::llm::openai_compat::list_models(
                &http,
                &ep.base_url,
                bearer.as_ref(),
            )
            .await
            {
                Ok(ids) => {
                    st.reachable = true;
                    st.models = ids
                        .into_iter()
                        .map(|m| {
                            let id = format!("endpoint:{}/{m}", ep.id);
                            EndpointModelEntry {
                                id,
                                name: m,
                                tools_capable: None,
                            }
                        })
                        .collect();
                }
                Err(e) => st.error = Some(e),
            }
        }
    }
    st
}

/// Dotted-version comparison tolerant of a `v` prefix and pre-release
/// suffixes (`v0.32.2-rc0` → `[0, 32, 2]`). `None` when unparseable.
fn version_at_least(version: &str, floor: &str) -> Option<bool> {
    fn parse(s: &str) -> Option<Vec<u64>> {
        s.trim()
            .trim_start_matches('v')
            .split('.')
            .map(|part| part.split('-').next().unwrap_or(part).parse::<u64>().ok())
            .collect()
    }
    Some(parse(version)? >= parse(floor)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_floor_comparisons() {
        assert_eq!(version_at_least("0.32.1", "0.6.4"), Some(true));
        assert_eq!(version_at_least("0.6.4", "0.6.4"), Some(true));
        assert_eq!(version_at_least("0.6.3", "0.6.4"), Some(false));
        assert_eq!(version_at_least("0.5.13", "0.6.4"), Some(false));
        assert_eq!(version_at_least("v0.32.2-rc0", "0.6.4"), Some(true));
        assert_eq!(version_at_least("garbage", "0.6.4"), None);
    }
}
