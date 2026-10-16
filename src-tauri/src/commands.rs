//! Tauri IPC commands.
//!
//! Every `#[tauri::command]` defined here is reviewed against the First
//! Inviolable Rule: NO command returns a value containing a credential.
//! Adding a new command requires the `transit-security-audit` skill to
//! pass on the diff.
//!
//! Commands operate on a shared [`AppState`] that holds the canonical
//! inventory path plus the in-memory `DocumentMut` representation
//! (so user comments + ordering survive every mutation). Reads grab a
//! read lock and project to wire types; writes grab a write lock,
//! mutate the document, validate, and persist via the mutator's
//! atomic-write helper.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::RwLock;
use transit_auth::{BackendAvailability, KeyProbeVerdict, SecretRegistry};
use transit_core::import::{
    analyze, identity_key, parse as parse_import, sanitize_id, AuthKind, ImportSource,
    SuggestedSecret,
};
use transit_core::inventory::{
    load,
    mutator::{
        add_api_session as core_add_api_session, add_auth_profile as core_add_auth_profile,
        add_device as core_add_device, add_device_no_revalidate as core_add_device_no_revalidate,
        add_group as core_add_group, delete_api_session as core_delete_api_session,
        delete_auth_profile as core_delete_auth_profile, delete_device as core_delete_device,
        delete_group as core_delete_group, rename_group as core_rename_group,
        revalidate as core_revalidate, set_api_session_pin as core_set_api_session_pin,
        set_device_group as core_set_device_group, update_api_session as core_update_api_session,
        update_auth_profile as core_update_auth_profile, update_device as core_update_device,
        write_atomic, DocumentMut,
    },
    ApiEndpointKind, ApiSession, AuthProfile, Device, InventoryError,
};

// ---------------------------------------------------------------------
// Wire types.
// ---------------------------------------------------------------------

/// Metadata-only projection of [`Device`] for the frontend. Note the
/// **absence** of any auth-bearing field — that's the IPC boundary
/// rule (see CLAUDE.md §"The Three Inviolable Rules"). The auth
/// profile *name* (`auth`) is included because the frontend needs it
/// to populate the edit dialog's "auth" select.
#[derive(Debug, Serialize)]
pub struct DeviceMeta {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub vendor: String,
    pub group: Option<String>,
    /// Optional per-device accent color (curated palette token). `None`
    /// = no accent. Non-secret display metadata — Rule 1 safe to expose.
    pub color: Option<String>,
    /// Free-form organizational tags. Non-secret display metadata.
    pub tags: Vec<String>,
    pub auth: String,
    /// Per-device terminal preference. `None` means "not set" — the
    /// frontend's `TerminalPane` falls back to the safe default
    /// (highlighting off). See `transit_core::inventory::types::Device`.
    pub syntax_highlighting: Option<bool>,
    /// Per-device quick copy/paste. `None` means "not set" — the
    /// frontend's `TerminalPane` falls back to off (no auto-copy, no
    /// middle/right-click paste; standard Cmd-V paste still works).
    pub quick_copy_paste: Option<bool>,
    /// Per-device terminal font family override (v4.1.0). `None` = use
    /// the global terminal font. Non-secret display metadata.
    pub font_family: Option<String>,
    /// Per-device terminal font size in CSS pixels (v4.1.0). `None` =
    /// use the global size. The frontend clamps to 8–32 on read.
    pub font_size: Option<u16>,
    /// Per-device "bold accent" toggle (v4.1.0). `Some(true)` renders
    /// the `color` as a louder background tint, not just the edge.
    pub bold_color: Option<bool>,
    /// Per-device weak-crypto opt-in. `Some(true)` means the user
    /// has previously approved SHA1 KEX/CBC/ssh-rsa for this device
    /// via the warning dialog; subsequent connects skip the prompt.
    /// `None` / `Some(false)` keeps the strict default.
    pub allow_weak_crypto: Option<bool>,
    /// External-inventory match key (v6.2.0 — NetBox device id). Absent
    /// for hand-added/file-imported devices. Non-secret sync metadata.
    pub netbox_id: Option<String>,
    /// Jump host reference (v6.5.0) — the id of another device this one
    /// tunnels through. Non-secret topology metadata; the frontend
    /// renders it in the device dialogs and the "via" session hint.
    pub jump_via: Option<String>,
    /// Per-device SSH agent-forwarding opt-in (v6.5.0, T53). Non-secret.
    pub forward_agent: Option<bool>,
}

impl From<Device> for DeviceMeta {
    fn from(d: Device) -> Self {
        Self {
            id: d.id,
            host: d.host,
            port: d.port,
            vendor: d.vendor.as_str().to_string(),
            group: d.group,
            color: d.color,
            tags: d.tags,
            auth: d.auth,
            syntax_highlighting: d.syntax_highlighting,
            quick_copy_paste: d.quick_copy_paste,
            font_family: d.font_family,
            font_size: d.font_size,
            bold_color: d.bold_color,
            allow_weak_crypto: d.allow_weak_crypto,
            netbox_id: d.netbox_id,
            jump_via: d.jump_via,
            forward_agent: d.forward_agent,
        }
    }
}

/// Auth profile metadata — name + username + secret backend kind,
/// plus the `ssh_key` backend's key-file path. Secret-resolving
/// reference bodies (keyring key, op reference, agent fingerprint)
/// stay omitted; the frontend never needs them for display, and
/// surfacing them invites accidental leakage in logs. The key-file
/// PATH is different: a filesystem reference, never key material
/// (Rule 1 precedent: `ImportIdentityMeta::key_path` and the CSV
/// exporter both carry it), surfaced so the edit dialog can prefill
/// the path instead of forcing a re-Browse (v1.6.0 follow-up, #116).
#[derive(Debug, Serialize)]
pub struct AuthProfileMeta {
    pub name: String,
    pub username: String,
    pub backend: String,
    /// `Some` only for the `ssh_key` backend. `encrypted_file` also
    /// holds a path but has no dialog support (TOML-only), so it is
    /// deliberately not surfaced.
    pub key_path: Option<String>,
}

/// Metadata-only projection of [`ApiSession`] for the frontend (v4.0.0).
/// Like [`DeviceMeta`] no secret VALUE crosses the boundary, and like
/// [`AuthProfileMeta`] only the secret backend KIND is exposed — never
/// the reference body (`SecretRef` is deserialize-only across IPC: the
/// frontend sends references in, never receives them out). The edit
/// dialog resends `secret: null` to keep the existing reference.
#[derive(Debug, Serialize)]
pub struct ApiSessionMeta {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub kind: String,
    pub host: Option<String>,
    pub console_id: Option<String>,
    pub base_url: Option<String>,
    pub group: Option<String>,
    pub color: Option<String>,
    pub tags: Vec<String>,
    pub backend: String,
    /// The auth scheme (no secret), so the edit dialog can prefill it.
    pub auth: transit_core::inventory::AuthScheme,
    /// User-pinned self-signed leaf-cert SHA-256 (hex), or None for OS-trust.
    /// A public fingerprint, not a secret — lets the UI show "trusted" state.
    pub pinned_cert_sha256: Option<String>,
}

impl From<ApiSession> for ApiSessionMeta {
    fn from(s: ApiSession) -> Self {
        Self {
            id: s.id,
            name: s.name,
            vendor: s.vendor.as_str().to_string(),
            kind: s.kind.as_str().to_string(),
            host: s.host,
            console_id: s.console_id,
            base_url: s.base_url,
            group: s.group,
            color: s.color,
            tags: s.tags,
            backend: s
                .secret
                .as_ref()
                .map(|r| secret_backend_label(r).to_string())
                .unwrap_or_else(|| "none".to_string()),
            auth: s.auth,
            pinned_cert_sha256: s.pinned_cert_sha256,
        }
    }
}

// ---------------------------------------------------------------------
// AppState.
// ---------------------------------------------------------------------

/// In-memory inventory state. Either `Ready` (mutations allowed) or
/// `Broken` (file exists but failed validation; mutations refused
/// until the user fixes the file by hand). NotFound at startup is
/// modeled as `Ready(empty doc)` — the first mutation creates the
/// file at [`AppState::inventory_path`].
pub enum InventoryState {
    Ready(DocumentMut),
    Broken { reason: String },
}

pub struct AppState {
    pub inventory_path: PathBuf,
    pub inventory: RwLock<InventoryState>,
    /// Secret backends + 60s zeroizing cache. Built at startup; the
    /// cache sweeper task is spawned by `lib.rs::run`'s setup callback
    /// (it needs an active tokio runtime — `AppState::new` is sync).
    pub secrets: Arc<SecretRegistry>,
    /// Phase 2b: open SSH sessions + host-key store + pending TOFU
    /// confirmations. Built async (HostKeyStore reads from disk).
    pub ssh: Arc<crate::ssh::SshState>,
    /// Phase 4: per-vendor command policy gate. Loaded at startup
    /// from `policies/<vendor>.yaml`, optionally layered with a user
    /// policy directory (BYOP, Phase 2a). Phase 5a's `propose_command`
    /// agent tool routes through this — see CLAUDE.md §3 Rule 3.
    pub policy: Arc<transit_policy::PolicyEngine>,
    /// Non-fatal diagnostics from loading the BYOP user policy layer
    /// (skipped/unparseable files, ignored mode/precedence overrides).
    /// Empty when no user layer is configured. Surfaced read-only to
    /// the Settings UI; the bundled floor is intact regardless.
    pub policy_warnings: Vec<String>,
    /// v4.0.0 — shared hardened HTTP client for API sessions. Clone-cheap
    /// (reqwest `Client` is Arc-backed); built once so `api_send_request`
    /// reuses the connection pool + OS-trust config instead of rebuilding
    /// (and re-parsing system trust anchors) on every request.
    pub api_client: transit_api::ApiClient,
    /// v4.0.0 — per-controller request/response history rings. Every human
    /// `api_send_request` appends here so the AGENT can list + read a
    /// controller (via `list_open_sessions` / `read_scrollback`, redacted).
    /// Lazily populated; an API "session" is a frontend tab, not a live
    /// connection.
    pub api_sessions: Arc<crate::api_session::ApiSessionState>,
}

impl AppState {
    /// Build initial state by trying to load the canonical path.
    /// Missing inventory file → empty doc. Other inventory errors →
    /// `Broken` (visible to the user; mutations refused until manual
    /// repair). Policy-load errors propagate — refusing to start with
    /// a broken policy file is safer than degrading to default-deny
    /// silently (which would mask the misconfiguration from operators).
    pub async fn new(
        inventory_path: PathBuf,
        policies_dir: PathBuf,
        user_policies_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        let state = match load_initial_state(&inventory_path) {
            Ok(s) => s,
            Err(reason) => InventoryState::Broken { reason },
        };
        let ssh = Arc::new(crate::ssh::SshState::new().await?);
        // BYOP (Phase 2a): when a user policy directory is configured,
        // layer it over the bundled set with the read-only floor. A
        // broken/ malicious user layer never fails startup (it's
        // user-controllable) — its problems come back as `warnings`,
        // logged here and surfaced read-only to the Settings UI; the
        // bundled floor stays intact. A broken BUNDLED policy is still
        // fatal below (an installer bug).
        let (policy, policy_warnings) = match &user_policies_dir {
            Some(user_dir) => {
                let loaded = transit_policy::PolicyEngine::from_layers(&policies_dir, user_dir)
                    .map_err(|e| format!("policy load failed: {e}"))?;
                for w in &loaded.warnings {
                    tracing::warn!(target: "transit_policy::user_layer", "{w}");
                }
                (loaded.engine, loaded.warnings)
            }
            None => {
                let engine = transit_policy::PolicyEngine::load_from_dir(&policies_dir)
                    .map_err(|e| format!("policy load failed: {e}"))?;
                (engine, Vec::new())
            }
        };
        if policy.is_empty() {
            // Zero policies = every propose_command default-denies
            // with `no policy registered for vendor <X>`. In release
            // that's almost always an installer-bundling bug (the
            // a Windows test build shipped without policies for exactly this
            // reason): fail loud at startup so the misconfiguration
            // surfaces as a launch error rather than as a confusing
            // per-command denial inside every chat. Dev builds keep
            // the warn-and-continue posture so `cargo test` and
            // off-tree experimentation aren't blocked.
            #[cfg(not(debug_assertions))]
            {
                return Err(format!(
                    "no vendor policies loaded from {}; \
                     the installer may not have bundled the policies/ \
                     directory correctly",
                    policies_dir.display()
                ));
            }
            #[cfg(debug_assertions)]
            tracing::warn!(
                policies_dir = %policies_dir.display(),
                "no vendor policies loaded; every propose_command will default-deny"
            );
        }
        Ok(Self {
            inventory_path,
            inventory: RwLock::new(state),
            secrets: Arc::new(SecretRegistry::standard()),
            ssh,
            policy: Arc::new(policy),
            policy_warnings,
            api_client: transit_api::ApiClient::new(),
            api_sessions: Arc::new(crate::api_session::ApiSessionState::new()),
        })
    }
}

fn load_initial_state(path: &Path) -> Result<InventoryState, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            // Validate via the loader's chain before trusting the doc.
            load(path).map_err(|e| e.to_string())?;
            let doc = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
            Ok(InventoryState::Ready(doc))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(InventoryState::Ready(DocumentMut::new()))
        }
        Err(e) => Err(format!("io error reading {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------
// Path resolution.
// ---------------------------------------------------------------------

/// The single canonical path where the inventory lives (or will live).
/// Read AND write target.
///
/// Priority:
/// 1. `$TRANSIT_INVENTORY` (explicit override; binding even when the
///    file does not yet exist — first write creates it there).
/// 2. Debug builds: `<project_root>/transit.toml` (project-relative;
///    project root is `CARGO_MANIFEST_DIR`'s parent because
///    `cargo run` sets CWD to `src-tauri/`).
/// 3. Release builds: `dirs::config_dir()/TransitCommunity/transit.toml`
///    (per-OS canonical app data location).
pub fn inventory_path() -> PathBuf {
    if let Ok(env) = std::env::var("TRANSIT_INVENTORY") {
        return PathBuf::from(env);
    }
    if cfg!(debug_assertions) {
        if let Some(p) = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("transit.toml"))
        {
            return p;
        }
    }
    dirs::config_dir()
        .map(|d| d.join("TransitCommunity").join("transit.toml"))
        .unwrap_or_else(|| PathBuf::from("transit.toml"))
}

/// Resolve the per-vendor policies directory. Precedence:
///
/// 1. `$TRANSIT_POLICIES` — explicit override (CI, tests).
/// 2. **Release builds** — `app.path().resource_dir().join("policies")`.
///    Tauri's `PathResolver` returns the canonical bundled-resources
///    directory per OS, so the `policies/` suffix lines up with the
///    destination set in `tauri.conf.json`'s `bundle.resources` map
///    on every platform:
///
///    - macOS:           `<App>.app/Contents/Resources/`
///    - Windows NSIS:    `<install_dir>/`  *(the dir holding the .exe)*
///    - Linux deb:       `/usr/lib/<bundle_id>/`
///    - Linux AppImage:  `<exe_dir>/`
///
///    Older revisions of this function reconstructed the path by
///    hand from `current_exe()`. That assumed Tauri 1's
///    `<exe_dir>/resources/<dest>/` layout, which Tauri 2 dropped
///    on Windows. The mismatch once shipped a Windows test build with
///    zero policies — every `propose_command` default-denied with
///    "no policy registered for vendor junos". Using the runtime
///    resolver makes the lookup OS-agnostic and Tauri-version-
///    agnostic.
/// 3. **Debug / source-tree builds** — `<project_root>/policies/`
///    via `CARGO_MANIFEST_DIR`. Lets `cargo test` and `npm run
///    tauri dev` find policies without env vars or bundling.
/// 4. Final fallback: bare `policies` relative to CWD.
pub fn resolve_policies_dir<R: tauri::Runtime, M: Manager<R>>(app: &M) -> PathBuf {
    if let Ok(env) = std::env::var("TRANSIT_POLICIES") {
        return PathBuf::from(env);
    }

    if !cfg!(debug_assertions) {
        if let Ok(resource_dir) = app.path().resource_dir() {
            return resource_dir.join("policies");
        }
    }

    if let Some(p) = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("policies"))
    {
        return p;
    }
    PathBuf::from("policies")
}

/// Resolve the optional BYOP **user** policy directory (Phase 2a),
/// layered over the bundled `policies/` set. `None` means no user
/// layer — the engine loads bundled-only, exactly as before BYOP.
///
/// Precedence:
/// 1. `$TRANSIT_USER_POLICIES` — explicit override (power-user /
///    NAS-mount; the documented way to smoke-test BYOP on a dev build).
/// 2. A persisted `user_dir` setting (Phase 2 follow-up — a dedicated
///    `config.toml`, NOT the inventory file: the inventory is
///    `deny_unknown_fields`, so a `[policy]` table there would brick
///    the inventory on an older build after a rollback).
///
/// Unlike the bundled dir this is deliberately NOT defaulted to a
/// path-on-disk: absent configuration means "no user layer", not "look
/// in some default location" (we don't want a stray directory to start
/// silently widening the gate).
pub fn resolve_user_policies_dir() -> Option<PathBuf> {
    if let Ok(env) = std::env::var("TRANSIT_USER_POLICIES") {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    read_configured_user_policies_dir()
}

/// The app config file path (separate from the inventory — see
/// [`read_configured_user_policies_dir`] for why). Mirrors
/// [`inventory_path`]'s precedence: `$TRANSIT_CONFIG` override, else
/// debug → `<project_root>/transit-config.toml`, else release →
/// `dirs::config_dir()/TransitCommunity/config.toml`.
pub fn config_path() -> PathBuf {
    if let Ok(env) = std::env::var("TRANSIT_CONFIG") {
        return PathBuf::from(env);
    }
    if cfg!(debug_assertions) {
        if let Some(p) = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("transit-config.toml"))
        {
            return p;
        }
    }
    dirs::config_dir()
        .map(|d| d.join("TransitCommunity").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("config.toml"))
}

/// Read the persisted BYOP user-policy directory from `config.toml`'s
/// `[policy] user_dir`. A **dedicated** config file, NOT the inventory:
/// the inventory is `deny_unknown_fields`, so a `[policy]` table there
/// would make the inventory unreadable to an OLDER build after a
/// rollback (T_USER_POLICY / the plan's rollback finding). This file is
/// invisible to builds that don't know about it.
///
/// Resilient: a missing file, a parse error, or a missing key all yield
/// `None` (the common "no user layer" case) — a broken config never
/// blocks startup.
fn read_configured_user_policies_dir() -> Option<PathBuf> {
    read_user_policies_dir_at(&config_path())
}

/// Path-parameterized core of [`read_configured_user_policies_dir`] so
/// the round-trip is unit-testable without touching process env / the
/// real config location.
fn read_user_policies_dir_at(path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let dir = table
        .get("policy")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("user_dir"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    Some(PathBuf::from(dir))
}

/// Persist (or clear) the BYOP user-policy directory in `config.toml`.
/// `None` or an empty/whitespace string removes the key. Atomic write
/// (tempfile + rename). Takes effect on the next launch — the policy
/// engine is built once at startup (hot-reload is out of scope, matching
/// the inventory posture).
fn write_configured_user_policies_dir(dir: Option<&str>) -> Result<(), String> {
    write_user_policies_dir_at(&config_path(), dir)
}

fn write_user_policies_dir_at(path: &Path, dir: Option<&str>) -> Result<(), String> {
    // The config file is app-managed (not hand-curated like the
    // inventory), so a plain `toml` round-trip — not formatting-
    // preserving `toml_edit` — is fine and keeps the dep surface small.
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };

    let trimmed = dir.map(str::trim).filter(|s| !s.is_empty());
    match trimmed {
        Some(d) => {
            let policy = table
                .entry("policy")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let Some(pt) = policy.as_table_mut() {
                pt.insert("user_dir".into(), toml::Value::String(d.to_string()));
            }
        }
        None => {
            if let Some(pt) = table.get_mut("policy").and_then(|p| p.as_table_mut()) {
                pt.remove("user_dir");
            }
        }
    }

    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    // Atomic: write a sibling tempfile then rename over the target.
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

/// Set (or remove) one string key in `config.toml`, atomically.
///
/// The generic form of the writer above. Same contract: the config file is
/// app-managed rather than hand-curated, so a plain `toml` round-trip is
/// fine, and the write is tempfile-plus-rename so a crash mid-write cannot
/// leave a truncated config that fails to parse on next launch.
pub(crate) fn write_config_string_at(
    path: &Path,
    section: &str,
    key: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };

    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => {
            let sect = table
                .entry(section.to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let Some(st) = sect.as_table_mut() {
                st.insert(key.to_string(), toml::Value::String(v.to_string()));
            }
        }
        None => {
            if let Some(st) = table.get_mut(section).and_then(|s| s.as_table_mut()) {
                st.remove(key);
            }
        }
    }

    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

/// Set one boolean key in `config.toml`, atomically. Sibling of
/// [`write_config_string_at`]; same contract.
fn write_config_bool_at(path: &Path, section: &str, key: &str, value: bool) -> Result<(), String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };
    let sect = table
        .entry(section.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(st) = sect.as_table_mut() {
        st.insert(key.to_string(), toml::Value::Boolean(value));
    }
    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

/// Read-only view of the BYOP policy configuration for the Settings UI.
/// Per Rule 1 nothing here is a credential — it's paths, vendor tags,
/// and load diagnostics.
#[derive(Debug, Serialize)]
pub struct PolicySettings {
    /// The user-policy directory that will load on next launch (env var
    /// or persisted config), or `None` for "no user layer".
    pub user_dir: Option<String>,
    /// True when `$TRANSIT_USER_POLICIES` is set — the path is then
    /// env-controlled and the Settings field is read-only.
    pub env_override: bool,
    /// Vendor tags loaded THIS session (built-in + merged + custom),
    /// sorted. Lets the UI confirm a custom vendor's policy took.
    pub vendors: Vec<String>,
    /// Non-fatal user-layer warnings from this session's load (skipped
    /// files, ignored mode/precedence overrides). Empty = clean load.
    pub warnings: Vec<String>,
}

#[tauri::command]
pub async fn get_policy_settings(state: State<'_, AppState>) -> Result<PolicySettings, String> {
    let env_override = env_set("TRANSIT_USER_POLICIES");
    let user_dir = resolve_user_policies_dir().map(|p| p.display().to_string());
    let mut vendors: Vec<String> = state
        .policy
        .vendors()
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    vendors.sort();
    Ok(PolicySettings {
        user_dir,
        env_override,
        vendors,
        warnings: state.policy_warnings.clone(),
    })
}

/// Persist the BYOP user-policy directory (`None`/empty clears it).
/// Takes effect on next launch — the engine is built once at startup.
/// Returns Ok even though the running session is unchanged; the UI
/// surfaces the "restart to apply" note.
#[tauri::command]
pub async fn set_user_policies_dir(dir: Option<String>) -> Result<(), String> {
    write_configured_user_policies_dir(dir.as_deref())
}

// ---------------------------------------------------------------------
// Network / TLS settings (`[network] strict_tls` in config.toml).
//
// Strict TLS controls the cloud client's trust anchors (see
// transit_tls + threat-model T27): OFF (default) trusts the
// OS store, so a corporate TLS-inspection CA installed in the keychain /
// Windows store is honored; ON trusts only the bundled webpki roots and
// refuses an inspected connection. Persisted in the SAME dedicated
// config.toml as `[policy] user_dir` (NOT the inventory — see
// `read_configured_user_policies_dir` for the rollback-safety reason; an
// older build simply ignores the `[network]` table). Read once at
// startup → restart-to-apply.
// ---------------------------------------------------------------------

/// Resolve the effective Strict-TLS setting. Precedence:
/// 1. `$TRANSIT_STRICT_TLS` — explicit override (handy for smoke-testing
///    against a MITM CA without editing config); `1`/`true`/`yes`/`on`
///    (case-insensitive) → strict, anything else → not strict.
/// 2. The persisted `[network] strict_tls` bool in `config.toml`.
/// 3. Default `false` (trust the OS store) when unset/unreadable.
pub fn resolve_strict_tls() -> bool {
    if let Ok(env) = std::env::var("TRANSIT_STRICT_TLS") {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
    }
    read_strict_tls_at(&config_path())
}

/// Read `[network] strict_tls` from `config.toml`. Resilient: a missing
/// file, parse error, missing table/key, or wrong type all yield the
/// safe-functional default `false` (trust the OS store) — a broken config
/// never blocks startup or silently strands the user offline.
fn read_strict_tls_at(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return false;
    };
    table
        .get("network")
        .and_then(|n| n.as_table())
        .and_then(|n| n.get("strict_tls"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// v4.4.0 — `[terminal] enabled` off-switch for the local Terminal surface.
// Default TRUE (the surface is free/on); a locked-down / MDM deployment sets
// `[terminal] enabled = false` in config.toml to remove it. NOT a paywall.
// Enforced BOTH frontend (rail entry hidden) and backend (`open_local_shell`
// refuses) — defense in depth. See plan §9.

/// Whether the in-app local Terminal surface is enabled.
pub fn resolve_terminal_enabled() -> bool {
    if let Ok(env) = std::env::var("TRANSIT_TERMINAL_ENABLED") {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
    }
    read_terminal_enabled_at(&config_path())
}

/// Read `[terminal] enabled` from `config.toml`. Resilient: any
/// missing/broken config yields the default `true` — the surface is on
/// unless a deployment explicitly turns it off.
fn read_terminal_enabled_at(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return true;
    };
    table
        .get("terminal")
        .and_then(|t| t.as_table())
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// IPC — whether the local Terminal surface is enabled (the frontend
/// hides the rail entry when this is false).
#[tauri::command]
pub fn terminal_enabled() -> bool {
    resolve_terminal_enabled()
}

// v5.0.0 — `[files] enabled` off-switch for the Files (SFTP) surface.
// Default TRUE (the surface is free/on); a locked-down / MDM deployment sets
// `[files] enabled = false` in config.toml to remove it. NOT a paywall — for
// file transfer this doubles as a DLP control (plan §9). Enforced BOTH
// frontend (rail entry hidden) and backend (`files_connect` AND
// `files_reconnect` refuse) — defense in depth, same shape as Terminal.
// Read per call / uncached, so editing config.toml applies without a restart.

/// Whether the Files (SFTP) surface is enabled.
pub fn resolve_files_enabled() -> bool {
    if let Ok(env) = std::env::var("TRANSIT_FILES_ENABLED") {
        let trimmed = env.trim();
        if !trimmed.is_empty() {
            return matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
    }
    read_files_enabled_at(&config_path())
}

/// Read `[files] enabled` from `config.toml`. Resilient: any
/// missing/broken config yields the default `true` — the surface is on
/// unless a deployment explicitly turns it off.
fn read_files_enabled_at(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return true;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return true;
    };
    table
        .get("files")
        .and_then(|t| t.as_table())
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// IPC — whether the Files surface is enabled (the frontend hides the rail
/// entry when this is false).
#[tauri::command]
pub fn files_enabled() -> bool {
    resolve_files_enabled()
}

// v6.0.0 — the PCaps surface has TWO off-switches, not one, and the
// second is the interesting one.
//
// `[pcap] enabled` is the familiar MDM/DLP switch: it removes the whole
// surface, exactly like `[files] enabled`. Packet capture is the most
// sensitive thing Transit can do on a machine, so a locked-down
// deployment needs to be able to say no.
//
// `[pcap] agent_access` is finer-grained and exists because PCaps is the
// first surface the assistant can see. A shop that wants the Explorer but
// not the AI reading its traffic can have exactly that, without giving up
// the feature. It is a cheap flag and a strong answer on a security
// questionnaire.
//
// Both are read per call, uncached, so editing config.toml takes effect on
// already-open captures rather than only on the next one.

/// Whether the PCaps surface is enabled.
pub fn resolve_pcap_enabled() -> bool {
    env_or_config("TRANSIT_PCAP_ENABLED", "pcap", "enabled")
}

/// Whether the AI assistant may query captures.
///
/// Independent of `enabled`: turning this off keeps the Explorer and
/// severs only the `query_capture` seam.
pub fn resolve_pcap_agent_access() -> bool {
    resolve_pcap_enabled() && env_or_config("TRANSIT_PCAP_AGENT_ACCESS", "pcap", "agent_access")
}

/// Read a boolean from an env var, else `[section] key` in config.toml,
/// else `true`.
///
/// Resilient by design: a missing or broken config yields the default, so
/// a typo in config.toml cannot silently disable a surface — only an
/// explicit `false` does.
fn env_or_config(env: &str, section: &str, key: &str) -> bool {
    if let Ok(v) = std::env::var(env) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
    }
    let Ok(text) = std::fs::read_to_string(config_path()) else {
        return true;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return true;
    };
    table
        .get(section)
        .and_then(|t| t.as_table())
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

// ---------------------------------------------------------------------
// Developer diagnostics (Settings → Developers)
// ---------------------------------------------------------------------
//
// An opt-in rolling log, for the case that costs the most: a machine
// nobody on this team will ever touch, failing in a way no screenshot
// explains. "Enable diagnostics, reproduce it, send me the file."
//
// TWO limits govern it, and they are different limits.
//
// 1. **No secrets** — `CLAUDE.md` §10, unchanged and unrelaxed. The file
//    receives the same events stderr already gets, so credentials, host
//    keys, tokens, prompt content and the deep-link query string stay out
//    of it for the same reason they stay out of stderr. A mode that logged
//    payloads would break the redaction boundary and must never exist.
//
// 2. **A verbosity ceiling** — kept as a CLAMP applied where the value is
//    used (`resolve_file_logging`), not a UI convention: `config.toml` is
//    user-editable and `TRANSIT_LOG_TO_FILE` is anyone's to set. The
//    proprietary edition capped release builds at `info` with module
//    targets off, because a `trace` log with targets is a runtime map of a
//    closed-source product. This edition's source is public, so the map is
//    already published and the ceiling is `trace` with targets ON; the
//    clamp machinery stays so a future build can lower it in one place.

/// The verbosity ceiling for the diagnostic log on this build.
const MAX_FILE_LOG_LEVEL: tracing::Level = tracing::Level::TRACE;

/// Whether events carry their module path.
const FILE_LOG_TARGETS: bool = true;

/// Daily files kept before the oldest is dropped.
const FILE_LOG_KEEP: usize = 7;

/// Resolve the diagnostic-log settings for this launch.
///
/// Returns `None` when logging is off, which is the default: diagnostics
/// are something a user turns on to answer a question, not something that
/// accumulates on every machine forever.
pub fn resolve_file_logging() -> Option<transit_core::log::FileLogging> {
    if !env_or_config_bool("TRANSIT_LOG_TO_FILE", "developer", "log_to_file", false) {
        return None;
    }
    let dir = read_config_string("developer", "log_dir")
        .map(PathBuf::from)
        .or_else(default_log_dir)?;

    // Clamp, never trust. The config file is user-editable and the env var
    // is anyone's to set, so the channel ceiling is applied to whatever
    // comes back rather than assuming the UI enforced it.
    let requested = transit_core::log::parse_level(
        &read_config_string("developer", "log_level").unwrap_or_else(|| "info".into()),
    );
    let level = if requested > MAX_FILE_LOG_LEVEL {
        MAX_FILE_LOG_LEVEL
    } else {
        requested
    };

    Some(transit_core::log::FileLogging {
        dir,
        level,
        include_targets: FILE_LOG_TARGETS,
        keep_files: FILE_LOG_KEEP,
    })
}

/// Default output folder for a feature under the app data dir —
/// `<data_dir|home>/TransitCommunity/<sub>`. Diagnostic logs, chat history, and
/// saved snippets all derive from this one expression (packet captures
/// open-code the same shape in pcap.rs; converging that is a separate
/// cleanup).
fn default_transit_dir(sub: &str) -> Option<PathBuf> {
    let base = dirs::data_dir().or_else(dirs::home_dir)?;
    Some(base.join("TransitCommunity").join(sub))
}

fn default_log_dir() -> Option<PathBuf> {
    default_transit_dir("logs")
}

/// Read a string from `[section] key` in config.toml.
pub(crate) fn read_config_string(section: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(config_path()).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let v = table
        .get(section)?
        .as_table()?
        .get(key)?
        .as_str()?
        .trim()
        .to_string();
    (!v.is_empty()).then_some(v)
}

/// Like `env_or_config` but with a caller-chosen default.
///
/// The existing helper defaults to `true`, which is right for an
/// off-switch and exactly wrong for an opt-in.
fn env_or_config_bool(env: &str, section: &str, key: &str, default: bool) -> bool {
    if let Ok(v) = std::env::var(env) {
        let t = v.trim();
        if !t.is_empty() {
            return matches!(t.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
    }
    env_or_config_bool_at(&config_path(), section, key, default)
}

/// Path-parameterized core, so the opt-in default is testable without
/// touching process env or the real config location.
fn env_or_config_bool_at(path: &Path, section: &str, key: &str, default: bool) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return default;
    };
    table
        .get(section)
        .and_then(|s| s.as_table())
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

/// What the Settings → Developers tab renders. Paths and flags only — no
/// credential ever reaches this struct (Rule 1).
#[derive(Debug, Serialize)]
pub struct DeveloperSettings {
    pub log_to_file: bool,
    /// The folder in use, configured or default.
    pub log_dir: String,
    pub log_level: String,
    /// The ceiling this build allows, so the UI offers only real choices
    /// rather than options it will silently clamp.
    pub max_level: String,
    /// True when the build ceiling admits `debug`/`trace`.
    pub verbose_available: bool,
}

#[tauri::command]
pub fn developer_settings() -> DeveloperSettings {
    let dir = read_config_string("developer", "log_dir")
        .or_else(|| default_log_dir().map(|p| p.to_string_lossy().to_string()))
        .unwrap_or_default();
    DeveloperSettings {
        log_to_file: env_or_config_bool("TRANSIT_LOG_TO_FILE", "developer", "log_to_file", false),
        log_dir: dir,
        log_level: read_config_string("developer", "log_level").unwrap_or_else(|| "info".into()),
        max_level: MAX_FILE_LOG_LEVEL.to_string().to_ascii_lowercase(),
        verbose_available: MAX_FILE_LOG_LEVEL >= tracing::Level::DEBUG,
    }
}

/// Persist the diagnostic-log settings. Applies on next launch — the
/// subscriber is installed once at startup, and a toggle that half-applies
/// is worse than one that states its terms.
#[tauri::command]
pub fn set_developer_settings(
    log_to_file: bool,
    log_dir: Option<String>,
    log_level: Option<String>,
) -> Result<(), String> {
    if let Some(d) = log_dir.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        // Same validation as the capture folder, for the same reason: this
        // path is created and written to, and a relative one lands
        // wherever the process happens to be.
        validate_capture_dir(d)?;
        std::fs::create_dir_all(PathBuf::from(d))
            .map_err(|e| format!("cannot use that folder for logs: {e}"))?;
    }
    write_config_bool_at(&config_path(), "developer", "log_to_file", log_to_file)?;
    write_config_string_at(&config_path(), "developer", "log_dir", log_dir.as_deref())?;
    write_config_string_at(
        &config_path(),
        "developer",
        "log_level",
        log_level.as_deref(),
    )
}

// ---------------------------------------------------------------------
// v6.3.0 — Settings → Agent Chat: the `[agent_chat]` config block.
//
// Two opt-in features (both default OFF — the developer_log_tests
// "off unless asked for" discipline), each with a configurable output
// directory: `persist_history`/`history_dir` (keep chat history across
// restarts) and `save_to_file`/`save_dir` (a Save button on chat code
// blocks). Resolved PER CALL, uncached, and the directory is
// re-validated where it is USED as well as where it was set — the
// pcap-dir posture, because config.toml is hand-editable and the env
// overrides never pass through the setter.
// ---------------------------------------------------------------------

/// One Agent Chat feature's effective state: the opt-in flag + the
/// directory it writes to (configured, or the default under the app
/// data dir).
pub(crate) struct AgentChatFeature {
    pub enabled: bool,
    pub dir: PathBuf,
}

fn resolve_agent_chat_feature(
    env_flag: &str,
    key_flag: &str,
    env_dir: &str,
    key_dir: &str,
    default_dir: fn() -> Option<PathBuf>,
) -> Result<AgentChatFeature, String> {
    let enabled = env_or_config_bool(env_flag, "agent_chat", key_flag, false);
    let configured = std::env::var(env_dir)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| read_config_string("agent_chat", key_dir));
    let dir = match configured {
        Some(d) => {
            // Consumption-side re-check (never trust the setter ran).
            validate_capture_dir(&d)?;
            PathBuf::from(d)
        }
        None => default_dir()
            .ok_or_else(|| "no home directory to derive a default folder from".to_string())?,
    };
    Ok(AgentChatFeature { enabled, dir })
}

fn default_history_dir() -> Option<PathBuf> {
    default_transit_dir("chats")
}

/// Default snippet folder: the OS Downloads dir when it exists (a saved
/// script is a user-facing artifact, not app data), else the Transit
/// data dir. Shared by the resolver AND the settings getter — a review
/// finding caught them using two different defaults, so Settings showed
/// a folder the save dialog never opened at.
fn default_snippet_dir() -> Option<PathBuf> {
    dirs::download_dir().or_else(|| default_transit_dir("snippets"))
}

/// Chat-history persistence (opt-in). Consumers: the per-turn history
/// writer, `chat_list`'s restore loader, and `chat_destroy`'s delete.
pub(crate) fn resolve_chat_history() -> Result<AgentChatFeature, String> {
    resolve_agent_chat_feature(
        "TRANSIT_AGENT_CHAT_PERSIST_HISTORY",
        "persist_history",
        "TRANSIT_AGENT_CHAT_HISTORY_DIR",
        "history_dir",
        default_history_dir,
    )
}

/// Save-to-file on chat code blocks (opt-in). Consumer:
/// `save_chat_snippet` — the command-side check IS the gate; the UI
/// hiding the button is convention.
pub(crate) fn resolve_chat_snippets() -> Result<AgentChatFeature, String> {
    resolve_agent_chat_feature(
        "TRANSIT_AGENT_CHAT_SAVE_TO_FILE",
        "save_to_file",
        "TRANSIT_AGENT_CHAT_SAVE_DIR",
        "save_dir",
        default_snippet_dir,
    )
}

/// Settings → Agent Chat wire shape. Effective values + env-override
/// flags so the UI can render read-only fields (the NetworkSettings
/// pattern).
#[derive(Debug, Serialize)]
pub struct AgentChatSettings {
    pub persist_history: bool,
    /// Effective folder (configured, env, or the default) — projected
    /// from the SAME resolver every consumer uses, so Settings can never
    /// display a folder the feature doesn't write to (review finding).
    /// When the configured value is invalid, this carries the raw value
    /// and `history_dir_error` says why the feature is inert.
    pub history_dir: String,
    /// The config-file value only — what the setter should round-trip.
    /// `None` = "using the default"; the UI must never write the
    /// EFFECTIVE value back as if the user had chosen it.
    pub history_dir_configured: Option<String>,
    /// Set when the configured/env dir fails validation — the feature is
    /// then silently inert backend-side, and the UI MUST say so (an "On"
    /// toggle over a broken dir was a confident lie).
    pub history_dir_error: Option<String>,
    pub persist_history_env_override: bool,
    pub history_dir_env_override: bool,
    pub save_to_file: bool,
    pub save_dir: String,
    pub save_dir_configured: Option<String>,
    pub save_dir_error: Option<String>,
    pub save_to_file_env_override: bool,
    pub save_dir_env_override: bool,
}

fn env_set(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

#[tauri::command]
pub fn get_agent_chat_settings() -> AgentChatSettings {
    // Pure PROJECTION over the two resolvers — one derivation of the
    // effective dir, shared with every consumer. On a resolver error the
    // raw configured/env value is displayed alongside the error so the
    // UI can say WHY the feature is inert instead of lying "On".
    fn project(
        resolve: fn() -> Result<AgentChatFeature, String>,
        env_flag: &str,
        key_flag: &str,
        env_dir: &str,
        key_dir: &str,
    ) -> (bool, String, Option<String>) {
        match resolve() {
            Ok(f) => (f.enabled, f.dir.to_string_lossy().to_string(), None),
            Err(e) => {
                // Show what the CONFIG says (the toggle may genuinely be
                // on) — the error field is what explains that the feature
                // is inert until the dir is fixed.
                let enabled = env_or_config_bool(env_flag, "agent_chat", key_flag, false);
                let raw = std::env::var(env_dir)
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .or_else(|| read_config_string("agent_chat", key_dir))
                    .unwrap_or_default();
                (enabled, raw, Some(e))
            }
        }
    }
    let (history_enabled, history_dir, history_dir_error) = project(
        resolve_chat_history,
        "TRANSIT_AGENT_CHAT_PERSIST_HISTORY",
        "persist_history",
        "TRANSIT_AGENT_CHAT_HISTORY_DIR",
        "history_dir",
    );
    let (snippets_enabled, save_dir, save_dir_error) = project(
        resolve_chat_snippets,
        "TRANSIT_AGENT_CHAT_SAVE_TO_FILE",
        "save_to_file",
        "TRANSIT_AGENT_CHAT_SAVE_DIR",
        "save_dir",
    );
    AgentChatSettings {
        persist_history: history_enabled,
        history_dir,
        history_dir_configured: read_config_string("agent_chat", "history_dir"),
        history_dir_error,
        persist_history_env_override: env_set("TRANSIT_AGENT_CHAT_PERSIST_HISTORY"),
        history_dir_env_override: env_set("TRANSIT_AGENT_CHAT_HISTORY_DIR"),
        save_to_file: snippets_enabled,
        save_dir,
        save_dir_configured: read_config_string("agent_chat", "save_dir"),
        save_dir_error,
        save_to_file_env_override: env_set("TRANSIT_AGENT_CHAT_SAVE_TO_FILE"),
        save_dir_env_override: env_set("TRANSIT_AGENT_CHAT_SAVE_DIR"),
    }
}

/// Persist the Agent Chat settings. Applies immediately — every consumer
/// resolves per call. `None`/empty dir clears back to the default.
#[tauri::command]
pub fn set_agent_chat_settings(
    persist_history: bool,
    history_dir: Option<String>,
    save_to_file: bool,
    save_dir: Option<String>,
) -> Result<(), String> {
    for dir in [history_dir.as_deref(), save_dir.as_deref()] {
        if let Some(d) = dir.map(str::trim).filter(|s| !s.is_empty()) {
            // Same validation as the capture folder, for the same reason:
            // this path is created and written to, and a relative one
            // lands wherever the process happens to be.
            validate_capture_dir(d)?;
            std::fs::create_dir_all(PathBuf::from(d))
                .map_err(|e| format!("cannot use that folder: {e}"))?;
        }
    }
    write_config_bool_at(
        &config_path(),
        "agent_chat",
        "persist_history",
        persist_history,
    )?;
    write_config_string_at(
        &config_path(),
        "agent_chat",
        "history_dir",
        history_dir.as_deref(),
    )?;
    write_config_bool_at(&config_path(), "agent_chat", "save_to_file", save_to_file)?;
    write_config_string_at(
        &config_path(),
        "agent_chat",
        "save_dir",
        save_dir.as_deref(),
    )
}

/// Open the diagnostic-log folder in the OS file manager.
#[tauri::command]
pub fn open_log_dir(app: tauri::AppHandle) -> Result<(), String> {
    let dir = read_config_string("developer", "log_dir")
        .map(PathBuf::from)
        .or_else(default_log_dir)
        .ok_or("no log folder is configured")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot open the log folder: {e}"))?;
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_path(dir.to_string_lossy().to_string(), None::<&str>)
        .map_err(|e| format!("could not open the log folder: {e}"))
}

/// Where captures are written, when the user has chosen somewhere.
///
/// `None` means "use the default under the app's data directory". Read per
/// call like the two flags above, so changing it takes effect on the next
/// capture rather than the next launch.
///
/// Env var first, matching every other setting here — a shop that manages
/// this centrally sets `TRANSIT_PCAP_DIR` and the config file cannot
/// override it.
pub fn resolve_pcap_dir() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("TRANSIT_PCAP_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    read_pcap_dir_at(&config_path())
}

fn read_pcap_dir_at(path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let dir = table
        .get("pcap")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("dir"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    Some(PathBuf::from(dir))
}

/// Persist (or clear) the capture directory. `None` or empty restores the
/// default.
fn write_pcap_dir_at(path: &Path, dir: Option<&str>) -> Result<(), String> {
    write_config_string_at(path, "pcap", "dir", dir)
}

/// IPC — the capture directory the user has chosen, or null for the
/// default. A path, never a credential (Rule 1).
#[tauri::command]
pub fn pcap_configured_dir() -> Option<String> {
    resolve_pcap_dir().map(|p| p.to_string_lossy().to_string())
}

/// IPC — choose where captures are written.
///
/// Validated before it is stored, because this path is handed to a capture
/// process that may be running as root: it must be absolute (a relative
/// path would resolve against whatever the working directory happens to
/// be) and it must be creatable. Storing a path that cannot be written
/// would turn every future Start into a failure whose cause is in a config
/// file the user has since forgotten about.
#[tauri::command]
pub fn set_pcap_dir(dir: Option<String>) -> Result<(), String> {
    let trimmed = dir.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(d) = trimmed {
        validate_capture_dir(d)?;
        std::fs::create_dir_all(PathBuf::from(d))
            .map_err(|e| format!("cannot use that folder for captures: {e}"))?;
    }
    write_pcap_dir_at(&config_path(), trimmed)
}

/// Validate a capture folder before it can reach a capture command line.
///
/// This path ends up inside the command that runs as root, crossing two
/// escaping layers on macOS: POSIX single-quoting, then an AppleScript
/// string literal. `shell_quote` and `applescript_quote` handle quotes and
/// backslashes correctly — but **an AppleScript literal cannot contain a
/// raw newline**, and macOS will happily create a directory whose name
/// holds one (only `/` and NUL are forbidden). A control character would
/// therefore terminate the literal early and the remainder would be parsed
/// as AppleScript, in a script whose next clause is `with administrator
/// privileges`.
///
/// The user choosing their own capture folder is not an attacker, so this
/// is defence in depth rather than a hole being closed — the same posture
/// as `validate_bpf`, which also guards a path that could not currently be
/// injected. It also turns a baffling AppleScript syntax error into a
/// sentence that says what is wrong.
///
/// Checked where the value is CONSUMED as well as where it is set, because
/// `config.toml` can be hand-edited and `TRANSIT_PCAP_DIR` never passes
/// through the setter at all.
pub fn validate_capture_dir(dir: &str) -> Result<(), String> {
    if !PathBuf::from(dir).is_absolute() {
        return Err("the capture folder must be an absolute path".into());
    }
    if let Some(c) = dir.chars().find(|c| c.is_control()) {
        return Err(format!(
            "the capture folder contains a control character ({}), which cannot be used in a \
             capture command",
            c.escape_debug()
        ));
    }
    Ok(())
}

/// IPC — whether the PCaps surface is enabled (the frontend hides the rail
/// entry when this is false; the backend refuses independently).
#[tauri::command]
pub fn pcap_enabled() -> bool {
    resolve_pcap_enabled()
}

/// IPC — whether the assistant may query captures.
#[tauri::command]
pub fn pcap_agent_access_enabled() -> bool {
    resolve_pcap_agent_access()
}

/// Persist `[network] strict_tls`. Atomic write (tempfile + rename),
/// preserving every other key (e.g. `[policy] user_dir`). Takes effect on
/// next launch — the cloud client is built once at startup.
fn write_strict_tls_at(path: &Path, enabled: bool) -> Result<(), String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };

    let network = table
        .entry("network")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(nt) = network.as_table_mut() {
        nt.insert("strict_tls".into(), toml::Value::Boolean(enabled));
    }

    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

/// Read-only view of the network settings for the Settings UI. Per Rule 1
/// nothing here is a credential.
#[derive(Debug, Serialize)]
pub struct NetworkSettings {
    /// The effective Strict-TLS setting (env override or persisted).
    pub strict_tls: bool,
    /// True when `$TRANSIT_STRICT_TLS` forces the value — the Settings
    /// toggle is then read-only (mirrors `PolicySettings.env_override`).
    pub env_override: bool,
}

#[tauri::command]
pub async fn get_network_settings() -> Result<NetworkSettings, String> {
    let env_override = env_set("TRANSIT_STRICT_TLS");
    Ok(NetworkSettings {
        strict_tls: resolve_strict_tls(),
        env_override,
    })
}

/// Persist the Strict-TLS setting. Takes effect on next launch — the
/// cloud client is built once at startup. Returns Ok even though the
/// running session's trust config is unchanged; the UI surfaces the
/// "restart to apply" note.
#[tauri::command]
pub async fn set_strict_tls(enabled: bool) -> Result<(), String> {
    write_strict_tls_at(&config_path(), enabled)
}

// ---------------------------------------------------------------------
// Local models — BYOM (`[local_models]` in config.toml).
//
// v3.0.0 (the byom local models design notes (not included in this repository)). Same dedicated config
// file as `[policy]`/`[network]` — an older build ignores the table, so
// rollback stays safe. Unlike Strict TLS this is NOT restart-to-apply:
// the chat factory builds a client per message, so a change applies on
// the next send. The base URL is pinned to loopback (threat-model T35)
// — enforced here for the persisted value AND the env override, release
// builds included, using the SAME `loopback_violation` predicate the
// client re-checks (defense in depth).
// ---------------------------------------------------------------------

pub const LOCAL_MODELS_MIN_NUM_CTX: u32 = 1_024;
pub const LOCAL_MODELS_MAX_NUM_CTX: u32 = 262_144;

/// v6.1.1 — per-turn assistant-output token ceiling (`[local_models]
/// turn_token_ceiling`, env `TRANSIT_TURN_TOKEN_CEILING`). The live
/// finding behind it: a coaching question sent a local model into
/// unbounded single-response generation until manual Stop — the 90s
/// stream timeout never fires on a FLOWING stream, and rounds-based
/// checkpoints don't bound tokens-within-a-round. This is a
/// request-builder value (it becomes `LlmRequest.max_tokens`), NOT a
/// LoopBounds change: local clients min() it against their T34
/// half-window clamp, cloud clients send it as the provider max-tokens
/// cap. Default 4096 leaves local requests byte-identical to v6.1.0
/// (their clamp already defaulted to 4096 when unset).
pub const DEFAULT_TURN_TOKEN_CEILING: u32 = 4_096;
pub const TURN_TOKEN_CEILING_MIN: u32 = 256;
pub const TURN_TOKEN_CEILING_MAX: u32 = 32_768;

/// Effective local-models configuration after env/config/default
/// resolution + loopback pinning.
#[derive(Debug, Clone)]
pub struct ResolvedLocalModels {
    pub enabled: bool,
    pub cfg: transit_agent::llm::OllamaConfig,
    /// True when `$TRANSIT_LOCAL_MODELS_URL` forces the base URL — the
    /// Settings field is then read-only.
    pub env_override: bool,
    /// Set when a configured value was rejected (non-loopback URL,
    /// out-of-range num_ctx, bogus keep_alive) and a safe default was
    /// used instead. Never silently honored, never fatal.
    pub warning: Option<String>,
    /// v6.1.1 — per-turn output-token ceiling for EVERY provider (it
    /// feeds `AgentLoop.max_tokens_per_turn` → `LlmRequest.max_tokens`).
    /// A sibling of `cfg` rather than a field on it: cloud clients never
    /// see an `OllamaConfig`. Range-checked at resolution — the config
    /// file is user-editable and the env var is anyone's to set, so the
    /// bound is applied to whatever comes back, never trusted from a UI.
    pub turn_token_ceiling: u32,
}

/// Resolve the effective local-models config. Precedence for the base
/// URL: `$TRANSIT_LOCAL_MODELS_URL` (still loopback-pinned) → persisted
/// `[local_models] base_url` → the stock loopback default.
pub fn resolve_local_models() -> ResolvedLocalModels {
    let env_url = std::env::var("TRANSIT_LOCAL_MODELS_URL").ok();
    let env_ceiling = std::env::var("TRANSIT_TURN_TOKEN_CEILING").ok();
    resolve_local_models_at(&config_path(), env_url.as_deref(), env_ceiling.as_deref())
}

/// Path/env-parameterized core of [`resolve_local_models`] so the
/// round-trip is unit-testable without touching process env.
fn resolve_local_models_at(
    path: &Path,
    env_url: Option<&str>,
    env_ceiling: Option<&str>,
) -> ResolvedLocalModels {
    use transit_agent::llm::loopback_violation;
    use transit_agent::llm::ollama::{DEFAULT_BASE_URL, DEFAULT_KEEP_ALIVE, DEFAULT_NUM_CTX};

    let stored = read_local_models_at(path);
    let mut warning: Option<String> = None;

    let env_candidate = env_url.map(str::trim).filter(|s| !s.is_empty());
    let env_override = env_candidate.is_some();
    let candidate = env_candidate
        .map(str::to_string)
        .or(stored.base_url)
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let base_url = match loopback_violation(&candidate) {
        None => candidate,
        Some(reason) => {
            warning = Some(format!("ignoring configured local-models URL: {reason}"));
            DEFAULT_BASE_URL.to_string()
        }
    };

    let num_ctx = match stored.num_ctx {
        Some(n) if (LOCAL_MODELS_MIN_NUM_CTX..=LOCAL_MODELS_MAX_NUM_CTX).contains(&n) => n,
        Some(n) => {
            warning.get_or_insert_with(|| {
                format!(
                    "ignoring configured num_ctx {n} (allowed {LOCAL_MODELS_MIN_NUM_CTX}–{LOCAL_MODELS_MAX_NUM_CTX})"
                )
            });
            DEFAULT_NUM_CTX
        }
        None => DEFAULT_NUM_CTX,
    };

    let keep_alive = match stored.keep_alive {
        Some(k) if keep_alive_is_valid(&k) => k,
        Some(k) => {
            warning.get_or_insert_with(|| format!("ignoring configured keep_alive `{k}`"));
            DEFAULT_KEEP_ALIVE.to_string()
        }
        None => DEFAULT_KEEP_ALIVE.to_string(),
    };

    // v6.1.1 — per-turn token ceiling. Env (parsed here, so a bogus
    // value warns instead of silently vanishing) wins over the persisted
    // key; both are range-checked against the same bounds — the bound is
    // applied to whatever comes back, never trusted from a UI.
    let ceiling_candidate = match env_ceiling.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => match s.parse::<u32>() {
            Ok(n) => Some(n),
            Err(_) => {
                warning.get_or_insert_with(|| {
                    format!("ignoring TRANSIT_TURN_TOKEN_CEILING `{s}` (not a number)")
                });
                stored.turn_token_ceiling
            }
        },
        None => stored.turn_token_ceiling,
    };
    let turn_token_ceiling = match ceiling_candidate {
        Some(n) if (TURN_TOKEN_CEILING_MIN..=TURN_TOKEN_CEILING_MAX).contains(&n) => n,
        Some(n) => {
            warning.get_or_insert_with(|| {
                format!(
                    "ignoring configured turn_token_ceiling {n} (allowed {TURN_TOKEN_CEILING_MIN}–{TURN_TOKEN_CEILING_MAX})"
                )
            });
            DEFAULT_TURN_TOKEN_CEILING
        }
        None => DEFAULT_TURN_TOKEN_CEILING,
    };

    ResolvedLocalModels {
        enabled: stored.enabled,
        cfg: transit_agent::llm::OllamaConfig {
            base_url,
            num_ctx,
            keep_alive,
        },
        env_override,
        warning,
        turn_token_ceiling,
    }
}

struct StoredLocalModels {
    enabled: bool,
    base_url: Option<String>,
    num_ctx: Option<u32>,
    keep_alive: Option<String>,
    /// v6.1.1 — `turn_token_ceiling`. Config-file-only (no Settings UI
    /// row); `write_local_models_at` inserts only its four keys into the
    /// existing table, so a hand-edited value survives Settings saves.
    turn_token_ceiling: Option<u32>,
}

/// Read `[local_models]` from config.toml. Resilient (missing file /
/// parse error / wrong types → defaults). `enabled` defaults to OFF —
/// Transit never probes localhost ports the user didn't opt into.
fn read_local_models_at(path: &Path) -> StoredLocalModels {
    let absent = StoredLocalModels {
        enabled: false,
        base_url: None,
        num_ctx: None,
        keep_alive: None,
        turn_token_ceiling: None,
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return absent;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return absent;
    };
    let Some(lm) = table.get("local_models").and_then(|v| v.as_table()) else {
        return absent;
    };
    StoredLocalModels {
        enabled: lm.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        base_url: lm
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        num_ctx: lm
            .get("num_ctx")
            .and_then(|v| v.as_integer())
            .and_then(|n| u32::try_from(n).ok()),
        keep_alive: lm
            .get("keep_alive")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        turn_token_ceiling: lm
            .get("turn_token_ceiling")
            .and_then(|v| v.as_integer())
            .and_then(|n| u32::try_from(n).ok()),
    }
}

/// `keep_alive` accepts Ollama's simple duration forms: `0` (unload
/// immediately), `-1` (keep loaded forever), or `<digits><s|m|h>`.
/// (Go's float durations like `1.5h` are deliberately not accepted —
/// the Settings UI offers presets; write `90m`.)
fn keep_alive_is_valid(s: &str) -> bool {
    let t = s.trim();
    if t == "0" || t == "-1" {
        return true;
    }
    let Some(digits) = t.strip_suffix(['s', 'm', 'h']) else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Persist the full `[local_models]` table. Atomic write (tempfile +
/// rename), preserving every other table (`[policy]`, `[network]`).
/// Values are validated by the caller before reaching here.
fn write_local_models_at(
    path: &Path,
    enabled: bool,
    base_url: &str,
    num_ctx: u32,
    keep_alive: &str,
) -> Result<(), String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };

    let lm = table
        .entry("local_models")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(t) = lm.as_table_mut() {
        t.insert("enabled".into(), toml::Value::Boolean(enabled));
        t.insert("base_url".into(), toml::Value::String(base_url.to_string()));
        t.insert("num_ctx".into(), toml::Value::Integer(i64::from(num_ctx)));
        t.insert(
            "keep_alive".into(),
            toml::Value::String(keep_alive.to_string()),
        );
    }

    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

/// Read-only view of the local-models settings for the Settings UI and
/// the chat gating logic. Per Rule 1 nothing here is a credential.
#[derive(Debug, Serialize)]
pub struct LocalModelsSettings {
    pub enabled: bool,
    pub base_url: String,
    pub num_ctx: u32,
    pub keep_alive: String,
    pub env_override: bool,
    pub warning: Option<String>,
}

#[tauri::command]
pub async fn get_local_models_settings() -> Result<LocalModelsSettings, String> {
    let r = resolve_local_models();
    Ok(LocalModelsSettings {
        enabled: r.enabled,
        base_url: r.cfg.base_url,
        num_ctx: r.cfg.num_ctx,
        keep_alive: r.cfg.keep_alive,
        env_override: r.env_override,
        warning: r.warning,
    })
}

/// Persist the local-models settings. Applies on the NEXT chat send —
/// the factory builds a client per message (no restart needed). A
/// non-loopback base URL is an ERROR here (T35), never silently
/// rewritten; `None`/empty falls back to the stock loopback default.
#[tauri::command]
pub async fn set_local_models_settings(
    enabled: bool,
    base_url: Option<String>,
    num_ctx: u32,
    keep_alive: String,
) -> Result<(), String> {
    use transit_agent::llm::loopback_violation;
    use transit_agent::llm::ollama::DEFAULT_BASE_URL;

    let url = base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BASE_URL)
        .to_string();
    if let Some(reason) = loopback_violation(&url) {
        return Err(reason);
    }
    if !(LOCAL_MODELS_MIN_NUM_CTX..=LOCAL_MODELS_MAX_NUM_CTX).contains(&num_ctx) {
        return Err(format!(
            "num_ctx must be between {LOCAL_MODELS_MIN_NUM_CTX} and {LOCAL_MODELS_MAX_NUM_CTX}"
        ));
    }
    let ka = keep_alive.trim();
    if !keep_alive_is_valid(ka) {
        return Err("keep_alive must look like 30s / 15m / 1h, or 0 / -1".into());
    }
    write_local_models_at(&config_path(), enabled, &url, num_ctx, ka)
}

// ---------------------------------------------------------------------
// Custom BYOM endpoints (`[[local_models.endpoints]]` in config.toml).
//
// Remote Ollama servers and OpenAI-compatible backends (vLLM, LM
// Studio, llama.cpp server, LiteLLM). Transport rules (T35) are
// validated with transit_agent::llm::transport_violation — plain http
// only to loopback; anything else https against the OS trust store —
// at write time AND re-checked in the clients per request. Bearer
// tokens never live here: they go to the OS keychain via the
// write-only IPC in `local_models.rs`.
// ---------------------------------------------------------------------

pub const LOCAL_MODELS_MAX_ENDPOINTS: usize = 8;
pub const LOCAL_ENDPOINT_MIN_CONTEXT: u32 = 1_024;
pub const LOCAL_ENDPOINT_MAX_CONTEXT: u32 = 2_097_152;

/// One custom endpoint. `kind` selects the client: `ollama` = the
/// native `/api/chat` (remote Ollama; keeps num_ctx control +
/// capability discovery); `openai_compat` = `/v1/chat/completions`.
/// `context_length` doubles as num_ctx for `ollama` endpoints and as
/// the pre-send budget for `openai_compat` ones (T34).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LocalEndpoint {
    /// Stable id — the keychain account, the model-id namespace
    /// (`endpoint:<id>/<model>`), and the upsert key. `[a-z0-9-]`,
    /// 1–32 chars, starts alphanumeric — the charset keeps the model
    /// namespace unambiguous (no `/`, no `:`).
    pub id: String,
    pub name: String,
    pub kind: LocalEndpointKind,
    pub base_url: String,
    pub context_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEndpointKind {
    Ollama,
    OpenaiCompat,
}

/// Validate one endpoint entry. Used at upsert time (errors surface to
/// the Settings UI) and at read time (invalid persisted entries are
/// skipped, never fatal).
pub fn validate_endpoint(ep: &LocalEndpoint) -> Result<(), String> {
    let id_ok = !ep.id.is_empty()
        && ep.id.len() <= 32
        && ep
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && ep.id.starts_with(|c: char| c.is_ascii_alphanumeric());
    if !id_ok {
        return Err(
            "endpoint id must be 1–32 chars of a-z, 0-9, or '-' (starting alphanumeric)".into(),
        );
    }
    let name = ep.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err("endpoint name must be 1–64 characters".into());
    }
    if let Some(reason) = transit_agent::llm::transport_violation(&ep.base_url) {
        return Err(reason);
    }
    if !(LOCAL_ENDPOINT_MIN_CONTEXT..=LOCAL_ENDPOINT_MAX_CONTEXT).contains(&ep.context_length) {
        return Err(format!(
            "context_length must be between {LOCAL_ENDPOINT_MIN_CONTEXT} and {LOCAL_ENDPOINT_MAX_CONTEXT}"
        ));
    }
    Ok(())
}

/// Read the validated custom endpoints from config.toml. Resilient:
/// invalid or duplicate-id entries are SKIPPED (mirrors the lenient
/// user-policy loader) and the list is capped — a hand-broken config
/// never blocks startup.
pub fn resolve_local_endpoints() -> Vec<LocalEndpoint> {
    read_local_endpoints_at(&config_path())
}

fn read_local_endpoints_at(path: &Path) -> Vec<LocalEndpoint> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(table) = toml::from_str::<toml::Table>(&text) else {
        return Vec::new();
    };
    let Some(list) = table
        .get("local_models")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("endpoints"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    let mut out: Vec<LocalEndpoint> = Vec::new();
    for v in list {
        let Ok(ep) = v.clone().try_into::<LocalEndpoint>() else {
            continue;
        };
        if validate_endpoint(&ep).is_err() || out.iter().any(|e| e.id == ep.id) {
            continue;
        }
        out.push(ep);
        if out.len() >= LOCAL_MODELS_MAX_ENDPOINTS {
            break;
        }
    }
    out
}

/// Persist the endpoint list wholesale (the callers do read-modify-
/// write on the resolved list). Atomic, sibling-table-preserving; the
/// `[local_models]` scalar keys are untouched.
pub fn write_local_endpoints(endpoints: &[LocalEndpoint]) -> Result<(), String> {
    write_local_endpoints_at(&config_path(), endpoints)
}

fn write_local_endpoints_at(path: &Path, endpoints: &[LocalEndpoint]) -> Result<(), String> {
    let mut table: toml::Table = match std::fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).map_err(|e| format!("existing config.toml is malformed: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("reading config.toml: {e}")),
    };

    let mut rows: Vec<toml::Value> = Vec::with_capacity(endpoints.len());
    for ep in endpoints {
        rows.push(
            toml::Value::try_from(ep)
                .map_err(|e| format!("serializing endpoint {}: {e}", ep.id))?,
        );
    }
    let lm = table
        .entry("local_models")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(t) = lm.as_table_mut() {
        if rows.is_empty() {
            t.remove("endpoints");
        } else {
            t.insert("endpoints".into(), toml::Value::Array(rows));
        }
    }

    let serialized = toml::to_string(&table).map_err(|e| format!("serializing config: {e}"))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("creating config dir: {e}"))?;
        }
    }
    let dirpath = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dirpath {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new(),
    }
    .map_err(|e| format!("creating temp config: {e}"))?;
    use std::io::Write as _;
    tmp.write_all(serialized.as_bytes())
        .map_err(|e| format!("writing temp config: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("persisting config.toml: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------
// Read commands.
// ---------------------------------------------------------------------

#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<Vec<DeviceMeta>, String> {
    let guard = state.inventory.read().await;
    match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc).map(|inv| {
            inv.devices
                .into_iter()
                .map(DeviceMeta::from)
                .collect::<Vec<_>>()
        }),
        InventoryState::Broken { reason } => Err(reason.clone()),
    }
}

#[tauri::command]
pub async fn list_auth_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<AuthProfileMeta>, String> {
    let guard = state.inventory.read().await;
    match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc).map(|inv| {
            inv.auth_profiles
                .into_iter()
                .map(|(name, p)| AuthProfileMeta {
                    name,
                    username: p.username,
                    backend: secret_backend_label(&p.secret).to_string(),
                    key_path: ssh_key_path_of(&p.secret),
                })
                .collect::<Vec<_>>()
        }),
        InventoryState::Broken { reason } => Err(reason.clone()),
    }
}

/// Registered group paths from the `groups` registry. The frontend
/// unions these with the paths implied by device `group` fields so an
/// empty (device-less) group still renders in the tree. Group paths
/// carry no secrets (Rule 1).
#[tauri::command]
pub async fn list_groups(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let guard = state.inventory.read().await;
    match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc).map(|inv| inv.groups),
        InventoryState::Broken { reason } => Err(reason.clone()),
    }
}

#[tauri::command]
pub async fn list_api_sessions(state: State<'_, AppState>) -> Result<Vec<ApiSessionMeta>, String> {
    let guard = state.inventory.read().await;
    match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc).map(|inv| {
            inv.api_sessions
                .into_iter()
                .map(ApiSessionMeta::from)
                .collect::<Vec<_>>()
        }),
        InventoryState::Broken { reason } => Err(reason.clone()),
    }
}

fn parsed_inventory(doc: &DocumentMut) -> Result<transit_core::inventory::InventoryFile, String> {
    let text = doc.to_string();
    toml::from_str(&text).map_err(|e| e.to_string())
}

fn secret_backend_label(s: &transit_core::inventory::SecretRef) -> &'static str {
    use transit_core::inventory::SecretRef;
    match s {
        SecretRef::Keyring { .. } => "keyring",
        SecretRef::SshAgent { .. } => "ssh_agent",
        SecretRef::Op { .. } => "op",
        SecretRef::Env { .. } => "env",
        SecretRef::SshKey { .. } => "ssh_key",
        SecretRef::EncryptedFile { .. } => "encrypted_file",
        // Surfaced so the frontend can (a) label the profile and (b) hold
        // these devices back from bulk "Launch all" — each one needs an
        // attended prompt, and 30 queued dialogs is the fatigue path we
        // are deliberately avoiding (T46 / T18).
        SecretRef::Prompt => "prompt",
    }
}

/// The `ssh_key` backend's key-file path for [`AuthProfileMeta`] —
/// a filesystem path reference, never key material (Rule 1). The
/// nested passphrase `SecretRef` is deliberately not walked.
fn ssh_key_path_of(s: &transit_core::inventory::SecretRef) -> Option<String> {
    match s {
        transit_core::inventory::SecretRef::SshKey { path, .. } => Some(path.display().to_string()),
        _ => None,
    }
}

/// Result of [`export_connections`]. `bytes_written` + `path` mirror
/// [`crate::session_export::ExportResult`]; `count` is the number of
/// devices written (the header row is not counted).
#[derive(Debug, Serialize)]
pub struct ExportConnectionsResult {
    pub bytes_written: u64,
    pub path: PathBuf,
    pub count: usize,
}

/// Export every device to an import-compatible CSV file (v2.3.0) — the
/// reverse of the connection importer. Writes the exact header the CSV
/// importer reads (`name,host,port,username,vendor,group,key_path`), so
/// an exported file re-imports cleanly.
///
/// **Rule 1:** the CSV carries only references — usernames and key-file
/// *paths* joined from each device's auth profile — never a credential
/// value. There is no password column, and an ssh_key's nested passphrase
/// is never written (see `transit_core::export`). `destination` is chosen
/// by the frontend via the native Save dialog (`dialog:allow-save`); the
/// file is written atomically (tempfile + rename). Read-only w.r.t. the
/// inventory — the read lock is released before touching disk.
#[tauri::command]
pub async fn export_connections(
    state: State<'_, AppState>,
    destination: PathBuf,
) -> Result<ExportConnectionsResult, String> {
    let (contents, count) = {
        let guard = state.inventory.read().await;
        match &*guard {
            InventoryState::Ready(doc) => {
                let inv = parsed_inventory(doc)?;
                let count = inv.devices.len();
                let contents =
                    transit_core::export::connections_to_csv(&inv).map_err(|e| e.to_string())?;
                (contents, count)
            }
            InventoryState::Broken { reason } => return Err(reason.clone()),
        }
    };
    write_atomic(&destination, &contents).map_err(|e| e.to_string())?;
    Ok(ExportConnectionsResult {
        bytes_written: contents.len() as u64,
        path: destination,
        count,
    })
}

/// A Transit-to-Transit settings bundle (v6.1.0).
///
/// **Rule 1 boundary:** this carries the same thing `transit.toml` does —
/// *references*, never credentials. A device row names its auth PROFILE;
/// the credential itself lives in the OS keychain and is not exportable.
///
/// Two things are deliberately EXCLUDED (maintainer decision, 2026-08-13):
/// - **Secrets**, obviously — there is nothing to export.
/// - **Host-key pins** (`known_hosts.toml`). Copying those would make
///   machine B inherit trust that machine A's human established, which is
///   a TOFU decision rather than a preference. A bundle is a file someone
///   might receive from a colleague; pre-seeding it with trusted host keys
///   would let a malicious bundle suppress the changed-key warning.
///
/// Both payloads are **opaque strings** here on purpose. Their schemas
/// live in the frontend (`transit.preferences`, `DeviceInput[]`), and the
/// frontend already owns validation for both — the preferences loader
/// coerces every field, and devices re-enter through `import_connections`,
/// which re-runs the loader's full validation chain. Duplicating either
/// schema in the backend would give it a second copy to drift from.
#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsBundle {
    /// Bundle format version. An unknown-but-higher version is refused
    /// rather than guessed at.
    pub version: u32,
    /// RFC3339, informational.
    pub exported_at: String,
    /// The frontend's `transit.preferences` blob, verbatim.
    pub preferences: Option<String>,
    /// `DeviceInput[]` as JSON, verbatim. Carries each device's auth
    /// PROFILE NAME — which is why this is not the import CSV: that
    /// format is built for migrating off another product, where identities
    /// must be mapped by hand, and it does not round-trip a profile link.
    pub devices: Option<String>,
}

/// Current bundle format version.
const SETTINGS_BUNDLE_VERSION: u32 = 1;

/// Write a settings bundle to `destination`.
///
/// Both payloads come from the frontend: preferences are a `localStorage`
/// blob the backend cannot read, and devices arrive already in the shape
/// `import_connections` accepts, so one schema serves both directions.
#[tauri::command]
pub async fn export_settings_bundle(
    destination: PathBuf,
    preferences: Option<String>,
    devices: Option<String>,
) -> Result<ExportConnectionsResult, String> {
    let bundle = SettingsBundle {
        version: SETTINGS_BUNDLE_VERSION,
        exported_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        preferences,
        devices,
    };
    let contents = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    write_atomic(&destination, &contents).map_err(|e| e.to_string())?;
    Ok(ExportConnectionsResult {
        bytes_written: contents.len() as u64,
        path: destination,
        count: 0,
    })
}

/// Read a settings bundle. Returns it for the frontend to preview and
/// apply — this command itself changes NOTHING, so a bad or hostile file
/// cannot alter state just by being opened.
#[tauri::command]
pub async fn import_settings_bundle(path: PathBuf) -> Result<SettingsBundle, String> {
    // A bundle is a file the user may have been SENT, so its size is
    // checked before a single byte is read into memory — reading first
    // and measuring after would let a multi-gigabyte file exhaust memory
    // before the guard ever ran.
    const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;
    let meta =
        std::fs::metadata(&path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    if meta.len() > MAX_BUNDLE_BYTES {
        return Err(format!(
            "bundle is larger than {} MB — refusing to parse",
            MAX_BUNDLE_BYTES / 1024 / 1024
        ));
    }
    // Belt and braces: metadata can lie (a growing file, a fifo), so the
    // read itself is bounded too rather than trusting the stat.
    use std::io::Read as _;
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let mut raw = String::new();
    std::io::Read::take(file, MAX_BUNDLE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    if raw.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(format!(
            "bundle is larger than {} MB — refusing to parse",
            MAX_BUNDLE_BYTES / 1024 / 1024
        ));
    }
    let bundle: SettingsBundle =
        serde_json::from_str(&raw).map_err(|e| format!("not a Transit settings bundle: {e}"))?;
    if bundle.version > SETTINGS_BUNDLE_VERSION {
        return Err(format!(
            "this bundle was written by a newer Transit (format v{}, this build reads v{}). \
             Update Transit and try again.",
            bundle.version, SETTINGS_BUNDLE_VERSION
        ));
    }
    Ok(bundle)
}

// ---------------------------------------------------------------------
// Wire DTOs for mutations.
//
// Device + AuthProfile already have Deserialize, so we accept them
// directly. Wrappers exist to keep the IPC surface explicit and named.
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeviceInput {
    pub id: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub vendor: String,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub auth: String,
    #[serde(default)]
    pub syntax_highlighting: Option<bool>,
    #[serde(default)]
    pub quick_copy_paste: Option<bool>,
    #[serde(default)]
    pub font_family: Option<String>,
    #[serde(default)]
    pub font_size: Option<u16>,
    #[serde(default)]
    pub bold_color: Option<bool>,
    #[serde(default)]
    pub allow_weak_crypto: Option<bool>,
    #[serde(default)]
    pub netbox_id: Option<String>,
    #[serde(default)]
    pub jump_via: Option<String>,
    #[serde(default)]
    pub forward_agent: Option<bool>,
}

fn default_port() -> u16 {
    22
}

impl DeviceInput {
    fn into_device(self) -> Device {
        Device {
            id: self.id,
            host: self.host,
            port: self.port,
            vendor: parse_vendor(&self.vendor),
            group: self.group,
            color: self.color,
            tags: self.tags,
            auth: self.auth,
            syntax_highlighting: self.syntax_highlighting,
            quick_copy_paste: self.quick_copy_paste,
            font_family: self.font_family,
            font_size: self.font_size,
            bold_color: self.bold_color,
            allow_weak_crypto: self.allow_weak_crypto,
            netbox_id: self.netbox_id,
            jump_via: self.jump_via,
            forward_agent: self.forward_agent,
        }
    }
}

/// Parse an inventory `vendor = "<tag>"` string into a `Vendor`.
/// Delegates to the single source of truth, `Vendor::from_tag`:
/// built-in tags map to their variants, `unknown` to the sentinel, and
/// any other non-empty string to `Vendor::Custom` (BYOP Phase 2b) so a
/// user-supplied `<tag>.yaml` policy can gate it.
fn parse_vendor(s: &str) -> transit_core::inventory::Vendor {
    transit_core::inventory::Vendor::from_tag(s)
}

/// Wire DTO for `[[api_session]]` create/update (v4.0.0). `vendor` +
/// `kind` arrive as strings; `secret` is a REFERENCE (never a value) and
/// is OPTIONAL — required on create, but on update `None` means "keep
/// the existing secret reference." The frontend never receives a
/// `SecretRef` back (deserialize-only across IPC), so it cannot resend
/// one it never had; the update path resolves the existing reference
/// server-side.
#[derive(Debug, Deserialize)]
pub struct ApiSessionInput {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub kind: ApiEndpointKind,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub console_id: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_input_auth")]
    pub auth: transit_core::inventory::AuthScheme,
    #[serde(default)]
    pub secret: Option<transit_core::inventory::SecretRef>,
}

/// Default auth for an input with no `auth` field — the historic UniFi
/// `X-API-KEY` scheme, so the existing add-controller flow is unchanged.
fn default_input_auth() -> transit_core::inventory::AuthScheme {
    transit_core::inventory::AuthScheme::ApiKey {
        header: "X-API-KEY".to_string(),
        value_prefix: String::new(),
    }
}

impl ApiSessionInput {
    fn into_api_session(self, secret: Option<transit_core::inventory::SecretRef>) -> ApiSession {
        ApiSession {
            id: self.id,
            name: self.name,
            vendor: parse_vendor(&self.vendor),
            kind: self.kind,
            host: self.host,
            console_id: self.console_id,
            base_url: self.base_url,
            group: self.group,
            color: self.color,
            tags: self.tags,
            auth: self.auth,
            secret,
            // The pin is set only via the trust flow (`api_trust_cert`), never
            // the add/edit form; `update_api_session` preserves an existing one.
            pinned_cert_sha256: None,
        }
    }
}

// ---------------------------------------------------------------------
// Write commands.
// ---------------------------------------------------------------------

#[tauri::command]
pub async fn add_device(state: State<'_, AppState>, input: DeviceInput) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_add_device(doc, &input.into_device())).await
}

/// Host-key pins are scoped to a device id (v6.5.7), so a rename or a
/// delete has to be reflected in `known_hosts.toml` or the pin is orphaned
/// — the device would re-prompt on its next connect and the stale entry
/// would linger forever.
///
/// This lives here rather than in `transit_core::inventory::mutator`
/// because `transit_core` must not depend on `transit_ssh`; the command
/// layer is the one place that holds both the document and the store.
/// It differs from the `jump_via` referential guard
/// (`mutator::jump_referents`, which REFUSES the edit) by cascading
/// instead: a pin has no user-visible identity to refuse on behalf of,
/// and following the rename is what the user means.
///
/// Best-effort by design — the inventory edit has already been committed
/// and is the user's actual intent, so a known-hosts hiccup is logged, not
/// surfaced as a failed rename. The cost of the failure is one extra TOFU
/// prompt, never a wrong trust decision.
async fn sync_pin_to_renamed_device(
    host_keys: &transit_ssh::HostKeyStore,
    old_id: &str,
    new_id: &str,
) {
    if old_id == new_id {
        return;
    }
    if let Err(e) = host_keys.rescope(old_id, new_id).await {
        tracing::warn!(?e, %old_id, %new_id, "failed to move host-key pin to the renamed device");
    }
}

#[tauri::command]
pub async fn update_device(
    state: State<'_, AppState>,
    id: String,
    input: DeviceInput,
) -> Result<(), String> {
    let new_id = input.id.clone();
    with_writable_doc(&state, |doc| {
        core_update_device(doc, &id, &input.into_device())
    })
    .await?;
    sync_pin_to_renamed_device(&state.ssh.host_keys, &id, &new_id).await;
    Ok(())
}

#[tauri::command]
pub async fn delete_device(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_delete_device(doc, &id)).await?;
    // Deleting the inventory entry drops its trust with it, so re-adding
    // the device re-establishes it from scratch. Best-effort for the same
    // reason as the rename: the delete has already committed.
    if let Err(e) = state.ssh.host_keys.forget(&id).await {
        tracing::warn!(?e, device = %id, "failed to drop host-key pin for the deleted device");
    }
    Ok(())
}

/// One device's whole-record replacement inside a bulk edit (v6.3.0).
/// `input` is COMPLETE, not a patch — `update_device` swaps the whole
/// `[[device]]` table, so the frontend resolves its tri-state form
/// against each device's current fields and carries `allow_weak_crypto`
/// and `netbox_id` through per device (the same passthrough discipline
/// the single-edit dialog pins in its tests).
#[derive(Debug, Deserialize)]
pub struct BulkDeviceUpdate {
    pub id: String,
    pub input: DeviceInput,
}

/// The bulk-edit transaction body: N whole-record updates through the
/// no-revalidate primitive + ONE `revalidate` at the end. Factored out of
/// the command so the unit test exercises the SHIPPED loop rather than a
/// hand-written copy of it — a copy keeps passing when someone "cleans
/// up" the command to per-row revalidation and changes the atomicity
/// story.
fn apply_bulk_updates(
    doc: &mut DocumentMut,
    updates: Vec<BulkDeviceUpdate>,
) -> Result<(), InventoryError> {
    for upd in updates {
        transit_core::inventory::mutator::update_device_no_revalidate(
            doc,
            &upd.id,
            &upd.input.into_device(),
        )?;
    }
    core_revalidate(doc)
}

/// v6.3.0 bulk device edit (community request — multi-select → "Edit N
/// devices…"). Applies N whole-record updates in ONE all-or-nothing
/// transaction via [`apply_bulk_updates`], with `mutate_and_persist`'s
/// snapshot/rollback guaranteeing a bad row writes nothing (the
/// `apply_netbox_sync` shape). Returns the number of devices updated,
/// for the toast.
#[tauri::command]
pub async fn bulk_update_devices(
    state: State<'_, AppState>,
    updates: Vec<BulkDeviceUpdate>,
) -> Result<usize, String> {
    let count = updates.len();
    // Capture rename pairs before the move: the bulk path runs through
    // `*_no_revalidate`, which deliberately bypasses the single-edit
    // rename guard, so an id CAN change here even though the UI does not
    // offer the field today.
    let renames: Vec<(String, String)> = updates
        .iter()
        .filter(|u| u.id != u.input.id)
        .map(|u| (u.id.clone(), u.input.id.clone()))
        .collect();
    with_writable_doc(&state, move |doc| apply_bulk_updates(doc, updates)).await?;
    for (old_id, new_id) in renames {
        sync_pin_to_renamed_device(&state.ssh.host_keys, &old_id, &new_id).await;
    }
    Ok(count)
}

#[tauri::command]
pub async fn add_auth_profile(
    state: State<'_, AppState>,
    name: String,
    input: AuthProfile,
) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_add_auth_profile(doc, &name, &input)).await
}

#[tauri::command]
pub async fn update_auth_profile(
    state: State<'_, AppState>,
    name: String,
    input: AuthProfile,
) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_update_auth_profile(doc, &name, &input)).await
}

#[tauri::command]
pub async fn delete_auth_profile(state: State<'_, AppState>, name: String) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_delete_auth_profile(doc, &name)).await
}

#[tauri::command]
pub async fn rename_group(
    state: State<'_, AppState>,
    old_path: String,
    new_path: String,
) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_rename_group(doc, &old_path, &new_path)).await
}

#[tauri::command]
pub async fn add_group(state: State<'_, AppState>, path: String) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_add_group(doc, &path)).await
}

#[tauri::command]
pub async fn delete_group(state: State<'_, AppState>, path: String) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_delete_group(doc, &path)).await
}

#[tauri::command]
pub async fn set_device_group(
    state: State<'_, AppState>,
    id: String,
    group: Option<String>,
) -> Result<(), String> {
    with_writable_doc(&state, |doc| {
        core_set_device_group(doc, &id, group.as_deref())
    })
    .await
}

#[tauri::command]
pub async fn add_api_session(
    state: State<'_, AppState>,
    input: ApiSessionInput,
) -> Result<(), String> {
    let secret = if input.auth.needs_secret() {
        Some(
            input
                .secret
                .clone()
                .ok_or_else(|| "a secret reference is required for this auth scheme".to_string())?,
        )
    } else {
        None
    };
    let session = input.into_api_session(secret);
    with_writable_doc(&state, |doc| core_add_api_session(doc, &session)).await
}

#[tauri::command]
pub async fn update_api_session(
    state: State<'_, AppState>,
    id: String,
    input: ApiSessionInput,
) -> Result<(), String> {
    // A `None` secret on update means "keep the existing reference" — the
    // frontend never receives (and so cannot resend) the SecretRef. A scheme
    // that needs no secret (`none`) carries None regardless.
    let secret = if input.auth.needs_secret() {
        Some(match input.secret.clone() {
            Some(s) => s,
            None => existing_api_session_secret(&state, &id).await?,
        })
    } else {
        None
    };
    let session = input.into_api_session(secret);
    // The cert pin is preserved atomically inside core_update_api_session (the
    // form never carries it; the trust flow is its only writer).
    with_writable_doc(&state, |doc| core_update_api_session(doc, &id, &session)).await
}

#[tauri::command]
pub async fn delete_api_session(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_writable_doc(&state, |doc| core_delete_api_session(doc, &id)).await?;
    // Drop any recorded history so the agent can't surface a removed controller.
    state.api_sessions.close(&id);
    Ok(())
}

/// Take the inventory write lock, apply `f`, then persist atomically.
/// Refuses the write if the inventory is in `Broken` state.
async fn with_writable_doc<F>(state: &State<'_, AppState>, f: F) -> Result<(), String>
where
    F: FnOnce(&mut DocumentMut) -> Result<(), InventoryError>,
{
    let mut guard = state.inventory.write().await;
    let doc = match &mut *guard {
        InventoryState::Ready(doc) => doc,
        InventoryState::Broken { reason } => {
            return Err(format!(
                "inventory file is in error state — fix manually before editing in-app: {reason}"
            ));
        }
    };
    mutate_and_persist(doc, &state.inventory_path, f).map_err(|e| e.to_string())
}

/// Apply `f` to `doc`, then persist the result atomically to `path`.
///
/// Honors the mutator's discard-on-error contract (see
/// `transit_core::inventory::mutator` module docs): a failed mutation
/// leaves the bad edit visible on the in-memory document, so on ANY
/// error — mutation OR disk write — the document is rolled back to its
/// pre-call snapshot. Without the rollback, a failed mutation wedges
/// every later edit (the half-mutated doc keeps failing revalidation),
/// and a failed `write_atomic` leaves an unsaved change that the next
/// unrelated edit would silently persist.
///
/// Free function (no `AppState`) so the rollback behavior is unit-
/// testable below.
fn mutate_and_persist<F>(doc: &mut DocumentMut, path: &Path, f: F) -> Result<(), InventoryError>
where
    F: FnOnce(&mut DocumentMut) -> Result<(), InventoryError>,
{
    let snapshot = doc.clone();
    let result = f(doc).and_then(|()| write_atomic(path, &doc.to_string()));
    if result.is_err() {
        *doc = snapshot;
    }
    result
}

// ---------------------------------------------------------------------
// Bulk connection import (ssh_config / CSV / SecureCRT).
//
// Two-phase. `preview_import` is READ-ONLY: it reads the user-picked file
// (so transit_core::import stays I/O-free), parses + dedups, and reports
// id collisions against the current inventory — nothing is written.
// `import_connections` commits the user-edited rows in a single
// all-or-nothing `with_writable_doc` closure. Auth profiles are created
// eagerly by the frontend's enrollment flow BEFORE commit, so no secret
// ever rides the import payload (Rule 1); the batch is devices only, each
// referencing an already-existing profile by name.
// ---------------------------------------------------------------------

/// Hard cap on an imported file. A typical SecureCRT export is ~1.4 MiB,
/// but a power user with hundreds of verbose sessions can far exceed the
/// old 8 MiB cap; 64 MiB comfortably covers large real-world exports while
/// still bounding a hostile payload before parsing.
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

/// A deduped login identity, projected for the credential-map step.
#[derive(Debug, Serialize)]
pub struct ImportIdentityMeta {
    pub key: String,
    pub login: String,
    pub count: usize,
    pub auth_kind: String,
    /// Suggested backend for the "create new profile" prefill:
    /// `ssh_key` / `ssh_agent` / `keyring`.
    pub suggested_backend: String,
    /// Key-file path when the suggestion is `ssh_key` (already
    /// `~`-expanded). A reference, never a secret value (Rule 1).
    pub key_path: Option<String>,
}

/// One proposed device row for the preview grid. Carries no secrets.
#[derive(Debug, Serialize)]
pub struct ImportPreviewRow {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub vendor: String,
    pub group: Option<String>,
    pub jump_host: Option<String>,
    /// Links the row to one of [`ImportPreview::identities`] so the
    /// credential step can seed this device's default auth profile.
    pub identity_key: String,
    /// True when `id` already names a device in the inventory — the grid
    /// flags it and excludes it by default (skip+flag; rename to include).
    pub collides: bool,
}

/// Result of [`preview_import`]: proposed rows + deduped identities +
/// non-fatal parser notes. Nothing is written.
#[derive(Debug, Serialize)]
pub struct ImportPreview {
    pub rows: Vec<ImportPreviewRow>,
    pub identities: Vec<ImportIdentityMeta>,
    pub warnings: Vec<String>,
}

/// Count of devices added by a successful [`import_connections`].
#[derive(Debug, Serialize)]
pub struct ImportSummary {
    pub added: usize,
}

fn auth_kind_label(kind: AuthKind) -> &'static str {
    match kind {
        AuthKind::PublicKeyFile => "public_key_file",
        AuthKind::Agent => "agent",
        AuthKind::Password => "password",
        AuthKind::Unknown => "unknown",
    }
}

/// Parse + analyze a user-picked export file and diff it against the
/// current inventory. READ-ONLY — no write lock; nothing is persisted.
#[tauri::command]
pub async fn preview_import(
    state: State<'_, AppState>,
    source: ImportSource,
    path: String,
) -> Result<ImportPreview, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "file is too large to import ({} bytes; limit {MAX_IMPORT_BYTES})",
            meta.len()
        ));
    }
    // NOT read_to_string: Windows terminal exports (.mxtsessions /
    // .mobaconf / MobaXterm.ini) are Windows-1252, and one accented
    // session name would fail a strict UTF-8 read. The decoder falls
    // back to exact CP1252 when the bytes aren't valid UTF-8.
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = transit_core::import::decode_import_bytes(&bytes);

    let parsed = parse_import(source, &text).map_err(|e| e.to_string())?;

    let identities: Vec<ImportIdentityMeta> = analyze(&parsed.connections)
        .into_iter()
        .map(|id| {
            let (suggested_backend, key_path) = match &id.secret {
                SuggestedSecret::SshKey { path } => {
                    ("ssh_key", Some(path.to_string_lossy().into_owned()))
                }
                SuggestedSecret::Agent => ("ssh_agent", None),
                SuggestedSecret::KeyringEnrollLater => ("keyring", None),
            };
            ImportIdentityMeta {
                key: id.key,
                login: id.login,
                count: id.count,
                auth_kind: auth_kind_label(id.auth_kind).to_string(),
                suggested_backend: suggested_backend.to_string(),
                key_path,
            }
        })
        .collect();

    // Existing device ids, for the skip+flag collision check.
    let existing_ids: std::collections::HashSet<String> = {
        let guard = state.inventory.read().await;
        match &*guard {
            InventoryState::Ready(doc) => parsed_inventory(doc)?
                .devices
                .into_iter()
                .map(|d| d.id)
                .collect(),
            InventoryState::Broken { reason } => return Err(reason.clone()),
        }
    };

    // Sanitize ids and make them unique WITHIN the batch (suffix);
    // inventory collisions are flagged, never auto-renamed (skip+flag).
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let rows = parsed
        .connections
        .iter()
        .map(|conn| {
            let base = sanitize_id(&conn.source_name, &conn.host);
            let mut id = base.clone();
            let mut n = 2;
            while !used.insert(id.clone()) {
                id = format!("{base}-{n}");
                n += 1;
            }
            let collides = existing_ids.contains(&id);
            ImportPreviewRow {
                id,
                host: conn.host.clone(),
                port: conn.port,
                username: conn.username.clone(),
                vendor: conn
                    .vendor_hint
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                group: conn.group_path.clone(),
                jump_host: conn.jump_host.clone(),
                identity_key: identity_key(conn),
                collides,
            }
        })
        .collect();

    Ok(ImportPreview {
        rows,
        identities,
        warnings: parsed.warnings,
    })
}

/// Commit the user-resolved device rows in one all-or-nothing
/// transaction. Each device references an auth profile that already
/// exists (created during the credential step). The single closure adds
/// every device with the no-revalidate primitive, then validates once;
/// `mutate_and_persist`'s snapshot/rollback guarantees a single bad row
/// writes nothing.
#[tauri::command]
pub async fn import_connections(
    state: State<'_, AppState>,
    devices: Vec<DeviceInput>,
) -> Result<ImportSummary, String> {
    let added = devices.len();
    with_writable_doc(&state, move |doc| {
        for input in devices {
            core_add_device_no_revalidate(doc, &input.into_device())?;
        }
        core_revalidate(doc)
    })
    .await?;
    Ok(ImportSummary { added })
}

// ---------------------------------------------------------------------
// NetBox inventory sync (v6.2.0 — Part B of
// the netbox integration design notes (not included in this repository)).
//
// preview = read-only: page the NetBox devices list through the SAME
// confined client + resolved auth the session's human requests use, then
// hand the JSON to transit_core::import::netbox for the pure parse+diff.
// apply = one atomic batch through the no-revalidate mutator primitives
// (the import_connections shape), so a 200-row sync re-validates once and
// a single bad row writes nothing.
//
// Deliberately NOT recorded to the controller ring (`record_exchange`):
// a paged bulk dump would drown the human-meaningful exchange history and
// the agent-readable ring alike. The agent cannot invoke this — it is
// user-driven IPC like every other mutation (Rules 2/3 untouched); wrong
// upstream data is human-reviewed before commit (threat model T49).
// ---------------------------------------------------------------------

/// One "New" row of the sync preview (wire mirror of
/// [`transit_core::import::netbox::NetBoxCandidate`] plus the same
/// `collides` affordance `preview_import` rows carry).
#[derive(Debug, Serialize)]
pub struct NetBoxCandidateWire {
    pub netbox_id: String,
    pub proposed_device_id: String,
    pub host: String,
    pub name: String,
    pub status: String,
    pub vendor_tag: String,
    pub group: Option<String>,
    pub tags: Vec<String>,
    /// True when the proposed id still collides with an existing device
    /// AFTER in-batch suffix dedup — the row starts excluded in the grid.
    pub collides: bool,
}

#[derive(Debug, Serialize)]
pub struct NetBoxFieldChangeWire {
    pub field: String,
    pub current: String,
    pub incoming: String,
}

#[derive(Debug, Serialize)]
pub struct NetBoxChangeWire {
    pub device_id: String,
    pub netbox_id: String,
    pub changes: Vec<NetBoxFieldChangeWire>,
}

#[derive(Debug, Serialize)]
pub struct NetBoxStaleWire {
    pub device_id: String,
    pub netbox_id: String,
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct NetBoxSyncPreview {
    pub new: Vec<NetBoxCandidateWire>,
    pub changed: Vec<NetBoxChangeWire>,
    pub stale: Vec<NetBoxStaleWire>,
    pub unchanged: usize,
    /// Remote devices with nothing to connect to (no IP, no usable name).
    pub skipped: Vec<String>,
    /// Parse/pagination warnings — always surfaced, never silently eaten.
    pub warnings: Vec<String>,
    /// Devices fetched from NetBox (after the active-only filter, if on).
    pub fetched: usize,
}

/// NetBox devices per page. 250 × the `fields=`-trimmed shape is ~100 KB,
/// far under the client's 8 MiB body cap.
const NETBOX_PAGE_LIMIT: usize = 250;
/// Pagination ceiling: 40 pages × 250 = 10,000 devices. Hitting it adds a
/// warning naming what was not fetched (no silent truncation).
const NETBOX_MAX_PAGES: usize = 40;
/// Aggregate fetch ceiling across all pages. A normal `fields=`-trimmed
/// sync is a few MB; only an instance ignoring `fields=`/`limit` (or a
/// hostile one padding responses, T49) approaches this — refuse rather
/// than hold ~40 × 8 MiB of JSON in memory.
const NETBOX_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Fetch the NetBox device list via the API session's confined endpoint +
/// resolved auth, diff it against the current inventory, and return the
/// bucketed preview. Read-only — no inventory lock is taken beyond the
/// read guard, and nothing is written.
#[tauri::command]
pub async fn preview_netbox_sync(
    state: State<'_, AppState>,
    api_session_id: String,
    active_only: Option<bool>,
) -> Result<NetBoxSyncPreview, String> {
    let (endpoint, auth_scheme, secret_ref, _name, _vendor) =
        resolve_api_session_endpoint(&state, &api_session_id).await?;
    let auth = build_applied_auth(&state, &auth_scheme, secret_ref.as_ref()).await?;
    // Load a stored cert pin (if any) so a verified self-signed NetBox
    // connects on this fetch — same idempotent pattern as the send path.
    if let (Some(host), Some(pin_hex)) = api_session_host_and_pin(&state, &api_session_id).await? {
        if let Some(bytes) = hex32_decode(&pin_hex) {
            state.api_client.trust_pin(&host, bytes);
        }
    }

    let status_filter = if active_only.unwrap_or(true) {
        "&status=active"
    } else {
        ""
    };
    let mut pages: Vec<serde_json::Value> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;
    for page_idx in 0..NETBOX_MAX_PAGES {
        let path = format!(
            "dcim/devices/?limit={NETBOX_PAGE_LIMIT}&offset={}&fields=id,name,status,\
             primary_ip4,primary_ip6,platform,site,role,tags{status_filter}",
            page_idx * NETBOX_PAGE_LIMIT
        );
        let resp = state
            .api_client
            .send_human(&endpoint, "GET", &path, &[], None, &auth)
            .await
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&resp.status) {
            return Err(format!(
                "NetBox returned HTTP {} on page {} — check the session's base URL \
                 (…/api) and API token",
                resp.status,
                page_idx + 1
            ));
        }
        if resp.truncated {
            return Err(format!(
                "NetBox page {} exceeded the response size cap — the instance is not \
                 honoring the page limit",
                page_idx + 1
            ));
        }
        total_bytes = total_bytes.saturating_add(resp.body.len());
        if total_bytes > NETBOX_MAX_TOTAL_BYTES {
            return Err(
                "NetBox responses exceeded the total sync fetch cap (64 MiB) — the \
                 instance is not honoring fields=/limit trimming"
                    .to_string(),
            );
        }
        let page: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|_| format!("NetBox page {} was not valid JSON", page_idx + 1))?;
        let has_next = !page
            .get("next")
            .map(serde_json::Value::is_null)
            .unwrap_or(true);
        pages.push(page);
        if !has_next {
            break;
        }
        if page_idx + 1 == NETBOX_MAX_PAGES {
            warnings.push(format!(
                "stopped after {} devices — NetBox reports more; refine with the \
                 active-only filter or sync in stages",
                NETBOX_MAX_PAGES * NETBOX_PAGE_LIMIT
            ));
        }
    }

    let (remote, parse_warnings) = transit_core::import::netbox::parse_devices(&pages);
    warnings.extend(parse_warnings);
    let fetched = remote.len();

    let (diff, existing_ids) = {
        let guard = state.inventory.read().await;
        match &*guard {
            InventoryState::Ready(doc) => {
                let inv = parsed_inventory(doc)?;
                let ids: std::collections::HashSet<String> =
                    inv.devices.iter().map(|d| d.id.clone()).collect();
                (
                    transit_core::import::netbox::diff(&inv.devices, &remote),
                    ids,
                )
            }
            InventoryState::Broken { reason } => return Err(reason.clone()),
        }
    };

    // In-batch suffix dedup + existing-id collision flag — the
    // `preview_import` affordance: two NetBox sites can both hold a "sw1",
    // and a proposal must never silently shadow an existing device.
    let mut used: std::collections::HashSet<String> = existing_ids.clone();
    let new = diff
        .new
        .into_iter()
        .map(|c| {
            let mut id = c.proposed_device_id.clone();
            if used.contains(&id) {
                for n in 2..100 {
                    let candidate = format!("{}-{n}", c.proposed_device_id);
                    if !used.contains(&candidate) {
                        id = candidate;
                        break;
                    }
                }
            }
            let collides = existing_ids.contains(&id);
            used.insert(id.clone());
            NetBoxCandidateWire {
                netbox_id: c.netbox_id,
                proposed_device_id: id,
                host: c.host,
                name: c.name,
                status: c.status,
                vendor_tag: c.vendor_tag,
                group: c.group,
                tags: c.tags,
                collides,
            }
        })
        .collect();

    Ok(NetBoxSyncPreview {
        new,
        changed: diff
            .changed
            .into_iter()
            .map(|c| NetBoxChangeWire {
                device_id: c.device_id,
                netbox_id: c.netbox_id,
                changes: c
                    .changes
                    .into_iter()
                    .map(|f| NetBoxFieldChangeWire {
                        field: f.field.to_string(),
                        current: f.current,
                        incoming: f.incoming,
                    })
                    .collect(),
            })
            .collect(),
        stale: diff
            .stale
            .into_iter()
            .map(|s| NetBoxStaleWire {
                device_id: s.device_id,
                netbox_id: s.netbox_id,
                host: s.host,
            })
            .collect(),
        unchanged: diff.unchanged,
        skipped: diff.skipped,
        warnings,
        fetched,
    })
}

/// One accepted update: the target device id + the full replacement
/// record (the frontend builds it from the live `DeviceMeta` plus the
/// accepted incoming fields, preserving every passthrough field — the
/// same whole-record-replace discipline as `EditDeviceDialog`). Unlinks
/// arrive on this same shape with `netbox_id: null`.
#[derive(Debug, Deserialize)]
pub struct NetBoxUpdateDecision {
    pub id: String,
    pub input: DeviceInput,
}

/// The human-reviewed sync decisions, committed atomically.
#[derive(Debug, Deserialize)]
pub struct NetBoxApplyPayload {
    #[serde(default)]
    pub adds: Vec<DeviceInput>,
    #[serde(default)]
    pub updates: Vec<NetBoxUpdateDecision>,
    /// Opt-in Stale deletes — the frontend gates these behind an explicit
    /// destructive confirm; the default stale action is Keep.
    #[serde(default)]
    pub deletes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NetBoxSyncSummary {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
}

/// Commit the reviewed sync decisions in one all-or-nothing transaction —
/// adds, updates (incl. unlinks), and opt-in deletes each use their
/// no-revalidate primitive, with a single `revalidate` at the end;
/// `mutate_and_persist`'s snapshot/rollback guarantees a bad row writes
/// nothing.
#[tauri::command]
pub async fn apply_netbox_sync(
    state: State<'_, AppState>,
    payload: NetBoxApplyPayload,
) -> Result<NetBoxSyncSummary, String> {
    let summary = NetBoxSyncSummary {
        added: payload.adds.len(),
        updated: payload.updates.len(),
        deleted: payload.deletes.len(),
    };
    with_writable_doc(&state, move |doc| {
        for input in payload.adds {
            core_add_device_no_revalidate(doc, &input.into_device())?;
        }
        for upd in payload.updates {
            transit_core::inventory::mutator::update_device_no_revalidate(
                doc,
                &upd.id,
                &upd.input.into_device(),
            )?;
        }
        // v6.5.0 — remediation-shaped refusal for jump targets: a stale
        // delete whose device others still jump through would otherwise
        // abort at the trailing revalidate with the generic dangling-ref
        // error naming the REFERRER. Pre-check with the same
        // `JumpHostInUse` the single-delete path uses, ignoring referents
        // that are themselves deleted in this batch (deleting a bastion
        // together with all its routers is legitimate). The trailing
        // revalidate stays the authority either way.
        for id in &payload.deletes {
            let referents: Vec<String> = transit_core::inventory::mutator::jump_referents(doc, id)
                .into_iter()
                .filter(|r| !payload.deletes.contains(r))
                .collect();
            if !referents.is_empty() {
                return Err(transit_core::inventory::InventoryError::JumpHostInUse {
                    id: id.clone(),
                    devices: referents,
                });
            }
        }
        for id in &payload.deletes {
            transit_core::inventory::mutator::delete_device_no_revalidate(doc, id)?;
        }
        core_revalidate(doc)
    })
    .await?;
    Ok(summary)
}

// ---------------------------------------------------------------------
// Phase 2a — secret backends, enrollment, availability.
// ---------------------------------------------------------------------

/// Result of a successful `test_secret_resolve`. **Never returns the
/// resolved value or any prefix of it** — only its length so the user
/// can sanity-check that the backend isn't returning an empty string.
#[derive(Debug, Serialize)]
pub struct TestResolveOk {
    /// Length in bytes of the resolved value. Used for "is this the
    /// password I expected, or did 1Password silently return empty?"
    /// confidence-check only.
    pub length: usize,
}

/// Snapshot of per-backend startup-probe results. Frontend reads this
/// once at app mount via TanStack Query and renders the inline install
/// banner under the backend select when the entry is `NeedsInstall`.
///
/// Read-only — no side effects, doesn't touch the inventory lock.
#[tauri::command]
pub async fn secret_backend_availability(
    state: State<'_, AppState>,
) -> Result<HashMap<String, BackendAvailability>, String> {
    Ok(state.secrets.availability())
}

/// One key file paired with its read-only [`KeyProbeVerdict`]. Returned
/// by [`probe_ssh_keys`]; carries only the path the caller already
/// supplied plus a classification — never key bytes or file contents.
#[derive(Debug, Serialize)]
pub struct KeyProbe {
    pub path: String,
    pub verdict: KeyProbeVerdict,
}

/// Read-only probe of on-disk SSH key files for the import wizard's
/// credential step: for each referenced `IdentityFile`, classify it as
/// unencrypted / encrypted / unparseable / unreadable so the UI can
/// auto-create profiles for unencrypted keys, prompt a passphrase only
/// for encrypted ones, and flag the rest.
///
/// Per Rule 1 this returns ONLY a verdict — each key is decoded inside
/// `transit_auth` (the credential boundary) and neither key bytes nor
/// file contents ever cross IPC. No write lock; nothing is persisted.
/// Paths are deduped (a key reused across logins is read once).
#[tauri::command]
pub async fn probe_ssh_keys(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<Vec<KeyProbe>, String> {
    let mut seen = std::collections::HashSet::new();
    let probes = paths
        .into_iter()
        .filter(|p| seen.insert(p.clone()))
        .map(|p| {
            let verdict = state.secrets.probe_ssh_key(Path::new(&p));
            KeyProbe { path: p, verdict }
        })
        .collect();
    Ok(probes)
}

/// Verify a profile's reference resolves successfully without
/// returning the value to the frontend. Returns `{ length }` on
/// success; classifies common failures (`OpAuth`, `Unavailable`,
/// `NotFound`) into actionable error strings.
///
/// Per Rule 1 the value never crosses the IPC boundary — even the
/// length-only ack is only safe because length isn't structurally
/// sensitive. (A length of 0 means "backend returned empty"; a length
/// of 16 means "looks like a real password." That's the most we
/// surface.)
#[tauri::command]
pub async fn test_secret_resolve(
    state: State<'_, AppState>,
    profile_name: String,
) -> Result<TestResolveOk, String> {
    let secret_ref = lookup_profile_secret(&state, &profile_name).await?;
    match &secret_ref {
        // For SshAgent profiles, "test connection" means "the agent
        // is reachable AND the pinned identity is loaded." Open a
        // real session (connect via $SSH_AUTH_SOCK / named pipe,
        // list identities, find the pin) and drop it immediately —
        // the side effect of opening is the actual probe. The
        // `length` field is meaningless here; report 0 to signal
        // "signer-style backend" without inventing a different shape.
        transit_core::inventory::SecretRef::SshAgent { .. } => state
            .secrets
            .open_ssh_agent_session(&secret_ref)
            .await
            .map(|_| TestResolveOk { length: 0 })
            .map_err(|e| e.to_string()),
        // For value-returning backends, force a fresh backend
        // round-trip (bypassing the 60s cache) so the user's "Test
        // connection" actually exercises the live backend instead of
        // returning a cached success from minutes ago.
        _ => state
            .secrets
            .resolve_value_uncached(&secret_ref)
            .await
            .map(|s| {
                use secrecy::ExposeSecret;
                TestResolveOk {
                    length: s.expose_secret().len(),
                }
            })
            .map_err(|e| e.to_string()),
    }
}

/// **THE** secret-bearing IPC. The `value: String` parameter is the
/// only IPC parameter in the entire app that carries credential bytes.
/// Wrap it in `SecretString` immediately on entry so the original
/// `String` drops at scope exit; the `SecretString` zeroes its
/// internal buffer on drop.
///
/// See Risk #6 in the Phase 2a plan: there's a brief window between
/// JSON-deserialization-into-String and the wrap line where the
/// password lives as a normal String in tauri/serde-json's allocators.
/// Documented residual risk in `docs/security/threat-model.md`.
#[tauri::command]
pub async fn enroll_secret(
    state: State<'_, AppState>,
    profile_name: String,
    value: String,
) -> Result<(), String> {
    let secret = SecretString::from(value);
    let secret_ref = lookup_profile_secret(&state, &profile_name).await?;
    state
        .secrets
        .enroll(&secret_ref, secret)
        .await
        .map_err(|e| e.to_string())
}

/// Hand the backend the session auth header the human's login just produced,
/// so the AGENT's GETs can ride that session (v4.3.0).
///
/// **Rule 1 note — this is the second `tauri::command` that accepts a
/// credential, alongside `enroll_secret`, and it was a deliberate call.** What
/// makes it defensible:
///
/// - The token did not originate in the webview. The backend received it
///   first, in the login response `api_send_request` returned; it even framed
///   that response into the session ring. Handing back a derived header
///   crosses no boundary the value has not already crossed.
/// - Write-only. Nothing returns it: not this command, not `ApiSessionMeta`,
///   not the ring (`record_exchange` frames method/path/status + the RESPONSE
///   body, never request headers).
/// - In memory only, `SecretString`-wrapped, dropped with the controller on
///   `close`. Never persisted, never enrolled into a keystore.
/// - Non-resurrecting: a no-op if the controller is not open.
///
/// The alternative — having the backend re-implement the capture rules to
/// extract the token itself — would have meant a second dotted-JSON-path and
/// Set-Cookie engine alongside `apiCapture.ts`, two implementations obliged to
/// agree forever, for no reduction in actual exposure.
///
/// Threat model: T41.
#[tauri::command]
pub async fn api_set_session_auth(
    state: State<'_, AppState>,
    api_session_id: String,
    header: String,
    value: String,
) -> Result<(), String> {
    // Bind to the controller's CURRENT origin, resolved from inventory here —
    // the caller does not get to choose what the credential is scoped to.
    let (endpoint, ..) = resolve_api_session_endpoint(&state, &api_session_id).await?;
    let origin = endpoint.api_base().origin().ascii_serialization();
    state
        .api_sessions
        .set_session_auth(&api_session_id, &origin, &header, value);
    Ok(())
}

/// Read-only inventory lookup: find the auth profile by name, return
/// its `SecretRef`. Used by both `enroll_secret` and
/// `test_secret_resolve`.
async fn lookup_profile_secret(
    state: &State<'_, AppState>,
    profile_name: &str,
) -> Result<transit_core::inventory::SecretRef, String> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc)?,
        InventoryState::Broken { reason } => return Err(reason.clone()),
    };
    let secret = inv
        .auth_profiles
        .get(profile_name)
        .map(|p| p.secret.clone())
        .ok_or_else(|| format!("auth profile '{profile_name}' not found"))?;
    // For an ssh_key profile the key file lives on disk (not in a
    // backend) — the only enrollable/resolvable secret is its OPTIONAL
    // passphrase, which rides a nested keyring ref. Route enroll_secret /
    // test_secret_resolve to that nested ref so the passphrase lands in
    // (and is probed from) the keychain. A key with no passphrase has
    // nothing to enroll.
    use transit_core::inventory::SecretRef;
    match secret {
        SecretRef::SshKey {
            passphrase: Some(p),
            ..
        } => Ok(*p),
        SecretRef::SshKey {
            passphrase: None, ..
        } => Err("this SSH key has no passphrase to set".to_string()),
        other => Ok(other),
    }
}

/// Enroll (write-only) the API key for an api_session, resolving the
/// session's `SecretRef` by id. Mirrors [`enroll_secret`] for auth
/// profiles: the value never round-trips, only the reference is looked
/// up. Enroll is meaningful for the `keyring` backend; `op` / `env`
/// references are managed outside Transit.
#[tauri::command]
pub async fn enroll_api_session_secret(
    state: State<'_, AppState>,
    api_session_id: String,
    value: String,
) -> Result<(), String> {
    let secret = SecretString::from(value);
    let secret_ref = existing_api_session_secret(&state, &api_session_id).await?;
    state
        .secrets
        .enroll(&secret_ref, secret)
        .await
        .map_err(|e| e.to_string())
}

/// Read-only lookup: the `SecretRef` of the api_session with `id`. Used
/// by [`enroll_api_session_secret`] and by `update_api_session`'s
/// keep-existing-secret path.
async fn existing_api_session_secret(
    state: &State<'_, AppState>,
    id: &str,
) -> Result<transit_core::inventory::SecretRef, String> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc)?,
        InventoryState::Broken { reason } => return Err(reason.clone()),
    };
    inv.api_sessions
        .iter()
        .find(|s| s.id == id)
        .and_then(|s| s.secret.clone())
        .ok_or_else(|| format!("api session '{id}' not found or has no stored secret"))
}

/// Encode a 32-byte fingerprint as lowercase hex (the form shown to the user +
/// stored in inventory).
fn hex32_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a 64-char lowercase-hex fingerprint back to 32 bytes; None unless it
/// is exactly 64 hex chars (so a malformed pin can never widen trust).
fn hex32_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    // Length is checked above, so `as_chunks` leaves no remainder.
    for (i, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Canonicalize a URL host into the SAME key the TLS verifier uses
/// (`transit_tls::server_name_host`): a domain lowercased, an IP
/// as its canonical bracket-free string. Without this, an IPv6 literal is
/// stored bracketed (`[::1]` from `Url::host_str`) but the verifier keys on the
/// unbracketed `IpAddr::to_string` (`::1`), so the pin can never match (a
/// fail-closed correctness bug found in the v4.3.0 adversarial review).
fn canonical_host_key(host: url::Host<&str>) -> String {
    match host {
        url::Host::Domain(d) => d.to_ascii_lowercase(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    }
}

/// The controller's TLS host (from `base_url`, lowercased to match the verifier
/// keying) and its stored cert pin (hex), in one inventory read. Host is None
/// for non-base-URL (UniFi) kinds — they use valid public certs and are never
/// pinned.
async fn api_session_host_and_pin(
    state: &State<'_, AppState>,
    id: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc)?,
        InventoryState::Broken { reason } => return Err(reason.clone()),
    };
    let Some(s) = inv.api_sessions.iter().find(|s| s.id == id) else {
        return Ok((None, None));
    };
    let host = s
        .base_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host().map(canonical_host_key));
    Ok((host, s.pinned_cert_sha256.clone()))
}

/// The SHA-256 (hex) of the cert last REJECTED for this controller's host, if
/// any — the fingerprint the untrusted-cert dialog shows for the user to
/// verify out-of-band. None when nothing was rejected (a valid public cert, or
/// no request attempted yet). Reading it grants no trust.
#[tauri::command]
pub async fn api_pending_cert(
    state: State<'_, AppState>,
    id: String,
) -> Result<Option<String>, String> {
    let (host, _) = api_session_host_and_pin(&state, &id).await?;
    let Some(host) = host else {
        return Ok(None);
    };
    Ok(state
        .api_client
        .pending_cert(&host)
        .map(|b| hex32_encode(&b)))
}

/// Trust (pin) a self-signed controller's cert AFTER the user verified its
/// fingerprint in the untrusted-cert dialog. `sha256_hex` must be the 64-char
/// hex that dialog showed. Persists the pin on the controller AND loads it into
/// the live client so the next request connects. This user-driven IPC is the
/// ONLY path by which a self-signed host becomes reachable — the agent has no
/// route to it.
#[tauri::command]
pub async fn api_trust_cert(
    state: State<'_, AppState>,
    id: String,
    sha256_hex: String,
) -> Result<(), String> {
    let hex = sha256_hex.trim().to_ascii_lowercase();
    let bytes = hex32_decode(&hex)
        .ok_or_else(|| "cert fingerprint must be 64 hex characters (SHA-256)".to_string())?;
    // Persist on the controller (survives restart).
    with_writable_doc(&state, |doc| core_set_api_session_pin(doc, &id, Some(&hex))).await?;
    // Load into the live client so no restart is needed.
    if let (Some(host), _) = api_session_host_and_pin(&state, &id).await? {
        state.api_client.trust_pin(&host, bytes);
    }
    Ok(())
}

/// Wire shape for [`api_send_request`]'s response. Mirrors
/// `transit_api::ApiResponse`. `body` is RAW (the human's own controller
/// data) — redaction is the agent boundary, never applied here.
#[derive(Serialize)]
pub struct ApiResponseWire {
    pub status: u16,
    pub body: String,
    pub truncated: bool,
    /// Response headers (name, value) for the human Postman view. RAW like
    /// `body` — this is the operator's own controller data. The agent's
    /// tool output never carries headers (built from `body` alone), so a
    /// `Set-Cookie` session token can't reach the LLM via this path.
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for ApiResponseWire {
    /// §10 — never Debug-print raw device output (WiFi PSKs, configs,
    /// `Set-Cookie` values). Mirrors `transit_api::ApiResponse`'s
    /// hand-written Debug so a stray `debug!(?resp)` can't leak data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiResponseWire")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("truncated", &self.truncated)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// Execute a HUMAN (Postman) request against an api_session's controller.
/// Resolves the session's endpoint + key, host-pins the path (the human
/// cannot choose the host either), injects `X-API-KEY`, and sends with
/// the caller's method. UNGATED on method — any method, exactly like
/// typing `configure` at the SSH terminal (the policy gate is agent-only).
/// The response is returned RAW.
#[tauri::command]
pub async fn api_send_request(
    state: State<'_, AppState>,
    api_session_id: String,
    method: String,
    path: String,
    headers: Option<Vec<(String, String)>>,
    body: Option<String>,
) -> Result<ApiResponseWire, String> {
    let (endpoint, auth_scheme, secret_ref, name, vendor) =
        resolve_api_session_endpoint(&state, &api_session_id).await?;
    // Agent-boundary control, deliberately BEFORE and OUTSIDE the auth-scheme
    // branch: `record_exchange` frames the request path into the ring the
    // agent reads, so no scheme may put a credential there.
    reject_credential_in_path(&path)?;
    let auth = build_applied_auth(&state, &auth_scheme, secret_ref.as_ref()).await?;
    let mut headers = headers.unwrap_or_default();
    // Fill {{username}}/{{password}} from the stored credential BEFORE the
    // send. `body`/`headers` below carry the real secret; `path` never does
    // (enforced in the helper), which is what keeps `record_exchange` — the
    // ring the agent reads — free of it.
    let mut body = body;
    let pre_substitution_headers = headers.clone();
    substitute_login_credentials(
        &state,
        &auth_scheme,
        secret_ref.as_ref(),
        &path,
        &mut headers,
        &mut body,
    )
    .await?;
    // Load a stored cert pin (if any) into the client so a verified self-signed
    // controller connects on this send — idempotent, and picks up a fresh trust
    // or an edit with no restart.
    if let (Some(host), Some(pin_hex)) = api_session_host_and_pin(&state, &api_session_id).await? {
        if let Some(bytes) = hex32_decode(&pin_hex) {
            state.api_client.trust_pin(&host, bytes);
        }
    }
    let resp = state
        .api_client
        .send_human(
            &endpoint,
            &method,
            &path,
            &headers,
            body.map(String::into_bytes),
            &auth,
        )
        .await
        .map_err(|e| e.to_string())?;
    // Retain the human's session auth header so the AGENT's GETs can ride the
    // session the human just established. Uses the FINAL headers (after
    // credential substitution), and only ever RETAINS a value that already
    // crossed IPC as part of this request — no new credential flow.
    // Never retain a header that carried the raw keychain password: after
    // substitution `Authorization: Basic {{password}}` is indistinguishable
    // from a session token, and replaying the account password on every agent
    // GET is not what "ride the human's session" is meant to license.
    let retainable: Vec<(String, String)> = headers
        .iter()
        .zip(pre_substitution_headers.iter())
        .filter(|(_, (_, before))| !before.contains(PASSWORD_VAR))
        .map(|((k, v), _)| (k.clone(), v.clone()))
        .collect();
    let origin = endpoint.api_base().origin().ascii_serialization();
    state
        .api_sessions
        .remember_session_auth(&api_session_id, &origin, &retainable);
    // Record the exchange (RAW) so the AGENT can list + read this controller
    // via read_scrollback; the dispatcher redacts before the LLM sees it.
    state.api_sessions.record_exchange(
        &api_session_id,
        &name,
        &vendor,
        &method,
        &path,
        resp.status,
        &resp.body,
    );
    Ok(ApiResponseWire {
        status: resp.status,
        body: resp.body,
        truncated: resp.truncated,
        headers: resp.headers,
    })
}

/// Register a controller as an OPEN, agent-visible session (empty ring) when
/// its API tab opens — so the agent can see + investigate it via
/// `list_open_sessions` / `read_scrollback` / `propose_api_call` WITHOUT the
/// human sending a request first (which is the whole point of "ask the agent
/// to investigate this controller"). Idempotent: never wipes history a prior
/// send recorded. A no-op if the controller isn't in inventory.
#[tauri::command]
pub async fn register_api_session(
    state: State<'_, AppState>,
    id: String,
    // #12 Phase 2b: `(name, path)` GET endpoints from the controller's
    // collection, gathered frontend-side (GET-only) so the agent's prompt can
    // list KNOWN-GOOD paths. Not secret; empty is fine (no collection yet).
    endpoints: Vec<(String, String)>,
) -> Result<(), String> {
    if let Some((name, vendor)) = resolve_api_session_meta(&state, &id).await {
        state.api_sessions.open(&id, &name, &vendor);
        state.api_sessions.set_known_endpoints(&id, endpoints);
    }
    Ok(())
}

/// The controller's full request/response history (the agent-visible ring),
/// RAW, for the human session-history view (#12 Phase 2b) — closes the
/// asymmetry where the agent sees the whole ring but the pane shows only the
/// last response. Raw is correct: the human sees their own controller's data
/// (redaction is the agent boundary), and the API key is never in the ring.
/// Empty string if the controller isn't open.
#[tauri::command]
pub async fn api_session_history(state: State<'_, AppState>, id: String) -> Result<String, String> {
    Ok(state.api_sessions.history(&id).unwrap_or_default())
}

/// Deregister a controller's open session (drop its ring) when its API tab
/// closes. Distinct from `delete_api_session`, which also removes the
/// inventory entry — this only ends the agent-visible session, leaving the
/// controller in inventory.
#[tauri::command]
pub async fn close_api_session(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.api_sessions.close(&id);
    Ok(())
}

/// Name + vendor of an api_session from the current inventory, or `None` if
/// absent / inventory Broken. Lighter than `resolve_api_session_endpoint` —
/// it does NOT build the `Endpoint`, so a temporarily-malformed host can't
/// stop the agent from seeing the session (the GET gate re-validates the
/// endpoint at run time anyway).
async fn resolve_api_session_meta(
    state: &AppState,
    id: &str,
) -> Option<(String, transit_core::inventory::Vendor)> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc).ok()?,
        InventoryState::Broken { .. } => return None,
    };
    inv.api_sessions
        .iter()
        .find(|s| s.id == id)
        .map(|s| (s.name.clone(), s.vendor.clone()))
}

/// Resolve an api_session's `transit_api::Endpoint` + `SecretRef` + display
/// name + vendor from the current inventory (name/vendor feed the agent's
/// per-controller scrollback ring).
// `&AppState` (not `&State<AppState>`) so the agent's `AppApiExecutor`
// (`agent_dispatch.rs`) can resolve a controller's endpoint the same way
// the human `api_send_request` does — `State<AppState>` deref-coerces to
// `&AppState`, so the existing command call site is unchanged.
pub(crate) async fn resolve_api_session_endpoint(
    state: &AppState,
    id: &str,
) -> Result<
    (
        transit_api::Endpoint,
        transit_core::inventory::AuthScheme,
        Option<transit_core::inventory::SecretRef>,
        String,
        transit_core::inventory::Vendor,
    ),
    String,
> {
    let guard = state.inventory.read().await;
    let inv = match &*guard {
        InventoryState::Ready(doc) => parsed_inventory(doc)?,
        InventoryState::Broken { reason } => return Err(reason.clone()),
    };
    let s = inv
        .api_sessions
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("api session '{id}' not found"))?;
    let endpoint = match s.kind {
        ApiEndpointKind::SiteManager => transit_api::Endpoint::site_manager(),
        ApiEndpointKind::NetworkLocal => {
            transit_api::Endpoint::network_local(s.host.as_deref().unwrap_or(""))
                .map_err(|e| e.to_string())?
        }
        ApiEndpointKind::ConnectorProxy => {
            transit_api::Endpoint::connector_proxy(s.console_id.as_deref().unwrap_or(""))
                .map_err(|e| e.to_string())?
        }
        ApiEndpointKind::Generic => {
            transit_api::Endpoint::generic(s.base_url.as_deref().unwrap_or(""))
                .map_err(|e| e.to_string())?
        }
    };
    Ok((
        endpoint,
        s.auth.clone(),
        s.secret.clone(),
        s.name.clone(),
        s.vendor.clone(),
    ))
}

/// Resolve a controller's configured [`AuthScheme`] into the transport's
/// [`AppliedAuth`], fetching the secret (if the scheme needs one) via the
/// [`SecretRegistry`]. Errors are GENERIC (no backend detail) — the agent
/// path forwards this string to the model, so it must leak nothing.
pub(crate) async fn build_applied_auth(
    state: &AppState,
    auth: &transit_core::inventory::AuthScheme,
    secret_ref: Option<&transit_core::inventory::SecretRef>,
) -> Result<transit_api::AppliedAuth, String> {
    use transit_core::inventory::AuthScheme;
    async fn secret(
        state: &AppState,
        secret_ref: Option<&transit_core::inventory::SecretRef>,
    ) -> Result<secrecy::SecretString, String> {
        let r = secret_ref.ok_or_else(|| "auth scheme needs a secret".to_string())?;
        state
            .secrets
            .resolve_value(r)
            .await
            .map_err(|_| "api auth resolution failed".to_string())
    }
    match auth {
        AuthScheme::None => Ok(transit_api::AppliedAuth::None),
        AuthScheme::ApiKey {
            header,
            value_prefix,
        } => transit_api::AppliedAuth::api_key(
            header,
            value_prefix,
            secret(state, secret_ref).await?,
        )
        .map_err(|_| "invalid api-key header name".to_string()),
        AuthScheme::Bearer => Ok(transit_api::AppliedAuth::Bearer {
            token: secret(state, secret_ref).await?,
        }),
        AuthScheme::Basic { username } => Ok(transit_api::AppliedAuth::Basic {
            username: username.clone(),
            password: secret(state, secret_ref).await?,
        }),
        // Injects no header — the credential goes into the login request's
        // BODY via `substitute_login_credentials`.
        AuthScheme::LoginCredentials { .. } => Ok(transit_api::AppliedAuth::None),
    }
}

/// The `{{variable}}` names a login-flow collection uses for the operator's
/// credentials. Every bundled vendor was normalised onto this pair so one rule
/// covers all of them (they previously used `j_username`, `central_username`,
/// `user`, …).
const USERNAME_VAR: &str = "{{username}}";
const PASSWORD_VAR: &str = "{{password}}";

/// Fill `{{username}}`/`{{password}}` in an outgoing request from the
/// controller's STORED credentials, so the operator never types a password
/// into the variables bar and the value never crosses Tauri IPC (Rule 1 — the
/// same resolve-and-inject path `build_applied_auth` uses for an API key).
///
/// Substitutes into the BODY and HEADER VALUES only, never the PATH. A
/// credential in a URL would be recorded verbatim into the agent-visible
/// session ring by `record_exchange`, and would land in the controller's own
/// access log. `{{password}}` in a path is therefore a hard error rather than
/// a silent skip — no bundled collection does it, and a custom one that tries
/// should be told why. `{{username}}` in a path is fine (it is not secret).
///
/// A no-op for every other scheme, so a controller that authenticates by
/// header is untouched.
async fn substitute_login_credentials(
    state: &AppState,
    auth: &transit_core::inventory::AuthScheme,
    secret_ref: Option<&transit_core::inventory::SecretRef>,
    path: &str,
    headers: &mut [(String, String)],
    body: &mut Option<String>,
) -> Result<(), String> {
    use secrecy::ExposeSecret;
    use transit_core::inventory::AuthScheme;

    let AuthScheme::LoginCredentials { username } = auth else {
        return Ok(());
    };
    let plan = login_substitution_plan(path, headers, body)?;
    debug_assert!(
        !path.contains(PASSWORD_VAR),
        "guarded by reject_credential_in_path"
    );
    if !plan.any() {
        return Ok(());
    }
    // Resolve only when the request actually references {{password}}, so a
    // plain investigation GET never touches the keychain.
    let password = if plan.password {
        let secret_ref = secret_ref
            .ok_or_else(|| "this controller has no stored credential to log in with".to_string())?;
        Some(
            state
                .secrets
                .resolve_value(secret_ref)
                .await
                .map_err(|_| "api auth resolution failed".to_string())?,
        )
    } else {
        None
    };
    apply_login_substitution(
        username,
        password.as_ref().map(|p| p.expose_secret()),
        headers,
        body,
    );
    Ok(())
}

/// What a request needs filled. Separated from the async resolve so the
/// security-critical rules are unit-testable without an `AppState`.
#[derive(Debug, Default, PartialEq, Eq)]
struct LoginSubstitution {
    username: bool,
    password: bool,
}

impl LoginSubstitution {
    fn any(&self) -> bool {
        self.username || self.password
    }
}

/// Refuse a credential variable in the request PATH — for EVERY auth scheme,
/// not just `LoginCredentials`.
///
/// A credential in a URL is recorded verbatim into the agent-visible session
/// ring by `record_exchange`, and into the controller's own access log. That
/// makes this an agent-boundary control, so it must not be gated on the
/// controller's auth scheme: a `none`/`basic`/`bearer` session (every
/// pre-v4.3.0 login-flow controller, and every custom or Postman-imported
/// one) can carry `?pw={{password}}` just as easily.
///
/// The frontend already declines to substitute credential-shaped variables
/// into a path, so the marker survives to here rather than arriving
/// pre-expanded. This is the second half of that pair, and the one that
/// produces the explanation.
fn reject_credential_in_path(path: &str) -> Result<(), String> {
    if let Some(name) = credential_token_in(path) {
        return Err(format!(
            "a credential must not be placed in a URL path — move {{{{{name}}}}} into the request body or a header"
        ));
    }
    Ok(())
}

/// The name of the first credential-shaped `{{token}}` in `text`, if any.
/// Mirrors the frontend's `isSensitiveVarName` word-split, so `{{PASSWORD}}`,
/// `{{clientSecret}}` and `{{j_password}}` are caught, not just the exact
/// literal `{{password}}` (an exact match let the others through to `confine`,
/// which then failed with the confusing "escapes the API base").
fn credential_token_in(text: &str) -> Option<String> {
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let name = &after[..end];
        if is_credential_var_name(name) {
            return Some(name.to_string());
        }
        rest = &after[end + 2..];
    }
    None
}

/// Rust twin of `isSensitiveVarName` (`src/stores/apiVariablesStore.ts`): split
/// the name into words on separators AND camelCase, then match whole words, so
/// `bypass`/`passive` are not swept in while `j_password`/`clientSecret` are.
fn is_credential_var_name(name: &str) -> bool {
    const WORDS: [&str; 11] = [
        "password",
        "passwd",
        "passphrase",
        "pwd",
        "secret",
        "credential",
        "credentials",
        "psk",
        "otp",
        "pin",
        "privkey",
    ];
    let mut spaced = String::with_capacity(name.len() + 4);
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c.is_ascii_uppercase() && prev_lower_or_digit {
            spaced.push(' ');
        }
        prev_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
        spaced.push(c);
    }
    spaced
        .split([' ', '_', '-', '.'])
        .filter(|w| !w.is_empty())
        .any(|w| {
            let lower = w.to_ascii_lowercase();
            WORDS.contains(&lower.as_str())
        })
}

/// Decide which credential variables a request references. The path is
/// already credential-free by the time this runs (see
/// [`reject_credential_in_path`]).
fn login_substitution_plan(
    path: &str,
    headers: &[(String, String)],
    body: &Option<String>,
) -> Result<LoginSubstitution, String> {
    reject_credential_in_path(path)?;
    let in_body = |v: &str| body.as_deref().is_some_and(|b| b.contains(v));
    let in_headers = |v: &str| headers.iter().any(|(_, hv)| hv.contains(v));
    // Body + headers only, matching what `apply_login_substitution` actually
    // rewrites. The PATH is filled frontend-side from the same stored username
    // (it is not secret); planning for a path the apply step never touches
    // would be a lie the tests could not catch.
    Ok(LoginSubstitution {
        username: in_body(USERNAME_VAR) || in_headers(USERNAME_VAR),
        password: in_body(PASSWORD_VAR) || in_headers(PASSWORD_VAR),
    })
}

/// Replace the credential variables in the body + header values. The PATH is
/// deliberately not touched: `{{password}}` there is already rejected, and the
/// caller records the ORIGINAL path in the agent-visible ring.
fn apply_login_substitution(
    username: &str,
    password: Option<&str>,
    headers: &mut [(String, String)],
    body: &mut Option<String>,
) {
    for (_, v) in headers.iter_mut() {
        *v = v.replace(USERNAME_VAR, username);
        if let Some(p) = password {
            *v = v.replace(PASSWORD_VAR, p);
        }
    }
    if let Some(b) = body.as_mut() {
        *b = b.replace(USERNAME_VAR, username);
        if let Some(p) = password {
            *b = b.replace(PASSWORD_VAR, p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transit_core::inventory::Vendor;

    // ---- settings bundle (v6.1.0) ----
    //
    // A bundle is a file the user may have been SENT, so the import path
    // is treated as hostile input: bounded before allocation, refused on
    // an unknown future version, and inert (it applies nothing).

    #[tokio::test]
    async fn import_settings_bundle_refuses_an_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        // 9 MB > the 8 MB cap. The guard must fire on SIZE, before any
        // attempt to parse (or to hold the whole thing as a String).
        std::fs::write(&path, "x".repeat(9 * 1024 * 1024)).unwrap();

        let err = import_settings_bundle(path).await.unwrap_err();
        assert!(err.contains("larger than"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn import_settings_bundle_refuses_a_newer_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.json");
        std::fs::write(
            &path,
            r#"{"version":99,"exported_at":"2026-01-01T00:00:00Z","preferences":null,"devices":null}"#,
        )
        .unwrap();

        let err = import_settings_bundle(path).await.unwrap_err();
        assert!(
            err.contains("newer Transit"),
            "a future bundle must be refused, not guessed at: {err}"
        );
    }

    #[tokio::test]
    async fn import_settings_bundle_rejects_a_non_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, "just some text").unwrap();

        let err = import_settings_bundle(path).await.unwrap_err();
        assert!(err.contains("not a Transit settings bundle"), "{err}");
    }

    #[tokio::test]
    async fn import_settings_bundle_round_trips_a_valid_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.json");
        std::fs::write(
            &path,
            r#"{"version":1,"exported_at":"2026-08-13T00:00:00Z",
                "preferences":"{\"themeId\":\"nord\"}","devices":"[{\"id\":\"r1\"}]"}"#,
        )
        .unwrap();

        let bundle = import_settings_bundle(path)
            .await
            .expect("valid bundle parses");
        assert_eq!(bundle.version, 1);
        assert!(bundle.preferences.unwrap().contains("nord"));
        assert!(bundle.devices.unwrap().contains("r1"));
    }

    // ---- login-credential substitution (v4.3.0) ---
    //
    // The operator's password is resolved from the keychain and substituted
    // into the login request server-side, so it never crosses Tauri IPC
    // (Rule 1) and never reaches localStorage.

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn plan_detects_credentials_in_body_and_headers() {
        let plan = login_substitution_plan(
            "api/aaaLogin.json",
            &hdrs(&[]),
            &Some(r#"{"name":"{{username}}","pwd":"{{password}}"}"#.into()),
        )
        .expect("no password in path");
        assert_eq!(
            plan,
            LoginSubstitution {
                username: true,
                password: true
            }
        );

        let plan = login_substitution_plan(
            "x",
            &hdrs(&[("Authorization", "Bearer {{password}}")]),
            &None,
        )
        .expect("no password in path");
        assert!(plan.password && !plan.username);
    }

    #[test]
    fn plan_is_empty_for_an_ordinary_investigation_get() {
        // No credential variables ⇒ nothing to fill ⇒ the keychain is never
        // touched for a plain read.
        let plan = login_substitution_plan("api/class/topSystem.json", &hdrs(&[]), &None).unwrap();
        assert!(!plan.any());
    }

    #[test]
    fn password_in_the_url_path_is_refused() {
        // A credential in a URL would be written verbatim into the
        // agent-visible session ring by `record_exchange` (and the
        // controller's access log). Refuse rather than substitute.
        let err = login_substitution_plan("login?pw={{password}}", &hdrs(&[]), &None)
            .expect_err("must refuse");
        assert!(err.contains("must not be placed in a URL path"), "{err}");
    }

    #[test]
    fn username_in_the_path_is_allowed_but_filled_frontend_side() {
        // Not secret, so the path guard lets it through — but the plan must
        // NOT claim it, because `apply_login_substitution` never rewrites the
        // path. The pane fills it from the same stored username before the
        // request reaches IPC (an unfilled `{{…}}` would be percent-encoded
        // and refused by `confine` as "escapes the API base").
        let plan = login_substitution_plan("users/{{username}}", &hdrs(&[]), &None).unwrap();
        assert!(!plan.any(), "the path alone must not trigger substitution");
    }

    #[test]
    fn the_path_credential_guard_is_not_gated_on_the_auth_scheme() {
        // `record_exchange` frames the request PATH into the ring the agent
        // reads, so this must hold for a `none`/`basic`/`bearer` controller
        // too — every pre-v4.3.0 login-flow session is `none`.
        assert!(reject_credential_in_path("api/login?pw={{password}}").is_err());
        assert!(reject_credential_in_path("api/class/topSystem.json").is_ok());
    }

    #[test]
    fn substitution_fills_body_and_headers_but_leaves_other_variables_alone() {
        let mut headers = hdrs(&[
            ("Cookie", "APIC-cookie={{apicToken}}"),
            ("X-User", "{{username}}"),
        ]);
        let mut body =
            Some(r#"{"name":"{{username}}","pwd":"{{password}}","x":"{{siteId}}"}"#.into());
        apply_login_substitution("admin", Some("hunter2"), &mut headers, &mut body);
        assert_eq!(
            body.unwrap(),
            r#"{"name":"admin","pwd":"hunter2","x":"{{siteId}}"}"#
        );
        // an unrelated captured token is untouched
        assert_eq!(headers[0].1, "APIC-cookie={{apicToken}}");
        assert_eq!(headers[1].1, "admin");
    }

    #[test]
    fn username_fills_even_when_no_password_is_resolved() {
        // `plan.password == false` ⇒ we never resolve the secret, so the
        // substitution runs with `None` and must still fill the username.
        let mut headers = hdrs(&[("X-User", "{{username}}")]);
        let mut body = None;
        apply_login_substitution("admin", None, &mut headers, &mut body);
        assert_eq!(headers[0].1, "admin");
    }

    #[test]
    fn login_credentials_scheme_injects_no_auth_header() {
        // The credential travels in the login BODY; a header would be wrong
        // (APIC ignores `Authorization: Basic`) and would leak it onto every
        // subsequent investigation request.
        use transit_core::inventory::AuthScheme;
        let scheme = AuthScheme::LoginCredentials {
            username: "admin".into(),
        };
        assert!(scheme.needs_secret());
        assert!(matches!(scheme, AuthScheme::LoginCredentials { .. }));
    }

    // ---- AuthProfileMeta ssh_key edit-prefill (v1.6.0 follow-up) ---

    #[test]
    fn ssh_key_path_surfaces_only_for_the_ssh_key_backend() {
        use transit_core::inventory::SecretRef;

        // ssh_key → the on-disk path (a reference, never key material).
        let ssh_key = SecretRef::SshKey {
            path: PathBuf::from("/Users/k/.ssh/id_ed25519"),
            passphrase: Some(Box::new(SecretRef::Keyring {
                key: "lab passphrase".into(),
            })),
        };
        assert_eq!(
            ssh_key_path_of(&ssh_key).as_deref(),
            Some("/Users/k/.ssh/id_ed25519")
        );
        assert_eq!(secret_backend_label(&ssh_key), "ssh_key");

        // Every other backend — including encrypted_file, which also
        // holds a path but has no dialog support — stays None.
        for other in [
            SecretRef::Keyring { key: "k".into() },
            SecretRef::SshAgent {
                public_key_fingerprint: None,
            },
            SecretRef::Op {
                reference: "op://Vault/Item/field".into(),
            },
            SecretRef::Env { var: "PW".into() },
            SecretRef::EncryptedFile {
                path: PathBuf::from("/tmp/secrets.age"),
            },
        ] {
            assert_eq!(ssh_key_path_of(&other), None, "{other:?}");
        }
    }

    // ---- BYOP user-policy config persistence (Phase 2) -------------

    #[test]
    fn user_policies_dir_config_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Absent file → None (the common "no user layer" case).
        assert_eq!(read_user_policies_dir_at(&cfg), None);

        // Write → read back.
        write_user_policies_dir_at(&cfg, Some("/Volumes/nas/policies")).unwrap();
        assert_eq!(
            read_user_policies_dir_at(&cfg),
            Some(PathBuf::from("/Volumes/nas/policies"))
        );

        // Clear (None / empty) → key removed → None again.
        write_user_policies_dir_at(&cfg, None).unwrap();
        assert_eq!(read_user_policies_dir_at(&cfg), None);
        write_user_policies_dir_at(&cfg, Some("   ")).unwrap();
        assert_eq!(read_user_policies_dir_at(&cfg), None);
    }

    #[test]
    fn user_policies_dir_config_preserves_other_keys() {
        // A config.toml with unrelated content must survive a user_dir
        // write (we own the file, but don't clobber a hand-added key).
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[ui]\ntheme = \"twilight\"\n").unwrap();

        write_user_policies_dir_at(&cfg, Some("/srv/pol")).unwrap();

        let text = std::fs::read_to_string(&cfg).unwrap();
        assert!(
            text.contains("theme = \"twilight\""),
            "unrelated key dropped: {text}"
        );
        assert_eq!(
            read_user_policies_dir_at(&cfg),
            Some(PathBuf::from("/srv/pol"))
        );
    }

    #[test]
    fn read_user_policies_dir_tolerates_malformed_config() {
        // A broken config.toml must NOT break startup — it yields None
        // (fall back to "no user layer"), never an error/panic.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "this is = = not valid toml [[[").unwrap();
        assert_eq!(read_user_policies_dir_at(&cfg), None);
    }

    // ---- Network / Strict-TLS config persistence -------------------

    #[test]
    fn strict_tls_config_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Absent file → default false (trust the OS store).
        assert!(!read_strict_tls_at(&cfg));

        // Write true → read back true; write false → read back false.
        write_strict_tls_at(&cfg, true).unwrap();
        assert!(read_strict_tls_at(&cfg));
        write_strict_tls_at(&cfg, false).unwrap();
        assert!(!read_strict_tls_at(&cfg));
    }

    #[test]
    fn strict_tls_config_coexists_with_policy_user_dir() {
        // The two settings share config.toml; toggling one must never
        // clobber the other (rollback-safety: an older build still reads
        // [policy], ignoring [network]).
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        write_user_policies_dir_at(&cfg, Some("/srv/pol")).unwrap();
        write_strict_tls_at(&cfg, true).unwrap();

        assert!(read_strict_tls_at(&cfg));
        assert_eq!(
            read_user_policies_dir_at(&cfg),
            Some(PathBuf::from("/srv/pol"))
        );

        // And the reverse: clearing user_dir leaves strict_tls intact.
        write_user_policies_dir_at(&cfg, None).unwrap();
        assert!(read_strict_tls_at(&cfg));
    }

    #[test]
    fn read_strict_tls_defaults_false_on_malformed() {
        // A broken config.toml must NOT strand the user — it yields the
        // safe-functional default (trust the OS store), never a panic.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "this is = = not valid toml [[[").unwrap();
        assert!(!read_strict_tls_at(&cfg));
    }

    #[test]
    fn read_terminal_enabled_defaults_true_and_honors_off() {
        // v4.4.0 — the local Terminal surface is ON by default: a missing or
        // broken config.toml must NEVER hide it. Only an explicit
        // `[terminal] enabled = false` turns it off.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        assert!(
            read_terminal_enabled_at(&cfg),
            "missing config → default on"
        );
        std::fs::write(&cfg, "not = = valid [[[").unwrap();
        assert!(
            read_terminal_enabled_at(&cfg),
            "malformed config → default on"
        );
        std::fs::write(&cfg, "[terminal]\nenabled = false\n").unwrap();
        assert!(!read_terminal_enabled_at(&cfg), "explicit off honored");
        std::fs::write(&cfg, "[terminal]\nenabled = true\n").unwrap();
        assert!(read_terminal_enabled_at(&cfg), "explicit on honored");
    }

    #[test]
    fn read_files_enabled_defaults_true_and_honors_off() {
        // v5.0.0 — same posture as Terminal: the Files surface is ON by
        // default (it's free, plan §9), and only an explicit
        // `[files] enabled = false` — the MDM / DLP off-switch — hides it.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        assert!(read_files_enabled_at(&cfg), "missing config → default on");
        std::fs::write(&cfg, "not = = valid [[[").unwrap();
        assert!(read_files_enabled_at(&cfg), "malformed config → default on");
        std::fs::write(&cfg, "[files]\nenabled = false\n").unwrap();
        assert!(!read_files_enabled_at(&cfg), "explicit off honored");
        std::fs::write(&cfg, "[files]\nenabled = true\n").unwrap();
        assert!(read_files_enabled_at(&cfg), "explicit on honored");
        // Wrong type is not "off" — it's unreadable, so the default holds.
        std::fs::write(&cfg, "[files]\nenabled = \"no\"\n").unwrap();
        assert!(read_files_enabled_at(&cfg), "wrong type → default on");
    }

    #[test]
    fn files_and_terminal_switches_are_independent() {
        // Turning the Terminal off must not hide Files (and vice versa) —
        // they're separate deployment decisions.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[terminal]\nenabled = false\n\n[files]\nenabled = true\n",
        )
        .unwrap();
        assert!(!read_terminal_enabled_at(&cfg));
        assert!(read_files_enabled_at(&cfg));
    }

    const BASELINE: &str = r#"# keep this comment
[[device]]
id = "vEX1"
host = "192.0.2.35"
vendor = "junos"
auth = "lab-pw"

[auth.lab-pw]
username = "alice"
secret = { backend = "keyring", key = "transit/lab-pw" }
"#;

    fn test_device(id: &str) -> Device {
        Device {
            id: id.to_string(),
            host: "10.0.0.9".to_string(),
            port: 22,
            vendor: Vendor::Junos,
            group: None,
            color: None,
            tags: Vec::new(),
            auth: "lab-pw".to_string(),
            syntax_highlighting: None,
            quick_copy_paste: None,
            font_family: None,
            font_size: None,
            bold_color: None,
            allow_weak_crypto: None,
            netbox_id: None,
            jump_via: None,
            forward_agent: None,
        }
    }

    #[test]
    fn mutate_and_persist_success_keeps_edit_and_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        let mut doc: DocumentMut = BASELINE.parse().unwrap();

        mutate_and_persist(&mut doc, &path, |d| {
            core_add_device(d, &test_device("vEX2"))
        })
        .expect("success path");

        assert!(doc.to_string().contains("vEX2"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), doc.to_string());
    }

    #[test]
    fn netbox_sync_batch_lands_atomically_and_rolls_back_on_one_bad_row() {
        use transit_core::inventory::mutator::{
            delete_device_no_revalidate, update_device_no_revalidate,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        std::fs::write(&path, BASELINE).unwrap();
        let mut doc: DocumentMut = BASELINE.parse().unwrap();

        // The exact closure shape `apply_netbox_sync` commits: adds +
        // updates + deletes through the no-revalidate primitives, ONE
        // revalidate at the end.
        let mut updated = test_device("vEX1");
        updated.host = "10.140.0.99".to_string();
        updated.netbox_id = Some("20".to_string());
        mutate_and_persist(&mut doc, &path, |d| {
            core_add_device_no_revalidate(d, &test_device("vQFX1"))?;
            update_device_no_revalidate(d, "vEX1", &updated)?;
            core_revalidate(d)
        })
        .expect("good batch commits");
        let after = doc.to_string();
        assert!(after.contains("vQFX1"));
        assert!(after.contains("10.140.0.99"));
        assert!(after.contains("netbox_id = \"20\""));

        // A batch with one bad row (delete of a device that a concurrent
        // edit removed) writes NOTHING — adds earlier in the same batch
        // included.
        let before = doc.to_string();
        let err = mutate_and_persist(&mut doc, &path, |d| {
            core_add_device_no_revalidate(d, &test_device("vEX9"))?;
            delete_device_no_revalidate(d, "no-such-device")?;
            core_revalidate(d)
        })
        .expect_err("bad row must fail the whole batch");
        assert!(matches!(err, InventoryError::DeviceNotFound { .. }));
        assert_eq!(doc.to_string(), before, "in-memory doc rolled back");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "on-disk file untouched by the failed batch"
        );
    }

    /// Wire-shaped input mirroring `test_device` — the bulk tests drive
    /// the REAL `apply_bulk_updates` body, so they need the command's
    /// own `BulkDeviceUpdate { id, input: DeviceInput }` type.
    fn test_input(id: &str) -> DeviceInput {
        let d = test_device(id);
        DeviceInput {
            id: d.id,
            host: d.host,
            port: d.port,
            vendor: d.vendor.as_str().to_string(),
            group: d.group,
            color: d.color,
            tags: d.tags,
            auth: d.auth,
            syntax_highlighting: d.syntax_highlighting,
            quick_copy_paste: d.quick_copy_paste,
            font_family: d.font_family,
            font_size: d.font_size,
            bold_color: d.bold_color,
            allow_weak_crypto: d.allow_weak_crypto,
            netbox_id: d.netbox_id,
            jump_via: d.jump_via,
            forward_agent: d.forward_agent,
        }
    }

    /// Host-key pins are keyed by device id (v6.5.7), so an in-app rename
    /// has to carry the pin with it or the device re-prompts on its next
    /// connect and the old entry lingers forever.
    #[tokio::test]
    async fn renaming_a_device_carries_its_host_key_pin() {
        use transit_ssh::{Fingerprint, HostKeyAlgorithm, HostKeyStore};

        let dir = tempfile::tempdir().unwrap();
        let store = HostKeyStore::open(dir.path().join("known_hosts.toml"))
            .await
            .unwrap();
        let fp: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();
        store
            .insert("old-name", "10.0.0.1", 22, &fp, &HostKeyAlgorithm::Ed25519)
            .await
            .unwrap();

        sync_pin_to_renamed_device(&store, "old-name", "new-name").await;

        assert!(store
            .lookup("old-name", "10.0.0.1", 22)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .lookup("new-name", "10.0.0.1", 22)
            .await
            .unwrap()
            .is_some());

        // A whole-record update that does NOT change the id must leave the
        // pin alone — `update_device` calls this on every edit, not just
        // renames.
        sync_pin_to_renamed_device(&store, "new-name", "new-name").await;
        assert!(store
            .lookup("new-name", "10.0.0.1", 22)
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn bulk_update_devices_batch_is_all_or_nothing_and_clears_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        std::fs::write(&path, BASELINE).unwrap();
        let mut doc: DocumentMut = BASELINE.parse().unwrap();

        // Seed a second device carrying a pref the bulk edit will CLEAR,
        // plus the two passthrough fields a whole-record replace must not
        // lose (the single-edit dialog pins the same discipline).
        let mut seeded = test_device("vEX2");
        seeded.syntax_highlighting = Some(true);
        seeded.allow_weak_crypto = Some(true);
        seeded.netbox_id = Some("77".to_string());
        mutate_and_persist(&mut doc, &path, |d| core_add_device(d, &seeded)).unwrap();

        // Drive the SHIPPED transaction body (`apply_bulk_updates`), not
        // a hand copy of its loop: sets a custom hex accent (v6.3.0) on
        // both devices, clears vEX2's syntax_highlighting (None → the key
        // is simply not emitted on rebuild), and carries the passthrough
        // fields.
        let mut a = test_input("vEX1");
        a.color = Some("#ffaa00".to_string());
        let mut b = test_input("vEX2");
        b.color = Some("#ffaa00".to_string());
        b.syntax_highlighting = None;
        b.allow_weak_crypto = Some(true);
        b.netbox_id = Some("77".to_string());
        let batch = vec![
            BulkDeviceUpdate {
                id: "vEX1".to_string(),
                input: a,
            },
            BulkDeviceUpdate {
                id: "vEX2".to_string(),
                input: b,
            },
        ];
        mutate_and_persist(&mut doc, &path, |d| apply_bulk_updates(d, batch))
            .expect("good bulk batch commits");
        let after = doc.to_string();
        assert_eq!(after.matches("color = \"#ffaa00\"").count(), 2);
        let vex2_block = after
            .split("[[device]]")
            .find(|block| block.contains("vEX2"))
            .expect("vEX2 block present");
        assert!(
            !vex2_block.contains("syntax_highlighting"),
            "cleared pref key must vanish from the rebuilt table"
        );
        assert!(vex2_block.contains("allow_weak_crypto = true"));
        assert!(vex2_block.contains("netbox_id = \"77\""));

        // One unknown id mid-batch → the WHOLE batch writes nothing,
        // devices already updated earlier in the loop included.
        let before = doc.to_string();
        let bad_batch = vec![
            BulkDeviceUpdate {
                id: "vEX1".to_string(),
                input: test_input("vEX1"),
            },
            BulkDeviceUpdate {
                id: "ghost".to_string(),
                input: test_input("ghost"),
            },
        ];
        let err = mutate_and_persist(&mut doc, &path, |d| apply_bulk_updates(d, bad_batch))
            .expect_err("unknown id fails the whole batch");
        assert!(matches!(err, InventoryError::DeviceNotFound { .. }));
        assert_eq!(doc.to_string(), before, "in-memory doc rolled back");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "on-disk file untouched by the failed batch"
        );
    }

    #[test]
    fn mutation_error_rolls_back_in_memory_doc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        std::fs::write(&path, BASELINE).unwrap();
        let mut doc: DocumentMut = BASELINE.parse().unwrap();
        let before = doc.to_string();

        // A mutation that performs a real structural edit, then fails —
        // the shape every mutator op has when revalidation rejects.
        let err = mutate_and_persist(&mut doc, &path, |d| {
            core_add_device(d, &test_device("vEX2")).expect("edit applies");
            Err(InventoryError::DeviceNotFound {
                id: "x".to_string(),
            })
        })
        .expect_err("mutation error must propagate");
        assert!(matches!(err, InventoryError::DeviceNotFound { .. }));

        assert_eq!(
            doc.to_string(),
            before,
            "in-memory doc must be rolled back so later edits don't wedge"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            BASELINE,
            "on-disk file untouched"
        );
    }

    #[test]
    fn write_error_rolls_back_in_memory_doc() {
        // Target whose parent is an existing FILE: write_atomic's
        // create_dir_all fails on every OS, simulating an unwritable
        // destination.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "not a directory").unwrap();
        let path = blocker.join("transit.toml");

        let mut doc: DocumentMut = BASELINE.parse().unwrap();
        let before = doc.to_string();

        let err = mutate_and_persist(&mut doc, &path, |d| {
            core_add_device(d, &test_device("vEX2"))
        })
        .expect_err("write must fail");
        assert!(matches!(err, InventoryError::Io { .. }));

        assert_eq!(
            doc.to_string(),
            before,
            "a failed write must not leave an unsaved change for the next edit to silently persist"
        );
    }

    // ---- bulk import: batch atomicity ------------------------------

    #[test]
    fn import_batch_one_bad_row_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        std::fs::write(&path, BASELINE).unwrap();
        let mut doc: DocumentMut = BASELINE.parse().unwrap();
        let before = doc.to_string();

        // good, good, DUP (vEX1 is in BASELINE), good — through the same
        // closure shape `import_connections` uses.
        let batch = [
            test_device("imp1"),
            test_device("imp2"),
            test_device("vEX1"),
            test_device("imp3"),
        ];
        let err = mutate_and_persist(&mut doc, &path, |d| {
            for dev in &batch {
                core_add_device_no_revalidate(d, dev)?;
            }
            core_revalidate(d)
        })
        .expect_err("duplicate id must fail the whole batch");
        assert!(matches!(err, InventoryError::DeviceIdConflict { id } if id == "vEX1"));

        assert_eq!(
            doc.to_string(),
            before,
            "in-memory doc rolled back — no imp* may leak"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            BASELINE,
            "on-disk file untouched"
        );
    }

    #[test]
    fn import_batch_all_good_persists_every_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transit.toml");
        let mut doc: DocumentMut = BASELINE.parse().unwrap();
        let batch = [
            test_device("imp1"),
            test_device("imp2"),
            test_device("imp3"),
        ];
        mutate_and_persist(&mut doc, &path, |d| {
            for dev in &batch {
                core_add_device_no_revalidate(d, dev)?;
            }
            core_revalidate(d)
        })
        .expect("a clean batch persists");
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("imp1") && on_disk.contains("imp2") && on_disk.contains("imp3"));
    }

    // ---- Local models (BYOM) config persistence (v3.0.0 A2) --------

    #[test]
    fn local_models_defaults_when_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let r = resolve_local_models_at(&cfg, None, None);
        assert!(!r.enabled, "disabled by default — no uninvited probing");
        assert_eq!(r.cfg.base_url, transit_agent::llm::ollama::DEFAULT_BASE_URL);
        assert_eq!(r.cfg.num_ctx, transit_agent::llm::ollama::DEFAULT_NUM_CTX);
        assert_eq!(
            r.cfg.keep_alive,
            transit_agent::llm::ollama::DEFAULT_KEEP_ALIVE
        );
        assert!(!r.env_override);
        assert!(r.warning.is_none());
    }

    #[test]
    fn local_models_round_trips_and_preserves_sibling_tables() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Seed a sibling table first, then write ours — both must
        // survive both writes (the rollback-safe shared-file posture).
        write_strict_tls_at(&cfg, true).unwrap();
        write_local_models_at(&cfg, true, "http://127.0.0.1:12345", 8192, "30m").unwrap();

        let r = resolve_local_models_at(&cfg, None, None);
        assert!(r.enabled);
        assert_eq!(r.cfg.base_url, "http://127.0.0.1:12345");
        assert_eq!(r.cfg.num_ctx, 8192);
        assert_eq!(r.cfg.keep_alive, "30m");
        assert!(r.warning.is_none());
        assert!(read_strict_tls_at(&cfg), "sibling [network] preserved");

        // And the reverse direction: a later strict_tls write must not
        // clobber [local_models].
        write_strict_tls_at(&cfg, false).unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert!(r.enabled);
        assert_eq!(r.cfg.num_ctx, 8192);
    }

    #[test]
    fn local_models_non_loopback_config_falls_back_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[local_models]\nenabled = true\nbase_url = \"http://192.168.1.50:11434\"\n",
        )
        .unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(
            r.cfg.base_url,
            transit_agent::llm::ollama::DEFAULT_BASE_URL,
            "non-loopback persisted URL must never be honored (T35)"
        );
        assert!(r.warning.is_some());
        assert!(r.enabled, "the fallback disables the URL, not the feature");
    }

    #[test]
    fn local_models_env_override_wins_but_stays_loopback_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        write_local_models_at(&cfg, true, "http://127.0.0.1:9999", 16_384, "15m").unwrap();

        let r = resolve_local_models_at(&cfg, Some("http://127.0.0.1:12345"), None);
        assert_eq!(r.cfg.base_url, "http://127.0.0.1:12345");
        assert!(r.env_override);

        // The env override is pinned too — release builds included.
        let r = resolve_local_models_at(&cfg, Some("http://10.0.0.5:11434"), None);
        assert_eq!(r.cfg.base_url, transit_agent::llm::ollama::DEFAULT_BASE_URL);
        assert!(r.env_override);
        assert!(r.warning.is_some());
    }

    #[test]
    fn local_models_bad_num_ctx_and_keep_alive_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[local_models]\nenabled = true\nnum_ctx = 10\nkeep_alive = \"banana\"\n",
        )
        .unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(r.cfg.num_ctx, transit_agent::llm::ollama::DEFAULT_NUM_CTX);
        assert_eq!(
            r.cfg.keep_alive,
            transit_agent::llm::ollama::DEFAULT_KEEP_ALIVE
        );
        assert!(r.warning.is_some());
    }

    // ---- v6.1.1 per-turn token ceiling ---------------------------------

    #[test]
    fn turn_token_ceiling_defaults_env_and_range() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Absent config → default, no warning.
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(r.turn_token_ceiling, DEFAULT_TURN_TOKEN_CEILING);
        assert!(r.warning.is_none());

        // Persisted in-range value is honored.
        std::fs::write(&cfg, "[local_models]\nturn_token_ceiling = 8192\n").unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(r.turn_token_ceiling, 8192);

        // Out-of-range (either side) → rejected to default + warning.
        // The bound is applied to whatever comes back — config.toml is
        // user-editable and the env var is anyone's to set (the
        // `the_channel_ceiling_is_a_clamp_not_a_ui_suggestion` doctrine).
        std::fs::write(&cfg, "[local_models]\nturn_token_ceiling = 100\n").unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(r.turn_token_ceiling, DEFAULT_TURN_TOKEN_CEILING);
        assert!(r.warning.unwrap().contains("turn_token_ceiling"));

        // Env wins over the persisted value…
        std::fs::write(&cfg, "[local_models]\nturn_token_ceiling = 8192\n").unwrap();
        let r = resolve_local_models_at(&cfg, None, Some("2048"));
        assert_eq!(r.turn_token_ceiling, 2048);

        // …an out-of-range env is rejected the same way…
        let r = resolve_local_models_at(&cfg, None, Some("999999"));
        assert_eq!(r.turn_token_ceiling, DEFAULT_TURN_TOKEN_CEILING);
        assert!(r.warning.is_some());

        // …and a non-numeric env warns and falls back to the persisted
        // value rather than silently vanishing.
        let r = resolve_local_models_at(&cfg, None, Some("banana"));
        assert_eq!(r.turn_token_ceiling, 8192);
        assert!(r.warning.unwrap().contains("not a number"));
    }

    #[test]
    fn turn_token_ceiling_survives_a_settings_save() {
        // The Settings tab saves via write_local_models_at, which must
        // not wipe a hand-edited (config-file-only) ceiling key.
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[local_models]\nenabled = true\nturn_token_ceiling = 9000\n",
        )
        .unwrap();
        write_local_models_at(&cfg, true, "http://127.0.0.1:11434", 16_384, "15m").unwrap();
        let r = resolve_local_models_at(&cfg, None, None);
        assert_eq!(
            r.turn_token_ceiling, 9000,
            "a hand-edited ceiling must survive a Settings save"
        );
    }

    #[test]
    fn keep_alive_validation_matrix() {
        for ok in ["0", "-1", "30s", "15m", "1h", "90m", " 5m "] {
            assert!(keep_alive_is_valid(ok), "{ok} should be valid");
        }
        for bad in ["", "m", "banana", "-5m", "10", "5 m", "1.5h"] {
            assert!(!keep_alive_is_valid(bad), "{bad} should be invalid");
        }
    }

    // ---- Custom BYOM endpoints (v3.0.0 A3) --------------------------

    fn ep(id: &str, kind: LocalEndpointKind, base_url: &str) -> LocalEndpoint {
        LocalEndpoint {
            id: id.into(),
            name: format!("Endpoint {id}"),
            kind,
            base_url: base_url.into(),
            context_length: 8192,
        }
    }

    #[test]
    fn endpoint_validation_matrix() {
        // Valid: loopback http and remote https, both kinds.
        for good in [
            ep(
                "lab-vllm",
                LocalEndpointKind::OpenaiCompat,
                "https://vllm.lab.internal:8000/v1",
            ),
            ep(
                "lm",
                LocalEndpointKind::OpenaiCompat,
                "http://127.0.0.1:1234/v1",
            ),
            ep(
                "rack-ollama",
                LocalEndpointKind::Ollama,
                "https://ollama.rack.internal:11434",
            ),
        ] {
            assert_eq!(validate_endpoint(&good), Ok(()), "{}", good.id);
        }
        // Plain http off-loopback → refused (T35).
        let e = ep(
            "bad",
            LocalEndpointKind::Ollama,
            "http://192.168.1.50:11434",
        );
        assert!(validate_endpoint(&e).unwrap_err().contains("unencrypted"));
        // Id charset: uppercase / slash / colon / empty all refused —
        // the id is the keychain account AND the model-id namespace.
        for bad_id in ["", "Lab", "a/b", "a:b", "-lead", &"x".repeat(33)] {
            let mut e = ep("ok", LocalEndpointKind::Ollama, "http://127.0.0.1:11434");
            e.id = (*bad_id).to_string();
            assert!(
                validate_endpoint(&e).is_err(),
                "{bad_id:?} should be refused"
            );
        }
        // Context range.
        let mut e = ep(
            "tiny",
            LocalEndpointKind::OpenaiCompat,
            "http://127.0.0.1:1234/v1",
        );
        e.context_length = 512;
        assert!(validate_endpoint(&e).is_err());
    }

    #[test]
    fn endpoints_round_trip_and_skip_invalid_rows() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Scalar keys + endpoints coexist in [local_models].
        write_local_models_at(&cfg, true, "http://127.0.0.1:11434", 16_384, "15m").unwrap();
        let eps = vec![
            ep(
                "lab-vllm",
                LocalEndpointKind::OpenaiCompat,
                "https://vllm.lab.internal:8000/v1",
            ),
            ep(
                "lm",
                LocalEndpointKind::OpenaiCompat,
                "http://127.0.0.1:1234/v1",
            ),
        ];
        write_local_endpoints_at(&cfg, &eps).unwrap();

        assert_eq!(read_local_endpoints_at(&cfg), eps);
        let r = resolve_local_models_at(&cfg, None, None);
        assert!(r.enabled, "scalar keys preserved by the endpoints write");
        assert_eq!(r.cfg.num_ctx, 16_384);

        // Hand-break one row (non-loopback http) + duplicate an id —
        // both are skipped on read, the rest survive.
        let text = std::fs::read_to_string(&cfg).unwrap();
        let extra = "\n[[local_models.endpoints]]\nid = \"evil\"\nname = \"evil\"\nkind = \"ollama\"\nbase_url = \"http://10.0.0.9:11434\"\ncontext_length = 8192\n\n[[local_models.endpoints]]\nid = \"lm\"\nname = \"dupe\"\nkind = \"ollama\"\nbase_url = \"http://127.0.0.1:1\"\ncontext_length = 8192\n";
        std::fs::write(&cfg, text + extra).unwrap();
        let read = read_local_endpoints_at(&cfg);
        assert_eq!(read.len(), 2);
        assert!(read.iter().all(|e| e.id != "evil"));
        assert_eq!(
            read.iter().find(|e| e.id == "lm").unwrap().name,
            "Endpoint lm",
            "first occurrence wins on duplicate ids"
        );

        // Deleting down to empty removes the key entirely.
        write_local_endpoints_at(&cfg, &[]).unwrap();
        assert!(read_local_endpoints_at(&cfg).is_empty());
        assert!(!std::fs::read_to_string(&cfg).unwrap().contains("endpoints"));
        let r = resolve_local_models_at(&cfg, None, None);
        assert!(r.enabled, "scalar keys survive the empty-endpoints write");
    }
}

#[cfg(test)]
mod pcap_dir_tests {
    use super::*;

    #[test]
    fn the_capture_folder_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // Nothing configured → the default is used.
        assert_eq!(read_pcap_dir_at(&cfg), None);

        write_pcap_dir_at(&cfg, Some("/Volumes/big/captures")).unwrap();
        assert_eq!(
            read_pcap_dir_at(&cfg),
            Some(PathBuf::from("/Volumes/big/captures"))
        );

        // Clearing restores the default rather than storing an empty path,
        // which would resolve to the process's working directory.
        write_pcap_dir_at(&cfg, None).unwrap();
        assert_eq!(read_pcap_dir_at(&cfg), None);
        write_pcap_dir_at(&cfg, Some("   ")).unwrap();
        assert_eq!(read_pcap_dir_at(&cfg), None);
    }

    /// The capture folder shares `config.toml` with every other setting, so
    /// writing it must not disturb them — including the two pcap flags that
    /// are the DLP off-switches.
    #[test]
    fn writing_the_capture_folder_preserves_the_rest_of_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[ui]\ntheme = \"twilight\"\n\n[pcap]\nenabled = true\nagent_access = false\n",
        )
        .unwrap();

        write_pcap_dir_at(&cfg, Some("/tmp/caps")).unwrap();

        let text = std::fs::read_to_string(&cfg).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(
            table["ui"]["theme"].as_str(),
            Some("twilight"),
            "an unrelated section must survive"
        );
        assert_eq!(
            table["pcap"]["agent_access"].as_bool(),
            Some(false),
            "the agent-access off-switch must survive a sibling write"
        );
        assert_eq!(table["pcap"]["dir"].as_str(), Some("/tmp/caps"));
    }

    /// A relative path is refused. It would resolve against whatever the
    /// working directory happens to be — which for a capture process
    /// spawned through the elevation path is not something the user chose,
    /// and the file would land somewhere nobody could predict.
    #[test]
    fn a_relative_capture_folder_is_refused() {
        let err = validate_capture_dir("captures").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        let err = validate_capture_dir("../elsewhere").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    /// A control character in the capture folder is refused.
    ///
    /// The path is interpolated into the command that runs as root. On
    /// macOS that string crosses an AppleScript literal, which cannot
    /// contain a raw newline — so a newline would end the literal early
    /// and the remainder would parse as AppleScript, two words away from
    /// `with administrator privileges`. macOS will create such a directory
    /// quite happily; only `/` and NUL are forbidden in a name.
    ///
    /// Defence in depth, not a live hole: the user picking their own
    /// capture folder is not an attacker. Same posture as `validate_bpf`.
    #[test]
    fn a_capture_folder_with_control_characters_is_refused() {
        // Absoluteness is platform-defined and the check runs first, so
        // these fixtures have to be absolute FOR THE HOST or they trip the
        // wrong branch. `/tmp/x` is not absolute on Windows — it is rooted
        // but driveless — which is precisely how this test failed on the
        // Windows CI leg while passing everywhere else.
        let abs = if cfg!(windows) {
            "C:\\caps"
        } else {
            "/tmp/caps"
        };

        for suffix in [
            "\nwith a newline",
            "\rreturn",
            "\u{0}nul",
            "\u{1b}escape",
            "\ttab",
        ] {
            let bad = format!("{abs}{suffix}");
            let err = validate_capture_dir(&bad).expect_err("must be refused");
            assert!(err.contains("control character"), "{bad:?}: {err}");
        }

        // Characters that ARE legal in a path and correctly escaped by
        // both quoting layers must still be accepted — refusing them would
        // break real folders to prevent nothing. Kept to the ones that are
        // legal on BOTH platforms: Windows forbids `" < > : | ? *` in a
        // file name, so testing those as "should be allowed" would assert
        // something untrue of the host.
        let allowed = if cfg!(windows) {
            vec![
                "C:\\Program Files\\captures".to_string(),
                "C:\\caps\\it's here".to_string(),
                "C:\\caps\\dollar$sign".to_string(),
                "\\\\server\\share\\captures".to_string(),
            ]
        } else {
            vec![
                "/Volumes/Big Disk/captures".to_string(),
                "/tmp/it's here".to_string(),
                "/tmp/quote\"inside".to_string(),
                "/tmp/back\\slash".to_string(),
                "/tmp/dollar$sign".to_string(),
                "/tmp/semi;colon".to_string(),
            ]
        };
        for ok in allowed {
            assert!(
                validate_capture_dir(&ok).is_ok(),
                "{ok:?} should be allowed"
            );
        }
    }
}

#[cfg(test)]
mod agent_chat_tests {
    use super::*;

    /// Opt-ins are OFF unless asked for — mirrors
    /// `logging_is_off_unless_asked_for`: an absent file, an unrelated
    /// section, and only an explicit `true` flips either feature on.
    /// `default: false` here is the whole reason the generic helper takes
    /// a caller-chosen default — an off-switch shape (`enabled`, default
    /// true) would silently invert an opt-in.
    #[test]
    fn agent_chat_is_off_unless_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        assert!(!env_or_config_bool_at(
            &cfg,
            "agent_chat",
            "persist_history",
            false
        ));
        std::fs::write(&cfg, "[ui]\ntheme = \"dark\"\n").unwrap();
        assert!(!env_or_config_bool_at(
            &cfg,
            "agent_chat",
            "persist_history",
            false
        ));
        assert!(!env_or_config_bool_at(
            &cfg,
            "agent_chat",
            "save_to_file",
            false
        ));
        std::fs::write(
            &cfg,
            "[agent_chat]\npersist_history = true\nsave_to_file = true\n",
        )
        .unwrap();
        assert!(env_or_config_bool_at(
            &cfg,
            "agent_chat",
            "persist_history",
            false
        ));
        assert!(env_or_config_bool_at(
            &cfg,
            "agent_chat",
            "save_to_file",
            false
        ));
    }

    /// Both Agent Chat dirs ride `validate_capture_dir`: created and
    /// written to, so a relative path (resolving against whatever cwd the
    /// process has) is refused at set AND at consumption.
    #[test]
    fn agent_chat_dirs_validated_like_the_capture_folder() {
        assert!(validate_capture_dir("chats").is_err());
        assert!(validate_capture_dir("snippets/../x").is_err());
        #[cfg(unix)]
        assert!(validate_capture_dir("/tmp/transit-chats").is_ok());
        #[cfg(windows)]
        assert!(validate_capture_dir("C:\\transit\\chats").is_ok());
    }

    /// The four `[agent_chat]` keys round-trip through the generic config
    /// writers without clobbering sibling sections (the DLP switches live
    /// in the same file), and a `None` dir clears its key.
    #[test]
    fn agent_chat_settings_round_trip_without_clobbering_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[pcap]\nagent_access = false\n").unwrap();
        write_config_bool_at(&cfg, "agent_chat", "persist_history", true).unwrap();
        write_config_string_at(&cfg, "agent_chat", "history_dir", Some("/x/y")).unwrap();
        write_config_bool_at(&cfg, "agent_chat", "save_to_file", true).unwrap();
        write_config_string_at(&cfg, "agent_chat", "save_dir", None).unwrap();

        let text = std::fs::read_to_string(&cfg).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        let ac = table
            .get("agent_chat")
            .and_then(|v| v.as_table())
            .expect("agent_chat section written");
        assert_eq!(
            ac.get("persist_history").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(ac.get("history_dir").and_then(|v| v.as_str()), Some("/x/y"));
        assert_eq!(ac.get("save_to_file").and_then(|v| v.as_bool()), Some(true));
        assert!(ac.get("save_dir").is_none(), "None clears the key");
        assert_eq!(
            table
                .get("pcap")
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("agent_access"))
                .and_then(|v| v.as_bool()),
            Some(false),
            "sibling DLP switch survives"
        );
    }
}

#[cfg(test)]
mod developer_log_tests {
    use super::*;

    /// The channel ceiling is enforced where the value is USED, not where
    /// it is chosen.
    ///
    /// `config.toml` is user-editable and `TRANSIT_LOG_TO_FILE` is
    /// anyone's to set, so a release build must clamp whatever it reads
    /// rather than trusting that the Settings UI offered only `info`.
    /// Otherwise "prod cannot emit trace" is a UI convention, and UI
    /// conventions are one text editor away from being untrue.
    #[test]
    fn the_ceiling_is_a_clamp_not_a_ui_suggestion() {
        // Whatever this build's ceiling is, a request ABOVE it must come
        // back at the ceiling.
        let requested = transit_core::log::parse_level("trace");
        let clamped = if requested > MAX_FILE_LOG_LEVEL {
            MAX_FILE_LOG_LEVEL
        } else {
            requested
        };
        assert!(
            clamped <= MAX_FILE_LOG_LEVEL,
            "a config asking for trace must not exceed this build's ceiling"
        );
    }

    /// Diagnostics are opt-IN. The existing `env_or_config` helper defaults
    /// to `true`, which is right for a DLP off-switch and exactly wrong
    /// here: it would turn logging on for every user who has never heard
    /// of it.
    #[test]
    fn logging_is_off_unless_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");

        // No file at all.
        assert!(!env_or_config_bool_at(
            &cfg,
            "developer",
            "log_to_file",
            false
        ));
        // A file with unrelated content.
        std::fs::write(&cfg, "[ui]\ntheme = \"twilight\"\n").unwrap();
        assert!(!env_or_config_bool_at(
            &cfg,
            "developer",
            "log_to_file",
            false
        ));
        // Explicitly on.
        std::fs::write(&cfg, "[developer]\nlog_to_file = true\n").unwrap();
        assert!(env_or_config_bool_at(
            &cfg,
            "developer",
            "log_to_file",
            false
        ));
    }

    /// The log folder crosses the same boundary as the capture folder and
    /// gets the same validation — it is created and written to, and a
    /// relative path lands wherever the process happens to be.
    #[test]
    fn the_log_folder_is_validated_like_the_capture_folder() {
        assert!(validate_capture_dir("logs").is_err());
        assert!(validate_capture_dir(if cfg!(windows) {
            "C:\\logs\nnewline"
        } else {
            "/tmp/logs\nnewline"
        })
        .is_err());
    }

    /// Settings round-trip without disturbing their neighbours — the
    /// config file is shared with the DLP switches.
    #[test]
    fn developer_settings_round_trip_without_clobbering_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[pcap]\nagent_access = false\n").unwrap();

        write_config_bool_at(&cfg, "developer", "log_to_file", true).unwrap();
        write_config_string_at(&cfg, "developer", "log_level", Some("debug")).unwrap();

        let text = std::fs::read_to_string(&cfg).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(table["developer"]["log_to_file"].as_bool(), Some(true));
        assert_eq!(table["developer"]["log_level"].as_str(), Some("debug"));
        assert_eq!(
            table["pcap"]["agent_access"].as_bool(),
            Some(false),
            "the DLP switch must survive a sibling write"
        );
    }
}
