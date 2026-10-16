use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Deserializer};

/// Default SSH port used when a `[[device]]` omits the `port` field.
const DEFAULT_SSH_PORT: u16 = 22;

fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}

/// Top-level shape of `transit.toml`.
///
/// Uses `BTreeMap` for `auth_profiles` so iteration order is stable
/// across runs (better for snapshot tests + deterministic UI).
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct InventoryFile {
    /// `[[device]]` array entries.
    #[serde(rename = "device", default)]
    pub devices: Vec<Device>,

    /// `[auth.<name>]` table entries.
    #[serde(rename = "auth", default)]
    pub auth_profiles: BTreeMap<String, AuthProfile>,

    /// Registry of known group paths (slash-separated, e.g.
    /// `"Lab/Empty"`). Unioned with the paths implied by each device's
    /// `group` field when the frontend builds the sidebar tree — this
    /// is what lets a group exist with NO devices (created empty, or
    /// its last device moved out). Devices still own their own group
    /// via [`Device::group`]; this only adds groups that would
    /// otherwise vanish. `#[serde(default)]` keeps every pre-existing
    /// file loading (the key is absent in older inventories, and the
    /// struct is `deny_unknown_fields`, which rejects unknown keys, not
    /// missing-with-default ones).
    #[serde(rename = "groups", default)]
    pub groups: Vec<String>,

    /// `[[api_session]]` array entries (v4.0.0 — UniFi & other REST
    /// controllers for API-based investigation). `#[serde(default)]` so
    /// every pre-v4 inventory still loads (the key is simply absent).
    #[serde(rename = "api_session", default)]
    pub api_sessions: Vec<ApiSession>,
}

/// One device the user has registered for SSH-based investigation.
///
/// `auth` is a key into [`InventoryFile::auth_profiles`]; the loader
/// validates that the reference resolves before returning the file.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Stable, human-readable id. Unique within the file.
    pub id: String,

    /// Hostname or IP address.
    pub host: String,

    /// SSH port. Defaults to 22 if omitted.
    #[serde(default = "default_ssh_port")]
    pub port: u16,

    /// Network OS family (drives policy lookup at command-execution time).
    pub vendor: Vendor,

    /// Optional folder path (e.g. `"Prod/Routers"`). Sub-groups are
    /// separated by `/`. Absent = "ungrouped" (renders at tree root).
    /// The frontend builds a nested tree by splitting on `/`; empty
    /// groups don't exist in the tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Optional per-device accent color, referenced as a curated palette
    /// token (e.g. `"red"`, `"blue"`). The frontend renders it as a
    /// left-edge accent on the sidebar row, session tab, and terminal
    /// pane — a visual "am I on prod?" safeguard. Stored as a free string
    /// (the picker constrains input); an unrecognized or absent token
    /// renders with no accent, so adding palette colors later never
    /// breaks an existing `transit.toml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,

    /// Free-form organizational tags (e.g. `["prod", "core", "pci"]`),
    /// orthogonal to the `group` folder hierarchy — a device lives in one
    /// group but can carry many tags. Absent/empty = untagged; the frontend
    /// filters the sidebar by tag. `skip_serializing_if` keeps untagged
    /// devices clean in TOML.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Reference to an entry in [`InventoryFile::auth_profiles`].
    pub auth: String,

    /// Per-device terminal preferences. Optional; the frontend's
    /// `TerminalPane` reads these from `DeviceMeta` and applies them
    /// when the device is connected. Absent fields fall back to safe
    /// defaults — see the field comments.
    ///
    /// Modeled per-device (not as a global UI preference) because
    /// SecureCRT's session-config model is the user expectation:
    /// some devices want syntax highlighting, others want plain
    /// black/white, and the choice should travel with the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax_highlighting: Option<bool>,

    /// Per-device quick copy/paste. When `Some(true)` the
    /// `TerminalPane` enables three SecureCRT-style behaviors at
    /// once: auto-copy on text selection, middle-click paste, and
    /// right-click paste. Multi-line pastes still gate on the
    /// confirmation dialog regardless of which trigger started them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quick_copy_paste: Option<bool>,

    /// Per-device terminal font family override (v4.1.0). A CSS
    /// font-family list, same shape as the global Settings font. `None`
    /// = use the global terminal font. The frontend's picker constrains
    /// input and always appends the default stack as a fallback, so an
    /// uninstalled (but CSS-valid) family degrades gracefully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_family: Option<String>,

    /// Per-device terminal font size in CSS pixels (v4.1.0). `None` =
    /// use the global terminal font size. The frontend clamps to the same
    /// 8–32 range as the global control on read, so a hand-edited
    /// out-of-range value can't produce an unusable pane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_size: Option<u16>,

    /// Per-device "bold" accent (v4.1.0). When `Some(true)` the frontend
    /// renders the `color` token as a louder background tint on the
    /// session tab (and pane) instead of only the thin left edge — a
    /// stronger "am I on prod?" signal for operators who found the edge
    /// accent too subtle. `None`/`Some(false)` keeps the subtle edge.
    /// No effect unless `color` is also set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bold_color: Option<bool>,

    /// Per-device weak-crypto opt-in.
    ///
    /// When `Some(true)` the SSH transport negotiates with
    /// `transit_ssh::ciphers::legacy_client_config` upfront —
    /// SHA1 KEX/MAC, CBC ciphers, and ssh-rsa host-key signatures
    /// are accepted. The strict floor is bypassed for this device
    /// only; every other device still requires modern crypto.
    ///
    /// `None` or `Some(false)` keeps the strict default. If the
    /// strict handshake fails with `SshError::CipherUnsupported`,
    /// the connect flow surfaces the `WeakCryptoConfirmDialog`;
    /// approving in the dialog flips this field to `Some(true)`
    /// via the inventory mutator so future connects skip the
    /// prompt.
    ///
    /// Cisco IOS-XE (vIOS, CSR1000v) and older Junos ship with
    /// SHA1-only KEX defaults; this field is the per-device
    /// escape hatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_weak_crypto: Option<bool>,

    /// Stable id in an external inventory source this device was imported
    /// or last synced from (v6.2.0 — currently NetBox's device id). The
    /// re-sync match key: a NetBox pull diffs against this, never against
    /// host/name (both legitimately change in a CMDB). Absent for
    /// hand-added and file-imported devices; existing `transit.toml`s
    /// round-trip unchanged. A `String` although NetBox's PK is an
    /// integer today — NetBox has floated UUID PKs for years, and the
    /// field is opaque to Transit (equality only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netbox_id: Option<String>,

    /// Jump host: the `id` of ANOTHER device in this file to tunnel
    /// through (v6.5.0 — OpenSSH `ProxyJump` semantics, SecureCRT's
    /// "Firewall"). The connect flow establishes the referenced device's
    /// connection first (its own auth profile, host-key pin, and
    /// weak-crypto opt-in), then reaches this device over a
    /// `direct-tcpip` channel — the jump box forwards ciphertext and is
    /// never trusted with this device's credentials or host-key verdict.
    /// Chains (a jump's jump) are allowed to depth 4. The loader
    /// enforces that the reference resolves, is not this device itself,
    /// and forms no cycle; deleting or renaming a device that others
    /// jump through is refused with the referent list. Distinct from the
    /// import layer's `jump_host` (a raw hostname from ssh_config /
    /// SecureCRT, resolved into this field best-effort at import).
    /// Threat model: T52 (T_JUMP_HOST).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_via: Option<String>,

    /// Per-device SSH agent forwarding opt-in (v6.5.0).
    ///
    /// When `Some(true)`, the PTY session requests
    /// `auth-agent-req@openssh.com` before the shell starts, and the
    /// transport accepts the server's `auth-agent@openssh.com` channels,
    /// pumping them to the LOCAL primary agent (`$SSH_AUTH_SOCK` /
    /// the OpenSSH named pipe). While connected, root on this device
    /// can sign with every key the local agent holds — that is the
    /// protocol's blast radius, which is why this is per-device,
    /// default-off, and gated behind an explicit dialog warning
    /// (agent-side per-use authorization, e.g. 1Password's, is the
    /// compensating control). `None`/`Some(false)`: inbound agent
    /// channels are rejected outright. Applies to connects made after
    /// the change; live sessions keep their connect-time behavior.
    /// Threat model: T53 (T_AGENT_FORWARD).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_agent: Option<bool>,
}

/// Network device vendor.
///
/// Built-in variants cover the vendors Transit ships a policy for.
/// `Custom(name)` (BYOP Phase 2b) carries a user-supplied vendor name
/// for a device gated by the user policy layer (`<name>.yaml`); it
/// gates exactly like a built-in once that policy is loaded, and
/// default-denies — like `Unknown` — when no policy is registered.
/// `Unknown` is the explicit "no/unrecognized vendor" sentinel
/// (`vendor = "unknown"`); historically ANY unrecognized string mapped
/// to `Unknown`, but unrecognized strings now map to `Custom` so a
/// user can supply a policy for them.
///
/// **Not `Copy`** — `Custom` holds an `Arc<str>`. Clones are cheap (an
/// Arc refcount bump), but call sites that consumed `Vendor` by value
/// via `Copy` now borrow (`&Vendor` / `vendor.as_str()`) or `.clone()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Vendor {
    Junos,
    CiscoIos,
    CiscoIosXe,
    /// Cisco IOS-XR — carrier-grade OS (ASR 9000 / NCS / CRS / XRv).
    /// Two-stage commit config model + XR-specific shell escapes
    /// (`run` / `bash` / `script` / `attach` / `admin`); see
    /// `policies/cisco_ios_xr.yaml`.
    CiscoIosXr,
    /// Cisco Nexus OS (data-center switches; Nexus 5k/7k/9k).
    /// Different command surface from IOS/IOS-XE — `feature` /
    /// `install` / `run bash` etc. live here.
    NxOs,
    AristaEos,
    /// Phase 8c — Palo Alto PAN-OS firewall. Distinct CLI surface
    /// from the Cisco family (`request restart system` vs `reload`,
    /// `debug software shell` shell escape, commit/save model for
    /// config). Gated like the other security/network vendors.
    PanOs,
    /// v6.1.0 — Ubiquiti UniFi device CLI (AP / switch / gateway),
    /// reached over SSH. Promoted from a BYOP sample once real gear
    /// confirmed the command surface.
    ///
    /// ⚠️ Its CLI is a **busybox shell**, not a vendor CLI, which makes
    /// it the first `gated` vendor whose safe surface is a judgement
    /// call rather than an enumerable command tree. That is deliberate
    /// and bounded: the allowlist is worth having (a bad command is
    /// refused before any human sees it), but the always-allow regex
    /// shortcut is **structurally refused** for this vendor exactly as
    /// it is for `Linux` and BYOP customs — see
    /// `agent_dispatch::refuse_always_allow` and threat-model T47.
    UniFi,
    /// Phase 8b — generic Linux/Unix server. Carries an UNRESTRICTED
    /// policy (`policies/linux.yaml` mode: unrestricted): the gate
    /// always allows, the per-command modal stays mandatory, and the
    /// always-allow regex shortcut is structurally refused. See
    /// `docs/security/threat-model.md` T_UNRESTRICTED_VENDOR for the
    /// carve-out rationale.
    Linux,
    /// The local OS shell (v4.4.0 Terminal surface). HUMAN-ONLY: the
    /// agent is structurally blind to local shells (never composed into
    /// the agent's unified session sources), so this variant never
    /// reaches the policy gate in practice. It ships with NO
    /// `local_shell.yaml`, so if it ever *were* routed to the gate it
    /// default-denies ("no policy registered") — it must NEVER inherit
    /// `Linux`'s unrestricted carve-out, which was written for a
    /// reimageable remote box, not the user's own filesystem. See
    /// the local terminal surface design notes (not included in this repository) + threat-model T42.
    LocalShell,
    /// BYOP Phase 2b — a user-defined vendor. The string is the policy
    /// file stem (`<name>.yaml`) and the inventory `vendor = "<name>"`
    /// tag. Never holds a built-in tag or `unknown` — those resolve to
    /// their own variants in [`Vendor::from_tag`].
    Custom(Arc<str>),
    Unknown,
}

impl Vendor {
    /// Stable string tag for serialization and display. Borrows `self`
    /// (it was by-value `Copy` before `Custom` joined). Built-ins return
    /// a `'static` literal; `Custom` borrows its `Arc<str>`.
    pub fn as_str(&self) -> &str {
        match self {
            Vendor::Junos => "junos",
            Vendor::CiscoIos => "cisco_ios",
            Vendor::CiscoIosXe => "cisco_ios_xe",
            Vendor::CiscoIosXr => "cisco_ios_xr",
            Vendor::NxOs => "nxos",
            Vendor::AristaEos => "arista_eos",
            Vendor::PanOs => "pan_os",
            Vendor::UniFi => "unifi",
            Vendor::Linux => "linux",
            Vendor::LocalShell => "local_shell",
            Vendor::Custom(name) => name,
            Vendor::Unknown => "unknown",
        }
    }

    /// Classify an inventory / policy-stem tag into a `Vendor`. The
    /// single source of truth for string → `Vendor`: the hand-written
    /// [`Deserialize`], `commands::parse_vendor`, and the policy
    /// loader's `vendor_from_stem` all route through it. Built-in tags
    /// (plus the `cisco_nxos` alias) map to their variants; `unknown`
    /// maps to `Unknown`; every other non-empty string becomes `Custom`.
    pub fn from_tag(tag: &str) -> Vendor {
        match tag {
            "junos" => Vendor::Junos,
            "cisco_ios" => Vendor::CiscoIos,
            "cisco_ios_xe" => Vendor::CiscoIosXe,
            "cisco_ios_xr" => Vendor::CiscoIosXr,
            "nxos" | "cisco_nxos" => Vendor::NxOs,
            "arista_eos" => Vendor::AristaEos,
            "pan_os" => Vendor::PanOs,
            "unifi" => Vendor::UniFi,
            "linux" => Vendor::Linux,
            "local_shell" => Vendor::LocalShell,
            "unknown" => Vendor::Unknown,
            other => Vendor::Custom(Arc::from(other)),
        }
    }
}

impl<'de> Deserialize<'de> for Vendor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // The inventory tag is a plain string (`vendor = "junos"`).
        // `#[serde(other)]` only works on a unit variant, so the
        // built-in-or-`Custom` split is hand-rolled via `from_tag`.
        let tag = String::deserialize(deserializer)?;
        Ok(Vendor::from_tag(&tag))
    }
}

#[cfg(test)]
impl serde::Serialize for Vendor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Symmetric with `Deserialize`: emit the plain string tag so
        // round-trip tests (and TOML re-serialization) match the
        // `vendor = "<tag>"` shape.
        serializer.serialize_str(self.as_str())
    }
}

/// One credential profile referenced by [`Device::auth`].
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct AuthProfile {
    pub username: String,
    pub secret: SecretRef,
}

/// Which REST API surface an [`ApiSession`] addresses (v4.0.0).
/// Serializes as a snake_case string (`kind = "site_manager"`); maps 1:1
/// onto `transit_api::EndpointKind` at connect time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "snake_case")]
pub enum ApiEndpointKind {
    /// UniFi Site Manager cloud (`api.ui.com`); account-wide, no host.
    SiteManager,
    /// A local / self-hosted controller's Network Integration API; needs
    /// [`ApiSession::host`].
    NetworkLocal,
    /// The cloud connector-proxy to a specific console; needs
    /// [`ApiSession::console_id`].
    ConnectorProxy,
    /// A generic / custom REST controller (any vendor); needs
    /// [`ApiSession::base_url`]. Permits http (dev/local, UI-warned).
    Generic,
}

impl ApiEndpointKind {
    /// Stable snake_case tag, matching the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiEndpointKind::SiteManager => "site_manager",
            ApiEndpointKind::NetworkLocal => "network_local",
            ApiEndpointKind::ConnectorProxy => "connector_proxy",
            ApiEndpointKind::Generic => "generic",
        }
    }
}

/// How an [`ApiSession`] authenticates. Serializes as an internally-tagged
/// snake_case object (`auth = { scheme = "bearer" }`). The credential itself
/// is the session's [`SecretRef`] ([`ApiSession::secret`]), never inline; the
/// scheme only says HOW to present it (+ the non-secret username / header
/// name). Existing UniFi sessions (no `auth` field) default to the historic
/// `X-API-KEY` scheme, so they load unchanged.
// AuthScheme carries NO secret (only the scheme + non-secret header/username),
// so it serializes at runtime — the read-side `ApiSessionMeta` surfaces it to
// the frontend for edit-prefill. (The enclosing `ApiSession` stays
// Deserialize-only so its `SecretRef` can never be accidentally serialized.)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum AuthScheme {
    /// No auth header — a public API (e.g. swapi.dev). No secret.
    None,
    /// A key in a custom header (defaults to `X-API-KEY`, the UniFi shape).
    /// The key is the session's `secret`.
    ApiKey {
        #[serde(default = "default_api_key_header")]
        header: String,
        /// Non-secret text prepended verbatim to the secret in the header
        /// value — `"Token "` yields NetBox's `Authorization: Token <key>`
        /// (the same shape serves Splunk-style `Authorization: <Word> <key>`
        /// APIs generally). Empty by default, so every existing session —
        /// whose TOML carries no such key — keeps today's bare-key behavior
        /// byte-identically.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        value_prefix: String,
    },
    /// `Authorization: Bearer <token>`; the token is the session's `secret`.
    Bearer,
    /// `Authorization: Basic base64(username:password)`; the password is the
    /// session's `secret`, the username is stored here (not secret).
    Basic { username: String },
    /// The controller authenticates by a LOGIN REQUEST, not a header: the
    /// collection's "Log in first" POST carries the credentials in its body
    /// and captures a token from the response (APIC's `aaaLogin`, vManage's
    /// `j_security_check`, Apstra/Aruba/FortiManager). Injects NO header —
    /// instead `{{username}}`/`{{password}}` are substituted into the outgoing
    /// request body + header values from these stored credentials.
    ///
    /// Distinct from [`AuthScheme::Basic`] on purpose: picking "Basic" on an
    /// APIC controller used to send an `Authorization: Basic` header that APIC
    /// ignores while the login body's variables stayed empty, so the operator
    /// did the obviously-right thing and got a silent dead end. Keeping the two
    /// apart means "Basic" still means a Basic header for a generic REST API.
    LoginCredentials { username: String },
}

fn default_api_key_header() -> String {
    "X-API-KEY".to_string()
}

/// The default scheme for a session with no `auth` field — the historic
/// UniFi `X-API-KEY` behaviour, so pre-v4.1 inventories load unchanged.
fn default_auth_scheme() -> AuthScheme {
    AuthScheme::ApiKey {
        header: default_api_key_header(),
        value_prefix: String::new(),
    }
}

impl AuthScheme {
    /// Whether this scheme needs a [`SecretRef`] (all but `None`).
    pub fn needs_secret(&self) -> bool {
        !matches!(self, AuthScheme::None)
    }
}

/// One REST controller (UniFi first) registered for API-based
/// investigation — the HTTP analog of [`Device`]. Holds a display
/// id/name, the API surface + how to reach it, a reference to where the
/// API key lives, and optional grouping metadata. It carries NO username
/// (an API key needs none) and NO terminal prefs.
///
/// The API key is a [`SecretRef`] table (`secret = { backend = ... }`),
/// enrolled via `enroll_secret` — never a literal string (the loader's
/// inline-secret prescan rejects `api_key = "..."` / `secret = "..."`).
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct ApiSession {
    /// Stable, human-readable id. Unique among api_sessions.
    pub id: String,

    /// Display name shown in the APIs sidebar + tab.
    pub name: String,

    /// API vendor — selects the bundled request collection and the
    /// agent's read-path policy. UniFi is `Vendor::Custom("unifi")`.
    pub vendor: Vendor,

    /// Which API surface + how it is reached.
    pub kind: ApiEndpointKind,

    /// Host (`host` or `host:port`, no scheme) for `network_local`.
    /// Required iff `kind == NetworkLocal`; ignored for other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Console id for `connector_proxy`. Required iff
    /// `kind == ConnectorProxy`; ignored for other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_id: Option<String>,

    /// Full base URL (`https://…`, or `http://…` for local/dev) for the
    /// `generic` kind. Required iff `kind == Generic`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    /// Optional folder path (e.g. `"MSP/ClientA"`), like [`Device::group`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Optional accent-color token, like [`Device::color`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,

    /// Free-form organizational tags, like [`Device::tags`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// How this controller authenticates. Defaults to the historic UniFi
    /// `X-API-KEY` scheme so pre-v4.1 inventories load unchanged.
    #[serde(default = "default_auth_scheme")]
    pub auth: AuthScheme,

    /// Where the credential is fetched from (the API key / bearer token /
    /// basic password, per `auth`). NEVER the credential itself. Absent iff
    /// `auth = { scheme = "none" }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,

    /// User-pinned self-signed leaf-cert SHA-256 (lowercase hex, 64 chars),
    /// set via the untrusted-cert confirm dialog after the user verifies the
    /// fingerprint. When present, the API client trusts THIS host iff it
    /// presents exactly this leaf (§9 `PinAwareVerifier`); absent = OS-trust
    /// only. NOT a secret — a public cert fingerprint, so it serializes plainly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_cert_sha256: Option<String>,
}

/// Where a credential is fetched from. Never the credential itself.
///
/// The `backend` discriminant is the TOML field name; matches the
/// `secret = { backend = "..." }` shape in `transit.toml.example`.
///
/// `Hash` is derived so `SecretRegistry` can use a `SecretRef` as the
/// key type for its zeroizing TTL cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum SecretRef {
    /// OS keystore (macOS Keychain / Windows Credential Manager / Linux
    /// Secret Service), keyed by [`Self::Keyring::key`].
    Keyring { key: String },

    /// `SSH_AUTH_SOCK` agent — covers 1Password SSH Agent transparently.
    /// `public_key_fingerprint` optionally pins to a specific key when
    /// the agent serves multiple.
    SshAgent {
        #[serde(default)]
        public_key_fingerprint: Option<String>,
    },

    /// 1Password CLI: `op read op://Vault/Item/field`.
    Op { reference: String },

    /// Environment variable. Headless / CI use only; not recommended
    /// for interactive desktop installs.
    Env { var: String },

    /// SSH private key file at [`Self::SshKey::path`]. If the key has a
    /// passphrase, it is itself a [`SecretRef`] (so the passphrase
    /// rides on a stronger backend like `keyring` or `op`).
    SshKey {
        path: PathBuf,
        #[serde(default)]
        passphrase: Option<Box<SecretRef>>,
    },

    /// `age`-encrypted file unlocked by a startup passphrase. Last-
    /// resort fallback for minimal Linux installs without Secret
    /// Service.
    EncryptedFile { path: PathBuf },

    /// **Ask the human at connect time.** Nothing is stored: no keystore
    /// entry, no file, no `op` reference. The connect path prompts via
    /// SSH `keyboard-interactive` (RFC 4256) and the answers live only
    /// for the duration of the auth attempt.
    ///
    /// Deliberately has **no [`crate::inventory::types::SecretRef`]
    /// backend implementation**: `SecretBackend`s exist to *fetch a
    /// stored credential*, and there is nothing stored here. The SSH
    /// connect path branches on this variant before it ever consults
    /// `SecretRegistry`, which is what keeps `transit_auth` the sole
    /// holder of *stored* secrets. It is likewise inert to the value
    /// cache — there is no value to cache.
    ///
    /// Enrollment is a category error for this variant: there is nothing
    /// to enroll, so `enroll_secret` refuses it rather than silently
    /// succeeding. See the interactive keyboard auth design notes (not included in this repository)
    /// and threat-model T46.
    Prompt,
}

impl SecretRef {
    /// Stable, credential-free name for the auth METHOD this ref selects.
    ///
    /// For logging only, and deliberately carries nothing from the ref's
    /// payload — no keyring key, no `op://` reference, no key path. §10's
    /// rule is to log the fact of an operation rather than its value, and
    /// a backend name is the fact.
    pub fn method_name(&self) -> &'static str {
        match self {
            SecretRef::Keyring { .. } => "keyring",
            SecretRef::SshAgent { .. } => "ssh-agent",
            SecretRef::Op { .. } => "op",
            SecretRef::Env { .. } => "env",
            SecretRef::SshKey { .. } => "ssh-key",
            SecretRef::EncryptedFile { .. } => "encrypted-file",
            SecretRef::Prompt => "prompt",
        }
    }
}
