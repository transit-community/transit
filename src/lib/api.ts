import { invoke } from "@tauri-apps/api/core";

/**
 * Mirror of the Rust `DeviceMeta` struct in
 * `src-tauri/src/commands.rs`. Auth-bearing fields are intentionally
 * absent — see CLAUDE.md §"The Three Inviolable Rules". `auth` is the
 * profile *name* (a key into the auth_profiles map), never a credential.
 */
export interface DeviceMeta {
  id: string;
  host: string;
  port: number;
  vendor: string;
  group: string | null;
  /** Optional per-device accent color (curated palette token, e.g.
   *  "red"). `null` = no accent. Non-secret display metadata. */
  color: string | null;
  /** Free-form organizational tags (orthogonal to `group`). Non-secret. */
  tags: string[];
  auth: string;
  /**
   * Per-device terminal preference: enable keyword highlighting
   * for this connection only. `null` (or missing) = "not set",
   * which the `TerminalPane` treats as off.
   */
  syntax_highlighting: boolean | null;
  /**
   * Per-device quick copy/paste. When `true`, the `TerminalPane`
   * enables three SecureCRT-style behaviors: auto-copy on
   * selection, middle-click paste, and right-click paste.
   * Multi-line pastes still confirm via the modal.
   */
  quick_copy_paste: boolean | null;
  /** Per-device terminal font family override (v4.1.0). `null` = use
   *  the global terminal font. Non-secret display metadata. */
  font_family: string | null;
  /** Per-device terminal font size in CSS pixels (v4.1.0). `null` = use
   *  the global size; the pane clamps to 8–32 on read. */
  font_size: number | null;
  /** Per-device "bold accent" (v4.1.0). When `true`, the accent color
   *  renders as a louder background tint, not just the thin edge. */
  bold_color: boolean | null;
  /**
   * Per-device weak-crypto opt-in (Phase 6 T20). When `true`,
   * `Connection::connect` negotiates with the legacy cipher
   * allowlist (SHA1 KEX/MAC, CBC ciphers, ssh-rsa host-key
   * signatures) upfront — skipping the `WeakCryptoConfirmDialog`
   * for this device only. `null` (or missing) keeps the strict
   * default. Set by the dialog's "Remember for this device"
   * checkbox.
   */
  allow_weak_crypto: boolean | null;
  /** External-inventory match key (v6.2.0 — NetBox device id). `null` for
   *  hand-added/file-imported devices. Machine-managed by the NetBox sync;
   *  never form-edited. Non-secret. */
  netbox_id: string | null;
  /** Jump host (v6.5.0): the id of ANOTHER inventory device this one
   *  tunnels through (OpenSSH ProxyJump / SecureCRT "Firewall").
   *  `null` = direct connection. Non-secret topology metadata. */
  jump_via: string | null;
  /** Per-device SSH agent-forwarding opt-in (v6.5.0, T53). `null` (or
   *  missing) = off, the safe default. Non-secret. */
  forward_agent: boolean | null;
}

/**
 * Mirror of `AuthProfileMeta`. Holds the backend tag (keyring, ssh_agent,
 * op, env, ssh_key, encrypted_file) — never a secret-resolving reference
 * body (keyring key, op reference, fingerprint). The one exception is
 * `key_path`: the `ssh_key` backend's on-disk key-file path, a non-secret
 * filesystem reference (same Rule 1 footing as `ImportIdentityMeta.key_path`)
 * surfaced so edit mode can prefill it instead of forcing a re-Browse.
 */
export interface AuthProfileMeta {
  name: string;
  username: string;
  backend: string;
  /** Non-null only when `backend === "ssh_key"`. */
  key_path: string | null;
}

/** Wire-shape sent to `add_device` / `update_device`. */
export interface DeviceInput {
  id: string;
  host: string;
  port: number;
  vendor: string;
  group: string | null;
  /** Optional per-device accent color (curated palette token) or `null`.
   *  The form uses `""` for none and collapses it to `null` on the wire. */
  color: string | null;
  /** Free-form organizational tags. */
  tags: string[];
  auth: string;
  /**
   * Optional per-device toggle. Sent as `null` when the user leaves
   * the dialog's checkbox in the indeterminate "not set" state.
   * Backend serializes the field only when explicitly true/false.
   */
  syntax_highlighting: boolean | null;
  /** Per-device quick copy/paste. Same null-vs-bool semantics as
   *  `syntax_highlighting`. */
  quick_copy_paste: boolean | null;
  /** Per-device terminal font family override, or `null`. The form uses
   *  `""` for "use global" and collapses it to `null` on the wire.
   *  Optional (like `allow_weak_crypto`) so the import path can omit it. */
  font_family?: string | null;
  /** Per-device terminal font size, or `null`. The form uses `0` for
   *  "use global" and collapses it to `null`. */
  font_size?: number | null;
  /** Per-device "bold accent" toggle, or `null` when unset. */
  bold_color?: boolean | null;
  /**
   * Per-device weak-crypto opt-in (see `DeviceMeta.allow_weak_crypto`).
   * No dialog renders a control for it — the WeakCryptoConfirmDialog's
   * "remember" checkbox is the only writer — but the edit dialog MUST
   * round-trip the device's current value: `update_device` is a
   * whole-record replace, so omitting the field (Rust deserializes
   * `None` via `#[serde(default)]`) silently wipes a remembered
   * opt-in. Optional so add-device flows can leave it absent.
   */
  allow_weak_crypto?: boolean | null;
  /**
   * External-inventory match key (v6.2.0 — NetBox device id). Same
   * round-trip contract as `allow_weak_crypto`: no form edits it, the
   * NetBox sync is the only writer, and the edit dialog MUST pass the
   * current value through or a whole-record replace orphans the device
   * from every future sync diff. Optional so add/import flows omit it.
   */
  netbox_id?: string | null;
  /** Jump host reference (v6.5.0), or `null` for direct. The form uses
   *  `""` for "direct" and collapses it to `null` on the wire. Backend
   *  validates the reference (existence/cycles) — zod deliberately does
   *  not, so a hand-edited transit.toml stays saveable. Optional so the
   *  import path can omit it. */
  jump_via?: string | null;
  /** Per-device SSH agent-forwarding opt-in (v6.5.0). `null` when the
   *  checkbox is unset — the backend serializes only explicit values.
   *  Deliberately NOT bulk-editable (a security toggle wants per-device
   *  deliberation), so the bulk dialog passes it through verbatim. */
  forward_agent?: boolean | null;
}

/**
 * Wire-shape sent to `add_auth_profile` / `update_auth_profile`. The
 * `secret` field is a `SecretRef` discriminated union mirroring the
 * Rust enum.
 */
export interface AuthProfileInput {
  username: string;
  secret: SecretRefInput;
}

export type SecretRefInput =
  | { backend: "keyring"; key: string }
  | { backend: "ssh_agent"; public_key_fingerprint?: string | null }
  | { backend: "op"; reference: string }
  | { backend: "env"; var: string }
  | { backend: "ssh_key"; path: string; passphrase?: SecretRefInput | null }
  | { backend: "encrypted_file"; path: string }
  // v6.1.0 — nothing stored; the credential is typed at connect time.
  | { backend: "prompt" };

/** Which UniFi API surface an api_session addresses. Mirrors the Rust
 *  `ApiEndpointKind` (serde snake_case). */
export type ApiEndpointKind = "site_manager" | "network_local" | "connector_proxy" | "generic";

/** Mirror of Rust `AuthScheme` (internally-tagged on `scheme`). Carries no
 *  secret — the credential is a separate `SecretRef`. */
export type AuthSchemeWire =
  | { scheme: "none" }
  // `value_prefix` is non-secret text prepended to the key in the header
  // value ("Token " → NetBox's `Authorization: Token <key>`). Optional on
  // the wire: Rust omits it when empty (skip_serializing_if) and defaults
  // it to "" on receive (serde default).
  | { scheme: "api_key"; header: string; value_prefix?: string }
  | { scheme: "bearer" }
  | { scheme: "basic"; username: string }
  | { scheme: "login_credentials"; username: string };

/**
 * Mirror of `ApiSessionMeta` (src-tauri/src/commands.rs). Like DeviceMeta,
 * no secret VALUE crosses the boundary; like AuthProfileMeta, only the
 * secret `backend` kind is exposed — never the reference body (`SecretRef`
 * is deserialize-only across IPC). The edit dialog resends `secret: null`
 * to keep the existing reference.
 */
export interface ApiSessionMeta {
  id: string;
  name: string;
  vendor: string;
  kind: ApiEndpointKind;
  host: string | null;
  console_id: string | null;
  base_url: string | null;
  group: string | null;
  color: string | null;
  tags: string[];
  backend: string;
  auth: AuthSchemeWire;
}

/**
 * Wire-shape sent to `add_api_session` / `update_api_session`. `secret`
 * is a REFERENCE (never a value) and is OPTIONAL: required on create, but
 * `null`/omitted on update means "keep the existing reference" — the
 * frontend never receives a SecretRef back to resend.
 */
export interface ApiSessionInput {
  id: string;
  name: string;
  vendor: string;
  kind: ApiEndpointKind;
  host?: string | null;
  console_id?: string | null;
  base_url?: string | null;
  group?: string | null;
  color?: string | null;
  tags: string[];
  auth: AuthSchemeWire;
  secret?: SecretRefInput | null;
}

// ---------------------------------------------------------------------
// Read commands.
// ---------------------------------------------------------------------

export async function listDevices(): Promise<DeviceMeta[]> {
  return invoke<DeviceMeta[]>("list_devices");
}

export async function listAuthProfiles(): Promise<AuthProfileMeta[]> {
  return invoke<AuthProfileMeta[]>("list_auth_profiles");
}

/** v4.0.0 — registered API sessions (UniFi & other REST controllers). */
export async function listApiSessions(): Promise<ApiSessionMeta[]> {
  return invoke<ApiSessionMeta[]>("list_api_sessions");
}

// ---------------------------------------------------------------------
// Mutation commands. All return void on success; failure surfaces as a
// rejected promise carrying the backend error string.
// ---------------------------------------------------------------------

export async function addDevice(input: DeviceInput): Promise<void> {
  await invoke("add_device", { input });
}

export async function updateDevice(id: string, input: DeviceInput): Promise<void> {
  await invoke("update_device", { id, input });
}

/** One device's whole-record replacement inside a bulk edit (v6.3.0).
 *  `input` is COMPLETE, not a patch — the tri-state dialog resolves it
 *  against each device's current fields client-side, carrying
 *  `allow_weak_crypto` + `netbox_id` through per device (the backend's
 *  `update_device` swaps the whole record). Mirrors Rust
 *  `commands::BulkDeviceUpdate`. */
export interface BulkDeviceUpdate {
  id: string;
  input: DeviceInput;
}

/** v6.3.0 bulk edit: apply N whole-record device updates in ONE
 *  all-or-nothing transaction (single atomic write; a bad row rolls the
 *  whole batch back). Resolves to the updated-device count. */
export async function bulkUpdateDevices(updates: BulkDeviceUpdate[]): Promise<number> {
  return invoke<number>("bulk_update_devices", { updates });
}

export async function deleteDevice(id: string): Promise<void> {
  await invoke("delete_device", { id });
}

export async function addAuthProfile(name: string, input: AuthProfileInput): Promise<void> {
  await invoke("add_auth_profile", { name, input });
}

export async function updateAuthProfile(name: string, input: AuthProfileInput): Promise<void> {
  await invoke("update_auth_profile", { name, input });
}

export async function deleteAuthProfile(name: string): Promise<void> {
  await invoke("delete_auth_profile", { name });
}

export async function renameGroup(oldPath: string, newPath: string): Promise<void> {
  await invoke("rename_group", { oldPath, newPath });
}

/** Registered group paths (the `groups` registry). Unioned with the
 *  paths implied by device `group` fields so empty groups still render. */
export async function listGroups(): Promise<string[]> {
  return invoke<string[]>("list_groups");
}

/** Create an empty group at `path`. Idempotent on the backend (a no-op
 *  if the path is already registered or device-implied). */
export async function addGroup(path: string): Promise<void> {
  await invoke("add_group", { path });
}

/** Delete a group, reparenting its devices + subgroups up one level. */
export async function deleteGroup(path: string): Promise<void> {
  await invoke("delete_group", { path });
}

/** Move a single device into `group` (drag-and-drop target). `null`
 *  ungroups it. Surgical — leaves the device's other fields untouched. */
export async function setDeviceGroup(id: string, group: string | null): Promise<void> {
  await invoke("set_device_group", { id, group });
}

// ---------------------------------------------------------------------
// v4.0.0 — API session (UniFi controller) mutations.
// ---------------------------------------------------------------------

export async function addApiSession(input: ApiSessionInput): Promise<void> {
  await invoke("add_api_session", { input });
}

export async function updateApiSession(id: string, input: ApiSessionInput): Promise<void> {
  await invoke("update_api_session", { id, input });
}

export async function deleteApiSession(id: string): Promise<void> {
  await invoke("delete_api_session", { id });
}

/** Enroll (write-only) the API key for an api_session. Mirrors
 *  `enrollSecret` for auth profiles — the value never round-trips. */
export async function enrollApiSessionSecret(apiSessionId: string, value: string): Promise<void> {
  await invoke("enroll_api_session_secret", { apiSessionId, value });
}

/** Mirror of the Rust `ApiResponseWire`. `body` is RAW (the human's own
 *  controller data) — redaction is the agent boundary, not applied here. */
export interface ApiResponseWire {
  status: number;
  body: string;
  truncated: boolean;
  /** Response headers (name, value) in wire order, RAW like `body`. Human
   *  Postman view only — the agent's tool output never carries headers. */
  headers: [string, string][];
}

/**
 * Execute a HUMAN (Postman) request against an api_session's controller.
 * Any method (ungated). The host is pinned to the controller and the API
 * key is injected server-side; only method/path/headers/body cross IPC.
 */
export async function apiSendRequest(
  apiSessionId: string,
  method: string,
  path: string,
  headers: [string, string][],
  body: string | null,
): Promise<ApiResponseWire> {
  return invoke<ApiResponseWire>("api_send_request", {
    apiSessionId,
    method,
    path,
    headers,
    body,
  });
}

/**
 * Register a controller as an OPEN, agent-visible session (empty ring) when
 * its API tab opens — so the agent can see + investigate it without the
 * human sending a request first. Idempotent; safe to call on every mount.
 */
/**
 * Hand the backend the session auth header a login capture just produced, so
 * the AI agent's GETs can ride the session (v4.3.0). WRITE-ONLY — nothing
 * reads it back; the backend keeps it in memory for the controller's lifetime.
 *
 * Called at capture time rather than inferred from later traffic: the token
 * exists the instant "Log in first" returns, and the operator normally asks
 * the agent straight afterwards without sending an investigation request in
 * between.
 */
export async function apiSetSessionAuth(
  apiSessionId: string,
  header: string,
  value: string,
): Promise<void> {
  await invoke("api_set_session_auth", { apiSessionId, header, value });
}

export async function registerApiSession(
  apiSessionId: string,
  // #12 Phase 2b: `[name, path]` GET endpoints from the controller's
  // collection, so the agent's prompt lists known-good paths. GET-only.
  endpoints: [string, string][],
): Promise<void> {
  await invoke("register_api_session", { id: apiSessionId, endpoints });
}

/** The controller's full raw request/response history — the ring the agent
 *  reads — for the human session-history view (#12 Phase 2b). Raw: the human
 *  sees their own controller's data. Empty string if the controller isn't
 *  open. */
export async function apiSessionHistory(apiSessionId: string): Promise<string> {
  return invoke<string>("api_session_history", { id: apiSessionId });
}

/** The SHA-256 (hex) of the cert last rejected for this controller's host, or
 *  null — the fingerprint the untrusted-cert dialog shows for verification.
 *  Reading it grants no trust (v4.3.0, threat-model T40). */
export async function apiPendingCert(apiSessionId: string): Promise<string | null> {
  return invoke<string | null>("api_pending_cert", { id: apiSessionId });
}

/** Trust (pin) a self-signed controller's cert after the user has verified its
 *  fingerprint. Persists it and loads it into the live client so the next
 *  request connects. The ONLY path to trusting a self-signed host. */
export async function apiTrustCert(apiSessionId: string, sha256Hex: string): Promise<void> {
  await invoke("api_trust_cert", { id: apiSessionId, sha256Hex });
}

/** Deregister a controller's open session when its API tab closes (drops the
 *  agent-visible ring; leaves the controller in inventory). */
export async function closeApiSession(apiSessionId: string): Promise<void> {
  await invoke("close_api_session", { id: apiSessionId });
}

// ---------------------------------------------------------------------
// Bulk connection import (ssh_config / CSV / SecureCRT). Two-phase:
// `previewImport` is read-only (parse + dedup + collision report);
// `importConnections` commits the user-edited rows atomically. No secret
// crosses either call — profiles are created via the enrollment flow.
// ---------------------------------------------------------------------

/** Which external format `previewImport` parses. Matches the Rust
 *  `ImportSource` serde tags. */
export type ImportSource = "ssh_config" | "csv" | "secure_crt" | "mt_putty" | "moba_xterm";

/** A deduped login identity from a parsed export — mirror of the Rust
 *  `ImportIdentityMeta`. Carries no secret value (Rule 1). */
export interface ImportIdentityMeta {
  key: string;
  login: string;
  count: number;
  /** "public_key_file" | "agent" | "password" | "unknown". */
  auth_kind: string;
  /** Prefill hint for "create new profile":
   *  "ssh_key" | "ssh_agent" | "keyring". */
  suggested_backend: string;
  /** Key-file path when `suggested_backend === "ssh_key"` (already
   *  ~-expanded). A reference, never a secret. */
  key_path: string | null;
}

/** One proposed device row — mirror of the Rust `ImportPreviewRow`. */
export interface ImportPreviewRow {
  id: string;
  host: string;
  port: number;
  username: string | null;
  vendor: string;
  group: string | null;
  jump_host: string | null;
  /** Links the row to an `ImportIdentityMeta` for auth seeding. */
  identity_key: string;
  /** `id` already exists in the inventory — flagged, excluded by default. */
  collides: boolean;
}

/** Result of `previewImport`. Nothing is written. */
export interface ImportPreview {
  rows: ImportPreviewRow[];
  identities: ImportIdentityMeta[];
  warnings: string[];
}

/** Result of a successful `importConnections`. */
export interface ImportSummary {
  added: number;
}

/** Parse + analyze a user-picked export file and diff it against the
 *  current inventory. Read-only — nothing is written. */
export async function previewImport(source: ImportSource, path: string): Promise<ImportPreview> {
  return invoke<ImportPreview>("preview_import", { source, path });
}

/** Commit the user-resolved device rows in one all-or-nothing batch. Each
 *  device's `auth` must name a profile that already exists (created during
 *  the credential step). */
export async function importConnections(devices: DeviceInput[]): Promise<ImportSummary> {
  return invoke<ImportSummary>("import_connections", { devices });
}

// ---------------------------------------------------------------------
// NetBox inventory sync (v6.2.0) — wire mirrors of the Rust DTOs.
// ---------------------------------------------------------------------

/** One "New" row of the sync preview (a NetBox device Transit doesn't
 *  know yet, mapped to an importable proposal). */
export interface NetBoxCandidateWire {
  netbox_id: string;
  proposed_device_id: string;
  host: string;
  name: string;
  status: string;
  vendor_tag: string;
  group: string | null;
  tags: string[];
  /** Still collides with an existing device after in-batch dedup —
   *  starts excluded in the grid, exactly like `ImportPreviewRow`. */
  collides: boolean;
}

export interface NetBoxFieldChangeWire {
  /** "host" | "vendor" | "group". */
  field: string;
  current: string;
  incoming: string;
}

export interface NetBoxChangeWire {
  device_id: string;
  netbox_id: string;
  changes: NetBoxFieldChangeWire[];
}

export interface NetBoxStaleWire {
  device_id: string;
  netbox_id: string;
  host: string;
}

/** Result of `previewNetboxSync`. Read-only — nothing was written. */
export interface NetBoxSyncPreviewWire {
  new: NetBoxCandidateWire[];
  changed: NetBoxChangeWire[];
  stale: NetBoxStaleWire[];
  unchanged: number;
  skipped: string[];
  warnings: string[];
  fetched: number;
}

/** One accepted update: target device id + the FULL replacement record
 *  (built from the live `DeviceMeta` + accepted fields — whole-record
 *  replace, so every passthrough field must be carried). Unlinks ride
 *  this shape with `netbox_id: null`. */
export interface NetBoxUpdateDecision {
  id: string;
  input: DeviceInput;
}

export interface NetBoxApplyPayload {
  adds: DeviceInput[];
  updates: NetBoxUpdateDecision[];
  /** Opt-in Stale deletes — gated behind a destructive confirm in the UI. */
  deletes: string[];
}

export interface NetBoxSyncSummary {
  added: number;
  updated: number;
  deleted: number;
}

/** Page the NetBox device list through the session's confined endpoint and
 *  diff it against the current inventory. Read-only. */
export async function previewNetboxSync(
  apiSessionId: string,
  activeOnly: boolean,
): Promise<NetBoxSyncPreviewWire> {
  return invoke<NetBoxSyncPreviewWire>("preview_netbox_sync", { apiSessionId, activeOnly });
}

/** Commit the reviewed sync decisions in one all-or-nothing batch. */
export async function applyNetboxSync(payload: NetBoxApplyPayload): Promise<NetBoxSyncSummary> {
  return invoke<NetBoxSyncSummary>("apply_netbox_sync", { payload });
}

/** Result of {@link exportConnections}. `count` excludes the header row. */
export interface ExportConnectionsResult {
  bytes_written: number;
  path: string;
  count: number;
}

/**
 * Export every device to an import-compatible CSV at `destination` — the
 * reverse of {@link importConnections}. The file uses the exact header the
 * CSV importer reads (`name,host,port,username,vendor,group,key_path`), so
 * it re-imports cleanly.
 *
 * Rule 1: the CSV carries only references — usernames and key-file *paths*
 * — never a credential value (no password column; ssh_key passphrases are
 * never written). Caller picks `destination` via the dialog plugin's
 * `save`. Read-only w.r.t. the inventory.
 */
export async function exportConnections(destination: string): Promise<ExportConnectionsResult> {
  return invoke<ExportConnectionsResult>("export_connections", { destination });
}

/**
 * A Transit-to-Transit settings bundle (v6.1.0).
 *
 * Carries *references*, never credentials — the same boundary
 * `transit.toml` keeps. Host-key pins are deliberately excluded: copying
 * them would make one machine inherit trust another machine's human
 * established, and a bundle is a file someone might receive from a
 * colleague.
 */
export interface SettingsBundle {
  version: number;
  exported_at: string;
  /** The `transit.preferences` localStorage blob, verbatim. */
  preferences: string | null;
  /** `DeviceInput[]` as JSON. Carries each device's auth PROFILE NAME —
   *  which is why this isn't the import CSV: that format exists for
   *  migrating off another product, where identities are mapped by hand,
   *  and it does not round-trip a profile link. */
  devices: string | null;
}

/** Write a settings bundle to `destination`. */
export async function exportSettingsBundle(
  destination: string,
  preferences: string | null,
  devices: string | null,
): Promise<ExportConnectionsResult> {
  return invoke<ExportConnectionsResult>("export_settings_bundle", {
    destination,
    preferences,
    devices,
  });
}

/**
 * Read a settings bundle. Changes nothing on its own — the caller
 * previews it and decides what to apply, so opening a bad or hostile
 * file cannot alter state.
 */
export async function importSettingsBundle(path: string): Promise<SettingsBundle> {
  return invoke<SettingsBundle>("import_settings_bundle", { path });
}

/** Read-only verdict for an on-disk SSH key file — mirror of the Rust
 *  `KeyProbeVerdict` (`#[serde(tag = "status")]`). Carries no key bytes;
 *  `hint`/`detail` are contents-free. */
export type KeyProbeVerdict =
  | { status: "unencrypted" }
  | { status: "encrypted" }
  | { status: "unparseable"; hint: string }
  | { status: "unreadable"; detail: string };

/** One probed key file paired with its verdict — mirror of Rust `KeyProbe`. */
export interface KeyProbe {
  path: string;
  verdict: KeyProbeVerdict;
}

/**
 * Probe on-disk SSH key files referenced by an import (read-only): for
 * each path, classify it as unencrypted / encrypted / unparseable /
 * unreadable so the credential step can auto-create profiles for
 * unencrypted keys and prompt a passphrase only for encrypted ones.
 * Verdict-only — no key bytes cross IPC. Paths are deduped server-side.
 */
export async function probeSshKeys(paths: string[]): Promise<KeyProbe[]> {
  return invoke<KeyProbe[]>("probe_ssh_keys", { paths });
}

// ---------------------------------------------------------------------
// BYOP — user policy directory (Phase 2).
// ---------------------------------------------------------------------

/** Read-only view of the Bring Your Own Policy configuration. Field
 *  names are snake_case to match the Rust `PolicySettings` serde shape. */
export interface PolicySettings {
  /** The user-policy directory that will load on next launch (env or
   *  persisted config), or null for "no user layer". */
  user_dir: string | null;
  /** True when `$TRANSIT_USER_POLICIES` is set — the path is then
   *  env-controlled and the Settings field is read-only. */
  env_override: boolean;
  /** Vendor tags loaded this session (built-in + merged + custom). */
  vendors: string[];
  /** Non-fatal user-layer warnings from this session's load. */
  warnings: string[];
}

export async function getPolicySettings(): Promise<PolicySettings> {
  return invoke<PolicySettings>("get_policy_settings");
}

/** Persist (or clear, with null/empty) the user-policy directory.
 *  Takes effect on next launch — the policy engine is built at startup. */
export async function setUserPoliciesDir(dir: string | null): Promise<void> {
  await invoke("set_user_policies_dir", { dir });
}

// ---------------------------------------------------------------------
// Strict TLS — cloud trust anchors (threat-model T27).
// ---------------------------------------------------------------------

/** Network/TLS settings surfaced to the Settings → Network tab. */
export interface NetworkSettings {
  /** Effective Strict-TLS setting (env override or persisted). When ON,
   *  the cloud client trusts only the bundled public web-PKI roots and
   *  refuses a TLS-inspection proxy's CA; when OFF (default) it trusts the
   *  OS store, so a corporate inspection CA installed there is honored. */
  strict_tls: boolean;
  /** True when $TRANSIT_STRICT_TLS forces the value — the toggle is then
   *  read-only. */
  env_override: boolean;
}

export async function getNetworkSettings(): Promise<NetworkSettings> {
  return invoke<NetworkSettings>("get_network_settings");
}

/** Persist the Strict-TLS setting. Takes effect on next launch — the
 *  cloud client's trust config is built once at startup. */
export async function setStrictTls(enabled: boolean): Promise<void> {
  await invoke("set_strict_tls", { enabled });
}

// ---------------------------------------------------------------------
// v1.0.2 — Settings font picker.
// ---------------------------------------------------------------------

/** Installed monospace font FAMILY NAMES (sorted, deduped) from the
 *  OS font database. Candidates only — callers should filter to what
 *  the webview can actually render (`lib/fonts.ts`). */
export async function listMonospaceFonts(): Promise<string[]> {
  return invoke<string[]>("list_monospace_fonts");
}

// ---------------------------------------------------------------------
// Phase 2a — secret backends.
// ---------------------------------------------------------------------

/**
 * Per-backend startup-probe result. Frontend renders the install
 * hint inline under the backend select when the entry is
 * `NeedsInstall`.
 */
export type BackendAvailability =
  { status: "ready" } | { status: "needs_install"; hint: string } | { status: "unsupported" };

/** Snapshot of every backend's availability — `keyring`, `ssh_agent`, `op`, `env`. */
export async function secretBackendAvailability(): Promise<Record<string, BackendAvailability>> {
  return invoke<Record<string, BackendAvailability>>("secret_backend_availability");
}

export interface TestResolveOk {
  /** Length in bytes of the resolved value. NOT the value itself. */
  length: number;
}

/**
 * Test that the backend resolves the profile's reference. The IPC
 * **never returns the value** — only `{ length }`. Per Rule 1, this is
 * read-only and the length is the most we surface.
 */
export async function testSecretResolve(profileName: string): Promise<TestResolveOk> {
  return invoke<TestResolveOk>("test_secret_resolve", { profileName });
}

/**
 * THE secret-bearing IPC. The `value` parameter is the only IPC
 * argument in the entire app that carries credential bytes. The Rust
 * side wraps it in `SecretString` immediately on entry.
 */
export async function enrollSecret(profileName: string, value: string): Promise<void> {
  await invoke("enroll_secret", { profileName, value });
}

// ---------------------------------------------------------------------
// Phase 2b — SSH connect / disconnect / TOFU.
// ---------------------------------------------------------------------

export interface SessionMetaWire {
  session_id: string;
  host: string;
  port: number;
  username: string;
  /** RFC3339 timestamp. */
  opened_at: string;
}

/**
 * Payload of the `host-key:confirm` event.
 *
 * `previous_fingerprint` is set when the host's key CHANGED since
 * last connect — it carries the pinned fingerprint the server no
 * longer matches, and the dialog renders the loud changed-key
 * warning variant instead of the first-contact TOFU prompt.
 */
export interface HostKeyConfirmPayload {
  /** Inventory id of the device being connected to. Pins are scoped per
   *  device, so two sites can both be at 192.168.1.1 — the address
   *  alone no longer says what is being trusted. */
  device_id: string;
  host: string;
  port: number;
  fingerprint: string;
  algorithm: string;
  previous_fingerprint: string | null;
}

/**
 * Payload of the `weak-crypto:confirm` event.
 *
 * `kind` is the SSH negotiation slot that didn't converge against
 * Transit's strict allowlist — typically `"Kex"` (Cisco IOS-XE ships
 * with `diffie-hellman-group14-sha1` only) but can also be
 * `"Cipher"`, `"Mac"`, or `"Key"`.
 *
 * `offered` is the server's advertised list for `kind`. The dialog
 * renders it so the user knows which weak algorithms are being asked
 * for; a server offering ONLY ssh-rsa host-key signatures is a
 * different risk than one offering ssh-rsa alongside ed25519.
 */
export interface WeakCryptoConfirmPayload {
  host: string;
  port: number;
  device_id: string;
  kind: string;
  offered: string[];
}

/**
 * One prompt in an interactive-auth challenge (v6.1.0).
 *
 * ⚠️ `text` is written by the SERVER, not by Transit. It is sanitized
 * backend-side (printable ASCII, capped) but the UI must still present
 * it as quoted, host-attributed foreign text — a host that sends
 * "Enter your Anthropic API key:" is the attack. Threat-model T46.1.
 */
export interface KbiPromptWire {
  text: string;
  /** RFC 4256 echo flag — `false` means mask the field. */
  echo: boolean;
}

/** Payload of `auth:kbi:request`. The question only; never an answer. */
export interface KbiPromptPayload {
  host: string;
  port: number;
  username: string;
  /** Server-authored challenge name. Often empty. */
  name: string;
  /** Server-authored instruction block. Often empty. */
  instruction: string;
  /** TRANSIT-authored explanation; empty for a real server challenge.
   *  Must render OUTSIDE the "Message from the server" block — server
   *  text and Transit's own copy are never interchangeable (T46.1). */
  notice: string;
  prompts: KbiPromptWire[];
}

/** Payload of `pty:{session_id}:output` events. */
export interface PtyOutputPayload {
  session_id: string;
  /** Base64-no-pad encoded PTY output bytes. */
  data_b64: string;
}

/** Payload of `pty:{session_id}:closed` events. */
export interface PtyClosedPayload {
  session_id: string;
  reason: string;
}

/**
 * Open an SSH session to a device. Returns the session id.
 *
 * If the host key is unseen, the backend will emit a
 * `host-key:confirm` event during this call; the UI must subscribe
 * and reply via `verifyHostKey` for `connectDevice` to resolve.
 * Otherwise this call hangs until the connect timeout (30s).
 */
export async function connectDevice(deviceId: string): Promise<string> {
  return invoke<string>("connect_device", { deviceId });
}

export async function disconnectSession(sessionId: string): Promise<void> {
  await invoke("disconnect_session", { sessionId });
}

/** Wipe a session's backend scrollback ring (v1.4.0 "Clear terminal").
 *  The visible xterm is cleared separately in the frontend. Resets the
 *  ring so the agent's `read_scrollback` returns only post-clear bytes. */
export async function clearScrollback(sessionId: string): Promise<void> {
  await invoke("clear_scrollback", { sessionId });
}

/** Send a serial BREAK to a console session (interrupt a boot sequence /
 *  reach ROMMON). Console sessions only. */
export async function consoleSendBreak(sessionId: string): Promise<void> {
  await invoke("console_send_break", { sessionId });
}

/** Mirror of the Rust `SessionLogInfo` — a session currently being logged. */
export interface SessionLogInfo {
  session_id: string;
  path: string;
}

/** Start streaming a session's output to `destination` (Phase 3). When
 *  `timestamped`, each line is prefixed with a UTC timestamp. Redacted
 *  per-chunk at the write boundary, like `exportSession`. */
export async function startSessionLog(
  sessionId: string,
  destination: string,
  timestamped: boolean,
): Promise<SessionLogInfo> {
  return invoke("start_session_log", {
    args: { session_id: sessionId, destination, timestamped },
  });
}

/** Stop logging a session. No-op if it wasn't being logged. */
export async function stopSessionLog(sessionId: string): Promise<void> {
  await invoke("stop_session_log", { sessionId });
}

/** The sessions currently being logged (drives the recording indicator). */
export async function listSessionLogs(): Promise<SessionLogInfo[]> {
  return invoke("list_session_logs");
}

/** Metadata for a saved command-output capture (Phase 3). */
export interface CaptureMeta {
  id: string;
  device_id: string;
  command: string;
  captured_at: string;
}

export type DiffOp = "equal" | "insert" | "delete";
export interface DiffLine {
  op: DiffOp;
  text: string;
}
export interface DiffResult {
  lines: DiffLine[];
  added: number;
  removed: number;
}

/** Run `command` in an SSH session and save its (redacted) output as a
 *  capture. Human-initiated — not policy-gated (the gate is agent-only). */
export async function captureCommand(sessionId: string, command: string): Promise<CaptureMeta> {
  return invoke("capture_command", { sessionId, command });
}

/** Run an ordered set of commands in a session, each saved as a capture
 *  (Phase 3 scriptable collection). Human-initiated — not policy-gated.
 *  Returns the captures that succeeded. */
export async function runCollection(sessionId: string, commands: string[]): Promise<CaptureMeta[]> {
  return invoke("run_collection", { sessionId, commands });
}

/** All saved captures, newest first. */
export async function listCaptures(): Promise<CaptureMeta[]> {
  return invoke("list_captures");
}

/** The redacted content of a saved capture. */
export async function readCapture(id: string): Promise<string> {
  return invoke("read_capture", { id });
}

/** Delete a saved capture. */
export async function deleteCapture(id: string): Promise<void> {
  await invoke("delete_capture", { id });
}

/** Line-diff two saved captures (old = `a`, new = `b`). */
export async function diffCaptures(a: string, b: string): Promise<DiffResult> {
  return invoke("diff_captures", { a, b });
}

/** Absolute path of the captures directory (for the dialog footer hint). */
export async function capturesDirPath(): Promise<string> {
  return invoke("captures_dir_path");
}

/** Reply to the backend's `app:confirm-quit` veto (v1.4.0): the user chose to
 *  quit with sessions still open. The backend latches the confirm + exits. */
export async function confirmQuit(): Promise<void> {
  await invoke("confirm_quit");
}

/** Reflect a native-menu checkable item's state (v1.4.0) — the frontend
 *  mirrors `showButtonBar` into the View → Button Bar checkmark. */
export async function setMenuChecked(id: string, checked: boolean): Promise<void> {
  await invoke("set_menu_checked", { id, checked });
}

export async function listOpenSessions(): Promise<SessionMetaWire[]> {
  return invoke<SessionMetaWire[]>("list_open_sessions");
}

/** Send keystroke / paste bytes to the remote shell. */
export async function sendInput(sessionId: string, dataB64: string): Promise<void> {
  await invoke("send_input", { sessionId, dataB64 });
}

export async function resizePty(sessionId: string, cols: number, rows: number): Promise<void> {
  await invoke("resize_pty", { sessionId, cols, rows });
}

/**
 * Reply to an in-flight `host-key:confirm` event. `trust = true`
 * accepts the fingerprint — a first contact pins it, a changed key
 * replaces the stale pin (either way persisted to `known_hosts.toml`
 * only after auth also succeeds). `trust = false` rejects: the
 * connect fails with `HostKeyRejected` (first contact) or
 * `HostKeyMismatch` (changed key), and the pin is untouched.
 */
export async function verifyHostKey(
  deviceId: string,
  host: string,
  port: number,
  trust: boolean,
): Promise<void> {
  await invoke("verify_host_key", { args: { device_id: deviceId, host, port, trust } });
}

/**
 * Reply to an in-flight `auth:kbi:request` with the user's answers.
 *
 * ⚠️ **This is the only IPC call besides `enrollSecret` that carries a
 * credential**, and unlike enrollment it stores nothing: the backend
 * wraps each answer in a `SecretString`, hands them to the parked auth
 * attempt, and drops them when it finishes. Nothing is persisted,
 * returned, or logged (Rule 1; threat-model T46).
 *
 * `answers` MUST have exactly one entry per prompt, in the order the
 * prompts arrived — the SSH layer maps them positionally, so a mismatch
 * would answer the wrong prompt. The backend refuses a wrong-length
 * array rather than guessing.
 */
export async function submitKbiAnswers(
  host: string,
  port: number,
  answers: string[],
): Promise<void> {
  await invoke("submit_kbi_answers", { args: { host, port, answers } });
}

/**
 * Abandon an in-flight interactive auth prompt. Fails the connect
 * cleanly instead of leaving it parked until the connect deadline.
 */
export async function cancelKbi(host: string, port: number): Promise<void> {
  await invoke("cancel_kbi", { args: { host, port } });
}

/**
 * Reply to an in-flight `weak-crypto:confirm` event.
 *
 * `accept = false` aborts the connect with a clear "user declined"
 * error. `accept = true` retries the handshake with the legacy
 * cipher allowlist (SHA1 KEX/MAC, CBC ciphers, ssh-rsa host-key
 * signatures).
 *
 * `remember = true` additionally flips the device's
 * `allow_weak_crypto` inventory field to `true` so future connects
 * skip the prompt for THIS device. Other devices stay strict.
 *
 * Per the threat model: `remember` is opt-in and not the default,
 * because a downgrade to weak crypto is a real MITM risk and we
 * don't want users granting it on autopilot. The dialog UX places
 * the remember-checkbox separately from the Accept button so the
 * decision is consciously made each time.
 */
export async function weakCryptoDecision(
  host: string,
  port: number,
  accept: boolean,
  remember: boolean,
): Promise<void> {
  await invoke("weak_crypto_decision", { args: { host, port, accept, remember } });
}

// ---------------------------------------------------------------------
// Phase 5d.A5 — chat sessions backed by `LlmClient`.
// ---------------------------------------------------------------------

/** Chronological message in a chat session. Mirrors Rust's `ChatMessage`. */
export type ChatMessage =
  | { role: "user"; text: string }
  | { role: "assistant"; text: string }
  | {
      role: "tool_use";
      id: string;
      name: string;
      /** Tool input as captured during the agent loop. May be Null
       * when the chat-side adapter didn't have it at hand (the
       * loop's emit path provides it via the begin event; the
       * tool-use ChatMessage is recorded at end). */
      input: unknown;
      /** JSON-stringified `ToolResult` on success; the policy or
       * dispatcher error text on failure. */
      output: string;
      is_error: boolean;
    };

/**
 * Per-turn token usage emitted on `chat:{id}:completed`. Mirrors
 * Rust's `ChatUsageWire` 1:1 with `transit_agent::TokenUsage`.
 */
export interface ChatUsage {
  input_uncached: number;
  input_cache_write: number;
  input_cache_read: number;
  output: number;
}

/**
 * Create a new chat session. Returns the chat id — caller stores
 * it and uses it as the prefix for `chat:{id}:*` event topics.
 */
export async function chatCreate(model: string): Promise<string> {
  return invoke<string>("chat_create", { model });
}

/** Tear down a chat session, aborting any in-flight stream. */
export async function chatDestroy(chatId: string): Promise<void> {
  await invoke("chat_destroy", { chatId });
}

/** v6.3.0 — one row per live backend chat session, lazily restoring
 *  persisted history first (opt-in — Settings → Agent Chat). Ordered
 *  oldest→newest for left-to-right tab order. Mirrors Rust
 *  `chat::ChatListEntry`. */
export interface ChatListEntry {
  chat_id: string;
  model: string;
}

export async function chatList(): Promise<ChatListEntry[]> {
  return invoke<ChatListEntry[]>("chat_list");
}

/** v6.3.0 — save one assistant code block via the NATIVE save dialog,
 *  opened Rust-side (this wrapper deliberately carries no path — the
 *  backend command has no path parameter at all). Resolves to the chosen
 *  path for the toast, or null when the user cancelled. Refused by the
 *  backend when the Settings → Agent Chat feature is off. */
export async function saveChatSnippet(
  contents: string,
  suggestedName: string,
): Promise<string | null> {
  return invoke<string | null>("save_chat_snippet", { contents, suggestedName });
}

/** The one query key for Agent Chat settings — shared by the Settings
 *  tab (writes + invalidates) and the chat panel (reads the Save-button
 *  gate). Exported so the coupling is a type-checked import, not two
 *  literals that happen to match (ME_QUERY_KEY precedent). */
export const AGENT_CHAT_SETTINGS_QUERY_KEY = ["agentChat", "settings"] as const;

/** v6.3.0 Settings → Agent Chat wire shape. Mirrors Rust
 *  `commands::AgentChatSettings` (effective values + env-override flags
 *  so the UI renders read-only fields). */
export interface AgentChatSettings {
  persist_history: boolean;
  /** Effective folder (configured, env, or the default) — projected from
   *  the same resolver every consumer uses. */
  history_dir: string;
  /** Config-file value only (null = using the default). The setter
   *  round-trips THIS, never the effective value. */
  history_dir_configured: string | null;
  /** Set when the configured/env dir fails validation — the feature is
   *  inert backend-side until fixed, and the UI must say so. */
  history_dir_error: string | null;
  persist_history_env_override: boolean;
  history_dir_env_override: boolean;
  save_to_file: boolean;
  save_dir: string;
  save_dir_configured: string | null;
  save_dir_error: string | null;
  save_to_file_env_override: boolean;
  save_dir_env_override: boolean;
}

export async function getAgentChatSettings(): Promise<AgentChatSettings> {
  return invoke<AgentChatSettings>("get_agent_chat_settings");
}

/** Persist the Agent Chat settings; a null dir clears back to the
 *  default. Applies immediately (every consumer resolves per call). */
export async function setAgentChatSettings(input: {
  persistHistory: boolean;
  historyDir: string | null;
  saveToFile: boolean;
  saveDir: string | null;
}): Promise<void> {
  await invoke("set_agent_chat_settings", input);
}

/** Read the current message log for a chat session. */
export async function chatMessages(chatId: string): Promise<ChatMessage[]> {
  return invoke<ChatMessage[]>("chat_messages", { chatId });
}

/** Switch the model used for subsequent turns in this chat. */
export async function chatSetModel(chatId: string, model: string): Promise<void> {
  await invoke("chat_set_model", { chatId, model });
}

/** v2.7.0 — set (or clear) a chat's device scope (T31). `null` =
 *  unscoped (all devices); `[]` = the agent sees no sessions. The
 *  parameter is deliberately REQUIRED (`string[] | null`, no `?`):
 *  with an optional param, a forgotten argument would deserialize as
 *  Rust `None` and silently unscope the chat. */
export async function chatSetScope(chatId: string, deviceIds: string[] | null): Promise<void> {
  await invoke("chat_set_scope", { chatId, deviceIds });
}

/** Opt a chat into (or out of) auto-approving the agent's read-only GETs for
 *  `propose_api_call` — suppresses the per-call approval modal while the
 *  GET+confine gate still runs on every call. Safe: the tool is structurally
 *  GET-only, so this only ever auto-approves reads. In-memory, chat-scoped. */
export async function chatSetAutoApproveGets(chatId: string, enabled: boolean): Promise<void> {
  await invoke("chat_set_auto_approve_gets", { chatId, enabled });
}

/**
 * Send a user message. Returns once the user message is appended
 * and the streaming task has spawned — listen for
 * `chat:{id}:text-delta` / `:completed` / `:error` for the rest.
 */
export async function chatSendMessage(chatId: string, text: string): Promise<void> {
  await invoke("chat_send_message", { chatId, text });
}

/**
 * Cancel the in-flight stream for a chat. Idempotent (no-op if no
 * stream is running). The partial assistant text is discarded —
 * callers should clear their UI-side accumulator.
 */
export async function chatCancel(chatId: string): Promise<void> {
  await invoke("chat_cancel", { chatId });
}

// ---------------------------------------------------------------------
// Provider API keys (Anthropic / OpenAI) — stored in the OS keychain.
// ---------------------------------------------------------------------

/** Provider identifier for key storage + model routing. Wire-compatible
 *  with Rust's `provider_keys::Provider` enum (lowercase serde). */
export type Provider = "anthropic" | "openai";

/** Mirrors `transit_app::provider_keys::Provider::for_model`: any id
 *  containing `claude` routes to Anthropic; everything else to OpenAI.
 *  Local (`ollama:` / `endpoint:`) ids never reach this. */
export function providerForModel(modelId: string): Provider {
  return modelId.includes("claude") ? "anthropic" : "openai";
}

/**
 * Frontend-visible status. Booleans only — keys themselves never
 * round-trip back across IPC (write-only set, see `providerKeySet`).
 */
export interface ProviderKeysStatus {
  anthropic: boolean;
  openai: boolean;
}

/**
 * Store a provider key in the OS keychain. Write-only — there is no
 * corresponding read IPC by design (Rule 1: no secret crosses IPC
 * except enrollment). At send time the Rust side reads it and sends it
 * ONLY to that provider's own API.
 */
export async function providerKeySet(provider: Provider, value: string): Promise<void> {
  await invoke("provider_key_set", { provider, value });
}

/** Remove a stored provider key. Idempotent. */
export async function providerKeyClear(provider: Provider): Promise<void> {
  await invoke("provider_key_clear", { provider });
}

/** Report which providers have a key configured (no key values). */
export async function providerKeysStatus(): Promise<ProviderKeysStatus> {
  return invoke<ProviderKeysStatus>("provider_keys_status");
}

/** Coarse capability tier, derived from the model id's family. Mirrors
 *  Rust `transit_agent::llm::ModelLevel`. */
export type ModelLevel = "easy" | "medium" | "advanced";

/** One model from the provider's own catalogue. Mirrors Rust
 *  `transit_agent::llm::ProviderModel` — metadata only. */
export interface ProviderModel {
  id: string;
  display_name: string;
  /** Unix seconds when the provider reports one. */
  created: number | null;
  level: ModelLevel;
  context_window: number | null;
}

/**
 * The live model catalogue for the enrolled key, newest first. The key is
 * read in-process and sent only to the provider's own host (Rule 1 / T54);
 * rejects with the same `missing_provider_key` / `provider_key_rejected`
 * markers as a chat would.
 */
export async function providerModelsList(provider: Provider): Promise<ProviderModel[]> {
  return invoke<ProviderModel[]>("provider_models_list", { provider });
}

// ---------------------------------------------------------------------
// Sign in with ChatGPT (preview) — OpenAI plan usage instead of a key.
// Tokens never cross IPC; see src-tauri/src/chatgpt_auth.rs (T55).
// ---------------------------------------------------------------------

/** Which credential the OpenAI side uses. Mirrors Rust `OpenAiMethod`. */
export type OpenAiMethod = "api_key" | "chatgpt";

export interface ChatGptStatus {
  signed_in: boolean;
  /** Display only — read from the ID token, never a credential. */
  email: string | null;
  method: OpenAiMethod;
}

/** Open the browser sign-in. Completion arrives as the
 *  `chatgpt:signin-success` / `chatgpt:signin-error` events. */
export async function chatgptSigninStart(): Promise<void> {
  await invoke("chatgpt_signin_start");
}

export async function chatgptSigninCancel(): Promise<void> {
  await invoke("chatgpt_signin_cancel");
}

export interface ChatGptSignout {
  /** OpenAI confirmed the revocation. False = cleared locally only; the
   *  user should disconnect the app in ChatGPT's security settings. */
  revoked: boolean;
}

/** Revoke the grant at OpenAI and forget it on this machine. */
export async function chatgptSignout(): Promise<ChatGptSignout> {
  return invoke<ChatGptSignout>("chatgpt_signout");
}

export async function chatgptStatus(): Promise<ChatGptStatus> {
  return invoke<ChatGptStatus>("chatgpt_status");
}

/** Persist the OpenAI method; applies on the next send. */
export async function providerOpenaiMethodSet(method: OpenAiMethod): Promise<void> {
  await invoke("provider_openai_method_set", { method });
}

// ---------------------------------------------------------------------
// Phase 6 — agent-loop tool-use approval surface
// ---------------------------------------------------------------------

/** Payload of the `propose-command:request` event. */
export interface ProposeCommandRequestPayload {
  request_id: string;
  chat_id: string;
  session_id: string;
  command: string;
  /** "allow" or "deny: <reason>" or "unrestricted: <warning>" — the
   * policy gate's verdict. The dialog should never see a "deny"
   * payload (the dispatcher short-circuits before emitting), but
   * render gracefully if a future code path lets one through.
   * Prefer `unrestricted` + `warning` over sniffing this string. */
  gate_decision: string;
  /** Phase 8b — true when the vendor's policy is `mode: unrestricted`
   * (generic Linux/Unix). The dialog must render an amber warning
   * banner. (Hiding the auto-approve affordance is driven by
   * `allow_auto_approve`, not this flag.) */
  unrestricted?: boolean;
  /** Verbatim warning string from the policy file's `warning:`
   * field. Present iff `unrestricted` is true. */
  warning?: string;
  /** True when the auto-approve ("remember this regex") affordance is
   * permitted for this command's vendor — i.e. the vendor has a shipped
   * read-only floor. False for `unrestricted` (Linux) AND custom (BYOP)
   * vendors, which both require a per-command click. The dialog hides
   * the affordance entirely when this is false. */
  allow_auto_approve?: boolean;
}

/** Payload of `ask-user:request` events. */
export interface AskUserRequestPayload {
  request_id: string;
  chat_id: string;
  question: string;
}

/** Payload of `propose-command:cancel` events — fired when the
 * loop terminates while a dialog is still open (chat closed,
 * cancel button, etc). The dialog should dismiss itself silently. */
export interface ProposeCommandCancelPayload {
  request_id: string;
  /** Owning chat — lets a per-chat modal / notification card filter
   *  cancels to its own chat (v2.5.0 multi-chat). */
  chat_id: string;
}

/** Payload of the `propose-api-call:request` event (v4.0.0). The GET-only
 * controller analog of {@link ProposeCommandRequestPayload}: a `path` (not
 * a `command`), and NO unrestricted/warning/auto-approve fields — an agent
 * controller call is always a per-call approval with no auto-approve
 * shortcut. Replies through the SHARED {@link respondProposeCommand} (same
 * `pending_approvals` map); a `propose-command:cancel` tears it down. */
export interface ProposeApiCallRequestPayload {
  request_id: string;
  chat_id: string;
  session_id: string;
  /** The GET path the agent proposes (e.g. `/v1/sites`). GET is implicit. */
  path: string;
  /** Gate result text ("allow (GET)" by the time the modal renders). */
  gate_decision: string;
}

/** Verdict shape for `respond_propose_command`. Mirrors the wire
 * tag the Rust side uses (`#[serde(tag = "kind", rename_all = "snake_case")]`). */
export type ProposeVerdictWire =
  { kind: "approve" } | { kind: "deny" } | { kind: "always_allow_regex"; regex: string };

/** Reply to a `propose-command:request` event. */
export async function respondProposeCommand(args: {
  request_id: string;
  verdict: ProposeVerdictWire;
}): Promise<void> {
  await invoke("respond_propose_command", { args });
}

/** Reply to an `ask-user:request` event with the user's typed answer. */
export async function respondAskUser(requestId: string, answer: string): Promise<void> {
  await invoke("respond_ask_user", {
    args: { request_id: requestId, answer },
  });
}

// ---------------------------------------------------------------------
// Phase 7b — USB-to-serial console cables.
// ---------------------------------------------------------------------

/** USB device metadata when the OS classifies the port as USB-CDC /
 *  USB-FTDI / etc. `null` for built-in / Bluetooth / unknown
 *  classifications. */
export interface UsbPortDetails {
  vid: number;
  pid: number;
  manufacturer: string | null;
  product: string | null;
  /** USB iSerial descriptor — stable across replug for FTDI and CP21x
   *  chips programmed with a per-unit serial at the factory. */
  serial_number: string | null;
}

/** One serial port the OS knows about. The sidebar renders these as
 *  rows; the connect modal hydrates its initial state from one. */
export interface SerialPortInfo {
  port_path: string;
  usb: UsbPortDetails | null;
}

/** Payload of `console:plug` events. */
export type HotplugEvent =
  { kind: "added"; port: SerialPortInfo } | { kind: "removed"; port: SerialPortInfo };

export type Parity = "none" | "odd" | "even";
export type DataBits = "five" | "six" | "seven" | "eight";
export type StopBits = "one" | "two";
export type FlowControl = "none" | "software" | "hardware";

/** Parameters the connect modal POSTs to `connect_console_cable`.
 *  Optional fields default per `transit_console::types` (8-N-1, no
 *  flow control). */
export interface ConsoleConnectArgs {
  port_path: string;
  baud: number;
  vendor: string;
  data_bits?: DataBits;
  parity?: Parity;
  stop_bits?: StopBits;
  flow_control?: FlowControl;
}

/** Successful `connect_console_cable` result. `label` is the sidebar
 *  label the frontend stashes on the tab strip. */
export interface ConsoleConnectResult {
  session_id: string;
  label: string;
}

/** Snapshot of currently-attached cables. Synchronous on the Rust
 *  side — reads the hot-plug watcher's cached snapshot. */
export async function listConsoleCables(): Promise<SerialPortInfo[]> {
  return invoke<SerialPortInfo[]>("list_console_cables");
}

/** Open a console session against `args.port_path`. */
export async function connectConsoleCable(args: ConsoleConnectArgs): Promise<ConsoleConnectResult> {
  return invoke<ConsoleConnectResult>("connect_console_cable", { args });
}

// ---- Local terminal (v4.4.0) ----

/** A discovered shell/REPL from `list_available_shells` (the "look under
 *  the hood" discovery). `version` is best-effort; `is_default` marks the
 *  platform default interactive shell. */
export interface ShellInfo {
  id: string;
  label: string;
  path: string;
  program: string;
  args: string[];
  kind: "shell" | "repl" | "wsl";
  version: string | null;
  is_default: boolean;
}

/** Parameters for `open_local_shell`. `args`/`cwd`/`cols`/`rows` default
 *  backend-side (`transit_localpty::OpenParams`). No vendor field — a
 *  local shell is ALWAYS `Vendor::LocalShell`, never caller-chosen. */
export interface OpenShellParams {
  program: string;
  label: string;
  args?: string[];
  cwd?: string | null;
  cols?: number;
  rows?: number;
}

/** Successful `open_local_shell` result. */
export interface LocalShellResult {
  session_id: string;
  label: string;
}

/** Enumerate installed shells + versions. */
export async function listAvailableShells(): Promise<ShellInfo[]> {
  return invoke<ShellInfo[]>("list_available_shells");
}

/** Spawn a local shell in a PTY. Tab-close uses the shared
 *  `disconnectSession` (which falls through to the local table). */
export async function openLocalShell(params: OpenShellParams): Promise<LocalShellResult> {
  return invoke<LocalShellResult>("open_local_shell", { params });
}

/** Whether the local Terminal surface is enabled (`[terminal] enabled` in
 *  config.toml; default true). The rail hides the Terminal entry when false. */
export async function terminalEnabled(): Promise<boolean> {
  return invoke<boolean>("terminal_enabled");
}

/** Restart a local shell IN PLACE (dead-shell "press Enter for a new shell").
 *  Re-spawns under the SAME session id, so the tab/pane resume. */
export async function restartLocalShell(sessionId: string): Promise<void> {
  await invoke("restart_local_shell", { sessionId });
}

/** Direct disconnect — the standard `disconnectSession` IPC also
 *  falls through to console, so the tab strip's X uses that. This
 *  exists for callers that know the session is console-backed. */
export async function disconnectConsoleSession(sessionId: string): Promise<void> {
  await invoke("disconnect_console_session", { sessionId });
}

/** A USB-to-serial chip the OS sees on the bus but has no driver
 *  loaded for. Surfaced as a sidebar banner so the user knows to
 *  install the vendor's VCP driver. */
export interface MissingDriver {
  chip: string;
  vid: string;
  pid: string;
  instruction: string;
}

export interface ConsoleDriverStatus {
  missing_drivers: MissingDriver[];
}

/** Detect USB-to-serial chips on the bus that don't have working
 *  VCP drivers. macOS only (empty elsewhere for v1). */
export async function listConsoleDriverStatus(): Promise<ConsoleDriverStatus> {
  return invoke<ConsoleDriverStatus>("list_console_driver_status");
}

// ---------------------------------------------------------------------
// Phase 8b — session export with redaction + optional age encryption.
// ---------------------------------------------------------------------

/** Encryption choice for `exportSession`. Plaintext writes the
 *  redacted scrollback verbatim. AgePassphrase wraps the same bytes
 *  in an age-passphrase envelope (scrypt KDF + ChaCha20-Poly1305);
 *  decrypt later with `age -d file.age` from the CLI. */
export type ExportEncryption = { kind: "none" } | { kind: "age_passphrase"; passphrase: string };

export interface ExportSessionArgs {
  session_id: string;
  destination: string;
  encryption: ExportEncryption;
}

export interface ExportSessionResult {
  bytes_written: number;
  path: string;
}

/**
 * Export an open session's scrollback to disk. The redaction filter
 * is re-run at the export boundary so the on-disk file matches what
 * the LLM saw (no raw PEM blocks / passwords / cloud creds).
 *
 * Caller is responsible for picking the `destination` via the dialog
 * plugin (`@tauri-apps/plugin-dialog`'s `save`).
 */
export async function exportSession(args: ExportSessionArgs): Promise<ExportSessionResult> {
  return invoke<ExportSessionResult>("export_session", { args });
}

// ---------------------------------------------------------------------
// v3.0.0 BYOM — local models (Ollama + custom endpoints) + the signed
// endpoint status. User-facing IPC only, NOT agent tools (Rule 2:
// the agent has no path to endpoint configuration). Nothing here
// carries a credential (Rule 1): endpoint bearer tokens are WRITE-ONLY
// (set/clear), status payloads are names + booleans, and the raw local
// pass never crosses IPC (only its verification metadata does).
// ---------------------------------------------------------------------

/** Mirrors `commands::LocalModelsSettings`. */
export interface LocalModelsSettings {
  enabled: boolean;
  base_url: string;
  num_ctx: number;
  keep_alive: string;
  /** True when `$TRANSIT_LOCAL_MODELS_URL` forces the base URL —
   *  the Settings field is then read-only. */
  env_override: boolean;
  /** Set when a persisted value was rejected (e.g. a non-loopback
   *  URL) and a safe default was used instead. */
  warning: string | null;
}

export async function getLocalModelsSettings(): Promise<LocalModelsSettings> {
  return invoke<LocalModelsSettings>("get_local_models_settings");
}

/** Persist the local-models settings. Applies on the NEXT chat send —
 *  no restart needed (the chat factory re-resolves per message). A
 *  non-loopback base URL is rejected with a user-shaped error (T35). */
export async function setLocalModelsSettings(args: {
  enabled: boolean;
  baseUrl: string | null;
  numCtx: number;
  keepAlive: string;
}): Promise<void> {
  await invoke("set_local_models_settings", args);
}

/** One installed Ollama model. `id` is the namespaced form the chat
 *  factory routes on (`ollama:<name>`). */
export interface LocalModelEntry {
  id: string;
  name: string;
  size_bytes: number;
  tools_capable: boolean;
}

/** Mirrors `local_models::LocalModelsStatus`. */
export interface LocalModelsStatus {
  enabled: boolean;
  reachable: boolean;
  base_url: string;
  version: string | null;
  /** `false` = the server predates capability discovery (< 0.6.4);
   *  prompt an upgrade. `null` = version unparseable. */
  version_supported: boolean | null;
  models: LocalModelEntry[];
  /** Installed `:cloud` tags — hidden from selection because they
   *  proxy inference through ollama.com (threat-model T33). */
  hidden_cloud_models: string[];
  error: string | null;
  warning: string | null;
}

/** Probe the loopback Ollama server. Short-circuits (reachable:false,
 *  no probe) while the feature is disabled. */
export async function localModelsStatus(): Promise<LocalModelsStatus> {
  return invoke<LocalModelsStatus>("local_models_status");
}

export type LocalEndpointKind = "ollama" | "openai_compat";

/** One configured custom endpoint (config row + has_token boolean). */
export interface LocalEndpointView {
  id: string;
  name: string;
  kind: LocalEndpointKind;
  base_url: string;
  context_length: number;
  has_token: boolean;
}

/** Upsert payload — everything but `has_token` (tokens have their own
 *  write-only path below). */
export interface LocalEndpointInput {
  id: string;
  name: string;
  kind: LocalEndpointKind;
  base_url: string;
  context_length: number;
}

export async function localEndpointsList(): Promise<LocalEndpointView[]> {
  return invoke<LocalEndpointView[]>("local_endpoints_list");
}

/** Create or replace (by id) a custom endpoint. Validation (id
 *  charset, https-off-loopback transport rule, context range) happens
 *  Rust-side and surfaces as the rejection string. */
export async function localEndpointUpsert(endpoint: LocalEndpointInput): Promise<void> {
  await invoke("local_endpoint_upsert", { endpoint });
}

/** Delete an endpoint and (best-effort) its keychain token. */
export async function localEndpointDelete(id: string): Promise<void> {
  await invoke("local_endpoint_delete", { id });
}

/** Store an endpoint bearer token in the OS keychain. Write-only —
 *  there is no corresponding read IPC by design (Rule 1; mirrors
 *  `provider_key_set`). */
export async function localEndpointSetToken(id: string, value: string): Promise<void> {
  await invoke("local_endpoint_set_token", { id, value });
}

export async function localEndpointClearToken(id: string): Promise<void> {
  await invoke("local_endpoint_clear_token", { id });
}

/** One model offered by a custom endpoint. `tools_capable` is null on
 *  OpenAI-compat endpoints — that wire has no capability metadata, so
 *  tool support is unverified. */
export interface EndpointModelEntry {
  id: string;
  name: string;
  tools_capable: boolean | null;
}

export interface LocalEndpointStatus {
  id: string;
  name: string;
  kind: LocalEndpointKind;
  reachable: boolean;
  error: string | null;
  models: EndpointModelEntry[];
  hidden_cloud_models: string[];
}

/** Probe every configured custom endpoint (sequential, 5s cap each). */
export async function localEndpointsStatus(): Promise<LocalEndpointStatus[]> {
  return invoke<LocalEndpointStatus[]>("local_endpoints_status");
}

// ---------------------------------------------------------------------
// v5.0.0 Files (SFTP) surface — the `files_*` IPC namespace: browse
// (`files_list_dir` …) plus transfers (`files_check_conflicts` /
// `files_enqueue` / `files_cancel` + the `files:transfer:update` event).
//
// Files sessions join NO shared transport dispatch: they are never
// reachable through `sendInput` / `resizePty` / `clearScrollback` /
// `disconnectSession` / `listOpenSessions`, and the AI agent is blind to
// them by construction (plan §2, threat model T43). Nothing here returns
// a credential (Rule 1) — session ids, paths, entry metadata, counts.
// ---------------------------------------------------------------------

/** Mirrors `transit_files::EntryKind` (serde `rename_all = "lowercase"`). */
export type FileEntryKind = "file" | "dir" | "symlink" | "other";

/** One row in a Files pane. Mirrors `transit_files::FileEntry`; `name` is
 *  always a single path component (the backend's `sanitize` boundary
 *  rejects separators and `.`/`..` before an entry can reach here). */
export interface FileEntry {
  name: string;
  kind: FileEntryKind;
  size: number | null;
  /** Modification time, whole seconds since the Unix epoch. */
  mtime: number | null;
  /** `"rwxr-xr-x"`, or null when the platform reports no mode bits. */
  perms: string | null;
  /** A symlink's target, when the backend resolved one; a plain listing
   *  leaves it null to skip the extra round-trip per link. */
  symlink_target: string | null;
}

/** A directory listing. `path` is the **canonical** path the server (or
 *  local OS) resolved: the path bar displays it and navigation builds on
 *  it, never on the string the user typed. */
export interface DirListing {
  path: string;
  parent: string | null;
  entries: FileEntry[];
  /** True when the directory held more entries than the backend cap and
   *  the tail was dropped — the pane says so explicitly. */
  truncated: boolean;
}

/** A local filesystem root for the local pane's roots menu. */
export interface LocalRoot {
  path: string;
  label: string;
}

/** Successful `files_connect`. `home` is the server's canonical login
 *  directory, so the remote pane opens somewhere useful. */
export interface FilesConnectResult {
  session_id: string;
  label: string;
  home: string;
}

export interface FilesReconnectResult {
  home: string;
}

/** Whether the Files surface is enabled (`[files] enabled` in
 *  config.toml; default true). The rail hides the entry when false. */
export async function filesEnabled(): Promise<boolean> {
  return invoke<boolean>("files_enabled");
}

/** Open an SFTP session against an inventory device. May emit
 *  `host-key:confirm` / `weak-crypto:confirm` mid-flight and block on the
 *  user's verdict — the responder maps are shared with SSH connect, which
 *  is why bulk Files launches must stay strictly sequential. */
export async function filesConnect(deviceId: string): Promise<FilesConnectResult> {
  return invoke<FilesConnectResult>("files_connect", { deviceId });
}

/** Re-establish a dead session under the SAME id, so the tab, its event
 *  topics, and the pane's cwds all survive. */
export async function filesReconnect(sessionId: string): Promise<FilesReconnectResult> {
  return invoke<FilesReconnectResult>("files_reconnect", { sessionId });
}

/** Close the SFTP session and drop its SSH connection. Deliberately NOT
 *  reachable from `disconnectSession` (plan decision 7). */
export async function filesDisconnect(sessionId: string): Promise<void> {
  await invoke("files_disconnect", { sessionId });
}

export async function filesListDir(sessionId: string, path: string): Promise<DirListing> {
  return invoke<DirListing>("files_list_dir", { sessionId, path });
}

export async function filesMkdir(sessionId: string, path: string): Promise<void> {
  await invoke("files_mkdir", { sessionId, path });
}

export async function filesRename(sessionId: string, from: string, to: string): Promise<void> {
  await invoke("files_rename", { sessionId, from, to });
}

/** Permanent delete (no trash in v1). `recursive` is required for a
 *  non-empty directory; the caller's confirm names the directory. */
export async function filesDelete(
  sessionId: string,
  path: string,
  recursive: boolean,
): Promise<void> {
  await invoke("files_delete", { sessionId, path, recursive });
}

/** Local pane listing. `path` omitted → the user's home directory. */
export async function filesLocalListDir(path?: string | null): Promise<DirListing> {
  return invoke<DirListing>("files_local_list_dir", { path: path ?? null });
}

export async function filesLocalRoots(): Promise<LocalRoot[]> {
  return invoke<LocalRoot[]>("files_local_roots");
}

export async function filesLocalMkdir(path: string): Promise<void> {
  await invoke("files_local_mkdir", { path });
}

export async function filesLocalRename(from: string, to: string): Promise<void> {
  await invoke("files_local_rename", { from, to });
}

export async function filesLocalDelete(path: string, recursive: boolean): Promise<void> {
  await invoke("files_local_delete", { path, recursive });
}

// ---------------------------------------------------------------------
// Transfers (v5.0.0 Commit C). Still Rule 1-clean: paths, counts, byte
// totals. Transfers are pure client↔device — nothing about them touches
// any AI path, and the agent is blind to the whole surface (T43).
// ---------------------------------------------------------------------

/** Which way the bytes move. Mirrors `transit_files::Direction`. */
export type TransferDirection = "upload" | "download";

/** Mirrors `transit_files::TransferState`. `done`/`error`/`cancelled` are
 *  terminal — the engine always emits those, never throttles them away. */
export type TransferState = "queued" | "running" | "done" | "error" | "cancelled";

/** Batch overwrite policy, decided pre-flight for the WHOLE batch from one
 *  dialog (`transit_files::OverwritePolicy`) — never per file mid-transfer. */
export type OverwritePolicy = "overwrite" | "skip";

/** One queued item: move `source_path` into the directory `dest_dir`. */
export interface TransferItem {
  source_path: string;
  dest_dir: string;
}

/** What `files_enqueue` hands back per item, in item order, so the queue
 *  strip can tie an id to the destination it was queued for. */
export interface TransferDescriptor {
  id: string;
  direction: TransferDirection;
  name: string;
}

/**
 * `files:transfer:update` payload — the engine's `TransferEvent`
 * **flattened** beside `session_id` (pinned Rust-side by
 * `files::tests::transfer_payload_flattens_the_engine_event`).
 *
 * `bytes_done` / `bytes_total` describe the **current file**, not the whole
 * job: a recursive directory transfer has no pre-scan in v1, so a job-wide
 * BYTE total doesn't exist. `files_done` counts completed files (so a
 * recursive job is on file `files_done + 1`), and `rate_bps` is measured
 * job-wide for a steadier reading.
 *
 * `files_total` is the file COUNT contract: `1` for a single-file /
 * non-directory job, and `null` ONLY for a recursive directory job (whose
 * count isn't known up front). So the queue strip's "file N" recursive
 * indicator keys off `files_total == null || files_total > 1` — never the
 * `files_done >= 1` heuristic, which misfires the instant the SECOND file of
 * a two-file job starts.
 */
export interface TransferUpdate {
  session_id: string;
  id: string;
  direction: TransferDirection;
  state: TransferState;
  /** The file currently moving, or the top-level item's name. */
  name: string;
  bytes_done: number;
  bytes_total: number | null;
  files_done: number;
  files_total: number | null;
  rate_bps: number | null;
  /** Entries deliberately not transferred: existing destinations under
   *  `skip`, symlinks met while walking, names the sanitizer refused. */
  skipped: number;
  /** Human-readable notes for those skips — capped at 20 by the engine so
   *  a hostile directory can't inflate the payload. */
  warnings: string[];
  error: string | null;
}

/** `files_check_conflicts` argument bundle. The backend takes ONE `args`
 *  object whose inner keys are the serde field names. */
export interface FilesConflictArgs {
  session_id: string;
  direction: TransferDirection;
  items: TransferItem[];
}

export interface FilesEnqueueArgs extends FilesConflictArgs {
  policy: OverwritePolicy;
}

/** Destinations that already exist (full destination paths), for the single
 *  pre-flight Overwrite-all / Skip-existing / Cancel dialog. Top-level items
 *  only — per-file collisions inside a recursive directory follow the batch
 *  policy the user picked here. */
export async function filesCheckConflicts(args: FilesConflictArgs): Promise<string[]> {
  return invoke<string[]>("files_check_conflicts", { args });
}

/** Queue one transfer per item (per-session FIFO). Returns a descriptor per
 *  item, in item order. */
export async function filesEnqueue(args: FilesEnqueueArgs): Promise<TransferDescriptor[]> {
  return invoke<TransferDescriptor[]>("files_enqueue", { args });
}

/** Cancel a queued or running transfer. Ids are session-agnostic on the
 *  wire (the queue strip is global across sessions). */
export async function filesCancel(transferId: string): Promise<void> {
  await invoke("files_cancel", { transferId });
}

// ---------------------------------------------------------------------
// Developer diagnostics (Settings → Developers)
// ---------------------------------------------------------------------

/** What the Developers tab renders. Paths and flags only — never a
 *  credential (Rule 1). */
export interface DeveloperSettings {
  log_to_file: boolean;
  log_dir: string;
  log_level: string;
  /** The ceiling this build allows. Prod stops at `info`; the deeper
   *  levels are where implementation detail lives, and a file a customer
   *  can read is a file a user can publish. */
  max_level: string;
  /** True when this build's ceiling admits debug/trace. */
  verbose_available: boolean;
}

export const developerSettings = () => invoke<DeveloperSettings>("developer_settings");

export const setDeveloperSettings = (
  logToFile: boolean,
  logDir: string | null,
  logLevel: string | null,
) =>
  invoke<void>("set_developer_settings", {
    logToFile,
    logDir,
    logLevel,
  });

export const openLogDir = () => invoke<void>("open_log_dir");
