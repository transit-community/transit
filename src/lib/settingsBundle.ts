import { open as openFileDialog, save } from "@tauri-apps/plugin-dialog";

import {
  exportSettingsBundle,
  importConnections,
  importSettingsBundle,
  listDevices,
  type DeviceInput,
  type DeviceMeta,
  type SettingsBundle,
} from "@/lib/api";
import { PREFERENCES_KEY } from "@/stores/uiStore";

/**
 * Transit-to-Transit settings export / import (v6.1.0).
 *
 * **What it moves:** the UI preferences blob (theme, fonts, button bars,
 * per-host colors, pane prefs) and your saved connections.
 *
 * **What it deliberately does NOT move:**
 * - **Secrets.** There are none to move — an auth profile stores a
 *   *reference*, and the credential lives in the OS keychain. Rule 1.
 * - **Host-key pins.** Copying `known_hosts.toml` would make the new
 *   machine inherit trust the old machine's human established. A bundle
 *   is a file you might be sent by a colleague; pre-seeding trusted host
 *   keys from it would be the wrong default in a security product.
 *
 * The preferences blob is passed through verbatim in both directions.
 * The store already sanitizes it on load — every field is coerced and
 * capped — so an edited or hostile bundle is exactly as (un)dangerous as
 * an edited `localStorage`, which is the boundary that already exists.
 */

/** Read the raw persisted preferences, or `null` if there are none yet. */
export function readPreferencesBlob(): string | null {
  if (typeof localStorage === "undefined") return null;
  try {
    return localStorage.getItem(PREFERENCES_KEY);
  } catch {
    return null;
  }
}

/**
 * Write a preferences blob back.
 *
 * Returns false if the value isn't parseable JSON — better to refuse than
 * to leave the store with a blob it will silently discard on next load.
 * The caller reloads afterwards: the store reads this key once at module
 * init, so applying it to a running instance would leave the in-memory
 * state and the persisted state disagreeing.
 */
export function writePreferencesBlob(raw: string): boolean {
  if (typeof localStorage === "undefined") return false;
  try {
    JSON.parse(raw);
  } catch {
    return false;
  }
  try {
    localStorage.setItem(PREFERENCES_KEY, raw);
    return true;
  } catch {
    return false;
  }
}

export interface ExportOutcome {
  path: string;
  deviceCount: number;
}

/**
 * A device row as it travels in a bundle.
 *
 * `DeviceMeta` (what `listDevices` returns) and `DeviceInput` (what
 * `importConnections` accepts) are the same shape, so the round-trip is a
 * pass-through. Rule 1 holds for free: `auth` is a profile NAME, and no
 * credential is reachable from here.
 */
function toDeviceInput(d: DeviceMeta): DeviceInput {
  return {
    id: d.id,
    host: d.host,
    port: d.port,
    vendor: d.vendor,
    group: d.group,
    color: d.color,
    tags: d.tags,
    auth: d.auth,
    syntax_highlighting: d.syntax_highlighting,
    quick_copy_paste: d.quick_copy_paste,
    // v6.2.0 — keep the NetBox sync link across a bundle restore, so a
    // re-imaged machine's first "Sync from NetBox" diffs instead of
    // proposing duplicates for every previously-synced device.
    netbox_id: d.netbox_id,
    // v6.5.0 — jump topology travels with the inventory (the whole
    // device set exports together, so references resolve in-batch on
    // restore). `forward_agent` deliberately does NOT travel — like the
    // weak-crypto opt-in, a security grant is re-made per machine, not
    // restored from a file.
    jump_via: d.jump_via,
  };
}

/** Prompt for a destination and write the bundle. `null` = user cancelled. */
export async function exportBundle(includeConnections = true): Promise<ExportOutcome | null> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const destination = await save({
    title: "Export Transit settings",
    defaultPath: `transit-settings-${stamp}.json`,
    filters: [{ name: "Transit settings bundle", extensions: ["json"] }],
  });
  if (!destination) return null;
  const devices = includeConnections ? (await listDevices()).map(toDeviceInput) : [];
  await exportSettingsBundle(
    destination,
    readPreferencesBlob(),
    includeConnections ? JSON.stringify(devices) : null,
  );
  return { path: destination, deviceCount: devices.length };
}

export interface ImportPreview {
  bundle: SettingsBundle;
  devices: DeviceInput[];
  hasPreferences: boolean;
}

/**
 * Prompt for a bundle and parse it. Applies NOTHING — the caller shows a
 * preview and asks first, so opening a file is never destructive.
 */
export async function pickAndPreviewBundle(): Promise<ImportPreview | null> {
  const path = await openFileDialog({
    title: "Import Transit settings",
    multiple: false,
    directory: false,
    filters: [{ name: "Transit settings bundle", extensions: ["json"] }],
  });
  if (!path || Array.isArray(path)) return null;

  const bundle = await importSettingsBundle(path);
  // Devices are validated where they are APPLIED: `import_connections`
  // re-runs the loader's full validation chain and refuses to write a
  // file the loader would reject. Parsing here only has to survive
  // malformed JSON.
  let devices: DeviceInput[] = [];
  if (bundle.devices) {
    try {
      const parsed: unknown = JSON.parse(bundle.devices);
      if (Array.isArray(parsed)) devices = parsed as DeviceInput[];
    } catch {
      throw new Error("the bundle's connections are not readable JSON");
    }
  }
  return { bundle, devices, hasPreferences: Boolean(bundle.preferences) };
}

export interface ApplyOutcome {
  devicesImported: number;
  preferencesApplied: boolean;
  /** True when the caller should reload for preferences to take effect. */
  needsReload: boolean;
}

/**
 * Apply a previewed bundle. Connections first, preferences last: a failed
 * device import should not leave the app mid-restart with new prefs and
 * no inventory.
 */
export async function applyBundle(
  preview: ImportPreview,
  opts: { preferences: boolean; connections: boolean },
): Promise<ApplyOutcome> {
  let devicesImported = 0;
  if (opts.connections && preview.devices.length > 0) {
    const summary = await importConnections(preview.devices);
    devicesImported = summary.added;
  }
  let preferencesApplied = false;
  if (opts.preferences && preview.bundle.preferences) {
    preferencesApplied = writePreferencesBlob(preview.bundle.preferences);
  }
  return {
    devicesImported,
    preferencesApplied,
    needsReload: preferencesApplied,
  };
}
