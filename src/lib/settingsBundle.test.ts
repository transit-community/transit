import { beforeEach, describe, expect, it, vi } from "vitest";

import { applyBundle, readPreferencesBlob, writePreferencesBlob } from "@/lib/settingsBundle";

const importConnections = vi.fn();

vi.mock("@/lib/api", () => ({
  exportSettingsBundle: vi.fn(),
  importSettingsBundle: vi.fn(),
  listDevices: vi.fn().mockResolvedValue([]),
  importConnections: (devices: unknown) => importConnections(devices),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: vi.fn(),
  open: vi.fn(),
}));

const PREFERENCES_KEY = "transit.preferences";

describe("settings bundle preferences round-trip (v6.1.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    importConnections.mockReset().mockResolvedValue({ added: 0 });
  });

  it("reads back exactly what was persisted", () => {
    const blob = JSON.stringify({ themeId: "nord", terminalFontSize: 14 });
    localStorage.setItem(PREFERENCES_KEY, blob);
    expect(readPreferencesBlob()).toBe(blob);
  });

  it("returns null when nothing has been persisted yet", () => {
    expect(readPreferencesBlob()).toBeNull();
  });

  it("refuses to write a blob that isn't valid JSON", () => {
    // Storing garbage would "succeed" and then be silently discarded on
    // next load, which looks like the import having quietly failed.
    expect(writePreferencesBlob("{not json")).toBe(false);
    expect(localStorage.getItem(PREFERENCES_KEY)).toBeNull();
  });

  it("writes a valid blob verbatim", () => {
    const blob = JSON.stringify({ themeId: "dracula" });
    expect(writePreferencesBlob(blob)).toBe(true);
    expect(localStorage.getItem(PREFERENCES_KEY)).toBe(blob);
  });
});

describe("applyBundle", () => {
  beforeEach(() => {
    localStorage.clear();
    importConnections.mockReset().mockResolvedValue({ added: 3 });
  });

  const preview = {
    bundle: {
      version: 1,
      exported_at: "2026-08-13T00:00:00Z",
      preferences: JSON.stringify({ themeId: "nord" }),
      devices: JSON.stringify([{ id: "r1" }, { id: "r2" }, { id: "r3" }]),
    },
    devices: [{ id: "r1" }, { id: "r2" }, { id: "r3" }] as never,
    hasPreferences: true,
  };

  it("imports connections and applies preferences when both are opted in", async () => {
    const outcome = await applyBundle(preview, { preferences: true, connections: true });
    expect(importConnections).toHaveBeenCalledOnce();
    expect(outcome.devicesImported).toBe(3);
    expect(outcome.preferencesApplied).toBe(true);
    // Preferences are read once at store init, so a running instance
    // would otherwise disagree with what's on disk.
    expect(outcome.needsReload).toBe(true);
  });

  it("honors opting out of connections", async () => {
    const outcome = await applyBundle(preview, { preferences: true, connections: false });
    expect(importConnections).not.toHaveBeenCalled();
    expect(outcome.devicesImported).toBe(0);
    expect(outcome.preferencesApplied).toBe(true);
  });

  it("honors opting out of preferences", async () => {
    const outcome = await applyBundle(preview, { preferences: false, connections: true });
    expect(outcome.preferencesApplied).toBe(false);
    expect(outcome.needsReload).toBe(false);
    expect(localStorage.getItem(PREFERENCES_KEY)).toBeNull();
  });

  it("does not claim to have applied preferences a bundle didn't carry", async () => {
    const outcome = await applyBundle(
      { ...preview, bundle: { ...preview.bundle, preferences: null }, hasPreferences: false },
      { preferences: true, connections: false },
    );
    expect(outcome.preferencesApplied).toBe(false);
    expect(outcome.needsReload).toBe(false);
  });

  it("imports connections BEFORE touching preferences", async () => {
    // Ordering matters on failure: a device import that throws must not
    // leave the app wanting a restart into new prefs with no inventory.
    // Observed from INSIDE the import — if preferences had been written
    // first, the key would already exist here.
    let prefsAtImportTime: string | null = "not-observed";
    importConnections.mockImplementation(() => {
      prefsAtImportTime = localStorage.getItem(PREFERENCES_KEY);
      return Promise.resolve({ added: 1 });
    });

    await applyBundle(preview, { preferences: true, connections: true });

    expect(prefsAtImportTime).toBeNull();
    expect(localStorage.getItem(PREFERENCES_KEY)).toBe(preview.bundle.preferences);
  });

  it("propagates a failed connection import instead of half-applying", async () => {
    importConnections.mockRejectedValue(new Error("inventory is broken"));
    await expect(applyBundle(preview, { preferences: true, connections: true })).rejects.toThrow(
      "inventory is broken",
    );
    // Preferences must NOT have been written — the throw happened first.
    expect(localStorage.getItem(PREFERENCES_KEY)).toBeNull();
  });
});
