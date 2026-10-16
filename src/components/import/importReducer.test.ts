import { describe, expect, it } from "vitest";

import type { ImportIdentityMeta, ImportPreviewRow } from "@/lib/api";

import {
  importReducer,
  initialImportState,
  validateRows,
  type ImportRow,
  type ImportState,
} from "./importReducer";

function previewRow(over: Partial<ImportPreviewRow> = {}): ImportPreviewRow {
  return {
    id: "dev",
    host: "10.0.0.1",
    port: 22,
    username: "root",
    vendor: "unknown",
    group: null,
    jump_host: null,
    identity_key: "user:root|",
    collides: false,
    ...over,
  };
}

function identity(over: Partial<ImportIdentityMeta> = {}): ImportIdentityMeta {
  return {
    key: "user:root|",
    login: "root",
    count: 1,
    auth_kind: "password",
    suggested_backend: "keyring",
    key_path: null,
    ...over,
  };
}

function row(over: Partial<ImportRow> = {}): ImportRow {
  return {
    key: "0",
    include: true,
    id: "dev",
    host: "10.0.0.1",
    port: 22,
    vendor: "unknown",
    group: "",
    auth: "prof",
    identityKey: "user:root|",
    username: "root",
    ...over,
  };
}

describe("importReducer", () => {
  it("PARSE_OK builds rows, excludes collisions, and advances to credentials", () => {
    const next = importReducer(initialImportState, {
      type: "PARSE_OK",
      rows: [
        previewRow({ id: "a" }),
        previewRow({ id: "b", collides: true }), // already exists → excluded
      ],
      identities: [identity()],
      warnings: ["1 note"],
    });
    expect(next.step).toBe("credentials");
    expect(next.rows).toHaveLength(2);
    expect(next.rows[0]).toMatchObject({ id: "a", include: true, auth: "" });
    expect(next.rows[1]).toMatchObject({ id: "b", include: false }); // skip+flag
    expect(next.warnings).toEqual(["1 note"]);
  });

  it("SEED_AUTH_DEFAULTS applies credential choices onto matching rows and advances", () => {
    let state: ImportState = importReducer(initialImportState, {
      type: "PARSE_OK",
      rows: [
        previewRow({ id: "a", identity_key: "k1" }),
        previewRow({ id: "b", identity_key: "k2" }),
      ],
      identities: [identity({ key: "k1" }), identity({ key: "k2" })],
      warnings: [],
    });
    state = importReducer(state, {
      type: "SET_CREDENTIAL",
      identityKey: "k1",
      profileName: "prof-1",
    });
    state = importReducer(state, {
      type: "SET_CREDENTIAL",
      identityKey: "k2",
      profileName: "prof-2",
    });
    state = importReducer(state, { type: "SEED_AUTH_DEFAULTS" });

    expect(state.step).toBe("preview");
    expect(state.rows.find((r) => r.id === "a")?.auth).toBe("prof-1");
    expect(state.rows.find((r) => r.id === "b")?.auth).toBe("prof-2");
  });

  it("SEED_AUTH_DEFAULTS does not clobber a row the user already edited", () => {
    let state: ImportState = importReducer(initialImportState, {
      type: "PARSE_OK",
      rows: [previewRow({ id: "a", identity_key: "k1" })],
      identities: [identity({ key: "k1" })],
      warnings: [],
    });
    state = importReducer(state, { type: "PATCH_ROW", key: "0", patch: { auth: "hand-picked" } });
    state = importReducer(state, {
      type: "SET_CREDENTIAL",
      identityKey: "k1",
      profileName: "default",
    });
    state = importReducer(state, { type: "SEED_AUTH_DEFAULTS" });
    expect(state.rows[0].auth).toBe("hand-picked");
  });

  it("BULK_SET only touches selected rows", () => {
    let state: ImportState = {
      ...initialImportState,
      rows: [row({ key: "0", id: "a" }), row({ key: "1", id: "b" }), row({ key: "2", id: "c" })],
    };
    state = importReducer(state, { type: "SELECT_KEYS", keys: ["0", "2"] });
    state = importReducer(state, { type: "BULK_SET", field: "vendor", value: "junos" });
    expect(state.rows.map((r) => r.vendor)).toEqual(["junos", "unknown", "junos"]);
  });

  it("BULK_INCLUDE flips include for the selection only", () => {
    let state: ImportState = {
      ...initialImportState,
      rows: [row({ key: "0" }), row({ key: "1" })],
      selected: new Set(["1"]),
    };
    state = importReducer(state, { type: "BULK_INCLUDE", include: false });
    expect(state.rows[0].include).toBe(true);
    expect(state.rows[1].include).toBe(false);
  });
});

describe("validateRows", () => {
  it("accepts a clean included row", () => {
    const errs = validateRows([row()], new Set());
    expect(errs.size).toBe(0);
  });

  it("flags bad id, host, port, vendor, and missing auth", () => {
    const errs = validateRows(
      [
        row({ key: "id", id: "bad id!" }),
        row({ key: "host", id: "h1", host: "  " }),
        row({ key: "port", id: "p1", port: 0 }),
        row({ key: "vendor", id: "v1", vendor: "Bad Vendor" }),
        row({ key: "auth", id: "a1", auth: "" }),
      ],
      new Set(),
    );
    expect(errs.get("id")?.[0]).toMatch(/Name allows/);
    expect(errs.get("host")?.[0]).toMatch(/Host is required/);
    expect(errs.get("port")?.[0]).toMatch(/Port must be/);
    expect(errs.get("vendor")?.[0]).toMatch(/vendor/i);
    expect(errs.get("auth")?.[0]).toMatch(/auth profile/i);
  });

  it("flags within-batch duplicate ids and collisions with existing inventory", () => {
    const dup = validateRows([row({ key: "0", id: "x" }), row({ key: "1", id: "x" })], new Set());
    expect(dup.get("0")?.[0]).toMatch(/Duplicate/);
    expect(dup.get("1")?.[0]).toMatch(/Duplicate/);

    const collide = validateRows([row({ key: "0", id: "exists" })], new Set(["exists"]));
    expect(collide.get("0")?.[0]).toMatch(/already exists/);
  });

  it("never blocks on excluded rows", () => {
    const errs = validateRows([row({ include: false, id: "", host: "", auth: "" })], new Set());
    expect(errs.size).toBe(0);
  });

  it("treats 'unknown' vendor as valid (the import default)", () => {
    expect(validateRows([row({ vendor: "unknown" })], new Set()).size).toBe(0);
    expect(validateRows([row({ vendor: "junos" })], new Set()).size).toBe(0);
  });
});

describe("importReducer — NetBox branch (v6.2.0)", () => {
  const previewWire = {
    new: [
      {
        netbox_id: "30",
        proposed_device_id: "vQFX1",
        host: "10.140.0.30",
        name: "vQFX1",
        status: "active",
        vendor_tag: "junos",
        group: "Springfield HQ",
        tags: ["lab", "role:access-switch"],
        collides: false,
      },
      {
        netbox_id: "31",
        proposed_device_id: "vEX1",
        host: "10.140.0.31",
        name: "vEX1",
        status: "active",
        vendor_tag: "junos",
        group: null,
        tags: [],
        collides: true, // still shadows an existing device
      },
    ],
    changed: [
      {
        device_id: "vEX2",
        netbox_id: "21",
        changes: [{ field: "host", current: "a", incoming: "b" }],
      },
    ],
    stale: [{ device_id: "old-box", netbox_id: "99", host: "10.9.9.9" }],
    unchanged: 3,
    skipped: [],
    warnings: ["page 2: skipped a device entry with no usable id"],
    fetched: 6,
  };

  function fetched(): ImportState {
    let s = importReducer(initialImportState, { type: "NETBOX_OPEN" });
    s = importReducer(s, { type: "NETBOX_SET_SESSION", sessionId: "netbox" });
    s = importReducer(s, { type: "NETBOX_FETCH_START" });
    return importReducer(s, { type: "NETBOX_FETCH_OK", preview: previewWire });
  }

  it("NETBOX_OPEN enters the netbox step without touching file-import state", () => {
    const s = importReducer(initialImportState, { type: "NETBOX_OPEN" });
    expect(s.step).toBe("netbox");
    expect(s.rows).toHaveLength(0);
  });

  it("NETBOX_FETCH_OK maps candidates into grid rows (collisions excluded) and seeds decisions", () => {
    const s = fetched();
    expect(s.netbox.fetching).toBe(false);
    expect(s.netbox.preview?.fetched).toBe(6);
    expect(s.rows).toHaveLength(2);
    expect(s.rows[0]).toMatchObject({
      key: "nb-30",
      include: true,
      id: "vQFX1",
      vendor: "junos",
      group: "Springfield HQ",
      netboxId: "30",
      tags: ["lab", "role:access-switch"],
    });
    expect(s.rows[1].include).toBe(false); // collides → starts excluded
    expect(s.warnings).toEqual(previewWire.warnings);
    // Decisions seeded: every change accepted, every stale row kept.
    expect(s.netbox.changeAccepts).toEqual({ vEX2: { host: true } });
    expect(s.netbox.staleActions).toEqual({ "old-box": "keep" });
  });

  it("NETBOX_TOGGLE_CHANGE flips one field; NETBOX_SET_STALE reassigns a row", () => {
    let s = fetched();
    s = importReducer(s, { type: "NETBOX_TOGGLE_CHANGE", deviceId: "vEX2", field: "host" });
    expect(s.netbox.changeAccepts.vEX2.host).toBe(false);
    s = importReducer(s, { type: "NETBOX_SET_STALE", deviceId: "old-box", action: "delete" });
    expect(s.netbox.staleActions["old-box"]).toBe("delete");
  });

  it("NETBOX_SEED_AUTH fills default/blank rows but never a hand-picked profile", () => {
    let s = fetched();
    s = importReducer(s, { type: "NETBOX_SEED_AUTH", profileName: "lab-pw" });
    expect(s.rows.every((r) => r.auth === "lab-pw")).toBe(true);
    // Hand-pick one row, then change the default: the hand-pick survives.
    s = importReducer(s, { type: "PATCH_ROW", key: "nb-30", patch: { auth: "special" } });
    s = importReducer(s, { type: "NETBOX_SEED_AUTH", profileName: "core-pw" });
    expect(s.rows.find((r) => r.key === "nb-30")?.auth).toBe("special");
    expect(s.rows.find((r) => r.key === "nb-31")?.auth).toBe("core-pw");
  });

  it("NETBOX_FETCH_ERR surfaces the message and clears the spinner", () => {
    let s = importReducer(initialImportState, { type: "NETBOX_OPEN" });
    s = importReducer(s, { type: "NETBOX_FETCH_START" });
    s = importReducer(s, { type: "NETBOX_FETCH_ERR", message: "NetBox returned HTTP 403" });
    expect(s.netbox.fetching).toBe(false);
    expect(s.netbox.fetchError).toMatch(/403/);
  });
});
