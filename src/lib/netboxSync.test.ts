import { describe, expect, it } from "vitest";

import type { DeviceMeta, NetBoxSyncPreviewWire } from "@/lib/api";
import type { ImportRow } from "@/components/import/importReducer";

import {
  buildApplyPayload,
  deviceMetaToInput,
  payloadOpCount,
  seedChangeAccepts,
  seedStaleActions,
} from "./netboxSync";

function meta(over: Partial<DeviceMeta> = {}): DeviceMeta {
  return {
    id: "vEX1",
    host: "10.140.0.11",
    port: 22,
    vendor: "junos",
    group: "Springfield HQ",
    color: "blue",
    tags: ["lab"],
    auth: "lab-pw",
    syntax_highlighting: true,
    quick_copy_paste: null,
    font_family: "JetBrains Mono",
    font_size: 15,
    bold_color: true,
    allow_weak_crypto: true,
    netbox_id: "20",
    // v6.5.0 — non-null on purpose: the mapper test below proves these
    // RIDE THROUGH (a null would pass even if the mapper dropped them).
    jump_via: "core-jump",
    forward_agent: true,
    ...over,
  };
}

function preview(over: Partial<NetBoxSyncPreviewWire> = {}): NetBoxSyncPreviewWire {
  return {
    new: [],
    changed: [],
    stale: [],
    unchanged: 0,
    skipped: [],
    warnings: [],
    fetched: 0,
    ...over,
  };
}

function nbRow(over: Partial<ImportRow> = {}): ImportRow {
  return {
    key: "nb-30",
    include: true,
    id: "vQFX1",
    host: "10.140.0.30",
    port: 22,
    vendor: "junos",
    group: "Springfield HQ",
    auth: "lab-pw",
    identityKey: "",
    username: null,
    netboxId: "30",
    tags: ["lab", "role:access-switch"],
    ...over,
  };
}

describe("deviceMetaToInput", () => {
  it("carries EVERY field — a whole-record replace must lose nothing", () => {
    const m = meta();
    const input = deviceMetaToInput(m);
    // Field-for-field: any DeviceMeta key missing here means an update
    // through the sync path silently wipes that field on the device.
    expect(input).toEqual({
      id: m.id,
      host: m.host,
      port: m.port,
      vendor: m.vendor,
      group: m.group,
      color: m.color,
      tags: m.tags,
      auth: m.auth,
      syntax_highlighting: m.syntax_highlighting,
      quick_copy_paste: m.quick_copy_paste,
      font_family: m.font_family,
      font_size: m.font_size,
      bold_color: m.bold_color,
      allow_weak_crypto: m.allow_weak_crypto,
      netbox_id: m.netbox_id,
      jump_via: m.jump_via,
      forward_agent: m.forward_agent,
    });
  });
});

describe("buildApplyPayload", () => {
  it("adds included+valid rows with their NetBox id and carried tags", () => {
    const p = buildApplyPayload({
      rows: [
        nbRow(),
        nbRow({ key: "nb-31", include: false, netboxId: "31" }), // excluded
        nbRow({ key: "nb-32", id: "bad id", netboxId: "32" }), // errored
      ],
      errors: new Map([["nb-32", ["Name allows letters, digits, _ and - only"]]]),
      preview: preview(),
      changeAccepts: {},
      staleActions: {},
      devices: [],
    });
    expect(p.adds).toHaveLength(1);
    expect(p.adds[0]).toMatchObject({
      id: "vQFX1",
      host: "10.140.0.30",
      vendor: "junos",
      group: "Springfield HQ",
      auth: "lab-pw",
      netbox_id: "30",
      tags: ["lab", "role:access-switch"],
    });
    expect(p.updates).toHaveLength(0);
    expect(p.deletes).toHaveLength(0);
  });

  it("applies ONLY accepted fields onto the full current record", () => {
    const pv = preview({
      changed: [
        {
          device_id: "vEX1",
          netbox_id: "20",
          changes: [
            { field: "host", current: "10.140.0.11", incoming: "10.140.0.99" },
            { field: "vendor", current: "junos", incoming: "arista_eos" },
            { field: "group", current: "Springfield HQ", incoming: "Riverside POP" },
          ],
        },
      ],
    });
    const p = buildApplyPayload({
      rows: [],
      errors: new Map(),
      preview: pv,
      // vendor deliberately unchecked.
      changeAccepts: { vEX1: { host: true, vendor: false, group: true } },
      staleActions: {},
      devices: [meta()],
    });
    expect(p.updates).toHaveLength(1);
    const u = p.updates[0];
    expect(u.id).toBe("vEX1");
    expect(u.input.host).toBe("10.140.0.99");
    expect(u.input.vendor).toBe("junos"); // rejected change: untouched
    expect(u.input.group).toBe("Riverside POP");
    // Passthroughs survive (the whole-record-replace discipline).
    expect(u.input.allow_weak_crypto).toBe(true);
    expect(u.input.font_size).toBe(15);
    expect(u.input.netbox_id).toBe("20");
  });

  it("a fully-unchecked change produces no update at all", () => {
    const pv = preview({
      changed: [
        {
          device_id: "vEX1",
          netbox_id: "20",
          changes: [{ field: "host", current: "a", incoming: "b" }],
        },
      ],
    });
    const p = buildApplyPayload({
      rows: [],
      errors: new Map(),
      preview: pv,
      changeAccepts: { vEX1: { host: false } },
      staleActions: {},
      devices: [meta()],
    });
    expect(p.updates).toHaveLength(0);
  });

  it("stale decisions: keep is a no-op, unlink clears netbox_id, delete lists the id", () => {
    const pv = preview({
      stale: [
        { device_id: "keep-me", netbox_id: "1", host: "10.0.0.1" },
        { device_id: "unlink-me", netbox_id: "2", host: "10.0.0.2" },
        { device_id: "delete-me", netbox_id: "3", host: "10.0.0.3" },
      ],
    });
    const p = buildApplyPayload({
      rows: [],
      errors: new Map(),
      preview: pv,
      changeAccepts: {},
      staleActions: { "unlink-me": "unlink", "delete-me": "delete" },
      devices: [
        meta({ id: "keep-me", netbox_id: "1" }),
        meta({ id: "unlink-me", netbox_id: "2" }),
        meta({ id: "delete-me", netbox_id: "3" }),
      ],
    });
    expect(p.deletes).toEqual(["delete-me"]);
    expect(p.updates).toHaveLength(1);
    expect(p.updates[0].id).toBe("unlink-me");
    expect(p.updates[0].input.netbox_id).toBeNull();
    // Unlink keeps everything else about the device.
    expect(p.updates[0].input.auth).toBe("lab-pw");
  });

  it("drops a decision whose device vanished from the live list", () => {
    const pv = preview({
      changed: [
        {
          device_id: "gone",
          netbox_id: "9",
          changes: [{ field: "host", current: "a", incoming: "b" }],
        },
      ],
      stale: [{ device_id: "also-gone", netbox_id: "8", host: "x" }],
    });
    const p = buildApplyPayload({
      rows: [],
      errors: new Map(),
      preview: pv,
      changeAccepts: { gone: { host: true } },
      staleActions: { "also-gone": "unlink" },
      devices: [], // concurrent delete emptied the inventory
    });
    expect(p.updates).toHaveLength(0);
    expect(p.deletes).toHaveLength(0);
  });

  it("payloadOpCount totals adds + updates + deletes", () => {
    expect(
      payloadOpCount({
        adds: [deviceMetaToInput(meta())],
        updates: [{ id: "x", input: deviceMetaToInput(meta()) }],
        deletes: ["y", "z"],
      }),
    ).toBe(4);
  });
});

describe("seed helpers", () => {
  it("seeds every change accepted and every stale row kept", () => {
    const pv = preview({
      changed: [
        {
          device_id: "d1",
          netbox_id: "1",
          changes: [
            { field: "host", current: "a", incoming: "b" },
            { field: "group", current: "g", incoming: "h" },
          ],
        },
      ],
      stale: [{ device_id: "s1", netbox_id: "2", host: "x" }],
    });
    expect(seedChangeAccepts(pv)).toEqual({ d1: { host: true, group: true } });
    expect(seedStaleActions(pv)).toEqual({ s1: "keep" });
  });
});
