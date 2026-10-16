/**
 * NetBox sync (v6.2.0) — pure helpers between the import pane's reviewed
 * state and the `apply_netbox_sync` wire payload. No IPC here; testable
 * with plain objects.
 */

import type { DeviceInput, DeviceMeta, NetBoxApplyPayload, NetBoxSyncPreviewWire } from "@/lib/api";

import type { ImportRow } from "@/components/import/importReducer";

/** What the Stale tab lets the user do with each stale row. */
export type StaleAction = "keep" | "unlink" | "delete";

/** deviceId → field → accepted? (Changed tab checkboxes, default true). */
export type ChangeAccepts = Record<string, Record<string, boolean>>;

/**
 * Full DeviceMeta → DeviceInput passthrough. `update_device` is a
 * whole-record replace, so every field must survive the round trip —
 * the EditDeviceDialog discipline, factored out for the sync path.
 */
export function deviceMetaToInput(d: DeviceMeta): DeviceInput {
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
    font_family: d.font_family,
    font_size: d.font_size,
    bold_color: d.bold_color,
    allow_weak_crypto: d.allow_weak_crypto,
    netbox_id: d.netbox_id,
    jump_via: d.jump_via,
    forward_agent: d.forward_agent,
  };
}

/** Seed default per-change acceptance: every field accepted (the point of
 *  a sync is to take updates; unchecking is the exception). */
export function seedChangeAccepts(preview: NetBoxSyncPreviewWire): ChangeAccepts {
  const out: ChangeAccepts = {};
  for (const c of preview.changed) {
    out[c.device_id] = Object.fromEntries(c.changes.map((f) => [f.field, true]));
  }
  return out;
}

/** Seed every stale row to the safe default. */
export function seedStaleActions(preview: NetBoxSyncPreviewWire): Record<string, StaleAction> {
  return Object.fromEntries(preview.stale.map((s) => [s.device_id, "keep" as StaleAction]));
}

/**
 * Build the atomic apply payload from the reviewed state.
 *
 * - `adds`: the included+valid New rows (already collision-validated by
 *   `validateRows`), each stamped with its NetBox id + carried tags.
 * - `updates`: Changed rows with ≥1 accepted field — the full current
 *   record with only the accepted fields swapped — plus Unlink rows
 *   (current record with `netbox_id: null`).
 * - `deletes`: Stale rows explicitly set to Delete.
 *
 * A Changed device that vanished from the live device list (deleted in a
 * concurrent session) is silently dropped — the backend would refuse the
 * whole batch otherwise, and the row no longer describes anything real.
 */
export function buildApplyPayload(args: {
  rows: ImportRow[];
  errors: Map<string, string[]>;
  preview: NetBoxSyncPreviewWire;
  changeAccepts: ChangeAccepts;
  staleActions: Record<string, StaleAction>;
  devices: DeviceMeta[];
}): NetBoxApplyPayload {
  const { rows, errors, preview, changeAccepts, staleActions, devices } = args;
  const byId = new Map(devices.map((d) => [d.id, d]));

  const adds: DeviceInput[] = rows.flatMap((r) =>
    r.include && !errors.has(r.key)
      ? [
          {
            id: r.id,
            host: r.host.trim(),
            port: r.port,
            vendor: r.vendor,
            group: r.group.trim() === "" ? null : r.group.trim(),
            color: null,
            tags: r.tags ?? [],
            auth: r.auth,
            syntax_highlighting: null,
            quick_copy_paste: null,
            netbox_id: r.netboxId ?? null,
          },
        ]
      : [],
  );

  const updates: NetBoxApplyPayload["updates"] = [];
  for (const c of preview.changed) {
    const meta = byId.get(c.device_id);
    if (!meta) continue;
    const accepted = c.changes.filter((f) => changeAccepts[c.device_id]?.[f.field]);
    if (accepted.length === 0) continue;
    const input = deviceMetaToInput(meta);
    for (const f of accepted) {
      if (f.field === "host") input.host = f.incoming;
      else if (f.field === "vendor") input.vendor = f.incoming;
      else if (f.field === "group") input.group = f.incoming === "" ? null : f.incoming;
    }
    updates.push({ id: c.device_id, input });
  }

  const deletes: string[] = [];
  for (const s of preview.stale) {
    const action = staleActions[s.device_id] ?? "keep";
    if (action === "delete") {
      deletes.push(s.device_id);
    } else if (action === "unlink") {
      const meta = byId.get(s.device_id);
      if (!meta) continue;
      updates.push({ id: s.device_id, input: { ...deviceMetaToInput(meta), netbox_id: null } });
    }
  }

  return { adds, updates, deletes };
}

/** Total operations a payload will perform (drives the commit button). */
export function payloadOpCount(p: NetBoxApplyPayload): number {
  return p.adds.length + p.updates.length + p.deletes.length;
}
