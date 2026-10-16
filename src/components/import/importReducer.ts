import type {
  ImportIdentityMeta,
  ImportPreviewRow,
  ImportSource,
  NetBoxSyncPreviewWire,
} from "@/lib/api";
import type { ChangeAccepts, StaleAction } from "@/lib/netboxSync";
import { seedChangeAccepts, seedStaleActions } from "@/lib/netboxSync";
import { CUSTOM_VENDOR_PATTERN } from "@/lib/schemas";

/** Device id charset (mirrors the Rust loader + `deviceFormSchema.id`). */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

/** `netbox` (v6.2.0) is the live-API source: one self-contained step that
 *  picks a session, fetches the diff, and reviews New/Changed/Stale —
 *  the file sources keep their three-step flow. */
export type ImportStep = "source" | "credentials" | "preview" | "netbox";

/** An editable grid row: the device fields plus wizard bookkeeping. An
 *  included, valid row maps 1:1 to a `DeviceInput`. */
export interface ImportRow {
  /** Stable client key (parse order) — React key + selection id. */
  key: string;
  include: boolean;
  id: string;
  host: string;
  port: number;
  vendor: string;
  /** "" = ungrouped. */
  group: string;
  /** Auth profile name, seeded from the credential step, editable here. */
  auth: string;
  /** Links back to the identity that seeds this row's default auth. */
  identityKey: string;
  username: string | null;
  /** v6.2.0 — set only on NetBox-sourced rows: the external match key,
   *  stamped onto the created device so future syncs diff instead of
   *  duplicating. */
  netboxId?: string;
  /** v6.2.0 — NetBox-sourced tags (tag slugs + `role:<slug>`), carried
   *  through commit; the grid doesn't edit them. */
  tags?: string[];
  /** v6.5.0 — raw jump-host value from the source (ssh_config
   *  `ProxyJump` / SecureCRT `Firewall Name`), possibly `user@host:port`
   *  shaped. Resolved against in-batch + existing devices at commit;
   *  unresolved values are dropped with a toast. */
  jumpHost?: string | null;
}

/** The NetBox branch's slice of wizard state (v6.2.0). */
export interface NetBoxState {
  /** Chosen API session id (vendor "netbox"). */
  sessionId: string | null;
  fetching: boolean;
  fetchError: string | null;
  /** The last fetched diff; null until the first successful fetch. */
  preview: NetBoxSyncPreviewWire | null;
  /** Changed tab: deviceId → field → accepted (default all true). */
  changeAccepts: ChangeAccepts;
  /** Stale tab: deviceId → Keep (default) / Unlink / Delete. */
  staleActions: Record<string, StaleAction>;
  /** The "auth profile for imported devices" default last applied. */
  defaultAuth: string;
}

const initialNetBoxState: NetBoxState = {
  sessionId: null,
  fetching: false,
  fetchError: null,
  preview: null,
  changeAccepts: {},
  staleActions: {},
  defaultAuth: "",
};

export interface ImportState {
  step: ImportStep;
  format: ImportSource | null;
  sourcePath: string | null;
  parsing: boolean;
  parseError: string | null;
  warnings: string[];
  identities: ImportIdentityMeta[];
  /** identityKey → chosen auth-profile name. */
  credentialChoices: Record<string, string>;
  rows: ImportRow[];
  /** Row keys selected for bulk edit. */
  selected: Set<string>;
  committing: boolean;
  commitError: string | null;
  /** v6.2.0 — the NetBox live-sync branch. */
  netbox: NetBoxState;
}

export const initialImportState: ImportState = {
  step: "source",
  format: null,
  sourcePath: null,
  parsing: false,
  parseError: null,
  warnings: [],
  identities: [],
  credentialChoices: {},
  rows: [],
  selected: new Set(),
  committing: false,
  commitError: null,
  netbox: initialNetBoxState,
};

export type ImportAction =
  | { type: "PARSE_START"; format: ImportSource; path: string }
  | {
      type: "PARSE_OK";
      rows: ImportPreviewRow[];
      identities: ImportIdentityMeta[];
      warnings: string[];
    }
  | { type: "PARSE_ERR"; message: string }
  | { type: "GOTO"; step: ImportStep }
  | { type: "SET_CREDENTIAL"; identityKey: string; profileName: string }
  | { type: "SEED_AUTH_DEFAULTS" }
  | { type: "PATCH_ROW"; key: string; patch: Partial<ImportRow> }
  | { type: "TOGGLE_INCLUDE"; key: string }
  | { type: "TOGGLE_SELECT"; key: string }
  | { type: "SELECT_KEYS"; keys: string[] }
  | { type: "CLEAR_SELECT" }
  | { type: "BULK_SET"; field: "vendor" | "group" | "auth"; value: string }
  | { type: "BULK_INCLUDE"; include: boolean }
  | { type: "COMMIT_START" }
  | { type: "COMMIT_ERR"; message: string }
  // v6.2.0 — the NetBox branch.
  | { type: "NETBOX_OPEN" }
  | { type: "NETBOX_SET_SESSION"; sessionId: string }
  | { type: "NETBOX_FETCH_START" }
  | { type: "NETBOX_FETCH_OK"; preview: NetBoxSyncPreviewWire }
  | { type: "NETBOX_FETCH_ERR"; message: string }
  | { type: "NETBOX_TOGGLE_CHANGE"; deviceId: string; field: string }
  | { type: "NETBOX_SET_STALE"; deviceId: string; action: StaleAction }
  | { type: "NETBOX_SEED_AUTH"; profileName: string };

export function importReducer(state: ImportState, action: ImportAction): ImportState {
  switch (action.type) {
    case "PARSE_START":
      return {
        ...state,
        parsing: true,
        parseError: null,
        format: action.format,
        sourcePath: action.path,
      };
    case "PARSE_OK": {
      const rows: ImportRow[] = action.rows.map((r, i) => ({
        key: String(i),
        // skip+flag: a row colliding with an existing device starts excluded.
        include: !r.collides,
        id: r.id,
        host: r.host,
        port: r.port,
        vendor: r.vendor,
        group: r.group ?? "",
        auth: "",
        identityKey: r.identity_key,
        username: r.username,
        jumpHost: r.jump_host,
      }));
      return {
        ...state,
        parsing: false,
        parseError: null,
        rows,
        identities: action.identities,
        warnings: action.warnings,
        credentialChoices: {},
        selected: new Set(),
        step: "credentials",
      };
    }
    case "PARSE_ERR":
      return { ...state, parsing: false, parseError: action.message };
    case "GOTO":
      return { ...state, step: action.step };
    case "SET_CREDENTIAL":
      return {
        ...state,
        credentialChoices: { ...state.credentialChoices, [action.identityKey]: action.profileName },
      };
    case "SEED_AUTH_DEFAULTS": {
      const rows = state.rows.map((row) => {
        const chosen = state.credentialChoices[row.identityKey];
        // Don't clobber a row the user already hand-edited to a profile.
        return chosen && !row.auth ? { ...row, auth: chosen } : row;
      });
      return { ...state, rows, step: "preview" };
    }
    case "PATCH_ROW":
      return {
        ...state,
        rows: state.rows.map((r) => (r.key === action.key ? { ...r, ...action.patch } : r)),
      };
    case "TOGGLE_INCLUDE":
      return {
        ...state,
        rows: state.rows.map((r) => (r.key === action.key ? { ...r, include: !r.include } : r)),
      };
    case "TOGGLE_SELECT": {
      const selected = new Set(state.selected);
      if (selected.has(action.key)) selected.delete(action.key);
      else selected.add(action.key);
      return { ...state, selected };
    }
    case "SELECT_KEYS":
      return { ...state, selected: new Set(action.keys) };
    case "CLEAR_SELECT":
      return { ...state, selected: new Set() };
    case "BULK_SET":
      return {
        ...state,
        rows: state.rows.map((r) =>
          state.selected.has(r.key) ? { ...r, [action.field]: action.value } : r,
        ),
      };
    case "BULK_INCLUDE":
      return {
        ...state,
        rows: state.rows.map((r) =>
          state.selected.has(r.key) ? { ...r, include: action.include } : r,
        ),
      };
    case "COMMIT_START":
      return { ...state, committing: true, commitError: null };
    case "COMMIT_ERR":
      return { ...state, committing: false, commitError: action.message };
    case "NETBOX_OPEN":
      return { ...state, step: "netbox", parseError: null };
    case "NETBOX_SET_SESSION":
      return { ...state, netbox: { ...state.netbox, sessionId: action.sessionId } };
    case "NETBOX_FETCH_START":
      return { ...state, netbox: { ...state.netbox, fetching: true, fetchError: null } };
    case "NETBOX_FETCH_OK": {
      // The New bucket rides `state.rows`, so the whole PreviewGridStep
      // (per-row edits, bulk bar, validation) is reused verbatim as the
      // New tab. Colliding rows start excluded, like a file import.
      const rows: ImportRow[] = action.preview.new.map((c) => ({
        key: `nb-${c.netbox_id}`,
        include: !c.collides,
        id: c.proposed_device_id,
        host: c.host,
        port: 22,
        vendor: c.vendor_tag,
        group: c.group ?? "",
        auth: state.netbox.defaultAuth,
        identityKey: "",
        username: null,
        netboxId: c.netbox_id,
        tags: c.tags,
      }));
      return {
        ...state,
        rows,
        selected: new Set(),
        warnings: action.preview.warnings,
        netbox: {
          ...state.netbox,
          fetching: false,
          fetchError: null,
          preview: action.preview,
          changeAccepts: seedChangeAccepts(action.preview),
          staleActions: seedStaleActions(action.preview),
        },
      };
    }
    case "NETBOX_FETCH_ERR":
      return {
        ...state,
        netbox: { ...state.netbox, fetching: false, fetchError: action.message },
      };
    case "NETBOX_TOGGLE_CHANGE": {
      const forDevice = state.netbox.changeAccepts[action.deviceId] ?? {};
      return {
        ...state,
        netbox: {
          ...state.netbox,
          changeAccepts: {
            ...state.netbox.changeAccepts,
            [action.deviceId]: { ...forDevice, [action.field]: !forDevice[action.field] },
          },
        },
      };
    }
    case "NETBOX_SET_STALE":
      return {
        ...state,
        netbox: {
          ...state.netbox,
          staleActions: { ...state.netbox.staleActions, [action.deviceId]: action.action },
        },
      };
    case "NETBOX_SEED_AUTH": {
      // Fill every row still on the PREVIOUS default (or blank) — a row
      // the user hand-picked a profile for is never clobbered.
      const prev = state.netbox.defaultAuth;
      const rows = state.rows.map((r) =>
        r.auth === "" || r.auth === prev ? { ...r, auth: action.profileName } : r,
      );
      return {
        ...state,
        rows,
        netbox: { ...state.netbox, defaultAuth: action.profileName },
      };
    }
    default:
      return state;
  }
}

/**
 * Hard errors per row key, computed live. Only INCLUDED rows are checked
 * (excluded rows never block the import). `existingIds` is the set of
 * device ids already in the inventory (from the live devices query), so
 * a collision clears the instant the user renames the row.
 */
export function validateRows(rows: ImportRow[], existingIds: Set<string>): Map<string, string[]> {
  const errors = new Map<string, string[]>();

  // Within-batch id frequency among included rows (a dup is a hard error).
  const counts = new Map<string, number>();
  for (const r of rows) {
    if (r.include) counts.set(r.id, (counts.get(r.id) ?? 0) + 1);
  }

  for (const r of rows) {
    if (!r.include) continue;
    const list: string[] = [];
    if (!r.id) list.push("Name is required");
    else if (!DEVICE_ID_PATTERN.test(r.id)) list.push("Name allows letters, digits, _ and - only");
    else if ((counts.get(r.id) ?? 0) > 1) list.push("Duplicate name within this import");
    else if (existingIds.has(r.id)) list.push("A device with this name already exists");
    if (!r.host.trim()) list.push("Host is required");
    if (!Number.isInteger(r.port) || r.port < 1 || r.port > 65535)
      list.push("Port must be 1–65535");
    if (r.vendor && !CUSTOM_VENDOR_PATTERN.test(r.vendor)) list.push("Invalid vendor tag");
    if (!r.auth) list.push("Pick an auth profile");
    if (list.length > 0) errors.set(r.key, list);
  }
  return errors;
}
