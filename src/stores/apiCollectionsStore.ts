import { create } from "zustand";

import {
  type ApiCollection,
  type ApiFolder,
  type ApiRequestTemplate,
  isDestructiveMethod,
} from "@/lib/apiCollections";

/**
 * v4.0.0 — the USER's own API collections, per controller.
 *
 * Bundled collections (`bundledCollections.ts`) ship read-only with the app;
 * these are the ones the operator creates or imports (Postman). Persisted to
 * localStorage, keyed by api_session id — like `apiVariablesStore`. A
 * collection holds only non-secret request SHAPES (method + path + headers +
 * body); the `X-API-KEY` is injected Rust-side and is never stored (the
 * importer already strips auth headers). Nothing here crosses the agent
 * boundary — the agent's GET-only gate never consults a template.
 */

const STORAGE_KEY = "transit.apiUserCollections";

/** apiSessionId -> the user's collections for that controller. */
type Store = Record<string, ApiCollection[]>;

// ---------------------------------------------------------------------
// Defensive load — localStorage may be corrupted / hand-edited / from an
// older shape. Keep valid nodes, coerce missing fields, drop the rest.
// ---------------------------------------------------------------------

function str(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

/** Keep only `{ key: string; value: string }` pairs (headers, variables). */
function pairs(v: unknown): { key: string; value: string }[] {
  if (!Array.isArray(v)) return [];
  const out: { key: string; value: string }[] = [];
  for (const item of v) {
    if (typeof item !== "object" || item === null) continue;
    const o = item as Record<string, unknown>;
    if (typeof o.key === "string" && typeof o.value === "string") {
      out.push({ key: o.key, value: o.value });
    }
  }
  return out;
}

function sanitizeRequest(v: unknown): ApiRequestTemplate | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  const id = str(r.id);
  if (!id) return null;
  const method = str(r.method, "GET");
  return {
    id,
    name: str(r.name, "Request"),
    method,
    path: str(r.path, "/"),
    headers: pairs(r.headers),
    body: typeof r.body === "string" ? r.body : null,
    destructive: typeof r.destructive === "boolean" ? r.destructive : isDestructiveMethod(method),
    ...(typeof r.description === "string" ? { description: r.description } : {}),
  };
}

function sanitizeFolder(v: unknown): ApiFolder | null {
  if (typeof v !== "object" || v === null) return null;
  const f = v as Record<string, unknown>;
  const id = str(f.id);
  if (!id) return null;
  return {
    id,
    name: str(f.name, "Folder"),
    requests: Array.isArray(f.requests)
      ? f.requests.map(sanitizeRequest).filter((x): x is ApiRequestTemplate => x !== null)
      : [],
    folders: Array.isArray(f.folders)
      ? f.folders.map(sanitizeFolder).filter((x): x is ApiFolder => x !== null)
      : [],
  };
}

function sanitizeCollection(v: unknown): ApiCollection | null {
  if (typeof v !== "object" || v === null) return null;
  const c = v as Record<string, unknown>;
  const id = str(c.id);
  const root = sanitizeFolder(c.root);
  if (!id || !root) return null;
  return {
    id,
    name: str(c.name, "Collection"),
    variables: pairs(c.variables),
    root,
    // User collections are never `bundled`; keep an imported `vendor` tag.
    ...(typeof c.vendor === "string" ? { vendor: c.vendor } : {}),
  };
}

function load(): Store {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return {};
    const out: Store = {};
    for (const [sid, cols] of Object.entries(parsed as Record<string, unknown>)) {
      if (!Array.isArray(cols)) continue;
      const clean = cols.map(sanitizeCollection).filter((x): x is ApiCollection => x !== null);
      if (clean.length) out[sid] = clean;
    }
    return out;
  } catch {
    return {};
  }
}

function persist(store: Store): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Quota / private-mode — nothing to do; state stays in memory.
  }
}

let idSeq = 0;
/** Deterministic-ish id; `crypto.randomUUID` when available, else a counter. */
function newId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    idSeq += 1;
    return `col-${idSeq}`;
  }
}

function emptyCollection(name: string): ApiCollection {
  return {
    id: newId(),
    name,
    variables: [],
    root: { id: newId(), name, requests: [], folders: [] },
  };
}

interface ApiCollectionsState {
  byController: Store;
  /** The user's collections for a controller (empty array if none). */
  collectionsFor: (apiSessionId: string) => ApiCollection[];
  /** Create an empty named collection; returns its id. */
  createCollection: (apiSessionId: string, name: string) => string;
  renameCollection: (apiSessionId: string, collectionId: string, name: string) => void;
  deleteCollection: (apiSessionId: string, collectionId: string) => void;
  /** Add an imported collection verbatim (already sanitized by the importer). */
  addCollection: (apiSessionId: string, collection: ApiCollection) => void;
  /** Save a request into a collection's root (the common flow: current
   *  request builder → a chosen collection). */
  saveRequest: (
    apiSessionId: string,
    collectionId: string,
    req: Omit<ApiRequestTemplate, "id">,
  ) => void;
  deleteRequest: (apiSessionId: string, collectionId: string, requestId: string) => void;
}

function update(
  store: Store,
  apiSessionId: string,
  f: (cols: ApiCollection[]) => ApiCollection[],
): Store {
  const next = { ...store, [apiSessionId]: f(store[apiSessionId] ?? []) };
  if (next[apiSessionId].length === 0) delete next[apiSessionId];
  persist(next);
  return next;
}

export const useApiCollectionsStore = create<ApiCollectionsState>((set, get) => ({
  byController: load(),

  collectionsFor: (apiSessionId) => get().byController[apiSessionId] ?? [],

  createCollection: (apiSessionId, name) => {
    const col = emptyCollection(name.trim() || "New collection");
    set((s) => ({ byController: update(s.byController, apiSessionId, (cols) => [...cols, col]) }));
    return col.id;
  },

  renameCollection: (apiSessionId, collectionId, name) =>
    set((s) => ({
      byController: update(s.byController, apiSessionId, (cols) =>
        cols.map((c) => (c.id === collectionId ? { ...c, name: name.trim() || c.name } : c)),
      ),
    })),

  deleteCollection: (apiSessionId, collectionId) =>
    set((s) => ({
      byController: update(s.byController, apiSessionId, (cols) =>
        cols.filter((c) => c.id !== collectionId),
      ),
    })),

  addCollection: (apiSessionId, collection) =>
    set((s) => ({
      byController: update(s.byController, apiSessionId, (cols) => [...cols, collection]),
    })),

  saveRequest: (apiSessionId, collectionId, req) =>
    set((s) => ({
      byController: update(s.byController, apiSessionId, (cols) =>
        cols.map((c) =>
          c.id === collectionId
            ? { ...c, root: { ...c.root, requests: [...c.root.requests, { ...req, id: newId() }] } }
            : c,
        ),
      ),
    })),

  deleteRequest: (apiSessionId, collectionId, requestId) =>
    set((s) => ({
      byController: update(s.byController, apiSessionId, (cols) =>
        cols.map((c) =>
          c.id === collectionId
            ? {
                ...c,
                root: { ...c.root, requests: c.root.requests.filter((r) => r.id !== requestId) },
              }
            : c,
        ),
      ),
    })),
}));
