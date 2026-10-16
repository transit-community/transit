/**
 * Saved command "collections" (Phase 3 scriptable collection) — a named,
 * ordered set of commands run against a session as one sweep, each command
 * captured. Persisted to localStorage, independent of the main preferences
 * blob (a self-contained concern).
 *
 * Running a collection is **human input**, exactly like firing the same
 * commands from the button bar — it is NOT policy-gated (the gate is
 * agent-only). We ship no enforcement that a collection is read-only; the
 * user owns what they put in one.
 */
export interface Collection {
  id: string;
  name: string;
  commands: string[];
}

const KEY = "transit.collections";

/** Load saved collections, tolerating a malformed/absent blob (returns []). */
export function loadCollections(): Collection[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (c): c is Collection =>
          !!c &&
          typeof (c as Collection).id === "string" &&
          typeof (c as Collection).name === "string" &&
          Array.isArray((c as Collection).commands),
      )
      .map((c) => ({
        id: c.id,
        name: c.name,
        commands: c.commands.filter((x): x is string => typeof x === "string"),
      }));
  } catch {
    return [];
  }
}

export function saveCollections(collections: Collection[]): void {
  localStorage.setItem(KEY, JSON.stringify(collections));
}
