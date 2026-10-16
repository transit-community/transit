import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiCollection } from "@/lib/apiCollections";

const KEY = "transit.apiUserCollections";

async function freshStore() {
  vi.resetModules();
  const mod = await import("./apiCollectionsStore");
  return mod.useApiCollectionsStore;
}

describe("useApiCollectionsStore", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it("creates a collection, saves a request, and persists per-controller", async () => {
    const store = await freshStore();
    const s = () => store.getState();

    const colId = s().createCollection("ctrl-1", "My UniFi reads");
    expect(s().collectionsFor("ctrl-1")).toHaveLength(1);
    expect(s().collectionsFor("ctrl-1")[0].name).toBe("My UniFi reads");
    // A different controller is isolated.
    expect(s().collectionsFor("ctrl-2")).toEqual([]);

    s().saveRequest("ctrl-1", colId, {
      name: "List hosts",
      method: "GET",
      path: "/v1/hosts",
      headers: [{ key: "Accept", value: "application/json" }],
      body: null,
      destructive: false,
    });
    const reqs = s().collectionsFor("ctrl-1")[0].root.requests;
    expect(reqs).toHaveLength(1);
    expect(reqs[0].name).toBe("List hosts");
    expect(reqs[0].id).toBeTruthy(); // an id was minted

    // Persisted to localStorage under the controller key.
    const persisted = JSON.parse(localStorage.getItem(KEY)!) as Record<string, ApiCollection[]>;
    expect(persisted["ctrl-1"][0].root.requests[0].path).toBe("/v1/hosts");
  });

  it("renames and deletes a request, then the collection", async () => {
    const store = await freshStore();
    const s = () => store.getState();
    const colId = s().createCollection("c", "A");
    s().saveRequest("c", colId, {
      name: "R1",
      method: "GET",
      path: "/a",
      headers: [],
      body: null,
      destructive: false,
    });
    const reqId = s().collectionsFor("c")[0].root.requests[0].id;

    s().renameCollection("c", colId, "Renamed");
    expect(s().collectionsFor("c")[0].name).toBe("Renamed");

    s().deleteRequest("c", colId, reqId);
    expect(s().collectionsFor("c")[0].root.requests).toEqual([]);

    s().deleteCollection("c", colId);
    expect(s().collectionsFor("c")).toEqual([]);
    // The now-empty controller key is pruned from storage.
    const raw = localStorage.getItem(KEY);
    expect(raw === null || JSON.parse(raw)["c"] === undefined).toBe(true);
  });

  it("addCollection appends an imported collection verbatim", async () => {
    const store = await freshStore();
    const s = () => store.getState();
    const imported: ApiCollection = {
      id: "imp-1",
      name: "Imported",
      variables: [],
      root: {
        id: "root-1",
        name: "Imported",
        requests: [
          {
            id: "r1",
            name: "X",
            method: "POST",
            path: "/x",
            headers: [],
            body: "{}",
            destructive: true,
          },
        ],
        folders: [],
      },
    };
    s().addCollection("c", imported);
    expect(s().collectionsFor("c")[0].id).toBe("imp-1");
    expect(s().collectionsFor("c")[0].root.requests[0].destructive).toBe(true);
  });

  it("rehydrates from localStorage, dropping malformed nodes and coercing fields", async () => {
    // Seed a mixed blob: one good collection, one with no id, one with no
    // root, plus a request with no id (drop) and one missing `destructive`
    // (coerced from method).
    localStorage.setItem(
      KEY,
      JSON.stringify({
        good: [
          {
            id: "col-a",
            name: "A",
            variables: [{ key: "siteId", value: "s1" }, { bad: 1 }],
            root: {
              id: "root-a",
              name: "A",
              requests: [
                { name: "no-id", method: "GET", path: "/x", headers: [], body: null }, // dropped (no id)
                { id: "r-ok", name: "ok", method: "DELETE", path: "/y", headers: [] }, // destructive coerced true
              ],
              folders: [],
            },
          },
          { name: "no-id-collection", root: { id: "z", name: "z", requests: [], folders: [] } }, // dropped
          { id: "no-root" }, // dropped
        ],
        empty: [], // pruned (no valid collections)
      }),
    );

    const store = await freshStore();
    const s = () => store.getState();

    const cols = s().collectionsFor("good");
    expect(cols).toHaveLength(1);
    expect(cols[0].id).toBe("col-a");
    // Only the pair-shaped variable survived.
    expect(cols[0].variables).toEqual([{ key: "siteId", value: "s1" }]);
    // The id-less request was dropped; the DELETE request kept + coerced.
    expect(cols[0].root.requests).toHaveLength(1);
    expect(cols[0].root.requests[0].id).toBe("r-ok");
    expect(cols[0].root.requests[0].destructive).toBe(true);
    // The malformed controller entry vanished entirely.
    expect(s().collectionsFor("empty")).toEqual([]);
  });

  it("survives a corrupt localStorage blob (returns empty, no throw)", async () => {
    localStorage.setItem(KEY, "{not json");
    const store = await freshStore();
    expect(store.getState().collectionsFor("anything")).toEqual([]);
  });
});
