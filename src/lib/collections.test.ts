import { afterEach, describe, expect, it } from "vitest";

import { loadCollections, saveCollections, type Collection } from "./collections";

afterEach(() => localStorage.clear());

describe("collections persistence", () => {
  it("returns [] when nothing is saved", () => {
    expect(loadCollections()).toEqual([]);
  });

  it("round-trips saved collections", () => {
    const cols: Collection[] = [
      { id: "1", name: "L3 health", commands: ["show ip route summary", "show bgp summary"] },
    ];
    saveCollections(cols);
    expect(loadCollections()).toEqual(cols);
  });

  it("tolerates a malformed blob", () => {
    localStorage.setItem("transit.collections", "{ not json");
    expect(loadCollections()).toEqual([]);
  });

  it("drops entries missing required fields", () => {
    localStorage.setItem(
      "transit.collections",
      JSON.stringify([
        { id: "ok", name: "ok", commands: ["a"] },
        { id: 5 },
        null,
        { name: "no id" },
      ]),
    );
    expect(loadCollections()).toEqual([{ id: "ok", name: "ok", commands: ["a"] }]);
  });
});
