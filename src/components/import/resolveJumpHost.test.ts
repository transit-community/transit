import { describe, expect, it } from "vitest";

import { pruneJumpRefs, resolveJumpHost, type JumpCandidate } from "./resolveJumpHost";

// The never-guess contract, pinned after adversarial review refuted the
// inline first-match resolver (order-dependent guessing, IPv6 mangling,
// ignored port qualifiers).
describe("resolveJumpHost (v6.5.0)", () => {
  const pool: JumpCandidate[] = [
    { id: "bastion", host: "10.0.0.254", port: 22 },
    { id: "edge-a", host: "shared.example", port: 22 },
    { id: "edge-b", host: "shared.example", port: 2222 },
    { id: "v6-box", host: "fe80::1", port: 22 },
    { id: "lonely", host: "unique.example", port: 2200 },
  ];

  it("matches by exact id (alias-first)", () => {
    expect(resolveJumpHost("bastion", pool)).toBe("bastion");
  });

  it("id match outranks a coincidental host match elsewhere in the pool", () => {
    // A candidate whose ID equals another candidate's HOST: the id wins.
    const tricky: JumpCandidate[] = [{ id: "shared.example", host: "10.9.9.9", port: 22 }, ...pool];
    expect(resolveJumpHost("shared.example", tricky)).toBe("shared.example");
  });

  it("strips user@ before matching", () => {
    expect(resolveJumpHost("alice@10.0.0.254", pool)).toBe("bastion");
  });

  it("host match resolves only when UNIQUE — shared hosts drop", () => {
    expect(resolveJumpHost("unique.example", pool)).toBe("lonely");
    expect(resolveJumpHost("shared.example", pool)).toBeNull();
  });

  it("a :port qualifier must agree with the matched device's port", () => {
    expect(resolveJumpHost("unique.example:2200", pool)).toBe("lonely");
    expect(resolveJumpHost("unique.example:22", pool)).toBeNull();
    expect(resolveJumpHost("alice@10.0.0.254:22", pool)).toBe("bastion");
    expect(resolveJumpHost("10.0.0.254:2222", pool)).toBeNull();
  });

  it("a :port qualifier disambiguates nothing by itself (host still shared)", () => {
    // Port-qualified shared host stays ambiguous by the unique-host rule:
    // never guess, even when the port would pick one.
    expect(resolveJumpHost("shared.example:2222", pool)).toBeNull();
  });

  it("bare IPv6 hosts are never port-stripped", () => {
    expect(resolveJumpHost("fe80::1", pool)).toBe("v6-box");
  });

  it("bracketed IPv6 with a port unbrackets and port-checks", () => {
    expect(resolveJumpHost("[fe80::1]:22", pool)).toBe("v6-box");
    expect(resolveJumpHost("[fe80::1]:2222", pool)).toBeNull();
    expect(resolveJumpHost("[fe80::1]", pool)).toBe("v6-box");
  });

  it("unknown values and empties drop", () => {
    expect(resolveJumpHost("no-such-thing", pool)).toBeNull();
    expect(resolveJumpHost("   ", pool)).toBeNull();
  });
});

describe("pruneJumpRefs (v6.5.0)", () => {
  const none = new Map<string, string>();

  it("keeps acyclic in-depth graphs untouched", () => {
    const jumps = new Map([
      ["r1", "bastion"],
      ["r2", "bastion"],
    ]);
    expect(pruneJumpRefs(jumps, none).size).toBe(0);
  });

  it("drops BOTH sides of a mutual pair (never guesses a survivor)", () => {
    const jumps = new Map([
      ["a", "b"],
      ["b", "a"],
    ]);
    const dropped = pruneJumpRefs(jumps, none);
    expect(dropped).toEqual(new Set(["a", "b"]));
  });

  it("drops every member of a longer cycle", () => {
    const jumps = new Map([
      ["a", "b"],
      ["b", "c"],
      ["c", "a"],
    ]);
    expect(pruneJumpRefs(jumps, none)).toEqual(new Set(["a", "b", "c"]));
  });

  it("enforces the 4-hop depth cap across batch chains", () => {
    // e→d→c→b→a is exactly 4 hops from e: kept. f→e…→a is 5: dropped.
    const jumps = new Map([
      ["b", "a"],
      ["c", "b"],
      ["d", "c"],
      ["e", "d"],
      ["f", "e"],
    ]);
    const dropped = pruneJumpRefs(jumps, none);
    expect(dropped.has("e")).toBe(false);
    expect(dropped.has("f")).toBe(true);
  });

  it("counts EXISTING inventory chains toward the depth cap", () => {
    // Existing: e1→e2→e3→e4 (3 hops from e1). A batch row jumping to e1
    // sits at 4 hops (kept); a batch row jumping to THAT row is 5 (drop).
    const existing = new Map([
      ["e1", "e2"],
      ["e2", "e3"],
      ["e3", "e4"],
    ]);
    const jumps = new Map([
      ["row-a", "e1"],
      ["row-b", "row-a"],
    ]);
    const dropped = pruneJumpRefs(jumps, existing);
    expect(dropped.has("row-a")).toBe(false);
    expect(dropped.has("row-b")).toBe(true);
  });
});
