import { describe, expect, it } from "vitest";

import {
  hasPane,
  insertNodeAt,
  leaf,
  neighborPane,
  paneCount,
  paneIds,
  removeLeaf,
  renameLeaf,
  splitLeaf,
  type PaneNode,
} from "./paneTree";

describe("paneTree", () => {
  it("a bare leaf reports itself", () => {
    const t = leaf("A");
    expect(paneIds(t)).toEqual(["A"]);
    expect(paneCount(t)).toBe(1);
    expect(hasPane(t, "A")).toBe(true);
    expect(hasPane(t, "B")).toBe(false);
  });

  it("splitLeaf on a bare leaf makes a 2-way split", () => {
    const t = splitLeaf(leaf("A"), "A", "B", "row");
    expect(t).toEqual({
      type: "split",
      dir: "row",
      children: [
        { type: "leaf", sessionId: "A" },
        { type: "leaf", sessionId: "B" },
      ],
    });
    expect(paneIds(t)).toEqual(["A", "B"]);
    expect(paneCount(t)).toBe(2);
  });

  it("splitLeaf is a no-op when the target isn't present", () => {
    const t = leaf("A");
    expect(splitLeaf(t, "Z", "B", "row")).toEqual(t);
  });

  it("same-direction split appends a flat sibling (3 columns, not nested)", () => {
    let t: PaneNode = leaf("A");
    t = splitLeaf(t, "A", "B", "row"); // [A|B]
    t = splitLeaf(t, "B", "C", "row"); // [A|B|C] — flat, NOT [A|[B|C]]
    expect(t).toEqual({
      type: "split",
      dir: "row",
      children: [
        { type: "leaf", sessionId: "A" },
        { type: "leaf", sessionId: "B" },
        { type: "leaf", sessionId: "C" },
      ],
    });
    expect(paneIds(t)).toEqual(["A", "B", "C"]);
  });

  it("cross-direction split nests (A left, B/C stacked right)", () => {
    let t: PaneNode = leaf("A");
    t = splitLeaf(t, "A", "B", "row"); // [A|B]
    t = splitLeaf(t, "B", "C", "col"); // [A | (B/C)]
    expect(t).toEqual({
      type: "split",
      dir: "row",
      children: [
        { type: "leaf", sessionId: "A" },
        {
          type: "split",
          dir: "col",
          children: [
            { type: "leaf", sessionId: "B" },
            { type: "leaf", sessionId: "C" },
          ],
        },
      ],
    });
    expect(paneIds(t)).toEqual(["A", "B", "C"]);
    expect(paneCount(t)).toBe(3);
  });

  it("removeLeaf drops one of three siblings, keeping the split", () => {
    const t: PaneNode = {
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("B"), leaf("C")],
    };
    expect(removeLeaf(t, "B")).toEqual({
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("C")],
    });
  });

  it("removeLeaf KEEPS a now-single-child split (no collapse — render stability)", () => {
    // Collapsing to the bare survivor would flip the element type React renders
    // at that position and remount the survivor's xterm (losing scrollback), so
    // the single-child split is deliberately retained — it renders identically.
    const t = splitLeaf(leaf("A"), "A", "B", "row"); // [A|B]
    expect(removeLeaf(t, "A")).toEqual({ type: "split", dir: "row", children: [leaf("B")] });
    expect(removeLeaf(t, "B")).toEqual({ type: "split", dir: "row", children: [leaf("A")] });
  });

  it("removeLeaf on the last pane returns null (tab is gone)", () => {
    expect(removeLeaf(leaf("A"), "A")).toBeNull();
  });

  it("removeLeaf keeps a nested split as a single-child split (no recursive collapse)", () => {
    // [A | (B/C)] — remove C → the col split retains B as its only child rather
    // than collapsing to a bare leaf B, so A (the untouched pane) never remounts.
    let t: PaneNode = leaf("A");
    t = splitLeaf(t, "A", "B", "row");
    t = splitLeaf(t, "B", "C", "col");
    expect(removeLeaf(t, "C")).toEqual({
      type: "split",
      dir: "row",
      children: [leaf("A"), { type: "split", dir: "col", children: [leaf("B")] }],
    });
  });

  it("insertNodeAt places a node after (right/bottom) or before (left/top) a bare leaf", () => {
    expect(insertNodeAt(leaf("A"), "A", leaf("B"), "row", false)).toEqual({
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("B")], // B to the right
    });
    expect(insertNodeAt(leaf("A"), "A", leaf("B"), "col", true)).toEqual({
      type: "split",
      dir: "col",
      children: [leaf("B"), leaf("A")], // B above
    });
  });

  it("insertNodeAt does a flat sibling insert in a same-direction parent", () => {
    const t: PaneNode = { type: "split", dir: "row", children: [leaf("A"), leaf("B")] };
    // Drop C on B's left → [A, C, B]; on B's right → [A, B, C].
    expect(insertNodeAt(t, "B", leaf("C"), "row", true)).toEqual({
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("C"), leaf("B")],
    });
    expect(insertNodeAt(t, "B", leaf("C"), "row", false)).toEqual({
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("B"), leaf("C")],
    });
  });

  it("insertNodeAt can insert a whole subtree (a dragged multi-pane tab)", () => {
    // Drag a 2-pane tab (X|Y) onto A's bottom edge in a single-pane tab.
    const dragged: PaneNode = { type: "split", dir: "row", children: [leaf("X"), leaf("Y")] };
    expect(insertNodeAt(leaf("A"), "A", dragged, "col", false)).toEqual({
      type: "split",
      dir: "col",
      children: [leaf("A"), dragged],
    });
  });

  it("insertNodeAt is a no-op when the target leaf is absent", () => {
    const t: PaneNode = { type: "split", dir: "row", children: [leaf("A"), leaf("B")] };
    expect(insertNodeAt(t, "Z", leaf("C"), "row", false)).toEqual(t);
  });

  it("removeLeaf of an absent id leaves the tree unchanged", () => {
    const t: PaneNode = { type: "split", dir: "row", children: [leaf("A"), leaf("B")] };
    expect(removeLeaf(t, "Z")).toEqual(t);
  });

  it("neighborPane picks the previous sibling, else the first survivor", () => {
    const t: PaneNode = {
      type: "split",
      dir: "row",
      children: [leaf("A"), leaf("B"), leaf("C")],
    };
    expect(neighborPane(t, "B")).toBe("A"); // previous sibling
    expect(neighborPane(t, "A")).toBe("B"); // no previous → first survivor
    expect(neighborPane(leaf("A"), "A")).toBeNull(); // nothing left
  });

  it("renameLeaf swaps a session id everywhere it appears", () => {
    const t: PaneNode = {
      type: "split",
      dir: "row",
      children: [leaf("A"), { type: "split", dir: "col", children: [leaf("B"), leaf("C")] }],
    };
    const r = renameLeaf(t, "B", "B2");
    expect(paneIds(r)).toEqual(["A", "B2", "C"]);
    expect(hasPane(r, "B")).toBe(false);
    // A no-op rename leaves the tree equal.
    expect(renameLeaf(t, "Z", "Z2")).toEqual(t);
  });

  it("original tree is never mutated (immutability)", () => {
    const t: PaneNode = { type: "split", dir: "row", children: [leaf("A"), leaf("B")] };
    const snapshot = JSON.parse(JSON.stringify(t));
    splitLeaf(t, "A", "C", "col");
    removeLeaf(t, "B");
    expect(t).toEqual(snapshot);
  });
});
