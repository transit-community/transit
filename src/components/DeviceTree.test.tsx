import { describe, expect, it } from "vitest";

import type { DeviceMeta } from "@/lib/api";

import {
  buildTree,
  collectSubtreeDevices,
  flattenVisibleDevices,
  resolveDeviceMove,
  type GroupNode,
} from "./DeviceTree";

function d(id: string, group: string | null): DeviceMeta {
  return {
    id,
    host: "h",
    port: 22,
    vendor: "junos",
    group,
    auth: "p",
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    color: null,
    tags: [],
    allow_weak_crypto: null,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
  };
}

describe("buildTree", () => {
  it("places ungrouped devices at root", () => {
    const tree = buildTree([d("a", null), d("b", null)]);
    expect(tree).toEqual([
      { kind: "device", device: d("a", null) },
      { kind: "device", device: d("b", null) },
    ]);
  });

  it("creates a single nested chain for a path-string group", () => {
    const tree = buildTree([d("vEX1", "Lab/Junos")]);
    expect(tree).toMatchObject([
      {
        kind: "group",
        name: "Lab",
        path: "Lab",
        children: [
          {
            kind: "group",
            name: "Junos",
            path: "Lab/Junos",
            children: [{ kind: "device", device: { id: "vEX1" } }],
          },
        ],
      },
    ]);
  });

  it("merges devices that share group prefixes", () => {
    const tree = buildTree([
      d("a", "Lab/Junos"),
      d("b", "Lab/Junos"),
      d("c", "Lab/Cisco"),
      d("d", "Prod/Routers"),
    ]);
    // Top-level: Lab, Prod (alphabetical, groups before devices).
    expect(tree).toHaveLength(2);
    expect(tree[0]).toMatchObject({ kind: "group", name: "Lab" });
    expect(tree[1]).toMatchObject({ kind: "group", name: "Prod" });

    // Lab has Cisco + Junos sub-groups (alphabetical).
    const lab = tree[0];
    if (lab.kind !== "group") throw new Error("expected group");
    expect(lab.children.map((c) => (c.kind === "group" ? c.name : "?"))).toEqual([
      "Cisco",
      "Junos",
    ]);
  });

  it("sorts groups before devices and devices alphabetically", () => {
    const tree = buildTree([d("zzz", null), d("aaa", null), d("inGroup", "G")]);
    expect(tree.map((n) => (n.kind === "group" ? `g:${n.name}` : `d:${n.device.id}`))).toEqual([
      "g:G",
      "d:aaa",
      "d:zzz",
    ]);
  });

  it("ignores empty path segments (defensive against //)", () => {
    const tree = buildTree([d("x", "//Lab//Junos//")]);
    expect(tree).toMatchObject([
      {
        kind: "group",
        name: "Lab",
        children: [
          {
            kind: "group",
            name: "Junos",
            children: [{ kind: "device", device: { id: "x" } }],
          },
        ],
      },
    ]);
  });

  // ----- registry union (empty / standalone groups) -----

  it("materializes a registry group that has no devices", () => {
    const tree = buildTree([], ["Lab/Empty"]);
    expect(tree).toMatchObject([
      {
        kind: "group",
        name: "Lab",
        path: "Lab",
        children: [{ kind: "group", name: "Empty", path: "Lab/Empty", children: [] }],
      },
    ]);
  });

  it("de-dupes a registry path that a device also implies", () => {
    const tree = buildTree([d("vEX1", "Lab/Junos")], ["Lab/Junos"]);
    // One "Lab" node, one "Junos" child holding the device — not two.
    expect(tree).toHaveLength(1);
    const lab = tree[0];
    if (lab.kind !== "group") throw new Error("expected group");
    expect(lab.children).toHaveLength(1);
    expect(lab.children[0]).toMatchObject({
      kind: "group",
      name: "Junos",
      children: [{ kind: "device", device: { id: "vEX1" } }],
    });
  });

  it("synthesizes ancestors for a registry-only nested path", () => {
    const tree = buildTree([], ["A/B/C"]);
    expect(tree).toMatchObject([
      {
        kind: "group",
        name: "A",
        children: [
          { kind: "group", name: "B", children: [{ kind: "group", name: "C", children: [] }] },
        ],
      },
    ]);
  });
});

describe("flattenVisibleDevices (v2.8.1 multi-select order)", () => {
  it("walks the tree depth-first in render order", () => {
    const tree = buildTree([
      d("root-z", null),
      d("vEX1", "Lab/Junos"),
      d("vEX2", "Lab"),
      d("edge1", "Prod"),
    ]);
    expect(flattenVisibleDevices(tree, {}).map((x) => x.id)).toEqual([
      // Lab → (Junos → vEX1), vEX2; Prod → edge1; then root devices.
      "vEX1",
      "vEX2",
      "edge1",
      "root-z",
    ]);
  });

  it("skips the contents of collapsed groups (nested subtrees included)", () => {
    const tree = buildTree([
      d("vEX1", "Lab/Junos"),
      d("vEX2", "Lab"),
      d("edge1", "Prod"),
      d("loose", null),
    ]);
    expect(flattenVisibleDevices(tree, { Lab: true }).map((x) => x.id)).toEqual(["edge1", "loose"]);
    // Collapsing only the nested subgroup hides just its devices.
    expect(flattenVisibleDevices(tree, { "Lab/Junos": true }).map((x) => x.id)).toEqual([
      "vEX2",
      "edge1",
      "loose",
    ]);
  });
});

describe("collectSubtreeDevices (v2.8.1 launch all in group)", () => {
  function labNode(): GroupNode {
    const tree = buildTree([d("vEX1", "Lab/Junos"), d("vEX2", "Lab"), d("edge1", "Prod")]);
    const lab = tree[0];
    if (lab.kind !== "group" || lab.name !== "Lab") throw new Error("expected Lab group first");
    return lab;
  }

  it("collects nested subgroup devices in tree order", () => {
    expect(collectSubtreeDevices(labNode()).map((x) => x.id)).toEqual(["vEX1", "vEX2"]);
  });

  it("returns empty for a device-less group", () => {
    const tree = buildTree([], ["Empty/Nested"]);
    const empty = tree[0];
    if (empty.kind !== "group") throw new Error("expected group");
    expect(collectSubtreeDevices(empty)).toEqual([]);
  });
});

describe("resolveDeviceMove", () => {
  const group = (path: string) => ({ kind: "group", path });

  it("moves a device into a target group", () => {
    expect(resolveDeviceMove("vEX1", "Lab", group("Prod/Routers"))).toEqual({
      id: "vEX1",
      group: "Prod/Routers",
    });
  });

  it("ungroups when dropped on the empty-path (root) zone", () => {
    expect(resolveDeviceMove("vEX1", "Lab", group(""))).toEqual({ id: "vEX1", group: null });
  });

  it("is a no-op when dropped back in the same group", () => {
    expect(resolveDeviceMove("vEX1", "Lab", group("Lab"))).toBeNull();
    // null current vs root target ("") is also unchanged.
    expect(resolveDeviceMove("vEX1", null, group(""))).toBeNull();
  });

  it("is a no-op when not over a group target", () => {
    expect(resolveDeviceMove("vEX1", "Lab", undefined)).toBeNull();
    expect(resolveDeviceMove("vEX1", "Lab", { kind: "device" })).toBeNull();
  });
});
