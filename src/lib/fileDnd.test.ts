import { describe, expect, it } from "vitest";

import {
  FILES_DND_MIME,
  parseFilesDragPayload,
  serializeFilesDrag,
  type FilesDragPayload,
} from "@/lib/fileDnd";

const payload: FilesDragPayload = {
  side: "local",
  sessionId: "s1",
  paths: ["/Users/alice/a.conf", "/Users/alice/b.conf"],
};

describe("fileDnd", () => {
  it("uses a Transit-specific MIME type (what a dragover handler can check)", () => {
    // The VALUE is unreadable until the drop in every browser, so the type
    // list is the only signal a dragover has — it must be ours alone.
    expect(FILES_DND_MIME).toBe("application/x-transit-files");
  });

  it("round-trips a payload", () => {
    expect(parseFilesDragPayload(serializeFilesDrag(payload))).toEqual(payload);
  });

  it("returns null for anything that isn't our exact shape", () => {
    // A drop handler must never throw: `dataTransfer` content is
    // attacker-adjacent (any page or app can claim a MIME type).
    expect(parseFilesDragPayload(null)).toBeNull();
    expect(parseFilesDragPayload(undefined)).toBeNull();
    expect(parseFilesDragPayload("")).toBeNull();
    expect(parseFilesDragPayload("not json")).toBeNull();
    expect(parseFilesDragPayload("[1,2,3]")).toBeNull();
    expect(parseFilesDragPayload("null")).toBeNull();
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, side: "elsewhere" }))).toBeNull();
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, sessionId: "" }))).toBeNull();
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, sessionId: 7 }))).toBeNull();
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, paths: "one" }))).toBeNull();
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, paths: [] }))).toBeNull();
  });

  it("drops non-string / empty path entries and refuses a payload left with none", () => {
    const mixed = JSON.stringify({ ...payload, paths: ["/a", "", 5, null, "/b"] });
    expect(parseFilesDragPayload(mixed)?.paths).toEqual(["/a", "/b"]);
    expect(parseFilesDragPayload(JSON.stringify({ ...payload, paths: ["", null] }))).toBeNull();
  });
});
