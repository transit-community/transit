import { describe, expect, it } from "vitest";

import { computeLabels, sessionDisplayLabel } from "@/lib/sessionLabels";
import { type SessionTab } from "@/stores/uiStore";

function tab(sessionId: string, deviceId: string, customLabel?: string): SessionTab {
  return { sessionId, deviceId, ended: false, customLabel: customLabel ?? null };
}

describe("computeLabels", () => {
  it("bare device id first, ' (N)' for later same-device sessions; customLabel verbatim", () => {
    expect(
      computeLabels([
        tab("a", "vEX1"),
        tab("b", "vEX2"),
        tab("c", "vEX1"),
        tab("d", "vEX1", "Core"),
      ]),
    ).toEqual(["vEX1", "vEX2", "vEX1 (2)", "Core"]);
  });
});

describe("sessionDisplayLabel", () => {
  const sessions = [tab("sess-1", "vEX1"), tab("sess-2", "vEX1"), tab("sess-3", "vEX2", "Edge")];

  it("resolves a known session to the same label its tab shows", () => {
    expect(sessionDisplayLabel(sessions, "sess-1")).toEqual({ label: "vEX1", resolved: true });
    expect(sessionDisplayLabel(sessions, "sess-2")).toEqual({ label: "vEX1 (2)", resolved: true });
    expect(sessionDisplayLabel(sessions, "sess-3")).toEqual({ label: "Edge", resolved: true });
  });

  it("falls back to the raw id (resolved:false) for an unknown / closed session", () => {
    expect(sessionDisplayLabel(sessions, "fff01105-0656")).toEqual({
      label: "fff01105-0656",
      resolved: false,
    });
    expect(sessionDisplayLabel([], "anything")).toEqual({ label: "anything", resolved: false });
  });
});
