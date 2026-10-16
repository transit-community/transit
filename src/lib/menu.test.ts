import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Handler = () => void;
const listeners = new Map<string, Handler[]>();

vi.mock("@tauri-apps/api/event", () => ({
  emit: vi.fn().mockResolvedValue(undefined),
  listen: vi.fn(async (topic: string, handler: Handler) => {
    listeners.set(topic, [...(listeners.get(topic) ?? []), handler]);
    return () => {
      listeners.set(
        topic,
        (listeners.get(topic) ?? []).filter((h) => h !== handler),
      );
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  clearScrollback: vi.fn().mockResolvedValue(undefined),
  setMenuChecked: vi.fn().mockResolvedValue(undefined),
}));

import { emit } from "@tauri-apps/api/event";

import { clearScrollback } from "@/lib/api";
import { useNativeMenu } from "@/lib/menu";
import { useUiStore } from "@/stores/uiStore";

function fireMenu(topic: string) {
  act(() => {
    for (const h of listeners.get(topic) ?? []) h();
  });
}

beforeEach(() => {
  listeners.clear();
  useUiStore.setState({ sessions: [], activeTabId: null, activePaneId: null, lastPaneByTab: {} });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("useNativeMenu — View → Clear Terminal", () => {
  async function mountMenu() {
    renderHook(() => useNativeMenu());
    await waitFor(() => expect(listeners.has("menu:clear-terminal")).toBe(true));
  }

  it("clears the ring AND emits the visual-clear event for a PTY tab", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    await mountMenu();
    fireMenu("menu:clear-terminal");

    await waitFor(() => expect(clearScrollback).toHaveBeenCalledWith("s1"));
    expect(emit).toHaveBeenCalledWith("ui:clear-terminal:s1");
  });

  it("still clears a local shell (it has a real PTY)", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "l1", deviceId: "zsh", ended: false, kind: "local" }],
      activeTabId: "l1",
    });
    await mountMenu();
    fireMenu("menu:clear-terminal");
    await waitFor(() => expect(clearScrollback).toHaveBeenCalledWith("l1"));
  });

  it("skips a tab with no PTY (API / Files) rather than firing a doomed IPC", async () => {
    for (const kind of ["api", "files"] as const) {
      vi.mocked(clearScrollback).mockClear();
      vi.mocked(emit).mockClear();
      listeners.clear();
      useUiStore.setState({
        sessions: [{ sessionId: "t1", deviceId: "x", ended: false, kind }],
        activeTabId: "t1",
      });
      await mountMenu();
      fireMenu("menu:clear-terminal");
      expect(clearScrollback).not.toHaveBeenCalled();
      expect(emit).not.toHaveBeenCalledWith("ui:clear-terminal:t1");
    }
  });

  it("is a no-op with no active tab", async () => {
    await mountMenu();
    fireMenu("menu:clear-terminal");
    expect(clearScrollback).not.toHaveBeenCalled();
  });
});

describe("useNativeMenu — Clear Terminal targets the focused PANE (v6.4.0)", () => {
  async function mountMenu() {
    renderHook(() => useNativeMenu());
    await waitFor(() => expect(listeners.has("menu:clear-terminal")).toBe(true));
  }

  /** Tab whose primary is s1, holding panes s1 | s2. */
  function seedSplit() {
    useUiStore.setState({
      sessions: [
        {
          sessionId: "s1",
          deviceId: "vEX1",
          ended: false,
          layout: {
            type: "split",
            dir: "row",
            children: [
              { type: "leaf", sessionId: "s1" },
              { type: "leaf", sessionId: "s2" },
            ],
          },
        },
        { sessionId: "s2", deviceId: "vEX2", ended: false, splitWith: "s1" },
      ],
      activeTabId: "s1",
      activePaneId: null,
      lastPaneByTab: {},
    });
  }

  // TerminalPane claims the Cmd/Ctrl+Shift+K chord itself and emits this same
  // event, so before v6.4.0 pressing it in a split's RIGHT pane wiped the LEFT
  // one — the same activeTabId-means-two-things bug as the button bar.
  it("clears the focused pane, not the tab's primary", async () => {
    seedSplit();
    useUiStore.getState().setActivePane("s2");
    await mountMenu();
    fireMenu("menu:clear-terminal");

    await waitFor(() => expect(clearScrollback).toHaveBeenCalledWith("s2"));
    expect(emit).toHaveBeenCalledWith("ui:clear-terminal:s2");
    expect(clearScrollback).not.toHaveBeenCalledWith("s1");
    expect(emit).not.toHaveBeenCalledWith("ui:clear-terminal:s1");
  });

  it("falls back to the primary when no pane has been focused", async () => {
    seedSplit();
    await mountMenu();
    fireMenu("menu:clear-terminal");

    await waitFor(() => expect(clearScrollback).toHaveBeenCalledWith("s1"));
  });
});
