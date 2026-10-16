import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { emit } from "@tauri-apps/api/event";

import { useGlobalHotkeys } from "@/lib/hotkeys";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@tauri-apps/api/event", () => ({
  emit: vi.fn(),
}));

function fireKey(opts: {
  key: string;
  metaKey?: boolean;
  ctrlKey?: boolean;
  altKey?: boolean;
  shiftKey?: boolean;
}) {
  const event = new KeyboardEvent("keydown", {
    key: opts.key,
    metaKey: opts.metaKey ?? false,
    ctrlKey: opts.ctrlKey ?? false,
    altKey: opts.altKey ?? false,
    shiftKey: opts.shiftKey ?? false,
    bubbles: true,
    cancelable: true,
  });
  act(() => {
    window.dispatchEvent(event);
  });
}

beforeEach(() => {
  vi.mocked(emit).mockClear();
  useUiStore.setState({
    sidebarCollapsed: false,
    chatPanelOpen: false,
    sessionInfoPanelOpen: false,
    commandPaletteOpen: false,
  });
});

afterEach(() => {
  // Clean up any focused element a test left behind.
  document.body.innerHTML = "";
  if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
});

describe("useGlobalHotkeys", () => {
  it("Cmd+B toggles sidebar (macOS path)", () => {
    renderHook(() => useGlobalHotkeys());
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
    fireKey({ key: "b", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
    fireKey({ key: "b", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  it("Ctrl+B toggles sidebar (Linux/Windows path)", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b", ctrlKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
  });

  it("Cmd+J toggles chat panel", () => {
    renderHook(() => useGlobalHotkeys());
    expect(useUiStore.getState().chatPanelOpen).toBe(false);
    fireKey({ key: "j", metaKey: true });
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });

  it("Cmd+I toggles session-info panel", () => {
    renderHook(() => useGlobalHotkeys());
    expect(useUiStore.getState().sessionInfoPanelOpen).toBe(false);
    fireKey({ key: "i", metaKey: true });
    expect(useUiStore.getState().sessionInfoPanelOpen).toBe(true);
    fireKey({ key: "i", metaKey: true });
    expect(useUiStore.getState().sessionInfoPanelOpen).toBe(false);
  });

  it("uppercase key still matches (caps-lock tolerant)", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "B", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
  });

  it("ignores Cmd+Shift+B (shift-modified shouldn't hijack)", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b", metaKey: true, shiftKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  it("ignores Cmd+Alt+B (alt-modified shouldn't hijack)", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b", metaKey: true, altKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  it("ignores plain `b` without an accelerator modifier", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b" });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  it("ignores unrelated keys (Cmd+K)", () => {
    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "k", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
    expect(useUiStore.getState().chatPanelOpen).toBe(false);
  });

  it("Ctrl+B does NOT fire when xterm-helper-textarea is focused (collides with readline)", () => {
    // Simulate xterm.js's focus state.
    const ta = document.createElement("textarea");
    ta.className = "xterm-helper-textarea";
    document.body.appendChild(ta);
    ta.focus();
    expect(document.activeElement).toBe(ta);

    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b", ctrlKey: true });
    fireKey({ key: "j", ctrlKey: true });
    fireKey({ key: "i", ctrlKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
    expect(useUiStore.getState().chatPanelOpen).toBe(false);
    expect(useUiStore.getState().sessionInfoPanelOpen).toBe(false);
  });

  it("Cmd+B/I/J DO fire even when xterm-helper-textarea is focused (Cmd is OS-level, never sent to PTY)", () => {
    const ta = document.createElement("textarea");
    ta.className = "xterm-helper-textarea";
    document.body.appendChild(ta);
    ta.focus();
    expect(document.activeElement).toBe(ta);

    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "i", metaKey: true });
    expect(useUiStore.getState().sessionInfoPanelOpen).toBe(true);
    fireKey({ key: "j", metaKey: true });
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
    fireKey({ key: "b", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
  });

  it("Ctrl+B does NOT fire when focus is inside .xterm-screen", () => {
    const screen = document.createElement("div");
    screen.className = "xterm-screen";
    const inner = document.createElement("button");
    screen.appendChild(inner);
    document.body.appendChild(screen);
    inner.focus();

    renderHook(() => useGlobalHotkeys());
    fireKey({ key: "b", ctrlKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  it("unmounts cleanly without leaking listeners", () => {
    const { unmount } = renderHook(() => useGlobalHotkeys());
    unmount();
    fireKey({ key: "b", metaKey: true });
    expect(useUiStore.getState().sidebarCollapsed).toBe(false);
  });

  describe("Cmd/Ctrl+Shift+K clears the active terminal", () => {
    it("emits menu:clear-terminal when focus is OUTSIDE the terminal (Cmd path)", () => {
      renderHook(() => useGlobalHotkeys());
      fireKey({ key: "k", metaKey: true, shiftKey: true });
      expect(emit).toHaveBeenCalledWith("menu:clear-terminal");
    });

    it("emits on the Ctrl path too (Windows/Linux, where the menu accelerator is swallowed)", () => {
      renderHook(() => useGlobalHotkeys());
      fireKey({ key: "k", ctrlKey: true, shiftKey: true });
      expect(emit).toHaveBeenCalledWith("menu:clear-terminal");
    });

    it("matches the shifted key value 'K' (Shift uppercases e.key)", () => {
      renderHook(() => useGlobalHotkeys());
      fireKey({ key: "K", ctrlKey: true, shiftKey: true });
      expect(emit).toHaveBeenCalledWith("menu:clear-terminal");
    });

    it("does NOT emit when the terminal is focused — TerminalPane owns it there (and blocks the PTY byte)", () => {
      const ta = document.createElement("textarea");
      ta.className = "xterm-helper-textarea";
      document.body.appendChild(ta);
      ta.focus();
      expect(document.activeElement).toBe(ta);

      renderHook(() => useGlobalHotkeys());
      fireKey({ key: "k", ctrlKey: true, shiftKey: true });
      expect(emit).not.toHaveBeenCalled();
    });

    it("never opens the command palette (Shift distinguishes it from Cmd/Ctrl+K)", () => {
      renderHook(() => useGlobalHotkeys());
      fireKey({ key: "k", metaKey: true, shiftKey: true });
      expect(useUiStore.getState().commandPaletteOpen).toBe(false);
    });
  });
});
