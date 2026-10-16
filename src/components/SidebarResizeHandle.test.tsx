import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  SIDEBAR_DEFAULT_WIDTH,
  SIDEBAR_MAX_WIDTH_PCT,
  SIDEBAR_MIN_WIDTH,
  SidebarResizeHandle,
} from "@/components/SidebarResizeHandle";
import { useUiStore } from "@/stores/uiStore";

/** v6.5.2 — the sidebar rail's drag handle. Rendered standalone: the
 *  handle's whole contract is (pointer/keyboard) → clamped width in the
 *  store, and mounting a full sidebar would drag in the inventory
 *  queries without testing anything more. The five sidebars' use of it
 *  is a two-line insertion each, covered by their own render tests. */
describe("SidebarResizeHandle (v6.5.2)", () => {
  beforeEach(() => {
    localStorage.clear();
    useUiStore.setState((s) => ({ preferences: { ...s.preferences, sidebarWidth: null } }));
    // jsdom's default innerWidth is 1024; pin it so the max clamp
    // (50% → 600px) is a stated number rather than an inherited one.
    Object.defineProperty(window, "innerWidth", { value: 1200, configurable: true });
  });

  const width = () => useUiStore.getState().preferences.sidebarWidth;

  function drag(clientX: number) {
    const handle = screen.getByTestId("sidebar-resize-handle");
    act(() => {
      handle.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, clientX: 280 }));
    });
    act(() => {
      window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX }));
    });
    act(() => {
      window.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    });
  }

  it("renders a vertical separator", () => {
    render(<SidebarResizeHandle />);
    const handle = screen.getByTestId("sidebar-resize-handle");
    expect(handle).toHaveAttribute("role", "separator");
    expect(handle).toHaveAttribute("aria-orientation", "vertical");
  });

  it("drag sets the width to the cursor's x position", () => {
    render(<SidebarResizeHandle />);
    // The rail is anchored on the LEFT, so its width IS clientX —
    // unlike the chat panel, where width = innerWidth - clientX.
    drag(430);
    expect(width()).toBe(430);
  });

  it("clamps below the minimum", () => {
    render(<SidebarResizeHandle />);
    drag(40);
    expect(width()).toBe(SIDEBAR_MIN_WIDTH);
  });

  it("clamps above 50% of the viewport", () => {
    render(<SidebarResizeHandle />);
    drag(1100);
    expect(width()).toBe(Math.floor(1200 * SIDEBAR_MAX_WIDTH_PCT));
  });

  it("ignores mousemove after mouseup (the drag is over)", () => {
    render(<SidebarResizeHandle />);
    drag(430);
    act(() => {
      window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 500 }));
    });
    expect(width()).toBe(430);
  });

  it("double-click resets to the default width", () => {
    render(<SidebarResizeHandle />);
    drag(500);
    expect(width()).toBe(500);
    act(() => {
      screen
        .getByTestId("sidebar-resize-handle")
        .dispatchEvent(new MouseEvent("dblclick", { bubbles: true }));
    });
    expect(width()).toBe(SIDEBAR_DEFAULT_WIDTH);
  });

  it("is keyboard-resizable — ArrowRight widens, ArrowLeft narrows", () => {
    render(<SidebarResizeHandle />);
    const handle = screen.getByTestId("sidebar-resize-handle");
    expect(handle).toHaveAttribute("tabindex", "0");

    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "ArrowRight" }));
    });
    expect(width()).toBe(SIDEBAR_DEFAULT_WIDTH + 16);

    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "ArrowLeft" }));
    });
    expect(width()).toBe(SIDEBAR_DEFAULT_WIDTH);
  });

  it("Shift+Arrow steps in a coarser increment, Home restores the default", () => {
    render(<SidebarResizeHandle />);
    const handle = screen.getByTestId("sidebar-resize-handle");
    act(() => {
      handle.dispatchEvent(
        new KeyboardEvent("keydown", { bubbles: true, key: "ArrowRight", shiftKey: true }),
      );
    });
    expect(width()).toBe(SIDEBAR_DEFAULT_WIDTH + 64);

    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Home" }));
    });
    expect(width()).toBe(SIDEBAR_DEFAULT_WIDTH);
  });

  it("keyboard resize obeys the same clamps as the drag", () => {
    render(<SidebarResizeHandle />);
    const handle = screen.getByTestId("sidebar-resize-handle");
    // act() so React re-renders before the keydown — the handler reads
    // the CURRENT width off the store through the render, not a closure
    // captured at mount.
    act(() => {
      useUiStore.setState((s) => ({
        preferences: { ...s.preferences, sidebarWidth: SIDEBAR_MIN_WIDTH },
      }));
    });
    act(() => {
      handle.dispatchEvent(
        new KeyboardEvent("keydown", { bubbles: true, key: "ArrowLeft", shiftKey: true }),
      );
    });
    expect(width()).toBe(SIDEBAR_MIN_WIDTH);
  });
});
