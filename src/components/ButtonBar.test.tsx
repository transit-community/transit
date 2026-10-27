import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ButtonBar } from "@/components/ButtonBar";
import { deviceColorTint } from "@/lib/deviceColors";
import {
  type ButtonBar as ButtonBarModel,
  type ButtonBarButton,
  useUiStore,
} from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  sendInput: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  readText: vi.fn().mockResolvedValue(""),
}));

vi.mock("@tauri-apps/api/event", () => ({
  emit: vi.fn().mockResolvedValue(undefined),
}));

// Partial mock: the real helper runs, but wrapped in a spy so the tint
// test can assert the wiring. happy-dom >= 20.12.1 validates inline color
// values and silently DROPS any `color-mix()` (probed on 21.0.4: every
// color-mix form, even with literal colors, leaves `style` null), so the
// rendered attribute can no longer carry the assertion; the helper's own
// unit test (deviceColors.test.ts) pins the color-mix string itself.
vi.mock("@/lib/deviceColors", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/deviceColors")>();
  return { ...actual, deviceColorTint: vi.fn(actual.deviceColorTint) };
});

// jsdom lacks ResizeObserver; the bar's overflow-scroll hook needs a
// stub (same pattern as TerminalArea.test.tsx).
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

/** Seed prefs. `buttonBarButtons` populates a single "Default" bar
 *  (the v1.4.0-era tests); `bars` seeds the full v2.7.0 multi-bar
 *  shape. */
function setPrefs(partial: {
  showButtonBar?: boolean;
  buttonBarButtons?: ButtonBarButton[];
  bars?: ButtonBarModel[];
  activeBarId?: string;
}) {
  useUiStore.setState((s) => {
    const bars = partial.bars ?? [
      { id: "bar-1", name: "Default", buttons: partial.buttonBarButtons ?? [] },
    ];
    return {
      preferences: {
        ...s.preferences,
        showButtonBar: partial.showButtonBar ?? false,
        buttonBars: bars,
        activeButtonBarId: partial.activeBarId ?? bars[0].id,
      },
    };
  });
}

/** The active bar's buttons (what the strip renders + edits). */
function activeButtons(): ButtonBarButton[] {
  const p = useUiStore.getState().preferences;
  return (p.buttonBars.find((b) => b.id === p.activeButtonBarId) ?? p.buttonBars[0]).buttons;
}

beforeEach(() => {
  useUiStore.setState({ sessions: [], activeTabId: null, activePaneId: null, lastPaneByTab: {} });
  setPrefs({ showButtonBar: false, buttonBarButtons: [] });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("ButtonBar", () => {
  it("renders nothing when the bar is hidden", () => {
    render(<ButtonBar />);
    expect(screen.queryByTestId("button-bar")).not.toBeInTheDocument();
  });

  it("shows a 'New button…' affordance when shown empty", () => {
    setPrefs({ showButtonBar: true });
    render(<ButtonBar />);
    expect(screen.getByTestId("button-bar")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /new button/i })).toBeInTheDocument();
  });

  it("clicking a button sends its macro to the active session", async () => {
    const { sendInput } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [{ id: "b1", label: "ver", value: "show version\\r" }],
    });
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    // "show version\r" base64-no-pad — command + Enter to the active PTY.
    await waitFor(() =>
      expect(vi.mocked(sendInput)).toHaveBeenCalledWith(
        "s1",
        btoa("show version\r").replace(/=+$/, ""),
      ),
    );
  });

  it("shades a colored button and leaves an uncolored one plain (Jeff Kish)", () => {
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [
        { id: "b1", label: "voip", value: "x", color: "blue" },
        { id: "b2", label: "plain", value: "y" },
      ],
    });
    const tint = vi.mocked(deviceColorTint);
    tint.mockClear();
    render(<ButtonBar />);

    // The colored button is styled with the background tint (color-mix over
    // the theme-aware palette var); the uncolored one gets no tint and keeps
    // the default. Asserted at the helper seam (see the module mock above).
    expect(screen.getByRole("button", { name: "voip" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "plain" })).toBeTruthy();
    const results = tint.mock.calls.map(([token], i) => ({
      token,
      bg: tint.mock.results[i]?.value?.backgroundColor,
    }));
    expect(results).toContainEqual({
      token: "blue",
      bg: expect.stringContaining("color-mix"),
    });
    expect(results).toContainEqual({ token: undefined, bg: undefined });
    expect(results.filter((r) => r.bg !== undefined).map((r) => r.token)).toEqual(["blue"]);
  });

  it("clicking a button returns focus to the active terminal", async () => {
    const { emit } = await import("@tauri-apps/api/event");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [{ id: "b1", label: "ver", value: "show version\\r" }],
    });
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    // The pane listens for this per-session event and calls term.focus().
    await waitFor(() => expect(vi.mocked(emit)).toHaveBeenCalledWith("ui:focus-terminal:s1"));
  });

  it("clicking a button is a no-op when the active session has ended", async () => {
    const { sendInput } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true }],
      activeTabId: "s1",
    });
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [{ id: "b1", label: "ver", value: "show version\\r" }],
    });
    render(<ButtonBar />);

    const { emit } = await import("@tauri-apps/api/event");
    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(vi.mocked(sendInput)).not.toHaveBeenCalled();
    // No live session → no focus hand-back either.
    expect(vi.mocked(emit)).not.toHaveBeenCalled();
  });

  it("right-click → Hide button bar turns the bar off", async () => {
    setPrefs({ showButtonBar: true });
    render(<ButtonBar />);
    await userEvent.pointer({ keys: "[MouseRight]", target: screen.getByTestId("button-bar") });
    await userEvent.click(await screen.findByText("Hide button bar"));
    expect(useUiStore.getState().preferences.showButtonBar).toBe(false);
  });

  it("New button… → fill + OK adds a macro to the store", async () => {
    setPrefs({ showButtonBar: true });
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: /new button/i }));
    await userEvent.type(screen.getByLabelText("Label"), "ping");
    await userEvent.type(screen.getByLabelText("String"), "ping 1.1.1.1\\r");
    await userEvent.click(screen.getByTestId("map-button-save"));

    const buttons = activeButtons();
    expect(buttons).toHaveLength(1);
    expect(buttons[0]).toMatchObject({ label: "ping", value: "ping 1.1.1.1\\r" });
  });

  describe("agent-target buttons (v6.1.0)", () => {
    it("fills the AI composer instead of sending bytes to the device", async () => {
      const { sendInput } = await import("@/lib/api");
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }] as never,
        activeTabId: "s1",
        chatPanelOpen: true,
      });
      setPrefs({
        showButtonBar: true,
        bars: [
          {
            id: "bar-1",
            name: "Default",
            buttons: [
              { id: "b1", label: "audit", value: "audit interface errors", target: "agent" },
            ],
          },
        ],
        activeBarId: "bar-1",
      });
      render(<ButtonBar />);

      await userEvent.click(screen.getByRole("button", { name: /audit/ }));

      // The whole point: nothing reaches the PTY.
      await waitFor(() =>
        expect(useUiStore.getState().pendingAgentPrompt).toBe("audit interface errors"),
      );
      expect(vi.mocked(sendInput)).not.toHaveBeenCalled();
    });

    it("opens the AI panel first when it is closed", async () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }] as never,
        activeTabId: "s1",
        chatPanelOpen: false,
      });
      setPrefs({
        showButtonBar: true,
        bars: [
          {
            id: "bar-1",
            name: "Default",
            buttons: [{ id: "b1", label: "why", value: "why is BGP down", target: "agent" }],
          },
        ],
        activeBarId: "bar-1",
      });
      render(<ButtonBar />);

      await userEvent.click(screen.getByRole("button", { name: /why/ }));

      // A prompt dropped into a composer nobody can see is a lost click.
      expect(useUiStore.getState().chatPanelOpen).toBe(true);
    });

    it("works with no live session — a prompt is not device input", async () => {
      useUiStore.setState({ sessions: [], activeTabId: null, chatPanelOpen: true });
      setPrefs({
        showButtonBar: true,
        bars: [
          {
            id: "bar-1",
            name: "Default",
            buttons: [{ id: "b1", label: "ask", value: "explain this capture", target: "agent" }],
          },
        ],
        activeBarId: "bar-1",
      });
      render(<ButtonBar />);

      await userEvent.click(screen.getByRole("button", { name: /ask/ }));

      // The PTY guards (no active tab / ended / no PTY) must NOT gate an
      // agent button — there is no device involved.
      await waitFor(() =>
        expect(useUiStore.getState().pendingAgentPrompt).toBe("explain this capture"),
      );
    });
  });

  describe("multiple bars (v2.7.0)", () => {
    const TWO_BARS: ButtonBarModel[] = [
      {
        id: "bar-voip",
        name: "VOIP",
        buttons: [{ id: "v1", label: "mute", value: "mute\\r" }],
      },
      {
        id: "bar-net",
        name: "Routers",
        buttons: [{ id: "n1", label: "ver", value: "show version\\r" }],
      },
    ];

    it("renders no cycle cluster with a single bar (v1.4.0 look preserved)", () => {
      setPrefs({ showButtonBar: true, buttonBarButtons: [] });
      render(<ButtonBar />);
      expect(screen.queryByTestId("button-bar-cycle-up")).not.toBeInTheDocument();
      expect(screen.queryByTestId("button-bar-name")).not.toBeInTheDocument();
    });

    it("cycling with the chevrons switches the rendered buttons and wraps", async () => {
      setPrefs({ showButtonBar: true, bars: TWO_BARS, activeBarId: "bar-voip" });
      render(<ButtonBar />);
      expect(screen.getByRole("button", { name: "mute" })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "ver" })).not.toBeInTheDocument();

      await userEvent.click(screen.getByTestId("button-bar-cycle-down"));
      expect(screen.getByRole("button", { name: "ver" })).toBeInTheDocument();
      expect(screen.getByTestId("button-bar-name")).toHaveTextContent("Routers");

      // Down again wraps back to the first bar.
      await userEvent.click(screen.getByTestId("button-bar-cycle-down"));
      expect(screen.getByRole("button", { name: "mute" })).toBeInTheDocument();
      expect(screen.getByTestId("button-bar-name")).toHaveTextContent("VOIP");

      // Up from the first wraps to the last.
      await userEvent.click(screen.getByTestId("button-bar-cycle-up"));
      expect(screen.getByTestId("button-bar-name")).toHaveTextContent("Routers");
    });

    it("the name popover jumps straight to a bar", async () => {
      setPrefs({ showButtonBar: true, bars: TWO_BARS, activeBarId: "bar-voip" });
      render(<ButtonBar />);
      await userEvent.click(screen.getByTestId("button-bar-name"));
      await userEvent.click(await screen.findByTestId("button-bar-jump-bar-net"));
      expect(useUiStore.getState().preferences.activeButtonBarId).toBe("bar-net");
      expect(screen.getByRole("button", { name: "ver" })).toBeInTheDocument();
    });

    it("Map Button edits land on the ACTIVE bar only", async () => {
      setPrefs({ showButtonBar: true, bars: TWO_BARS, activeBarId: "bar-net" });
      render(<ButtonBar />);
      await userEvent.pointer({ keys: "[MouseRight]", target: screen.getByTestId("button-bar") });
      await userEvent.click(await screen.findByText("New button…"));
      await userEvent.type(screen.getByLabelText("Label"), "ping");
      await userEvent.type(screen.getByLabelText("String"), "ping 1.1.1.1\\r");
      await userEvent.click(screen.getByTestId("map-button-save"));

      const bars = useUiStore.getState().preferences.buttonBars;
      expect(bars.find((b) => b.id === "bar-net")?.buttons).toHaveLength(2);
      expect(bars.find((b) => b.id === "bar-voip")?.buttons).toHaveLength(1);
    });

    it("context menu: New bar… creates + activates; Delete bar is disabled on the last bar", async () => {
      setPrefs({ showButtonBar: true, buttonBarButtons: [] });
      render(<ButtonBar />);
      await userEvent.pointer({ keys: "[MouseRight]", target: screen.getByTestId("button-bar") });
      // Single bar → Delete bar is disabled.
      const deleteItem = await screen.findByText("Delete bar");
      expect(deleteItem.closest("[data-disabled]")).not.toBeNull();

      await userEvent.click(screen.getByText("New bar…"));
      await userEvent.type(screen.getByLabelText("Name"), "Prod");
      await userEvent.click(screen.getByTestId("button-bar-name-save"));

      const p = useUiStore.getState().preferences;
      expect(p.buttonBars).toHaveLength(2);
      const prod = p.buttonBars.find((b) => b.name === "Prod");
      expect(prod).toBeDefined();
      // The new bar becomes active (user's about to fill it).
      expect(p.activeButtonBarId).toBe(prod?.id);
    });
  });

  describe("bar scrolling (v2.3.4)", () => {
    it("renders no chevrons while the buttons fit", () => {
      setPrefs({
        showButtonBar: true,
        buttonBarButtons: [{ id: "b1", label: "ver", value: "show version\\r" }],
      });
      render(<ButtonBar />);
      expect(screen.queryByLabelText(/scroll buttons/i)).not.toBeInTheDocument();
    });

    it("shows chevrons when the row overflows and pages on click", async () => {
      setPrefs({
        showButtonBar: true,
        buttonBarButtons: Array.from({ length: 8 }, (_, i) => ({
          id: `b${i}`,
          label: `macro-${i}`,
          value: `show something ${i}\\r`,
        })),
      });
      render(<ButtonBar />);

      // jsdom computes no layout — stub the strip's overflow metrics
      // and fire a scroll to trigger re-measure.
      const strip = screen.getByTestId("button-bar-strip");
      Object.defineProperty(strip, "scrollWidth", { configurable: true, value: 800 });
      Object.defineProperty(strip, "clientWidth", { configurable: true, value: 300 });
      Object.defineProperty(strip, "scrollLeft", {
        configurable: true,
        value: 0,
        writable: true,
      });
      // jsdom's scrollBy is a no-op; emulate browser semantics so the
      // production scrollBy branch is what's exercised.
      (strip as unknown as { scrollBy: (o: { left: number }) => void }).scrollBy = ({ left }) => {
        (strip as HTMLElement).scrollLeft += left;
      };
      fireEvent.scroll(strip);

      expect(await screen.findByLabelText("Scroll buttons right")).toBeEnabled();
      expect(screen.getByLabelText("Scroll buttons left")).toBeDisabled();

      await userEvent.click(screen.getByLabelText("Scroll buttons right"));
      // step = max(120, 300*0.6) = 180.
      expect(strip.scrollLeft).toBe(180);
      await waitFor(() => expect(screen.getByLabelText("Scroll buttons left")).toBeEnabled());
    });
  });

  it("is a no-op when the active tab has no PTY (API or Files) — v5.0.0", async () => {
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [{ id: "b1", label: "Ver", value: "show version\\r" }],
    });
    const { sendInput } = await import("@/lib/api");

    for (const kind of ["api", "files"] as const) {
      useUiStore.setState({
        sessions: [{ sessionId: "t1", deviceId: "x", ended: false, kind }],
        activeTabId: "t1",
      });
      render(<ButtonBar />);
      await userEvent.click(screen.getByRole("button", { name: "Ver" }));
      // An API tab silently misfired here before v5.0.0.
      expect(sendInput).not.toHaveBeenCalled();
      cleanup();
    }
  });
});

describe("ButtonBar split-pane targeting (v6.4.0)", () => {
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
    setPrefs({
      showButtonBar: true,
      buttonBarButtons: [{ id: "b1", label: "ver", value: "show version\\r" }],
    });
  }

  // THE user bug (2026-08-26): with two sessions side by side, macros fired
  // into the tab's primary no matter which pane the engineer was working in.
  it("sends to the FOCUSED pane, not the tab's primary", async () => {
    const { sendInput } = await import("@/lib/api");
    seedSplit();
    useUiStore.getState().setActivePane("s2");
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    await waitFor(() =>
      expect(vi.mocked(sendInput)).toHaveBeenCalledWith(
        "s2",
        btoa("show version\r").replace(/=+$/, ""),
      ),
    );
    expect(vi.mocked(sendInput)).not.toHaveBeenCalledWith("s1", expect.anything());
  });

  // Second half of the same bug: the post-send focus hand-back named the tab,
  // so every press dragged the cursor out of the pane being worked in.
  it("hands focus back to the focused pane, not the primary", async () => {
    const { emit } = await import("@tauri-apps/api/event");
    seedSplit();
    useUiStore.getState().setActivePane("s2");
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    await waitFor(() => expect(vi.mocked(emit)).toHaveBeenCalledWith("ui:focus-terminal:s2"));
    expect(vi.mocked(emit)).not.toHaveBeenCalledWith("ui:focus-terminal:s1");
  });

  it("still targets the primary when no pane has been focused yet", async () => {
    const { sendInput } = await import("@/lib/api");
    seedSplit(); // no setActivePane call — resolver falls back to the primary
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    await waitFor(() =>
      expect(vi.mocked(sendInput)).toHaveBeenCalledWith(
        "s1",
        btoa("show version\r").replace(/=+$/, ""),
      ),
    );
  });

  it("no-ops when the focused pane has ended", async () => {
    const { sendInput } = await import("@/lib/api");
    seedSplit();
    useUiStore.setState((st) => ({
      sessions: st.sessions.map((t) => (t.sessionId === "s2" ? { ...t, ended: true } : t)),
    }));
    useUiStore.getState().setActivePane("s2");
    render(<ButtonBar />);

    await userEvent.click(screen.getByRole("button", { name: "ver" }));
    // Must NOT silently fall back to the live primary — that would send a
    // command to a device the user wasn't looking at.
    await new Promise((r) => setTimeout(r, 20));
    expect(vi.mocked(sendInput)).not.toHaveBeenCalled();
  });
});
