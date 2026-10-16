import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

// ---------------------------------------------------------------------
// xterm.js + Tauri mocks. Reused from TerminalPane test file's pattern;
// we only need shallow doubles so the component renders without
// touching real APIs.
// ---------------------------------------------------------------------

// Vitest 4 enforces JS spec: arrow functions can't be called with `new`.
// Mock factories passed to mockImplementation must be `function` expressions
// (or classes) so `new Terminal(...)` works in the component under test.
vi.mock("@xterm/xterm", () => ({
  Terminal: vi.fn().mockImplementation(function () {
    return {
      write: vi.fn(),
      paste: vi.fn(),
      clear: vi.fn(),
      focus: vi.fn(),
      open: vi.fn(),
      loadAddon: vi.fn(),
      dispose: vi.fn(),
      unicode: { activeVersion: "6" },
      refresh: vi.fn(),
      resize: vi.fn(),
      options: {},
      cols: 80,
      rows: 24,
      parser: { registerOscHandler: vi.fn(() => ({ dispose: vi.fn() })) },
      onData: vi.fn(() => ({ dispose: vi.fn() })),
      onResize: vi.fn(() => ({ dispose: vi.fn() })),
      onSelectionChange: vi.fn(() => ({ dispose: vi.fn() })),
      attachCustomKeyEventHandler: vi.fn(),
      getSelection: vi.fn(() => ""),
    };
  }),
}));

vi.mock("@xterm/addon-fit", () => ({
  FitAddon: vi.fn().mockImplementation(function () {
    return { fit: vi.fn() };
  }),
}));

vi.mock("@xterm/addon-webgl", () => ({
  WebglAddon: vi.fn().mockImplementation(function () {
    return { onContextLoss: vi.fn(), dispose: vi.fn() };
  }),
}));

vi.mock("@xterm/addon-search", () => ({
  SearchAddon: vi.fn().mockImplementation(function () {
    return {
      findNext: vi.fn(),
      findPrevious: vi.fn(),
      clearDecorations: vi.fn(),
      onDidChangeResults: vi.fn(() => ({ dispose: vi.fn() })),
    };
  }),
}));

vi.mock("@xterm/addon-unicode11", () => ({
  Unicode11Addon: vi.fn().mockImplementation(function () {
    return { activate: vi.fn(), dispose: vi.fn() };
  }),
}));

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn().mockResolvedValue([]),
  listApiSessions: vi.fn().mockResolvedValue([]),
  listAuthProfiles: vi.fn().mockResolvedValue([]),
  sendInput: vi.fn().mockResolvedValue(undefined),
  resizePty: vi.fn().mockResolvedValue(undefined),
  disconnectSession: vi.fn().mockResolvedValue(undefined),
  clearScrollback: vi.fn().mockResolvedValue(undefined),
  connectDevice: vi.fn().mockResolvedValue("new-session-id"),
  listSessionLogs: vi.fn().mockResolvedValue([]),
  startSessionLog: vi.fn().mockResolvedValue({ session_id: "s", path: "/tmp/s.log" }),
  stopSessionLog: vi.fn().mockResolvedValue(undefined),
  restartLocalShell: vi.fn().mockResolvedValue(undefined),
  openLocalShell: vi.fn().mockResolvedValue({ session_id: "s", label: "zsh" }),
  listAvailableShells: vi.fn().mockResolvedValue([]),
  terminalEnabled: vi.fn().mockResolvedValue(true),
  // v5.0.0 Files surface (a kind:"files" tab renders <FilesPane>).
  filesDisconnect: vi.fn().mockResolvedValue(undefined),
  filesListDir: vi.fn().mockResolvedValue({
    path: "/home/lab",
    parent: "/home",
    entries: [],
    truncated: false,
  }),
  filesLocalListDir: vi.fn().mockResolvedValue({
    path: "/Users/alice",
    parent: "/Users",
    entries: [],
    truncated: false,
  }),
  filesLocalRoots: vi.fn().mockResolvedValue([]),
  filesMkdir: vi.fn().mockResolvedValue(undefined),
  filesRename: vi.fn().mockResolvedValue(undefined),
  filesDelete: vi.fn().mockResolvedValue(undefined),
  filesLocalMkdir: vi.fn().mockResolvedValue(undefined),
  filesLocalRename: vi.fn().mockResolvedValue(undefined),
  filesLocalDelete: vi.fn().mockResolvedValue(undefined),
  filesReconnect: vi.fn().mockResolvedValue({ home: "/home/lab" }),
  filesCheckConflicts: vi.fn().mockResolvedValue([]),
  filesEnqueue: vi.fn().mockResolvedValue([]),
  filesCancel: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({ onDragDropEvent: vi.fn(async () => () => {}) }),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
  emit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: vi.fn(),
  readText: vi.fn().mockResolvedValue(""),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: vi.fn().mockResolvedValue(null),
}));

vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastInfo: vi.fn(),
}));

class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}

(globalThis as any).ResizeObserver = StubResizeObserver;

import { disconnectSession, filesDisconnect, filesListDir, type TransferState } from "@/lib/api";

import { computeLabels, TerminalArea } from "./TerminalArea";

const mockedDisconnect = vi.mocked(disconnectSession);
const mockedFilesDisconnect = vi.mocked(filesDisconnect);
const mockedFilesList = vi.mocked(filesListDir);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  // Fresh store between tests so leftover sessions don't carry over.
  useUiStore.setState({ sessions: [], activeTabId: null });
  // `transferListenerReady: true` is the healthy default — the close guards
  // trust the (empty) transfers map, so an idle Files tab closes without a
  // confirm. The fail-safe (ready:false) path is exercised in its own test.
  useFilesStore.setState({
    panes: {},
    transfers: new Map(),
    transferTargets: new Map(),
    transferListenerReady: true,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("computeLabels", () => {
  it("returns bare device ids for unique deviceIds", () => {
    expect(
      computeLabels([
        { sessionId: "a", deviceId: "vEX1", ended: false },
        { sessionId: "b", deviceId: "vEX2", ended: false },
      ]),
    ).toEqual(["vEX1", "vEX2"]);
  });

  it("appends ' (N)' for second-and-later occurrences", () => {
    expect(
      computeLabels([
        { sessionId: "a", deviceId: "vEX1", ended: false },
        { sessionId: "b", deviceId: "vEX1", ended: false },
        { sessionId: "c", deviceId: "vEX2", ended: false },
        { sessionId: "d", deviceId: "vEX1", ended: false },
      ]),
    ).toEqual(["vEX1", "vEX1 (2)", "vEX2", "vEX1 (3)"]);
  });

  it("returns an empty array for an empty sessions array", () => {
    expect(computeLabels([])).toEqual([]);
  });
});

describe("TerminalArea", () => {
  it("renders nothing when no sessions are open", () => {
    renderWithQuery(<TerminalArea />);
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
  });

  it("renders one tab per open session", () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "vEX2", ended: false },
      ],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(2);
    expect(tabs[0]).toHaveTextContent("vEX1");
    expect(tabs[1]).toHaveTextContent("vEX2");
  });

  it("disambiguates labels when multiple sessions target the same device", () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "vEX1", ended: false },
        { sessionId: "s3", deviceId: "vEX1", ended: false },
      ],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs[0]).toHaveTextContent(/^vEX1$/);
    expect(tabs[1]).toHaveTextContent(/vEX1 \(2\)/);
    expect(tabs[2]).toHaveTextContent(/vEX1 \(3\)/);
  });

  it("clicking a tab updates activeTabId in the store", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "vEX2", ended: false },
      ],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("tab", { name: /vEX2/ }));

    expect(useUiStore.getState().activeTabId).toBe("s2");
  });

  it("renders an 'ended' pill on a session whose remote disconnected", () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true }],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);
    expect(screen.getByText("ended")).toBeInTheDocument();
  });

  it("close button on an ended tab removes the session AND cleans up the backend", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: true },
        { sessionId: "s2", deviceId: "vEX2", ended: false },
      ],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

    // No confirm dialog appeared (remote already closed).
    expect(screen.queryByText(/Close session\?/i)).not.toBeInTheDocument();
    // Backend disconnect IS called so SshState.sessions is cleaned —
    // otherwise the agent's list_open_sessions tool surfaces dead
    // entries (a 2026-05-11 bug report).
    await waitFor(() => expect(mockedDisconnect).toHaveBeenCalledWith("s1"));
    // Session removed from the UI; activeTabId moved to the other tab.
    const state = useUiStore.getState();
    expect(state.sessions).toHaveLength(1);
    expect(state.sessions[0].sessionId).toBe("s2");
    expect(state.activeTabId).toBe("s2");
  });

  it("close button on a connected tab opens the confirm dialog", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

    expect(await screen.findByText(/Close session\?/i)).toBeInTheDocument();
    // Backend not called yet — user must confirm first.
    expect(mockedDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(1);
  });

  it("confirming the close dialog disconnects and removes the session", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    await userEvent.click(screen.getByRole("button", { name: /^close$/i }));

    await waitFor(() => {
      expect(mockedDisconnect).toHaveBeenCalledWith("s1");
    });
    expect(useUiStore.getState().sessions).toHaveLength(0);
    expect(useUiStore.getState().activeTabId).toBeNull();
  });

  it("dismissing the confirm dialog leaves the session untouched", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    await userEvent.click(screen.getByRole("button", { name: /keep open/i }));

    expect(mockedDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(1);
  });

  describe("clear terminal (v1.4.0)", () => {
    it("the Clear terminal menu item wipes the ring and emits the visual-clear event", async () => {
      const { clearScrollback } = await import("@/lib/api");
      const { emit } = await import("@tauri-apps/api/event");
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.pointer({
        keys: "[MouseRight]",
        target: screen.getByRole("tab", { name: /vEX1/ }),
      });
      await userEvent.click(await screen.findByText("Clear terminal"));

      // Backend ring cleared so the agent's read_scrollback can't
      // resurface stale output...
      await waitFor(() => expect(clearScrollback).toHaveBeenCalledWith("s1"));
      // ...and the per-session ui event fires so the pane wipes xterm.
      expect(emit).toHaveBeenCalledWith("ui:clear-terminal:s1");
    });
  });

  describe("close-warning opt-out (v6.5.x, user request)", () => {
    function setWarn(warn: boolean) {
      useUiStore.setState((st) => ({
        preferences: { ...st.preferences, warnOnSessionClose: warn },
      }));
    }

    // Preferences are global store state, so a test that turns the
    // confirm off would otherwise leak into every later describe block
    // (it did: the split-pane close test lost its dialog). Restore the
    // shipped default after each case.
    afterEach(() => setWarn(true));

    it("closes a connected tab immediately when the confirm is off", async () => {
      setWarn(false);
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

      // No dialog, and the backend is told straight away.
      await waitFor(() => {
        expect(mockedDisconnect).toHaveBeenCalledWith("s1");
      });
      expect(screen.queryByText(/Close session\?/i)).not.toBeInTheDocument();
      expect(useUiStore.getState().sessions).toHaveLength(0);
    });

    it("still confirms when the setting is on (the default is unchanged)", async () => {
      setWarn(true);
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

      expect(await screen.findByText(/Close session\?/i)).toBeInTheDocument();
      expect(mockedDisconnect).not.toHaveBeenCalled();
    });

    it("takes effect on the NEXT close without a remount", async () => {
      // The component reads the preference through the store rather than
      // a snapshot, so flipping it mid-session applies immediately.
      setWarn(true);
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
      expect(await screen.findByText(/Close session\?/i)).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: /^close$/i }));

      act(() => setWarn(false));
      await userEvent.click(screen.getByRole("button", { name: /close vEX2/i }));
      await waitFor(() => {
        expect(mockedDisconnect).toHaveBeenCalledWith("s2");
      });
      expect(screen.queryByText(/Close session\?/i)).not.toBeInTheDocument();
    });

    it("does NOT suppress the 'Close all tabs' confirm", async () => {
      // Different risk class: close-all takes down the whole workspace,
      // so it keeps its combined confirm regardless of this preference.
      setWarn(false);
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      fireEvent.contextMenu(screen.getByRole("tab", { name: /vEX1/ }));
      await userEvent.click(await screen.findByText("Close all tabs"));

      expect(await screen.findByText(/Close all sessions\?/i)).toBeInTheDocument();
      expect(mockedDisconnect).not.toHaveBeenCalled();
    });
  });

  describe("close all sessions (v2.3.4)", () => {
    it("context-menu 'Close all tabs' opens the combined confirm dialog", async () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: true },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.pointer({
        keys: "[MouseRight]",
        target: screen.getByRole("tab", { name: /vEX1/ }),
      });
      await userEvent.click(await screen.findByText("Close all tabs"));

      expect(await screen.findByText(/Close all sessions\?/i)).toBeInTheDocument();
      // Copy names the live count: 1 of 2 still connected.
      expect(screen.getByText(/still connected/i)).toBeInTheDocument();
      // Nothing torn down until the user confirms.
      expect(mockedDisconnect).not.toHaveBeenCalled();
      expect(useUiStore.getState().sessions).toHaveLength(2);
    });

    it("confirming disconnects every session — right panes included — and clears the strip", async () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s1r", deviceId: "vEX3", ended: false, splitWith: "s1" },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.pointer({
        keys: "[MouseRight]",
        target: screen.getByRole("tab", { name: /vEX1/ }),
      });
      await userEvent.click(await screen.findByText("Close all tabs"));
      await userEvent.click(await screen.findByRole("button", { name: /^close all$/i }));

      // Backend disconnect for ALL THREE sessions — the split right
      // pane must not linger in SshState.sessions (agent's
      // list_open_sessions would surface it).
      await waitFor(() => {
        expect(mockedDisconnect).toHaveBeenCalledWith("s1");
        expect(mockedDisconnect).toHaveBeenCalledWith("s1r");
        expect(mockedDisconnect).toHaveBeenCalledWith("s2");
      });
      expect(useUiStore.getState().sessions).toHaveLength(0);
      expect(useUiStore.getState().activeTabId).toBeNull();
    });

    it("skips the dialog when every session already ended, still cleaning the backend", async () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: true },
          { sessionId: "s2", deviceId: "vEX2", ended: true },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.pointer({
        keys: "[MouseRight]",
        target: screen.getByRole("tab", { name: /vEX1/ }),
      });
      await userEvent.click(await screen.findByText("Close all tabs"));

      expect(screen.queryByText(/Close all sessions\?/i)).not.toBeInTheDocument();
      await waitFor(() => {
        expect(mockedDisconnect).toHaveBeenCalledWith("s1");
        expect(mockedDisconnect).toHaveBeenCalledWith("s2");
      });
      expect(useUiStore.getState().sessions).toHaveLength(0);
    });

    it("'Keep open' leaves every session untouched", async () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.pointer({
        keys: "[MouseRight]",
        target: screen.getByRole("tab", { name: /vEX1/ }),
      });
      await userEvent.click(await screen.findByText("Close all tabs"));
      await userEvent.click(await screen.findByRole("button", { name: /keep open/i }));

      expect(mockedDisconnect).not.toHaveBeenCalled();
      expect(useUiStore.getState().sessions).toHaveLength(2);
    });

    it("clearAllSessions store action empties sessions and activeTabId in one update", () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s1r", deviceId: "vEX2", ended: false, splitWith: "s1" },
        ],
        activeTabId: "s1",
      });
      useUiStore.getState().clearAllSessions();
      expect(useUiStore.getState().sessions).toHaveLength(0);
      expect(useUiStore.getState().activeTabId).toBeNull();
    });
  });

  describe("tab strip scrolling (v2.3.4)", () => {
    // jsdom computes no layout, so overflow metrics are stubbed onto
    // the tablist element and a scroll event triggers re-measure.
    function setStripMetrics(
      el: HTMLElement,
      m: { scrollWidth: number; clientWidth: number; scrollLeft: number },
    ) {
      Object.defineProperty(el, "scrollWidth", { configurable: true, value: m.scrollWidth });
      Object.defineProperty(el, "clientWidth", { configurable: true, value: m.clientWidth });
      Object.defineProperty(el, "scrollLeft", {
        configurable: true,
        value: m.scrollLeft,
        writable: true,
      });
      // jsdom's Element.scrollBy is a no-op; give it browser semantics
      // (mutate scrollLeft) so the production scrollBy branch is what's
      // actually under test, not the jsdom-only fallback.
      (el as unknown as { scrollBy: (o: { left: number }) => void }).scrollBy = ({ left }) => {
        (el as HTMLElement).scrollLeft += left;
      };
    }

    const threeSessions = () =>
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
          { sessionId: "s3", deviceId: "vEX3", ended: false },
        ],
        activeTabId: "s1",
      });

    it("renders no chevrons while the strip fits", () => {
      threeSessions();
      renderWithQuery(<TerminalArea />);
      expect(screen.queryByLabelText(/scroll tabs/i)).not.toBeInTheDocument();
    });

    it("shows chevrons when the strip overflows; left is disabled at the start", async () => {
      threeSessions();
      renderWithQuery(<TerminalArea />);

      const strip = screen.getByRole("tablist");
      setStripMetrics(strip, { scrollWidth: 600, clientWidth: 200, scrollLeft: 0 });
      fireEvent.scroll(strip);

      expect(await screen.findByLabelText("Scroll tabs right")).toBeEnabled();
      expect(screen.getByLabelText("Scroll tabs left")).toBeDisabled();
    });

    it("scrolls the STRIP (not an ancestor) to reveal an off-screen active tab", async () => {
      // Regression guard: the active-tab reveal must adjust the strip's own
      // scrollLeft, never call element.scrollIntoView() (which scrolls every
      // scrollable ancestor and shifted the whole app left — clipping the
      // sidebar + terminal's first column).
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
          { sessionId: "s3", deviceId: "vEX3", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);
      const strip = screen.getByRole("tablist");
      const scrollIntoViewSpy = vi.fn();
      // Any scrollIntoView call on a tab would be the ancestor-scrolling
      // bug — fail loudly if the reveal path ever regresses to it.
      Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
        configurable: true,
        value: scrollIntoViewSpy,
      });
      // Active tab sits to the right of the strip's visible box.
      const active = strip.querySelector<HTMLElement>('[data-state="active"]');
      strip.getBoundingClientRect = () => ({ left: 0, right: 200 }) as DOMRect;
      if (active) active.getBoundingClientRect = () => ({ left: 260, right: 320 }) as DOMRect;
      Object.defineProperty(strip, "scrollLeft", {
        configurable: true,
        value: 0,
        writable: true,
      });

      // Re-activate to trigger the reveal effect.
      await userEvent.click(screen.getByRole("tab", { name: /vEX2/ }));
      await userEvent.click(screen.getByRole("tab", { name: /vEX1/ }));

      expect(scrollIntoViewSpy).not.toHaveBeenCalled();
      delete (HTMLElement.prototype as unknown as { scrollIntoView?: unknown }).scrollIntoView;
    });

    it("clicking the right chevron pages the strip and enables the left chevron", async () => {
      threeSessions();
      renderWithQuery(<TerminalArea />);

      const strip = screen.getByRole("tablist");
      setStripMetrics(strip, { scrollWidth: 600, clientWidth: 200, scrollLeft: 0 });
      fireEvent.scroll(strip);

      await userEvent.click(await screen.findByLabelText("Scroll tabs right"));

      // step = max(120, 60% of 200px) = 120.
      expect(strip.scrollLeft).toBe(120);
      await waitFor(() => expect(screen.getByLabelText("Scroll tabs left")).toBeEnabled());
    });
  });

  describe("tab rename (Phase 7a C9)", () => {
    it("double-clicking a tab opens the rename input", async () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.dblClick(screen.getByRole("tab", { name: /vEX1/ }));
      expect(await screen.findByTestId("tab-rename-input-s1")).toBeInTheDocument();
    });

    it("Enter commits a non-empty draft to uiStore.customLabel", async () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.dblClick(screen.getByRole("tab", { name: /vEX1/ }));
      const input = await screen.findByTestId("tab-rename-input-s1");
      await userEvent.clear(input);
      await userEvent.type(input, "core-lab1{Enter}");

      expect(useUiStore.getState().sessions[0].customLabel).toBe("core-lab1");
      expect(screen.queryByTestId("tab-rename-input-s1")).not.toBeInTheDocument();
      expect(screen.getByRole("tab")).toHaveTextContent("core-lab1");
    });

    it("Escape cancels and reverts to the original label", async () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.dblClick(screen.getByRole("tab", { name: /vEX1/ }));
      const input = await screen.findByTestId("tab-rename-input-s1");
      await userEvent.clear(input);
      await userEvent.type(input, "draft-name{Escape}");

      expect(useUiStore.getState().sessions[0].customLabel ?? null).toBeNull();
      expect(screen.queryByTestId("tab-rename-input-s1")).not.toBeInTheDocument();
      expect(screen.getByRole("tab")).toHaveTextContent("vEX1");
    });

    it("empty input falls back to the auto-generated label on commit", async () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false, customLabel: "old" }],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.dblClick(screen.getByRole("tab", { name: /old/ }));
      const input = await screen.findByTestId("tab-rename-input-s1");
      await userEvent.clear(input);
      await userEvent.keyboard("{Enter}");

      expect(useUiStore.getState().sessions[0].customLabel).toBeNull();
      expect(screen.getByRole("tab")).toHaveTextContent("vEX1");
    });

    it("computeLabels skips the dedupe counter for tabs with a customLabel", () => {
      expect(
        computeLabels([
          { sessionId: "s1", deviceId: "vEX1", ended: false, customLabel: "prod-edge" },
          { sessionId: "s2", deviceId: "vEX1", ended: false },
          { sessionId: "s3", deviceId: "vEX1", ended: false },
        ]),
      ).toEqual(["prod-edge", "vEX1", "vEX1 (2)"]);
    });
  });

  describe("split pane (Phase 7a C11)", () => {
    it("renders a split tab's panes in a resizable PaneTree (one tab, one resize handle)", () => {
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
          { sessionId: "s2", deviceId: "vEX1", ended: false, splitWith: "s1" },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);
      expect(screen.getAllByRole("tab")).toHaveLength(1); // only s1 has a tab
      // A 2-pane split renders exactly one resize handle between the panes.
      expect(screen.getAllByTestId("pane-resize-handle")).toHaveLength(1);
    });

    // v6.4.0 — the user must be able to SEE which pane a button-bar macro will
    // hit; retargeting without an indicator just moves the guess.
    it("rings the focused pane in a split, and only that one", () => {
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
        activePaneId: "s2",
        lastPaneByTab: { s1: "s2" },
      });
      renderWithQuery(<TerminalArea />);
      expect(screen.getAllByTestId("pane-focused")).toHaveLength(1);
    });

    it("shows no focus ring and no 'Own tab' button on an un-split tab", () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
        activePaneId: "s1",
        lastPaneByTab: {},
      });
      renderWithQuery(<TerminalArea />);
      // Nothing to disambiguate, and nowhere to move to.
      expect(screen.queryByTestId("pane-focused")).toBeNull();
      expect(screen.queryByRole("button", { name: /own tab/i })).toBeNull();
    });

    it("offers 'Own tab' per pane in a split, and lifting one restores its tab", async () => {
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
        activePaneId: "s2",
        lastPaneByTab: { s1: "s2" },
      });
      renderWithQuery(<TerminalArea />);
      const buttons = screen.getAllByRole("button", { name: /own tab/i });
      expect(buttons).toHaveLength(2); // one per pane
      await userEvent.click(buttons[1]);
      // The split had exactly one exit before v6.4.0: closing the pane.
      await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(2));
    });

    it("drag-to-split (v4.4.0): tiling a dragged tab into a pane merges the strip", async () => {
      // Drag-to-split is the sole split affordance now (the tab-menu split was
      // removed). Simulating a @dnd-kit pointer drag in jsdom is brittle, so
      // this drives the wired store action `movePaneInto` (what onDragEnd calls
      // on an edge-zone drop) and asserts the resulting PaneTree render; the
      // tree math is covered in paneTree/uiStore tests.
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "CSR1", ended: false },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);
      expect(screen.getAllByRole("tab")).toHaveLength(2);

      // Drop s2's tab on s1's right edge → s1 = [s1 | s2].
      act(() => {
        useUiStore.getState().movePaneInto("s2", "s1", "row", false);
      });

      await waitFor(() => {
        // s2 folded into s1's tab: one tab left, one split → one resize handle.
        expect(screen.getAllByRole("tab")).toHaveLength(1);
        expect(screen.getAllByTestId("pane-resize-handle")).toHaveLength(1);
      });
      const state = useUiStore.getState();
      expect(state.sessions.find((t) => t.sessionId === "s2")?.splitWith).toBe("s1");
      expect(state.sessions.find((t) => t.sessionId === "s1")?.layout).toEqual({
        type: "split",
        dir: "row",
        children: [
          { type: "leaf", sessionId: "s1" },
          { type: "leaf", sessionId: "s2" },
        ],
      });
    });

    it("closing the primary tab disconnects BOTH sessions", async () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX1", ended: false, splitWith: "s1" },
        ],
        activeTabId: "s1",
      });
      renderWithQuery(<TerminalArea />);

      await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
      await userEvent.click(screen.getByRole("button", { name: /^close$/i }));

      await waitFor(() => {
        expect(mockedDisconnect).toHaveBeenCalledWith("s1");
        expect(mockedDisconnect).toHaveBeenCalledWith("s2");
      });
      // uiStore cascade drops both.
      expect(useUiStore.getState().sessions).toHaveLength(0);
    });

    it("removeSession on a primary cascades to its right pane", () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX1", ended: false, splitWith: "s1" },
          { sessionId: "s3", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      useUiStore.getState().removeSession("s1");
      const state = useUiStore.getState();
      // Both s1 (primary) and s2 (its right pane) are gone; s3 stays.
      expect(state.sessions.map((t) => t.sessionId)).toEqual(["s3"]);
      // Focus moves to the next top-level session.
      expect(state.activeTabId).toBe("s3");
    });

    it("reconnectSession swaps sessionId in place, clears ended, preserves customLabel + tab order", () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: true, customLabel: "lab1" },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      });
      useUiStore.getState().reconnectSession("s1", "s1-new");
      const state = useUiStore.getState();
      expect(state.sessions.map((t) => t.sessionId)).toEqual(["s1-new", "s2"]);
      expect(state.sessions[0]).toMatchObject({
        sessionId: "s1-new",
        deviceId: "vEX1",
        ended: false,
        customLabel: "lab1",
      });
      expect(state.activeTabId).toBe("s1-new");
    });

    it("reconnectSession on a primary rewrites the right pane's splitWith anchor", () => {
      useUiStore.setState({
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: true },
          { sessionId: "s2", deviceId: "vEX2", ended: false, splitWith: "s1" },
        ],
        activeTabId: "s1",
      });
      useUiStore.getState().reconnectSession("s1", "s1-new");
      const state = useUiStore.getState();
      expect(state.sessions[0].sessionId).toBe("s1-new");
      expect(state.sessions[1].splitWith).toBe("s1-new");
    });

    it("reconnectSession is a no-op when the session is not in the array", () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      useUiStore.getState().reconnectSession("missing", "anything");
      const state = useUiStore.getState();
      expect(state.sessions[0].sessionId).toBe("s1");
      expect(state.activeTabId).toBe("s1");
    });

    it("splitPaneWith adds a pane, builds the layout, and keeps focus on the tab", () => {
      useUiStore.setState({
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      });
      useUiStore.getState().splitPaneWith("s2", "vEX1", "s1", "row");
      const state = useUiStore.getState();
      expect(state.sessions.map((t) => t.sessionId)).toEqual(["s1", "s2"]);
      expect(state.sessions[1].splitWith).toBe("s1");
      // The primary gains a 2-pane row layout; the tab keeps focus.
      expect(state.sessions[0].layout).toEqual({
        type: "split",
        dir: "row",
        children: [
          { type: "leaf", sessionId: "s1" },
          { type: "leaf", sessionId: "s2" },
        ],
      });
      expect(state.activeTabId).toBe("s1");
    });
  });
});

describe("TerminalArea — Files tabs (v5.0.0)", () => {
  const filesTab = (sessionId = "f1", deviceId = "vEX1", ended = false) => ({
    sessionId,
    deviceId,
    ended,
    kind: "files" as const,
  });

  it("renders <FilesPane>, never a PaneTree/TerminalPane", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    renderWithQuery(<TerminalArea />);
    // The dual-pane browser mounted...
    expect(await screen.findByTestId("files-pane-f1")).toBeInTheDocument();
    expect(screen.getByTestId("files-pane-local")).toBeInTheDocument();
    expect(screen.getByTestId("files-pane-remote")).toBeInTheDocument();
    // ...and no terminal did (a PaneTree leaf hardcodes TerminalPane, which
    // would open an xterm against a session that has no PTY).
    expect(screen.queryByTestId("terminal-pane")).toBeNull();
    expect(screen.queryByTestId("pane-resize-handle")).toBeNull();
  });

  it("carries the folder glyph so a Files tab is distinguishable from an SSH tab on the same device", () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }, filesTab()],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);
    // Shared label namespace ("vEX1" / "vEX1 (2)") — the glyph is the
    // discriminator (plan veto #5).
    const tabs = screen.getAllByRole("tab");
    expect(tabs[0]).toHaveTextContent(/^vEX1$/);
    expect(tabs[1]).toHaveTextContent(/vEX1 \(2\)/);
    expect(screen.getByTestId("tab-files-glyph-f1")).toBeInTheDocument();
    expect(screen.queryByTestId("tab-files-glyph-s1")).toBeNull();
  });

  it("closing an IDLE files tab routes to files_disconnect WITHOUT a confirm, and never to disconnect_session", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    useFilesStore.getState().ensurePane("f1", "/home/lab");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

    // Nothing in flight → nothing to lose → no prompt.
    expect(screen.queryByText(/Close session\?/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Cancel transfers and close\?/i)).not.toBeInTheDocument();
    await waitFor(() => expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1"));
    // `disconnect_session` has NO files arm — routing there would leak the
    // SFTP session AND its SSH connection.
    expect(mockedDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(0);
    // The pane's UI state goes with the tab.
    expect(useFilesStore.getState().panes["f1"]).toBeUndefined();
  });

  it("does not fire a listing at the closing session — no snap to '.' during teardown (F8)", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    useFilesStore.getState().ensurePane("f1", "/home/lab");
    renderWithQuery(<TerminalArea />);
    // The pane's initial listing is at the seeded home.
    await waitFor(() => expect(mockedFilesList).toHaveBeenCalledWith("f1", "/home/lab"));
    mockedFilesList.mockClear();

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    await waitFor(() => expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1"));
    await waitFor(() => expect(useUiStore.getState().sessions).toHaveLength(0));

    // Clearing pane state AFTER unmount (not before the awaited disconnect)
    // means the still-mounted pane never lost its cwd and re-listed at the
    // "." fallback against the session being torn down.
    expect(mockedFilesList).not.toHaveBeenCalledWith("f1", ".");
  });

  it("close-all routes each tab to its OWN teardown IPC", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }, filesTab("f1", "vEX2")],
      activeTabId: "s1",
    });
    renderWithQuery(<TerminalArea />);

    fireEvent.contextMenu(screen.getByRole("tab", { name: /vEX1/ }));
    await userEvent.click(await screen.findByText("Close all tabs"));
    await userEvent.click(await screen.findByRole("button", { name: /^close all$/i }));

    await waitFor(() => {
      expect(mockedDisconnect).toHaveBeenCalledWith("s1");
      expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1");
    });
    expect(mockedDisconnect).not.toHaveBeenCalledWith("f1");
    expect(useUiStore.getState().sessions).toHaveLength(0);
  });

  it("close-all skips the confirm when only Files tabs are open, and still tears them down", async () => {
    useUiStore.setState({ sessions: [filesTab("f1"), filesTab("f2", "vEX2")], activeTabId: "f1" });
    renderWithQuery(<TerminalArea />);

    fireEvent.contextMenu(screen.getByRole("tab", { name: /vEX1/ }));
    await userEvent.click(await screen.findByText("Close all tabs"));

    expect(screen.queryByText(/Close all sessions\?/i)).not.toBeInTheDocument();
    await waitFor(() => {
      expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1");
      expect(mockedFilesDisconnect).toHaveBeenCalledWith("f2");
    });
    expect(useUiStore.getState().sessions).toHaveLength(0);
  });

  it("hides every PTY-only context action for a Files tab", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    renderWithQuery(<TerminalArea />);

    fireEvent.contextMenu(screen.getByRole("tab", { name: /vEX1/ }));
    // Rename + close stay; scrollback/log/capture/clear have no meaning
    // without a PTY.
    expect(await screen.findByText("Rename...")).toBeInTheDocument();
    expect(screen.getByText("Close tab")).toBeInTheDocument();
    expect(screen.queryByText("Export scrollback...")).toBeNull();
    expect(screen.queryByText("Log session to file...")).toBeNull();
    expect(screen.queryByText("Compare captures / diff output...")).toBeNull();
    expect(screen.queryByText("Clear terminal")).toBeNull();
  });

  /** Seed the event mirror with one in-flight transfer for `sessionId`. */
  const seedTransfer = (sessionId: string, id: string, state: TransferState = "running") => {
    useFilesStore.getState().applyTransferUpdate({
      session_id: sessionId,
      id,
      direction: "upload",
      state,
      name: "big.conf",
      bytes_done: 1,
      bytes_total: 10,
      files_done: 0,
      files_total: null,
      rate_bps: 1,
      skipped: 0,
      warnings: [],
      error: null,
    });
  };

  it("closing a files tab WITH transfers in flight confirms first, then tears down", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    useFilesStore.getState().ensurePane("f1", "/home/lab");
    seedTransfer("f1", "t1");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));

    // Cancelling a copy mid-flight is real data loss, so it must be a choice.
    expect(await screen.findByText(/Cancel transfers and close\?/i)).toBeInTheDocument();
    // The count sits in a <b>, so assert over the dialog's whole text.
    expect(screen.getByRole("alertdialog")).toHaveTextContent(
      /1 transfer is still in progress to vEX1/,
    );
    expect(mockedFilesDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(1);

    await userEvent.click(screen.getByRole("button", { name: /^close$/i }));
    // `files_disconnect` cancels the session's transfers backend-side — no
    // separate cancel call is needed on this path.
    await waitFor(() => expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1"));
    expect(mockedDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(0);
  });

  it("'Keep open' on the transfer confirm leaves the tab and the transfer alone", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    seedTransfer("f1", "t1");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    await userEvent.click(await screen.findByRole("button", { name: /keep open/i }));
    expect(mockedFilesDisconnect).not.toHaveBeenCalled();
    expect(useUiStore.getState().sessions).toHaveLength(1);
  });

  it("counts a QUEUED transfer as in-flight, and pluralizes", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    seedTransfer("f1", "t1", "running");
    seedTransfer("f1", "t2", "queued");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    await screen.findByText(/Cancel transfers and close\?/i);
    expect(screen.getByRole("alertdialog")).toHaveTextContent(/2 transfers are still in progress/);
  });

  it("ignores another session's transfers when closing this files tab", async () => {
    useUiStore.setState({
      sessions: [filesTab("f1"), filesTab("f2", "vEX2")],
      activeTabId: "f1",
    });
    // Work outstanding on f2 only — closing f1 loses nothing.
    seedTransfer("f2", "t1");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    expect(screen.queryByText(/Cancel transfers and close\?/i)).not.toBeInTheDocument();
    await waitFor(() => expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1"));
  });

  it("a FINISHED transfer never blocks a close", async () => {
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    seedTransfer("f1", "t1", "done");
    renderWithQuery(<TerminalArea />);

    await userEvent.click(screen.getByRole("button", { name: /close vEX1/i }));
    expect(screen.queryByText(/Cancel transfers and close\?/i)).not.toBeInTheDocument();
    await waitFor(() => expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1"));
  });

  it("close-all confirms for a files tab with transfers and names what gets cancelled", async () => {
    useUiStore.setState({ sessions: [filesTab("f1"), filesTab("f2", "vEX2")], activeTabId: "f1" });
    seedTransfer("f1", "t1");
    renderWithQuery(<TerminalArea />);

    fireEvent.contextMenu(screen.getByRole("tab", { name: /vEX1/ }));
    await userEvent.click(await screen.findByText("Close all tabs"));

    // Without a transfer this strip closes silently (Commit B behavior).
    expect(await screen.findByText(/Close all sessions\?/i)).toBeInTheDocument();
    expect(screen.getByText(/file transfer in progress/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /^close all$/i }));
    await waitFor(() => {
      expect(mockedFilesDisconnect).toHaveBeenCalledWith("f1");
      expect(mockedFilesDisconnect).toHaveBeenCalledWith("f2");
    });
  });

  it("keeps the per-host accent for a Files tab (its deviceId is a real inventory id)", async () => {
    const { listDevices } = await import("@/lib/api");
    vi.mocked(listDevices).mockResolvedValue([
      {
        id: "vEX1",
        host: "10.0.0.1",
        port: 22,
        vendor: "junos",
        group: null,
        color: "red",
        tags: [],
        auth: "lab-pw",
        syntax_highlighting: null,
        quick_copy_paste: null,
        font_family: null,
        font_size: null,
        bold_color: null,
        allow_weak_crypto: null,
        netbox_id: null,
        jump_via: null,
        forward_agent: null,
      },
    ]);
    useUiStore.setState({ sessions: [filesTab()], activeTabId: "f1" });
    renderWithQuery(<TerminalArea />);

    const chip = (await screen.findByRole("tab", { name: /vEX1/ })).parentElement!;
    await waitFor(() => expect(chip.getAttribute("style")).toContain("border-left"));
  });
});
