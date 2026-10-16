import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useUiStore } from "@/stores/uiStore";

// ---------------------------------------------------------------------
// xterm.js mocks. happy-dom can't drive xterm.js's WebGL renderer, and
// we don't need to verify rendering — only that the component wires
// the IPC events into the right calls. Each mock module exposes a
// minimal shim that captures calls for assertion.
// ---------------------------------------------------------------------

interface MockTerminal {
  write: ReturnType<typeof vi.fn>;
  paste: ReturnType<typeof vi.fn>;
  clear: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
  open: ReturnType<typeof vi.fn>;
  loadAddon: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
  unicode: { activeVersion: string };
  refresh: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  options: { disableStdin?: boolean; theme?: unknown; fontSize?: number; fontFamily?: string };
  parser: {
    registerOscHandler: ReturnType<typeof vi.fn>;
  };
  onData: ReturnType<typeof vi.fn>;
  onResize: ReturnType<typeof vi.fn>;
  onSelectionChange: ReturnType<typeof vi.fn>;
  attachCustomKeyEventHandler: ReturnType<typeof vi.fn>;
  /** Mocked current selection — set by a test, consumed via getSelection. */
  selection: string;
  getSelection: ReturnType<typeof vi.fn>;
  /** Dimensions the component reads when priming the backend on mount.
   *  fit() in the real terminal would set these after measuring the
   *  container; the mock just exposes the fields directly. */
  cols: number;
  rows: number;
  /** The handler the component registered with onData; tests invoke it
   *  directly to simulate a keystroke. */
  fireData: (data: string) => void;
  /** Trigger the registered onSelectionChange handler. */
  fireSelectionChange: () => void;
  /** Trigger the registered custom-key handler. Returns its verdict
   *  (true = let xterm.js process, false = swallow). */
  fireKey: (event: Partial<KeyboardEvent> & { key: string; type?: string }) => boolean;
  /** OSC 52 handler registered by the component. */
  oscHandlers: Map<number, (data: string) => boolean>;
}

interface MockSearch {
  findNext: ReturnType<typeof vi.fn>;
  findPrevious: ReturnType<typeof vi.fn>;
  clearDecorations: ReturnType<typeof vi.fn>;
  onDidChangeResults: ReturnType<typeof vi.fn>;
}

let mockSearch: MockSearch | null = null;
let searchResultsCb: ((e: { resultIndex: number; resultCount: number }) => void) | null = null;

let mockTerm: MockTerminal | null = null;

function createMockTerminal(): MockTerminal {
  let dataHandler: ((d: string) => void) | null = null;
  let selectionHandler: (() => void) | null = null;
  let keyHandler: ((e: KeyboardEvent) => boolean) | null = null;
  const oscHandlers = new Map<number, (data: string) => boolean>();
  const term: MockTerminal = {
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
    parser: {
      registerOscHandler: vi.fn((id: number, fn: (data: string) => boolean) => {
        oscHandlers.set(id, fn);
        return { dispose: vi.fn() };
      }),
    },
    onData: vi.fn((fn: (d: string) => void) => {
      dataHandler = fn;
      return { dispose: vi.fn() };
    }),
    onResize: vi.fn(() => ({ dispose: vi.fn() })),
    onSelectionChange: vi.fn((fn: () => void) => {
      selectionHandler = fn;
      return { dispose: vi.fn() };
    }),
    attachCustomKeyEventHandler: vi.fn((fn: (e: KeyboardEvent) => boolean) => {
      keyHandler = fn;
    }),
    selection: "",
    getSelection: vi.fn(),
    cols: 200,
    rows: 50,
    fireData: (data: string) => dataHandler?.(data),
    fireSelectionChange: () => selectionHandler?.(),
    fireKey: (event) => {
      if (!keyHandler) return true;
      // Synthesize the minimum surface attachCustomKeyEventHandler reads.
      const synthetic = {
        type: event.type ?? "keydown",
        key: event.key,
        metaKey: event.metaKey ?? false,
        ctrlKey: event.ctrlKey ?? false,
        altKey: event.altKey ?? false,
        shiftKey: event.shiftKey ?? false,
        preventDefault: vi.fn(),
      } as unknown as KeyboardEvent;
      return keyHandler(synthetic);
    },
    oscHandlers,
  };
  // Wire getSelection to read the test-controlled `selection` field.
  term.getSelection.mockImplementation(() => term.selection);
  return term;
}

// Vitest 4 enforces JS spec: arrow functions can't be called with `new`.
// Mock factories passed to mockImplementation must be `function` expressions
// (or classes) so `new Terminal(...)` works in the component under test.
vi.mock("@xterm/xterm", () => ({
  Terminal: vi.fn().mockImplementation(function () {
    mockTerm = createMockTerminal();
    return mockTerm;
  }),
}));

interface MockFit {
  fit: ReturnType<typeof vi.fn>;
}

let mockFit: MockFit | null = null;

vi.mock("@xterm/addon-fit", () => ({
  FitAddon: vi.fn().mockImplementation(function () {
    mockFit = { fit: vi.fn() };
    return mockFit;
  }),
}));

vi.mock("@xterm/addon-webgl", () => ({
  WebglAddon: vi.fn().mockImplementation(function () {
    return { onContextLoss: vi.fn(), dispose: vi.fn() };
  }),
}));

vi.mock("@xterm/addon-search", () => ({
  SearchAddon: vi.fn().mockImplementation(function () {
    mockSearch = {
      findNext: vi.fn(() => true),
      findPrevious: vi.fn(() => true),
      clearDecorations: vi.fn(),
      onDidChangeResults: vi.fn((cb: (e: { resultIndex: number; resultCount: number }) => void) => {
        searchResultsCb = cb;
        return { dispose: vi.fn() };
      }),
    };
    return mockSearch;
  }),
}));

vi.mock("@xterm/addon-unicode11", () => ({
  Unicode11Addon: vi.fn().mockImplementation(function () {
    return { activate: vi.fn(), dispose: vi.fn() };
  }),
}));

// ---------------------------------------------------------------------
// IPC mocks. Same surface as Phase 2b's ConsolePane test.
// ---------------------------------------------------------------------

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listAuthProfiles: vi.fn().mockResolvedValue([]),
  sendInput: vi.fn().mockResolvedValue(undefined),
  resizePty: vi.fn().mockResolvedValue(undefined),
  disconnectSession: vi.fn().mockResolvedValue(undefined),
  // useReconnectSession (called from TerminalPane for Enter-to-
  // reconnect) imports connectDevice through the mutations module.
  // Default resolution; tests override per-case.
  connectDevice: vi.fn().mockResolvedValue("new-session-id"),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
  testSecretResolve: vi.fn(),
  enrollSecret: vi.fn(),
  // v4.4.0 — TerminalPane uses useRestartLocalShell (Enter-to-restart on a
  // dead local shell), which imports restartLocalShell via lib/localShell.
  restartLocalShell: vi.fn().mockResolvedValue(undefined),
  openLocalShell: vi.fn().mockResolvedValue({ session_id: "s", label: "zsh" }),
  listAvailableShells: vi.fn().mockResolvedValue([]),
}));

interface MockTauriEvent {
  payload: unknown;
}

const eventListeners = new Map<string, Array<(e: MockTauriEvent) => void>>();

vi.mock("@tauri-apps/api/event", () => ({
  emit: vi.fn(),
  listen: vi.fn(async (name: string, handler: (e: MockTauriEvent) => void) => {
    const list = eventListeners.get(name) ?? [];
    list.push(handler);
    eventListeners.set(name, list);
    return () => {
      const next = (eventListeners.get(name) ?? []).filter((h) => h !== handler);
      eventListeners.set(name, next);
    };
  }),
}));

// ResizeObserver is unimplemented in happy-dom.
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}

(globalThis as any).ResizeObserver = StubResizeObserver;

import { emit } from "@tauri-apps/api/event";

import { listDevices, resizePty, sendInput, type DeviceMeta } from "@/lib/api";

import { TerminalPane } from "./TerminalPane";

const mockedListDevices = vi.mocked(listDevices);
const mockedSendInput = vi.mocked(sendInput);
const mockedResizePty = vi.mocked(resizePty);

function device(partial: Partial<DeviceMeta> & Pick<DeviceMeta, "id">): DeviceMeta {
  return {
    host: "10.0.0.1",
    port: 22,
    vendor: "junos",
    group: null,
    auth: "lab-pw",
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    color: null,
    tags: [],
    allow_weak_crypto: null,
    ...partial,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
  };
}

// Mock the Tauri clipboard plugin module. The component switched off
// `navigator.clipboard` because macOS WKWebView blocks `readText`;
// the plugin's IPC commands replace it. Tests set `clipboardText`
// to drive readText, and assert against `clipboardWriteText` calls.
let clipboardText = "";
const clipboardWriteText = vi.fn(async (s: string) => {
  clipboardText = s;
});
const clipboardReadText = vi.fn(async () => clipboardText);
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: (s: string) => clipboardWriteText(s),
  readText: () => clipboardReadText(),
}));

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

/**
 * Mirrors what `TerminalArea` does in production: subscribes to the
 * sessions array and feeds the per-tab pieces (deviceId, ended) as
 * props. Tests use this so end-to-end behavior (close event ->
 * `markSessionEnded` -> re-render with `ended=true`) is exercised
 * via the same wiring the real app uses.
 */
function renderTabbed() {
  function Harness() {
    const tab = useUiStore((s) => s.sessions.find((t) => t.sessionId === "sess-123"));
    if (!tab) return null;
    return (
      <TerminalPane sessionId={tab.sessionId} deviceId={tab.deviceId} ended={tab.ended} active />
    );
  }
  return renderWithQuery(<Harness />);
}

function fireBackendEvent(name: string, payload: unknown) {
  const list = eventListeners.get(name) ?? [];
  for (const h of list) h({ payload });
}

beforeEach(() => {
  mockTerm = null;
  eventListeners.clear();
  clipboardText = "";
  clipboardWriteText.mockClear();
  clipboardReadText.mockClear();
  // Phase 3: TerminalPane is prop-driven. The store still holds
  // sessions for the actions (removeSession, markSessionEnded) that
  // the pane invokes; seed it with the test session so those
  // actions are no-ops on a known shape.
  useUiStore.setState({
    sessions: [{ sessionId: "sess-123", deviceId: "vEX1", ended: false }],
    activeTabId: "sess-123",
  });
  mockedListDevices.mockResolvedValue([device({ id: "vEX1" })]);
});

afterEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------
// Layout stubs for the fit-on-visibility guard (`fitIfVisible`).
//
// happy-dom performs no layout, so every element reports
// clientWidth/clientHeight === 0 — which `fitIfVisible` reads as
// "hidden" and would make it skip EVERY fit(). Stub the prototype to a
// non-zero box so the default world is "laid out" (a visible, active
// pane); a test simulates a hidden inactive tab by overriding a
// specific node's box back to 0.
//
// Also swap the no-op ResizeObserver (from setup.ts) for one that
// captures the component's callback, so a test can drive the exact
// resize that fires when a tab is switched away/back.
// ---------------------------------------------------------------------
let roCallback: (() => void) | null = null;
class CapturingResizeObserver {
  constructor(cb: () => void) {
    roCallback = cb;
  }
  observe() {}
  disconnect() {}
  unobserve() {}
}

let originalClientWidth: PropertyDescriptor | undefined;
let originalClientHeight: PropertyDescriptor | undefined;

beforeEach(() => {
  roCallback = null;
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = CapturingResizeObserver;
  originalClientWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth");
  originalClientHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
  Object.defineProperty(HTMLElement.prototype, "clientWidth", {
    configurable: true,
    get: () => 1200,
  });
  Object.defineProperty(HTMLElement.prototype, "clientHeight", {
    configurable: true,
    get: () => 800,
  });
});

afterEach(() => {
  if (originalClientWidth) {
    Object.defineProperty(HTMLElement.prototype, "clientWidth", originalClientWidth);
  }
  if (originalClientHeight) {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", originalClientHeight);
  }
});

// Wait for the component's useEffect chain to finish initial mount and
// PTY-event subscription. listen() is async, so we poll until the
// listener is registered.
async function waitForMount() {
  await waitFor(() => {
    expect(mockTerm).not.toBeNull();
  });
  await waitFor(() => {
    expect(eventListeners.has("pty:sess-123:output")).toBe(true);
    expect(eventListeners.has("pty:sess-123:closed")).toBe(true);
  });
}

describe("TerminalPane", () => {
  it("mounts xterm and registers an OSC 52 handler that returns true", async () => {
    renderTabbed();
    await waitForMount();
    expect(mockTerm!.parser.registerOscHandler).toHaveBeenCalledWith(52, expect.any(Function));
    const handler = mockTerm!.oscHandlers.get(52)!;
    expect(handler("anything")).toBe(true);
  });

  // Regression for the "nano doesn't fill the pane" / "long bash
  // commands wrap-overwrite the prompt" bug. The mount-effect's
  // fit() fires xterm.js's synchronous `onResize` before the IPC
  // effect attaches its listener, so the initial event is lost; the
  // ResizeObserver re-fit then no-ops because dimensions are
  // unchanged. Without an explicit prime, the PTY stays at the
  // hardcoded 80×24 from Session::open forever.
  it("primes the backend with term cols/rows on mount", async () => {
    renderTabbed();
    await waitForMount();
    await waitFor(() => {
      expect(mockedResizePty).toHaveBeenCalledWith("sess-123", 200, 50);
    });
  });

  it("forwards onData keystrokes through sendInput", async () => {
    renderTabbed();
    await waitForMount();

    act(() => {
      mockTerm!.fireData("hello");
    });
    await waitFor(() => {
      expect(mockedSendInput).toHaveBeenCalledTimes(1);
    });
    expect(mockedSendInput.mock.calls[0][0]).toBe("sess-123");
    // Base64-no-pad of "hello" is "aGVsbG8".
    expect(mockedSendInput.mock.calls[0][1]).toBe("aGVsbG8");
  });

  it("clears the visible terminal when a ui:clear-terminal event fires", async () => {
    renderTabbed();
    await waitForMount();
    // The v1.4.0 clear listener registers alongside the pty listeners.
    await waitFor(() => expect(eventListeners.has("ui:clear-terminal:sess-123")).toBe(true));
    // Ignore the mount-effect's own clear(); count only the event-driven one.
    mockTerm!.clear.mockClear();
    act(() => {
      fireBackendEvent("ui:clear-terminal:sess-123", null);
    });
    expect(mockTerm!.clear).toHaveBeenCalledTimes(1);
  });

  describe("focus management (v1.4.1)", () => {
    it("focuses the terminal when a ui:focus-terminal event fires (button bar hand-back)", async () => {
      renderTabbed();
      await waitForMount();
      await waitFor(() => expect(eventListeners.has("ui:focus-terminal:sess-123")).toBe(true));
      // Ignore the mount/active-effect focus() calls; count only the event-driven one.
      mockTerm!.focus.mockClear();
      act(() => {
        fireBackendEvent("ui:focus-terminal:sess-123", null);
      });
      expect(mockTerm!.focus).toHaveBeenCalledTimes(1);
    });

    it("focuses the terminal when the pane transitions to active (tab click)", async () => {
      const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
      const ui = (active: boolean) => (
        <QueryClientProvider client={client}>
          <TerminalPane sessionId="sess-123" deviceId="vEX1" ended={false} active={active} />
        </QueryClientProvider>
      );
      const { rerender } = render(ui(false));
      await waitFor(() => expect(mockTerm).not.toBeNull());
      // Clear the mount-effect focus() so we assert specifically on the
      // inactive → active transition.
      mockTerm!.focus.mockClear();
      rerender(ui(true));
      await waitFor(() => expect(mockTerm!.focus).toHaveBeenCalled());
    });
  });

  it("Disconnect on a live session confirms before dropping the connection", async () => {
    const { disconnectSession } = await import("@/lib/api");
    renderTabbed();
    await waitForMount();

    // Pane-header Disconnect button (the only "disconnect" button so far).
    await userEvent.click(screen.getByRole("button", { name: /disconnect/i }));

    // Confirm dialog appears; backend NOT called yet (anti-misclick).
    expect(await screen.findByText(/Disconnect session\?/i)).toBeInTheDocument();
    expect(vi.mocked(disconnectSession)).not.toHaveBeenCalled();

    // Confirm via the dialog's action (scoped so it's not the header button).
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: /^disconnect$/i }));
    await waitFor(() => expect(vi.mocked(disconnectSession)).toHaveBeenCalledWith("sess-123"));
  });

  it("dismissing the disconnect confirm keeps the session open", async () => {
    const { disconnectSession } = await import("@/lib/api");
    renderTabbed();
    await waitForMount();

    await userEvent.click(screen.getByRole("button", { name: /disconnect/i }));
    await userEvent.click(await screen.findByRole("button", { name: /keep open/i }));

    expect(vi.mocked(disconnectSession)).not.toHaveBeenCalled();
  });

  it("writes decoded PTY output bytes to the terminal verbatim when highlighting is off", async () => {
    renderTabbed();
    await waitForMount();

    // Base64 of "interface up\n".
    const b64 = btoa("interface up\n").replace(/=+$/, "");
    act(() => {
      fireBackendEvent("pty:sess-123:output", { data_b64: b64 });
    });

    await waitFor(() => {
      expect(mockTerm!.write).toHaveBeenCalled();
    });
    const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
    // No ANSI color codes since highlighting is off.
    expect(written).toBe("interface up\n");
  });

  it("applies ANSI highlighting when the device opts in", async () => {
    mockedListDevices.mockResolvedValue([device({ id: "vEX1", syntax_highlighting: true })]);
    renderTabbed();
    await waitForMount();
    // Wait one extra tick for the device-query to populate the
    // enabled-ref via its dedicated effect.
    await waitFor(() => {
      // The query data is in the cache once listDevices resolves.
      // Nothing observable on the DOM yet, but firing the event next
      // verifies the wire-up.
    });

    const b64 = btoa("interface up\n").replace(/=+$/, "");
    act(() => {
      fireBackendEvent("pty:sess-123:output", { data_b64: b64 });
    });

    await waitFor(() => {
      const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
      // Highlighter wraps `up` in ANSI green (\x1b[32m...\x1b[0m).
      expect(written).toContain("\x1b[32mup\x1b[0m");
    });
  });

  it("renders the highlighting badge in the header when enabled", async () => {
    mockedListDevices.mockResolvedValue([device({ id: "vEX1", syntax_highlighting: true })]);
    renderTabbed();
    await waitForMount();
    expect(await screen.findByText(/syntax highlighting/i)).toBeInTheDocument();
  });

  it("does not render the badge when the device has highlighting off", async () => {
    renderTabbed();
    await waitForMount();
    // Allow the listDevices query to settle so we know the badge would
    // have rendered if it were going to.
    await waitFor(() => {
      expect(mockedListDevices).toHaveBeenCalled();
    });
    expect(screen.queryByText(/syntax highlighting/i)).not.toBeInTheDocument();
  });

  it("layers the vendor pack over the defaults (cisco syslog mnemonic)", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", vendor: "cisco_ios", syntax_highlighting: true }),
    ]);
    renderTabbed();
    await waitForMount();
    // Badge render proves the device record — and so the vendor-pack
    // effect — has applied before we feed output.
    await screen.findByText(/syntax highlighting/i);

    const b64 = btoa("%SYS-5-CONFIG_I: Configured from console\n").replace(/=+$/, "");
    act(() => {
      fireBackendEvent("pty:sess-123:output", { data_b64: b64 });
    });

    await waitFor(() => {
      const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
      // cisco-syslog-info wraps the mnemonic in cyan — a pattern the
      // generic set doesn't carry.
      expect(written).toContain("\x1b[36m%SYS-5-CONFIG_I\x1b[0m");
    });
  });

  it("junos vendor pack highlights `commit complete`", async () => {
    // The default device fixture is vendor: "junos".
    mockedListDevices.mockResolvedValue([device({ id: "vEX1", syntax_highlighting: true })]);
    renderTabbed();
    await waitForMount();
    await screen.findByText(/syntax highlighting/i);

    const b64 = btoa("commit complete\n").replace(/=+$/, "");
    act(() => {
      fireBackendEvent("pty:sess-123:output", { data_b64: b64 });
    });

    await waitFor(() => {
      const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
      expect(written).toContain("\x1b[92mcommit complete\x1b[0m");
    });
  });

  describe("font preferences", () => {
    afterEach(() => {
      useUiStore.setState((s) => ({
        preferences: { ...s.preferences, terminalFontSize: null, terminalFontFamily: null },
      }));
    });

    it("applies size + family changes to xterm options and refits on the next frame", async () => {
      renderTabbed();
      await waitForMount();
      mockFit!.fit.mockClear();

      act(() => useUiStore.getState().setTerminalFontSize(16));
      expect(mockTerm!.options.fontSize).toBe(16);

      act(() => useUiStore.getState().setTerminalFontFamily("JetBrains Mono"));
      // User family first, stock stack appended as the fallback.
      expect(mockTerm!.options.fontFamily).toMatch(/^JetBrains Mono, ui-monospace/);

      // The refit is deferred to requestAnimationFrame so xterm's cell
      // metrics settle before rows/cols are recomputed (the
      // bottom-border clipping fix) — poll until the frame fires.
      await waitFor(() => {
        expect(mockFit!.fit).toHaveBeenCalled();
      });
    });

    it("reverts to the stock stack when the family resets to null", async () => {
      renderTabbed();
      await waitForMount();

      act(() => useUiStore.getState().setTerminalFontFamily("Comic Sans MS"));
      expect(mockTerm!.options.fontFamily).toMatch(/^Comic Sans MS, /);

      act(() => useUiStore.getState().setTerminalFontFamily(null));
      expect(mockTerm!.options.fontFamily).toMatch(/^ui-monospace/);
    });
  });

  it("flips the header to 'ended' and disables stdin when the session closes", async () => {
    renderTabbed();
    await waitForMount();
    expect(screen.getByText("connected:")).toBeInTheDocument();

    act(() => {
      fireBackendEvent("pty:sess-123:closed", { reason: "remote sent EOF" });
    });

    await waitFor(() => {
      expect(screen.getByText("ended:")).toBeInTheDocument();
    });
    expect(screen.getByText(/remote sent EOF/i)).toBeInTheDocument();
    expect(mockTerm!.options.disableStdin).toBe(true);
  });

  it("opens a confirmation dialog on multi-line paste and forwards on accept", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "line1\nline2\nline3");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));

    await waitFor(() => {
      expect(mockTerm!.paste).toHaveBeenCalledWith("line1\nline2\nline3");
    });
  });

  it("gates multi-line paste even when an inner element stops propagation (capture-phase, finding #4)", async () => {
    // Reproduces the real xterm.js hazard: xterm registers its own paste
    // handler on an inner textarea/element and `stopPropagation()`s in the
    // target/bubble phase. A bubble-phase container listener is shadowed;
    // a capture-phase one still fires. Here `inner` stands in for xterm's
    // inner handler. If the component ever regresses to bubble phase, the
    // dialog never appears and this test fails.
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const inner = document.createElement("div");
    host.appendChild(inner);
    inner.addEventListener("paste", (e) => e.stopPropagation());

    const dt = new DataTransfer();
    dt.setData("text", "l1\nl2\nl3");
    const evt = new ClipboardEvent("paste", {
      clipboardData: dt,
      bubbles: true,
      cancelable: true,
    });
    act(() => {
      inner.dispatchEvent(evt);
    });

    expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
  });

  // Regression: the dialog has no Radix trigger, so on close Radix's
  // restore-focus-to-trigger is a no-op and focus falls to <body> — the
  // terminal cursor goes hollow and the user has to click back in to type.
  // onCloseAutoFocus must hand focus back to the terminal on EVERY close path.
  it("returns focus to the terminal after confirming a multi-line paste", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "line1\nline2");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    await screen.findByText(/paste multi-line content/i);
    mockTerm!.focus.mockClear();
    await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));

    await waitFor(() => expect(mockTerm!.focus).toHaveBeenCalled());
  });

  it("returns focus to the terminal after cancelling a multi-line paste", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "line1\nline2");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    await screen.findByText(/paste multi-line content/i);
    mockTerm!.focus.mockClear();
    await userEvent.click(screen.getByRole("button", { name: /^cancel$/i }));

    await waitFor(() => expect(mockTerm!.focus).toHaveBeenCalled());
  });

  it("editing the pending text pastes the edited content, not the original clipboard", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "line1\nline2\nline3");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    await screen.findByText(/paste multi-line content/i);
    const textarea = screen.getByTestId("paste-edit-textarea") as HTMLTextAreaElement;
    expect(textarea.value).toBe("line1\nline2\nline3");

    // Trim a line + fix a typo — the dialog sends what's in the box.
    fireEvent.change(textarea, { target: { value: "line1\nline3-fixed" } });
    await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));
    await waitFor(() => {
      expect(mockTerm!.paste).toHaveBeenCalledWith("line1\nline3-fixed");
    });
    expect(mockTerm!.paste).not.toHaveBeenCalledWith("line1\nline2\nline3");
  });

  it("replace-all edits inside the dialog are exactly what term.paste receives (v2.6.3)", async () => {
    // The §17 property end-to-end through the extracted PasteConfirmDialog:
    // Find & Replace mutates only the staged draft, and the confirmed draft
    // — never the original clipboard — is what reaches the PTY.
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "user admin secret1\nuser operator secret1");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    await screen.findByText(/paste multi-line content/i);
    await userEvent.click(screen.getByTestId("paste-find-toggle"));
    await userEvent.type(screen.getByTestId("paste-find-input"), "secret1");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "REDACTED");
    await userEvent.click(screen.getByTestId("paste-replace-all"));
    await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));

    await waitFor(() => {
      expect(mockTerm!.paste).toHaveBeenCalledWith("user admin REDACTED\nuser operator REDACTED");
    });
    expect(mockTerm!.paste).not.toHaveBeenCalledWith("user admin secret1\nuser operator secret1");
  });

  it("emptying the pending text disables Paste (Cancel is the only exit)", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "a\nb");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    await screen.findByText(/paste multi-line content/i);
    fireEvent.change(screen.getByTestId("paste-edit-textarea"), { target: { value: "" } });
    expect(screen.getByRole("button", { name: /^paste$/i })).toBeDisabled();
    expect(mockTerm!.paste).not.toHaveBeenCalled();
  });

  it("does not open the dialog for single-line pastes", async () => {
    renderTabbed();
    await waitForMount();

    const host = screen.getByTestId("xterm-host");
    const dt = new DataTransfer();
    dt.setData("text", "single line no newline");
    const evt = new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true });
    act(() => {
      host.dispatchEvent(evt);
    });

    // Wait a tick to give the listener a chance to fire.
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText(/paste multi-line content/i)).not.toBeInTheDocument();
  });

  describe("CR-only paste gate", () => {
    // `\r` is Enter to the remote shell — clipboard text with bare-CR
    // separators is just as multi-command as LF text, so it must hit
    // the same confirm dialog on every paste path.
    it("Cmd-V paste with bare-\\r separators opens the confirm dialog and counts lines", async () => {
      renderTabbed();
      await waitForMount();

      const host = screen.getByTestId("xterm-host");
      const dt = new DataTransfer();
      dt.setData("text", "line1\rline2\rline3");
      const evt = new ClipboardEvent("paste", {
        clipboardData: dt,
        bubbles: true,
        cancelable: true,
      });
      act(() => {
        host.dispatchEvent(evt);
      });

      expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
      expect(evt.defaultPrevented).toBe(true);
      // Line counter treats CR like LF: 3 lines, not 1.
      expect(screen.getByText("3")).toBeInTheDocument();

      // Accepting forwards the CR text verbatim.
      await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));
      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("line1\rline2\rline3");
      });
    });

    it("right-click quick-paste with CR-only clipboard opens the confirm dialog, never pastes directly", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "show version\rconfigure";
      const host = screen.getByTestId("xterm-host");
      act(() => {
        host.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      });

      expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
      expect(mockTerm!.paste).not.toHaveBeenCalled();
    });

    it("single-line text (no CR and no LF) still quick-pastes directly without the dialog", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "show interfaces terse";
      const host = screen.getByTestId("xterm-host");
      act(() => {
        host.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
      });

      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("show interfaces terse");
      });
      expect(screen.queryByText(/paste multi-line content/i)).not.toBeInTheDocument();
    });
  });

  describe("drag-and-drop paste gate", () => {
    // happy-dom has no DragEvent constructor; synthesize a plain Event
    // with a dataTransfer property — the handler only reads
    // `dataTransfer.getData`.
    function fireDrop(host: HTMLElement, text: string): Event {
      const dt = new DataTransfer();
      dt.setData("text/plain", text);
      const evt = new Event("drop", { bubbles: true, cancelable: true });
      Object.defineProperty(evt, "dataTransfer", { value: dt });
      act(() => {
        host.dispatchEvent(evt);
      });
      return evt;
    }

    it("dropping multi-line text opens the confirm dialog and never writes directly", async () => {
      renderTabbed();
      await waitForMount();

      const host = screen.getByTestId("xterm-host");
      const evt = fireDrop(host, "configure\nset system services ssh\ncommit");

      expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
      expect(evt.defaultPrevented).toBe(true);
      // Nothing reached the terminal or the PTY before confirmation.
      expect(mockTerm!.paste).not.toHaveBeenCalled();
      expect(mockedSendInput).not.toHaveBeenCalled();

      // Accepting routes through the same gated forward as paste.
      await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));
      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("configure\nset system services ssh\ncommit");
      });
    });

    it("dropping single-line text routes through term.paste (the gated dispatcher)", async () => {
      renderTabbed();
      await waitForMount();

      const host = screen.getByTestId("xterm-host");
      fireDrop(host, "show version");

      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("show version");
      });
      expect(screen.queryByText(/paste multi-line content/i)).not.toBeInTheDocument();
    });

    it("dragover is preventDefault'd so the drop event can fire", async () => {
      renderTabbed();
      await waitForMount();

      const host = screen.getByTestId("xterm-host");
      const evt = new Event("dragover", { bubbles: true, cancelable: true });
      act(() => {
        host.dispatchEvent(evt);
      });
      expect(evt.defaultPrevented).toBe(true);
    });
  });

  describe("quick copy/paste", () => {
    it("auto-copies the selection when the device opts in", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      // Wait for the toggle ref to pick up the device record.
      await waitFor(() => {
        expect(mockTerm!.onSelectionChange).toHaveBeenCalled();
      });
      // Settle the device query so the ref has the correct value.
      await new Promise((r) => setTimeout(r, 10));

      mockTerm!.selection = "show interfaces terse";
      act(() => {
        mockTerm!.fireSelectionChange();
      });

      await waitFor(() => {
        expect(clipboardWriteText).toHaveBeenCalledWith("show interfaces terse");
      });
    });

    it("does NOT auto-copy when the device pref is off", async () => {
      renderTabbed();
      await waitForMount();
      await waitFor(() => {
        expect(mockTerm!.onSelectionChange).toHaveBeenCalled();
      });

      mockTerm!.selection = "do not copy this";
      act(() => {
        mockTerm!.fireSelectionChange();
      });

      // Give the (skipped) clipboard write a chance to NOT fire.
      await new Promise((r) => setTimeout(r, 20));
      expect(clipboardWriteText).not.toHaveBeenCalled();
    });

    it("ignores empty-selection deselect events", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      mockTerm!.selection = "";
      act(() => {
        mockTerm!.fireSelectionChange();
      });

      await new Promise((r) => setTimeout(r, 20));
      expect(clipboardWriteText).not.toHaveBeenCalled();
    });

    it("right-click pastes the clipboard when the device opts in", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "show route";
      const host = screen.getByTestId("xterm-host");
      const evt = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
      act(() => {
        host.dispatchEvent(evt);
      });

      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("show route");
      });
      expect(evt.defaultPrevented).toBe(true);
    });

    it("right-click does NOT paste when the device pref is off", async () => {
      renderTabbed();
      await waitForMount();

      clipboardText = "show route";
      const host = screen.getByTestId("xterm-host");
      const evt = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
      act(() => {
        host.dispatchEvent(evt);
      });

      await new Promise((r) => setTimeout(r, 20));
      expect(mockTerm!.paste).not.toHaveBeenCalled();
      // The default context menu is allowed when the pref is off.
      expect(evt.defaultPrevented).toBe(false);
    });

    it("middle-click pastes the clipboard when the device opts in", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "ping 10.0.0.1";
      const host = screen.getByTestId("xterm-host");
      const evt = new MouseEvent("mousedown", { bubbles: true, cancelable: true, button: 1 });
      act(() => {
        host.dispatchEvent(evt);
      });

      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("ping 10.0.0.1");
      });
    });

    it("middle-click ignores left-button presses (button 0)", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "should not paste";
      const host = screen.getByTestId("xterm-host");
      const evt = new MouseEvent("mousedown", { bubbles: true, cancelable: true, button: 0 });
      act(() => {
        host.dispatchEvent(evt);
      });

      await new Promise((r) => setTimeout(r, 20));
      expect(mockTerm!.paste).not.toHaveBeenCalled();
    });

    it("right-click on a multi-line clipboard opens the confirm dialog instead of pasting directly", async () => {
      mockedListDevices.mockResolvedValue([device({ id: "vEX1", quick_copy_paste: true })]);
      renderTabbed();
      await waitForMount();
      await new Promise((r) => setTimeout(r, 10));

      clipboardText = "line1\nline2\nline3";
      const host = screen.getByTestId("xterm-host");
      const evt = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
      act(() => {
        host.dispatchEvent(evt);
      });

      // Confirm dialog should appear instead of immediate paste.
      expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
      expect(mockTerm!.paste).not.toHaveBeenCalled();

      // Accepting the dialog forwards the multi-line text.
      await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));
      await waitFor(() => {
        expect(mockTerm!.paste).toHaveBeenCalledWith("line1\nline2\nline3");
      });
    });
  });

  describe("Enter-to-reconnect", () => {
    it("pressing Enter on an ended session disconnects + connects + swaps in place", async () => {
      const { connectDevice, disconnectSession } = await import("@/lib/api");
      vi.mocked(connectDevice).mockResolvedValue("session-uuid-fresh");
      vi.mocked(disconnectSession).mockResolvedValue(undefined);

      renderTabbed();
      await waitForMount();

      act(() => {
        fireBackendEvent("pty:sess-123:closed", { reason: "logout" });
      });
      await waitFor(() => {
        expect(screen.getByText("ended:")).toBeInTheDocument();
      });

      let swallowed = true;
      act(() => {
        swallowed = mockTerm!.fireKey({ key: "Enter" });
      });
      expect(swallowed).toBe(false);

      await waitFor(() => {
        expect(disconnectSession).toHaveBeenCalledWith("sess-123");
      });
      await waitFor(() => {
        expect(connectDevice).toHaveBeenCalledWith("vEX1");
      });
      await waitFor(() => {
        const state = useUiStore.getState();
        expect(state.sessions[0]).toMatchObject({
          sessionId: "session-uuid-fresh",
          deviceId: "vEX1",
          ended: false,
        });
      });
    });

    it("Enter on a LIVE session is not claimed (xterm processes it normally)", async () => {
      const { connectDevice } = await import("@/lib/api");
      vi.mocked(connectDevice).mockClear();

      renderTabbed();
      await waitForMount();

      let swallowed = false;
      act(() => {
        swallowed = mockTerm!.fireKey({ key: "Enter" });
      });
      expect(swallowed).toBe(true);

      await new Promise((r) => setTimeout(r, 20));
      expect(connectDevice).not.toHaveBeenCalled();
    });

    it("Shift+Enter on an ended session is NOT a reconnect", async () => {
      const { connectDevice } = await import("@/lib/api");
      vi.mocked(connectDevice).mockClear();

      renderTabbed();
      await waitForMount();
      act(() => {
        fireBackendEvent("pty:sess-123:closed", { reason: "logout" });
      });
      await waitFor(() => expect(screen.getByText("ended:")).toBeInTheDocument());

      let swallowed = false;
      act(() => {
        swallowed = mockTerm!.fireKey({ key: "Enter", shiftKey: true });
      });
      expect(swallowed).toBe(true);

      await new Promise((r) => setTimeout(r, 20));
      expect(connectDevice).not.toHaveBeenCalled();
    });

    it("shows the reconnect hint in the close banner", async () => {
      renderTabbed();
      await waitForMount();
      act(() => {
        fireBackendEvent("pty:sess-123:closed", { reason: "logout" });
      });
      expect(await screen.findByText(/press Enter to reconnect/i)).toBeInTheDocument();
    });

    it("rapid Enter presses only fire one reconnect (in-flight guard)", async () => {
      const { connectDevice } = await import("@/lib/api");
      vi.mocked(connectDevice).mockClear();
      // Hold the connect promise pending so both Enter presses race the
      // in-flight ref. Without the guard, the second press would call
      // connectDevice a second time.
      let resolveConnect!: (s: string) => void;
      vi.mocked(connectDevice).mockReturnValueOnce(
        new Promise<string>((res) => {
          resolveConnect = res;
        }),
      );

      renderTabbed();
      await waitForMount();
      act(() => {
        fireBackendEvent("pty:sess-123:closed", { reason: "logout" });
      });
      await waitFor(() => expect(screen.getByText("ended:")).toBeInTheDocument());

      act(() => {
        mockTerm!.fireKey({ key: "Enter" });
      });
      act(() => {
        mockTerm!.fireKey({ key: "Enter" });
      });

      await waitFor(() => expect(connectDevice).toHaveBeenCalledTimes(1));
      // Resolve the suspended connect promise inside act() so the
      // mutation's onSuccess (which mutates the Zustand store) doesn't
      // schedule an unwrapped state update after the test returns.
      await act(async () => {
        resolveConnect("session-uuid-fresh-2");
        await Promise.resolve();
      });
    });
  });

  describe("streaming UTF-8 decode", () => {
    function bytesToB64(bytes: number[]): string {
      return btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
    }

    it("reassembles a 2-byte char split across two output events — one é, no U+FFFD", async () => {
      renderTabbed();
      await waitForMount();

      // "é" is 0xC3 0xA9; the PTY chunks bytes, not chars, so the
      // halves can arrive in separate events. A per-event TextDecoder
      // would emit U+FFFD twice; the per-session streaming decoder
      // must carry the partial sequence across the boundary.
      act(() => {
        fireBackendEvent("pty:sess-123:output", { data_b64: bytesToB64([0xc3]) });
      });
      act(() => {
        fireBackendEvent("pty:sess-123:output", { data_b64: bytesToB64([0xa9]) });
      });

      // Partial line: lands via the 30 ms flush timer.
      await waitFor(() => {
        const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
        expect(written).toContain("é");
      });
      const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
      expect(written).toBe("é");
      expect(written).not.toContain("�");
    });

    it("session close flushes a dangling partial sequence as U+FFFD instead of dropping it", async () => {
      renderTabbed();
      await waitForMount();

      // "ok" followed by a lone UTF-8 lead byte with no continuation.
      act(() => {
        fireBackendEvent("pty:sess-123:output", { data_b64: bytesToB64([0x6f, 0x6b, 0xc3]) });
      });
      act(() => {
        fireBackendEvent("pty:sess-123:closed", { reason: "EOF" });
      });

      await waitFor(() => {
        const written = mockTerm!.write.mock.calls.map((c) => c[0]).join("");
        expect(written).toContain("ok");
        expect(written).toContain("�");
      });
    });
  });

  describe("scrollback search", () => {
    it("Cmd+F (keydown) opens the search overlay; returns false to swallow the event", async () => {
      renderTabbed();
      await waitForMount();
      expect(screen.queryByTestId("search-overlay")).not.toBeInTheDocument();

      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "f", metaKey: true });
      });
      expect(verdict).toBe(false);
      expect(await screen.findByTestId("search-overlay")).toBeInTheDocument();
    });

    it("Ctrl+F also opens it (Linux/Windows path)", async () => {
      renderTabbed();
      await waitForMount();
      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "f", ctrlKey: true });
      });
      expect(verdict).toBe(false);
      expect(await screen.findByTestId("search-overlay")).toBeInTheDocument();
    });

    it("keyup for the same chord does not double-toggle", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true, type: "keydown" }));
      await screen.findByTestId("search-overlay");
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true, type: "keyup" }));
      expect(screen.getByTestId("search-overlay")).toBeInTheDocument();
    });

    it("typing into the input fires findNext; empty input clears decorations", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      const input = await screen.findByTestId("search-input");

      await userEvent.type(input, "bgp");
      expect(mockSearch!.findNext).toHaveBeenLastCalledWith(
        "bgp",
        expect.objectContaining({ decorations: expect.anything() }),
      );

      await userEvent.clear(input);
      expect(mockSearch!.clearDecorations).toHaveBeenCalled();
    });

    it("Enter cycles forward; Shift+Enter cycles back; arrows match", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      const input = await screen.findByTestId("search-input");
      await userEvent.type(input, "interface");
      mockSearch!.findNext.mockClear();
      mockSearch!.findPrevious.mockClear();

      await userEvent.keyboard("{Enter}");
      expect(mockSearch!.findNext).toHaveBeenCalledWith(
        "interface",
        expect.objectContaining({ decorations: expect.anything() }),
      );

      await userEvent.keyboard("{Shift>}{Enter}{/Shift}");
      expect(mockSearch!.findPrevious).toHaveBeenCalledWith(
        "interface",
        expect.objectContaining({ decorations: expect.anything() }),
      );

      await userEvent.keyboard("{ArrowDown}");
      expect(mockSearch!.findNext).toHaveBeenCalledTimes(2);
      await userEvent.keyboard("{ArrowUp}");
      expect(mockSearch!.findPrevious).toHaveBeenCalledTimes(2);
    });

    it("Esc closes and clears decorations", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      const input = await screen.findByTestId("search-input");
      await userEvent.type(input, "show");

      await userEvent.keyboard("{Escape}");
      await waitFor(() => expect(screen.queryByTestId("search-overlay")).not.toBeInTheDocument());
      expect(mockSearch!.clearDecorations).toHaveBeenCalled();
    });

    it("X button closes the overlay", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      await screen.findByTestId("search-overlay");
      await userEvent.click(screen.getByTestId("search-close"));
      expect(screen.queryByTestId("search-overlay")).not.toBeInTheDocument();
    });

    it("non-Find keys are not swallowed (let xterm.js process them)", async () => {
      renderTabbed();
      await waitForMount();
      let verdict = false;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "a", metaKey: true });
      });
      expect(verdict).toBe(true);
    });

    it("passes all-match decorations to findNext (highlight-all)", async () => {
      // allowProposedApi:true (on the Terminal) unblocks the SearchAddon's
      // decoration path, so search highlights every match on the pane +
      // overview ruler, not just the active selection.
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      const input = await screen.findByTestId("search-input");
      await userEvent.type(input, "vlan");
      const [term, opts] = mockSearch!.findNext.mock.calls.at(-1) ?? [];
      expect(term).toBe("vlan");
      expect((opts as { decorations?: unknown } | undefined)?.decorations).toBeDefined();
    });

    it("renders the live match counter from onDidChangeResults", async () => {
      renderTabbed();
      await waitForMount();
      act(() => mockTerm!.fireKey({ key: "f", metaKey: true }));
      const input = await screen.findByTestId("search-input");
      await userEvent.type(input, "vlan");
      // Simulate the addon reporting "match 3 of 5".
      act(() => searchResultsCb?.({ resultIndex: 2, resultCount: 5 }));
      expect(screen.getByTestId("search-count")).toHaveTextContent("3/5");
    });
  });

  describe("copy/paste shortcuts on Windows + Linux (v6.1.0)", () => {
    // These run with IS_MAC false (jsdom reports no mac platform), i.e.
    // the Windows/Linux branch — which is the only branch that exists.
    //
    // The trap being closed: xterm.js computes the control byte as
    // `keyCode - 64` REGARDLESS of Shift, so Ctrl+Shift+C is the same
    // byte as Ctrl+C (0x03, SIGINT) and Ctrl+Shift+V the same as
    // Ctrl+V (0x16). Not claiming the chord would interrupt the running
    // command while the user tried to copy.
    it("Ctrl+Shift+C copies the selection and keeps SIGINT off the PTY", async () => {
      renderTabbed();
      await waitForMount();
      clipboardWriteText.mockClear();
      mockTerm!.getSelection.mockReturnValue("show ip int brief");

      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "C", ctrlKey: true, shiftKey: true });
      });

      expect(verdict).toBe(false);
      expect(clipboardWriteText).toHaveBeenCalledWith("show ip int brief");
    });

    it("Ctrl+Shift+C with no selection is a no-op that STILL blocks the byte", async () => {
      renderTabbed();
      await waitForMount();
      clipboardWriteText.mockClear();
      mockTerm!.getSelection.mockReturnValue("");

      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "c", ctrlKey: true, shiftKey: true });
      });

      // Nothing copied, but the chord is still claimed — falling
      // through would send SIGINT to the device.
      expect(verdict).toBe(false);
      expect(clipboardWriteText).not.toHaveBeenCalled();
    });

    it("Ctrl+Shift+V routes through the multi-line confirm, not straight to the PTY", async () => {
      renderTabbed();
      await waitForMount();
      clipboardReadText.mockResolvedValue("conf t\ninterface Gi0/1\nshutdown");

      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "v", ctrlKey: true, shiftKey: true });
      });
      expect(verdict).toBe(false);

      // A multi-line clipboard must land in the confirm dialog — the
      // keyboard path gets no exemption from the paste gate.
      expect(await screen.findByText(/paste multi-line content/i)).toBeInTheDocument();
      expect(mockTerm!.paste).not.toHaveBeenCalled();
    });

    it("Ctrl+Shift+V with a single line pastes directly", async () => {
      renderTabbed();
      await waitForMount();
      clipboardReadText.mockResolvedValue("show version");

      act(() => {
        mockTerm!.fireKey({ key: "v", ctrlKey: true, shiftKey: true });
      });

      await waitFor(() => expect(mockTerm!.paste).toHaveBeenCalledWith("show version"));
    });

    it("plain Ctrl+C is untouched — SIGINT must still reach the device", async () => {
      renderTabbed();
      await waitForMount();
      clipboardWriteText.mockClear();
      mockTerm!.getSelection.mockReturnValue("some selection");

      let verdict = false;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "c", ctrlKey: true });
      });

      // The whole point of Ctrl+Shift+C existing: Ctrl+C stays an
      // interrupt even when text happens to be selected.
      expect(verdict).toBe(true);
      expect(clipboardWriteText).not.toHaveBeenCalled();
    });

    it("keyup for the same chord stays swallowed but does not re-copy", async () => {
      renderTabbed();
      await waitForMount();
      clipboardWriteText.mockClear();
      mockTerm!.getSelection.mockReturnValue("x");

      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "c", ctrlKey: true, shiftKey: true, type: "keyup" });
      });

      expect(verdict).toBe(false);
      expect(clipboardWriteText).not.toHaveBeenCalled();
    });
  });

  describe("clear-terminal shortcut (Cmd/Ctrl+Shift+K)", () => {
    // xterm.js translates Ctrl+Shift+K into 0x0B (kill-line) — same byte as
    // Ctrl+K — so the pane MUST claim the chord (return false) to keep it off
    // the PTY, then emit the same event the native menu emits. This is the
    // real Windows/Linux path; the menu accelerator only fires on macOS.
    it("Ctrl+Shift+K (keydown) returns false to block the PTY byte and emits menu:clear-terminal", async () => {
      renderTabbed();
      await waitForMount();
      vi.mocked(emit).mockClear();
      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "k", ctrlKey: true, shiftKey: true });
      });
      expect(verdict).toBe(false);
      expect(emit).toHaveBeenCalledWith("menu:clear-terminal");
    });

    it("Cmd+Shift+K also clears (macOS path)", async () => {
      renderTabbed();
      await waitForMount();
      vi.mocked(emit).mockClear();
      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "k", metaKey: true, shiftKey: true });
      });
      expect(verdict).toBe(false);
      expect(emit).toHaveBeenCalledWith("menu:clear-terminal");
    });

    it("keyup for the same chord stays swallowed but does not re-emit", async () => {
      renderTabbed();
      await waitForMount();
      vi.mocked(emit).mockClear();
      let verdict = true;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "k", ctrlKey: true, shiftKey: true, type: "keyup" });
      });
      expect(verdict).toBe(false);
      expect(emit).not.toHaveBeenCalled();
    });

    it("Ctrl+K (no Shift) is left for xterm — it must reach the PTY as kill-line", async () => {
      renderTabbed();
      await waitForMount();
      vi.mocked(emit).mockClear();
      let verdict = false;
      act(() => {
        verdict = mockTerm!.fireKey({ key: "k", ctrlKey: true });
      });
      expect(verdict).toBe(true);
      expect(emit).not.toHaveBeenCalled();
    });
  });

  describe("fit guard on tab visibility", () => {
    // Regression for the un-Entered-input corruption: typing a line
    // (no Enter) in one tab, switching to another tab, then switching
    // back left the cursor + text mangled ("R1#This is a line" came
    // back as "R1#This i" with a stray cursor). Cause: the hidden
    // pane's ResizeObserver fires fit() when the tab collapses to a
    // zero box (display:none), FitAddon proposes ~9 cols, and the
    // buffer reflows into that tiny grid. The fix skips fit() whenever
    // the container has no layout.
    it("does NOT fit when the pane is hidden (zero client box)", async () => {
      renderTabbed();
      await waitForMount();
      expect(typeof roCallback).toBe("function");

      // Simulate the inactive tab's display:none collapse on the
      // pane's own container (data-testid="xterm-host" === containerRef).
      const host = screen.getByTestId("xterm-host");
      Object.defineProperty(host, "clientWidth", { configurable: true, value: 0 });
      Object.defineProperty(host, "clientHeight", { configurable: true, value: 0 });

      mockFit!.fit.mockClear();
      act(() => {
        roCallback!();
      });
      expect(mockFit!.fit).not.toHaveBeenCalled();
    });

    it("DOES fit when the pane is visible (non-zero client box)", async () => {
      renderTabbed();
      await waitForMount();
      expect(typeof roCallback).toBe("function");

      // Host inherits the laid-out prototype box (a visible pane).
      mockFit!.fit.mockClear();
      act(() => {
        roCallback!();
      });
      expect(mockFit!.fit).toHaveBeenCalledTimes(1);
    });

    it("re-fits on activation so a resize deferred while hidden lands on switch-back", async () => {
      const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
      const ui = (active: boolean) => (
        <QueryClientProvider client={client}>
          <TerminalPane sessionId="sess-123" deviceId="vEX1" ended={false} active={active} />
        </QueryClientProvider>
      );
      const { rerender } = render(ui(false));
      await waitFor(() => expect(mockTerm).not.toBeNull());
      // Clear the mount-effect fit; assert specifically on the
      // inactive → active transition (the switch-back re-fit).
      mockFit!.fit.mockClear();
      rerender(ui(true));
      await waitFor(() => expect(mockFit!.fit).toHaveBeenCalled());
    });
  });
});
