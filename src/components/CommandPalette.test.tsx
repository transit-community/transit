import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  connectDevice: vi.fn(),
  disconnectSession: vi.fn(),
}));

import { connectDevice, listDevices } from "@/lib/api";
import { useUiStore } from "@/stores/uiStore";

import { CommandPalette } from "./CommandPalette";

const mockedListDevices = vi.mocked(listDevices);
const mockedConnectDevice = vi.mocked(connectDevice);

function renderPalette() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return renderWithClient(<CommandPalette />, client);
}

function renderWithClient(ui: ReactElement, client: QueryClient) {
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  // Reset zustand store between tests.
  useUiStore.setState({
    commandPaletteOpen: false,
    authProfileManagerOpen: false,
    sidebarCollapsed: false,
    chatPanelOpen: false,
    sessions: [],
    activeTabId: null,
    settingsDialogOpen: false,
  });

  mockedListDevices.mockResolvedValue([
    {
      id: "vEX1",
      host: "192.0.2.35",
      port: 22,
      vendor: "junos",
      group: "Lab",
      auth: "lab-pw",
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
    },
    {
      id: "CSR1",
      host: "192.0.2.86",
      port: 22,
      vendor: "cisco_ios_xe",
      group: "Cisco",
      auth: "labssh-ios",
      syntax_highlighting: null,
      quick_copy_paste: null,
      font_family: null,
      font_size: null,
      bold_color: null,
      color: null,
      tags: [],
      allow_weak_crypto: true,
      netbox_id: null,
      jump_via: null,
      forward_agent: null,
    },
  ]);
  // Default to signed-out — keeps tests simpler. The signed-out
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("CommandPalette", () => {
  it("renders nothing when closed", () => {
    renderPalette();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders Navigation + Devices groups when open", async () => {
    renderPalette();
    act(() => useUiStore.setState({ commandPaletteOpen: true }));

    await screen.findByRole("dialog");
    // Navigation entries
    expect(await screen.findByText("Manage auth profiles...")).toBeInTheDocument();
    expect(screen.getByText("Open settings...")).toBeInTheDocument();
    expect(screen.getByText("Toggle sidebar")).toBeInTheDocument();
    // Devices appear once listDevices resolves
    await waitFor(() => {
      expect(screen.getByText("Connect to vEX1")).toBeInTheDocument();
      expect(screen.getByText("Connect to CSR1")).toBeInTheDocument();
    });
  });

  it("filters items by the search input", async () => {
    renderPalette();
    act(() => useUiStore.setState({ commandPaletteOpen: true }));

    await screen.findByText("Connect to vEX1");
    const input = screen.getByPlaceholderText(/type a command/i);
    await userEvent.type(input, "csr");

    expect(screen.getByText("Connect to CSR1")).toBeInTheDocument();
    expect(screen.queryByText("Connect to vEX1")).not.toBeInTheDocument();
  });

  it("selecting a device runs connectDevice and closes the palette", async () => {
    renderPalette();
    act(() => useUiStore.setState({ commandPaletteOpen: true }));

    await screen.findByText("Connect to vEX1");
    await userEvent.click(screen.getByTestId("command-item-device-connect-vEX1"));

    await waitFor(() => {
      expect(mockedConnectDevice).toHaveBeenCalledWith("vEX1");
    });
    // Palette closed via store action
    expect(useUiStore.getState().commandPaletteOpen).toBe(false);
  });

  it("'Manage auth profiles...' opens the auth manager dialog", async () => {
    renderPalette();
    act(() => useUiStore.setState({ commandPaletteOpen: true }));

    await userEvent.click(await screen.findByTestId("command-item-nav-auth-profiles"));

    expect(useUiStore.getState().authProfileManagerOpen).toBe(true);
    expect(useUiStore.getState().commandPaletteOpen).toBe(false);
  });

  it("'Toggle sidebar' calls the store action", async () => {
    renderPalette();
    act(() => useUiStore.setState({ commandPaletteOpen: true, sidebarCollapsed: false }));

    await userEvent.click(await screen.findByTestId("command-item-nav-toggle-sidebar"));

    expect(useUiStore.getState().sidebarCollapsed).toBe(true);
  });

  it("scopes to Sessions when opened as Jump to Session (v6.1.0)", async () => {
    renderPalette();
    act(() =>
      useUiStore.setState({
        commandPaletteOpen: true,
        commandPaletteScope: "sessions",
        sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
        activeTabId: "s1",
      }),
    );

    expect(await screen.findByText("Focus vEX1")).toBeInTheDocument();
    // The bug this pins: with a real inventory the Devices group runs to
    // dozens of "Connect to …" entries and pushes the open sessions below
    // the fold, so the menu item looks like it does nothing.
    expect(screen.queryByText(/^Connect to /)).not.toBeInTheDocument();
    expect(screen.queryByText("Open Settings")).not.toBeInTheDocument();
  });

  it("says so plainly when there are no sessions to jump to", async () => {
    renderPalette();
    act(() =>
      useUiStore.setState({
        commandPaletteOpen: true,
        commandPaletteScope: "sessions",
        sessions: [],
        activeTabId: null,
      }),
    );

    expect(await screen.findByText("No open sessions to jump to.")).toBeInTheDocument();
  });

  it("Cmd/Ctrl+K returns to the full registry after a scoped open", async () => {
    renderPalette();
    act(() => useUiStore.getState().openCommandPalette("sessions"));
    expect(useUiStore.getState().commandPaletteScope).toBe("sessions");

    // Toggling shut then open again must not inherit the scope — a
    // leftover scope would silently hide half the palette.
    act(() => useUiStore.getState().toggleCommandPalette());
    act(() => useUiStore.getState().toggleCommandPalette());
    expect(useUiStore.getState().commandPaletteScope).toBe("all");
  });

  it("surfaces Focus + Close entries for open sessions", async () => {
    renderPalette();
    act(() =>
      useUiStore.setState({
        commandPaletteOpen: true,
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX1", ended: false },
        ],
        activeTabId: "s1",
      }),
    );

    // First session uses bare deviceId; second gets disambiguator.
    expect(await screen.findByText("Focus vEX1")).toBeInTheDocument();
    expect(screen.getByText("Focus vEX1 (2)")).toBeInTheDocument();
    expect(screen.getByText("Close vEX1")).toBeInTheDocument();
    expect(screen.getByText("Close vEX1 (2)")).toBeInTheDocument();
  });

  it("'Focus' switches the active tab", async () => {
    renderPalette();
    act(() =>
      useUiStore.setState({
        commandPaletteOpen: true,
        sessions: [
          { sessionId: "s1", deviceId: "vEX1", ended: false },
          { sessionId: "s2", deviceId: "vEX2", ended: false },
        ],
        activeTabId: "s1",
      }),
    );

    await userEvent.click(await screen.findByTestId("command-item-session-focus-s2"));

    expect(useUiStore.getState().activeTabId).toBe("s2");
  });

  it("offers Focus but NOT Close for a Files tab (v5.0.0)", async () => {
    // `Close` routes to `disconnect_session`, which has no files arm — the
    // `files_*` namespace is disjoint, so a palette Close would drop the tab
    // and leak the SFTP session. Closing goes through the tab ✕.
    useUiStore.setState({
      commandPaletteOpen: true,
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "f1", deviceId: "vEX9", ended: false, kind: "files" },
      ],
      activeTabId: "s1",
    });
    renderPalette();

    expect(await screen.findByText("Focus vEX9")).toBeInTheDocument();
    expect(screen.queryByText("Close vEX9")).toBeNull();
    // The SSH tab keeps both entries.
    expect(screen.getByText("Focus vEX1")).toBeInTheDocument();
    expect(screen.getByText("Close vEX1")).toBeInTheDocument();
  });
});
