import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useUiStore } from "@/stores/uiStore";

import { Sidebar } from "./Sidebar";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listAuthProfiles: vi.fn(),
  addDevice: vi.fn(),
  updateDevice: vi.fn(),
  deleteDevice: vi.fn(),
  addAuthProfile: vi.fn(),
  updateAuthProfile: vi.fn(),
  deleteAuthProfile: vi.fn(),
  renameGroup: vi.fn(),
  listGroups: vi.fn().mockResolvedValue([]),
  addGroup: vi.fn(),
  deleteGroup: vi.fn(),
  setDeviceGroup: vi.fn(),
  bulkUpdateDevices: vi.fn().mockResolvedValue(2),
  exportConnections: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
  testSecretResolve: vi.fn(),
  enrollSecret: vi.fn(),
  // Phase 2b SSH IPCs.
  connectDevice: vi.fn(),
  disconnectSession: vi.fn(),
  listOpenSessions: vi.fn().mockResolvedValue([]),
  sendInput: vi.fn(),
  resizePty: vi.fn(),
  verifyHostKey: vi.fn(),
  // Phase 7b — ConsoleCablesSection renders at the bottom of the
  // sidebar. Default to empty so it stays hidden in existing tests.
  listConsoleCables: vi.fn().mockResolvedValue([]),
  connectConsoleCable: vi.fn(),
  disconnectConsoleSession: vi.fn(),
  listConsoleDriverStatus: vi.fn().mockResolvedValue({ missing_drivers: [] }),
}));

// Console hot-plug + other listeners subscribe via `listen()`. Mock it
// so the real tauri internals don't try to call into a missing
// `window.__TAURI_INTERNALS__`.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

import { listAuthProfiles, listDevices, type DeviceMeta } from "@/lib/api";

const mockedListDevices = vi.mocked(listDevices);
const mockedListAuthProfiles = vi.mocked(listAuthProfiles);

function device(
  partial: Partial<DeviceMeta> & Pick<DeviceMeta, "id" | "host" | "vendor">,
): DeviceMeta {
  return {
    port: 22,
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

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  // Reset the Zustand store between tests so state from a prior test
  // doesn't bleed into the next.
  useUiStore.setState({
    activeDeviceId: null,
    sidebarCollapsed: false,
    sessions: [],
    activeTabId: null,
  });
  mockedListAuthProfiles.mockResolvedValue([]);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Sidebar", () => {
  it("renders the empty state when the inventory has no devices", async () => {
    mockedListDevices.mockResolvedValue([]);
    renderWithQuery(<Sidebar />);

    expect(await screen.findByText(/no devices yet\./i)).toBeInTheDocument();
    // Empty-state CTA button.
    expect(screen.getAllByText(/\+ new device/i)[0]).toBeInTheDocument();
  });

  it("renders an error banner when the IPC fetch fails", async () => {
    mockedListDevices.mockRejectedValue(
      new Error(
        "inline secret-shaped value at transit.toml:9: matched pattern 'password = \"...\"'",
      ),
    );
    renderWithQuery(<Sidebar />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/inline secret-shaped value/);
    expect(alert).toHaveTextContent(/transit\.toml:9/);
  });

  it("renders devices grouped by their hierarchical group path", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: "Lab/Junos" }),
      device({
        id: "core-sw1",
        host: "10.10.10.5",
        vendor: "cisco_ios_xe",
        group: "Prod/Switches",
      }),
      device({ id: "rt-edge", host: "10.0.0.1", vendor: "cisco_ios", group: "Prod/Routers" }),
      device({ id: "loose", host: "192.168.1.1", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    expect(await screen.findByText("vEX1")).toBeInTheDocument();
    // Group folders render their last path segment.
    expect(screen.getByText("Lab")).toBeInTheDocument();
    expect(screen.getByText("Prod")).toBeInTheDocument();
    expect(screen.getByText("Junos")).toBeInTheDocument();
    expect(screen.getByText("Switches")).toBeInTheDocument();
    expect(screen.getByText("Routers")).toBeInTheDocument();
    // Ungrouped device renders at root.
    expect(screen.getByText("loose")).toBeInTheDocument();

    // Three nested-tree devices + one ungrouped → 4 connection pills.
    expect(screen.getAllByText(/not connected/i)).toHaveLength(4);
  });

  it("filters devices by id, host, or group substring", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: "Lab/Junos" }),
      device({
        id: "core-sw1",
        host: "10.10.10.5",
        vendor: "cisco_ios_xe",
        group: "Prod/Switches",
      }),
    ]);
    renderWithQuery(<Sidebar />);

    await screen.findByText("vEX1");

    const search = screen.getByPlaceholderText(/search devices/i);
    await userEvent.type(search, "core");

    await waitFor(() => {
      expect(screen.queryByText("vEX1")).not.toBeInTheDocument();
    });
    expect(screen.getByText("core-sw1")).toBeInTheDocument();
  });

  it("clicking a device updates the active device id in the store", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    const row = await screen.findByRole("button", { name: /vEX1/ });
    await userEvent.click(row);

    expect(useUiStore.getState().activeDeviceId).toBe("vEX1");
  });

  it("clicking the refresh button invalidates the devices query", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    await screen.findByText("vEX1");
    expect(mockedListDevices).toHaveBeenCalledTimes(1);

    const refresh = screen.getByRole("button", { name: /refresh inventory/i });
    await userEvent.click(refresh);

    await waitFor(() => {
      expect(mockedListDevices).toHaveBeenCalledTimes(2);
    });
  });

  it("right-click → Connect calls the SSH IPC and updates the session store on success", async () => {
    const { connectDevice } = await import("@/lib/api");
    const mockedConnect = vi.mocked(connectDevice);
    mockedConnect.mockResolvedValue("session-uuid-abc");

    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    const row = await screen.findByRole("button", { name: /vEX1/ });
    // shadcn's ContextMenu opens on right-click (button=2).
    await userEvent.pointer({ keys: "[MouseRight]", target: row });

    const connect = await screen.findByRole("menuitem", { name: /^connect$/i });
    await userEvent.click(connect);

    await waitFor(() => {
      expect(mockedConnect).toHaveBeenCalledWith("vEX1");
    });
    await waitFor(() => {
      const state = useUiStore.getState();
      expect(state.sessions).toHaveLength(1);
      expect(state.sessions[0].sessionId).toBe("session-uuid-abc");
      expect(state.sessions[0].deviceId).toBe("vEX1");
      expect(state.sessions[0].ended).toBe(false);
      expect(state.activeTabId).toBe("session-uuid-abc");
    });
  });

  it("double-clicking a device row connects", async () => {
    const { connectDevice } = await import("@/lib/api");
    const mockedConnect = vi.mocked(connectDevice);
    mockedConnect.mockResolvedValue("session-uuid-dbl");

    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    const row = await screen.findByRole("button", { name: /vEX1/ });
    await userEvent.dblClick(row);

    await waitFor(() => {
      expect(mockedConnect).toHaveBeenCalledWith("vEX1");
    });
    await waitFor(() => {
      expect(useUiStore.getState().sessions).toHaveLength(1);
      expect(useUiStore.getState().sessions[0].sessionId).toBe("session-uuid-dbl");
    });
  });

  it("pressing Enter on a focused device row connects without going through the menu", async () => {
    const { connectDevice } = await import("@/lib/api");
    const mockedConnect = vi.mocked(connectDevice);
    mockedConnect.mockResolvedValue("session-uuid-enter");

    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    const row = await screen.findByRole("button", { name: /vEX1/ });
    row.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() => {
      expect(mockedConnect).toHaveBeenCalledWith("vEX1");
    });
  });

  // ----- v2.8.1 — sidebar multi-select + "Launch all" -----

  describe("multi-select launch all (v2.8.1)", () => {
    async function renderThreeDevices() {
      mockedListDevices.mockResolvedValue([
        device({ id: "sw-a", host: "10.0.0.1", vendor: "junos" }),
        device({ id: "sw-b", host: "10.0.0.2", vendor: "junos" }),
        device({ id: "sw-c", host: "10.0.0.3", vendor: "junos" }),
      ]);
      renderWithQuery(<Sidebar />);
      const rowA = await screen.findByRole("button", { name: /sw-a/ });
      const rowB = screen.getByRole("button", { name: /sw-b/ });
      const rowC = screen.getByRole("button", { name: /sw-c/ });
      return { rowA, rowB, rowC };
    }

    async function mockedConnectFn() {
      const { connectDevice } = await import("@/lib/api");
      const mocked = vi.mocked(connectDevice);
      mocked.mockReset();
      return mocked;
    }

    it("cmd-click selects; Launch all connects each device in visible order", async () => {
      const mockedConnect = await mockedConnectFn();
      mockedConnect.mockImplementation(async (id) => `sess-${id}`);

      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowB, { metaKey: true });

      expect(rowA).toHaveAttribute("data-selected", "true");
      expect(rowB).toHaveAttribute("data-selected", "true");
      expect(rowC).not.toHaveAttribute("data-selected");

      await userEvent.pointer({ keys: "[MouseRight]", target: rowB });
      const launch = await screen.findByRole("menuitem", {
        name: /launch all \(2 devices\)/i,
      });
      await userEvent.click(launch);

      await waitFor(() => {
        expect(useUiStore.getState().sessions).toHaveLength(2);
      });
      expect(mockedConnect.mock.calls.map((c) => c[0])).toEqual(["sw-a", "sw-b"]);
      const state = useUiStore.getState();
      expect(state.sessions.map((s) => s.sessionId)).toEqual(["sess-sw-a", "sess-sw-b"]);
      expect(state.sessions.map((s) => s.deviceId)).toEqual(["sw-a", "sw-b"]);
      // Tabs focus as they open — the last launched device ends up active.
      expect(state.activeTabId).toBe("sess-sw-b");
    });

    it("shift-click extends the selection over the visible range", async () => {
      await mockedConnectFn();
      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });

      expect(rowA).toHaveAttribute("data-selected", "true");
      expect(rowB).toHaveAttribute("data-selected", "true");
      expect(rowC).toHaveAttribute("data-selected", "true");

      await userEvent.pointer({ keys: "[MouseRight]", target: rowA });
      expect(
        await screen.findByRole("menuitem", { name: /launch all \(3 devices\)/i }),
      ).toBeInTheDocument();
    });

    it("ctrl-click toggles a selected row back out of the range", async () => {
      await mockedConnectFn();
      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });
      fireEvent.click(rowB, { ctrlKey: true });

      expect(rowB).not.toHaveAttribute("data-selected");

      await userEvent.pointer({ keys: "[MouseRight]", target: rowA });
      expect(
        await screen.findByRole("menuitem", { name: /launch all \(2 devices\)/i }),
      ).toBeInTheDocument();
    });

    it("plain click collapses the selection to the clicked row (single menu)", async () => {
      await mockedConnectFn();
      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });
      fireEvent.click(rowB);

      expect(rowA).not.toHaveAttribute("data-selected");
      expect(rowB).toHaveAttribute("data-selected", "true");
      expect(rowC).not.toHaveAttribute("data-selected");

      await userEvent.pointer({ keys: "[MouseRight]", target: rowB });
      expect(await screen.findByRole("menuitem", { name: /^connect$/i })).toBeInTheDocument();
      expect(screen.queryByRole("menuitem", { name: /launch all/i })).not.toBeInTheDocument();
    });

    it("right-clicking an unselected row retargets the selection to it", async () => {
      await mockedConnectFn();
      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowB, { metaKey: true });

      await userEvent.pointer({ keys: "[MouseRight]", target: rowC });

      // Ordinary single-device menu — never a launch-all aimed at rows
      // the user right-clicked away from.
      expect(await screen.findByRole("menuitem", { name: /^connect$/i })).toBeInTheDocument();
      expect(screen.queryByRole("menuitem", { name: /launch all/i })).not.toBeInTheDocument();
      expect(rowC).toHaveAttribute("data-selected", "true");
      expect(rowA).not.toHaveAttribute("data-selected");
      expect(rowB).not.toHaveAttribute("data-selected");
    });

    it("Clear selection empties the multi-selection", async () => {
      await mockedConnectFn();
      const { rowA, rowB, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });

      await userEvent.pointer({ keys: "[MouseRight]", target: rowB });
      const clear = await screen.findByRole("menuitem", { name: /clear selection/i });
      await userEvent.click(clear);

      await waitFor(() => {
        expect(rowA).not.toHaveAttribute("data-selected");
      });
      expect(rowB).not.toHaveAttribute("data-selected");
      expect(rowC).not.toHaveAttribute("data-selected");
    });

    it("group folder → Launch all in group connects the whole subtree", async () => {
      const mockedConnect = await mockedConnectFn();
      mockedConnect.mockImplementation(async (id) => `sess-${id}`);

      mockedListDevices.mockResolvedValue([
        device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: "Lab/Junos" }),
        device({ id: "vEX2", host: "192.0.2.36", vendor: "junos", group: "Lab" }),
        device({ id: "loose", host: "192.168.1.1", vendor: "junos", group: null }),
      ]);
      renderWithQuery(<Sidebar />);

      const labHeader = await screen.findByText("Lab");
      await userEvent.pointer({ keys: "[MouseRight]", target: labHeader });

      const launch = await screen.findByRole("menuitem", {
        name: /launch all in group \(2 devices\)/i,
      });
      await userEvent.click(launch);

      await waitFor(() => {
        expect(useUiStore.getState().sessions).toHaveLength(2);
      });
      // Subgroup devices included, tree order; devices outside the
      // folder untouched.
      expect(mockedConnect.mock.calls.map((c) => c[0])).toEqual(["vEX1", "vEX2"]);
    });

    it("Edit N devices… routes the multi-selection into the bulk dialog (v6.3.0)", async () => {
      const { rowA, rowB } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowB, { metaKey: true });

      await userEvent.pointer({ keys: "[MouseRight]", target: rowB });
      // Labeled by the RAW selection count (no launchable carve-out).
      const edit = await screen.findByRole("menuitem", { name: /edit 2 devices/i });
      await userEvent.click(edit);

      // The tri-state dialog opens naming the same two devices.
      expect(await screen.findByRole("heading", { name: /edit 2 devices/i })).toBeInTheDocument();
      expect(screen.getByText(/sw-a, sw-b/)).toBeInTheDocument();
    });

    it("group folder → Edit all in group opens the bulk dialog with the subtree (v6.3.0)", async () => {
      mockedListDevices.mockResolvedValue([
        device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: "Lab/Junos" }),
        device({ id: "vEX2", host: "192.0.2.36", vendor: "junos", group: "Lab" }),
        device({ id: "loose", host: "192.168.1.1", vendor: "junos", group: null }),
      ]);
      renderWithQuery(<Sidebar />);

      const labHeader = await screen.findByText("Lab");
      await userEvent.pointer({ keys: "[MouseRight]", target: labHeader });

      const edit = await screen.findByRole("menuitem", {
        name: /edit all in group \(2 devices\)/i,
      });
      await userEvent.click(edit);

      expect(await screen.findByRole("heading", { name: /edit 2 devices/i })).toBeInTheDocument();
      expect(screen.getByText(/vEX1, vEX2/)).toBeInTheDocument();
    });

    it("a failing device doesn't stop the rest of the batch", async () => {
      const mockedConnect = await mockedConnectFn();
      mockedConnect.mockImplementation(async (id) => {
        if (id === "sw-b") throw new Error("authentication failed for user 'alice'");
        return `sess-${id}`;
      });

      const { rowA, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });

      await userEvent.pointer({ keys: "[MouseRight]", target: rowA });
      const launch = await screen.findByRole("menuitem", {
        name: /launch all \(3 devices\)/i,
      });
      await userEvent.click(launch);

      await waitFor(() => {
        expect(mockedConnect).toHaveBeenCalledTimes(3);
      });
      await waitFor(() => {
        expect(useUiStore.getState().sessions.map((s) => s.deviceId)).toEqual(["sw-a", "sw-c"]);
      });
    });

    it("Stop halts the batch after the in-flight connect finishes", async () => {
      const mockedConnect = await mockedConnectFn();
      let releaseFirst!: (sessionId: string) => void;
      mockedConnect.mockImplementationOnce(
        () =>
          new Promise<string>((resolve) => {
            releaseFirst = resolve;
          }),
      );

      const { rowA, rowC } = await renderThreeDevices();
      fireEvent.click(rowA);
      fireEvent.click(rowC, { shiftKey: true });

      await userEvent.pointer({ keys: "[MouseRight]", target: rowA });
      const launch = await screen.findByRole("menuitem", {
        name: /launch all \(3 devices\)/i,
      });
      await userEvent.click(launch);

      // Progress banner is up while the first device connects.
      expect(await screen.findByText(/1 of 3/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: /^stop$/i }));
      expect(await screen.findByText(/stopping/i)).toBeInTheDocument();

      releaseFirst("sess-sw-a");

      await waitFor(() => {
        expect(screen.queryByText(/of 3/)).not.toBeInTheDocument();
      });
      // Only the in-flight device landed; the loop never reached 2 & 3.
      expect(mockedConnect).toHaveBeenCalledTimes(1);
      expect(useUiStore.getState().sessions.map((s) => s.deviceId)).toEqual(["sw-a"]);
    });
  });

  it("connect failure surfaces an inline banner", async () => {
    const { connectDevice } = await import("@/lib/api");
    const mockedConnect = vi.mocked(connectDevice);
    mockedConnect.mockRejectedValue(new Error("authentication failed for user 'alice'"));

    mockedListDevices.mockResolvedValue([
      device({ id: "vEX1", host: "192.0.2.35", vendor: "junos", group: null }),
    ]);
    renderWithQuery(<Sidebar />);

    const row = await screen.findByRole("button", { name: /vEX1/ });
    await userEvent.pointer({ keys: "[MouseRight]", target: row });

    const connect = await screen.findByRole("menuitem", { name: /^connect$/i });
    await userEvent.click(connect);

    const alert = await screen.findByText(/authentication failed for user/i);
    expect(alert).toBeInTheDocument();
    expect(useUiStore.getState().sessions).toHaveLength(0);
  });

  it("counts only SSH terminal sessions on the device dot (v5.0.0 kind filter)", async () => {
    mockedListDevices.mockResolvedValue([
      device({ id: "sw-a", host: "10.0.0.1", vendor: "junos" }),
      device({ id: "sw-b", host: "10.0.0.2", vendor: "junos" }),
    ]);
    useUiStore.setState({
      sessions: [
        // Two real SSH sessions on sw-a → connected ×2.
        { sessionId: "s1", deviceId: "sw-a", ended: false },
        { sessionId: "s2", deviceId: "sw-a", ended: false },
        // A Files session on sw-b must NOT light the SSH sidebar's dot — the
        // Files sidebar keeps its own count.
        { sessionId: "f1", deviceId: "sw-b", ended: false, kind: "files" },
      ],
      activeTabId: "s1",
    });
    renderWithQuery(<Sidebar />);

    const rowA = await screen.findByRole("button", { name: /sw-a/ });
    const rowB = screen.getByRole("button", { name: /sw-b/ });
    expect(rowA).toHaveTextContent("connected · 2 sessions");
    expect(rowB).toHaveTextContent("not connected");
  });
});
