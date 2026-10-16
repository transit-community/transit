import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listGroups: vi.fn().mockResolvedValue([]),
  listAuthProfiles: vi.fn().mockResolvedValue([]),
  addDevice: vi.fn(),
  updateDevice: vi.fn(),
  deleteDevice: vi.fn(),
  addAuthProfile: vi.fn(),
  updateAuthProfile: vi.fn(),
  deleteAuthProfile: vi.fn(),
  addGroup: vi.fn(),
  renameGroup: vi.fn(),
  deleteGroup: vi.fn(),
  setDeviceGroup: vi.fn(),
  exportConnections: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
  testSecretResolve: vi.fn(),
  enrollSecret: vi.fn(),
  // The Files IPC under test.
  filesConnect: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastInfo: vi.fn(),
}));

import { filesConnect, listDevices, type DeviceMeta } from "@/lib/api";
import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

import { FilesSidebar } from "./FilesSidebar";

const mockedListDevices = vi.mocked(listDevices);
const mockedFilesConnect = vi.mocked(filesConnect);

function device(partial: Partial<DeviceMeta> & Pick<DeviceMeta, "id">): DeviceMeta {
  return {
    host: `${partial.id}.lab`,
    port: 22,
    vendor: "junos",
    group: null,
    color: null,
    tags: [],
    auth: "lab-pw",
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    allow_weak_crypto: null,
    ...partial,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
  };
}

function renderSidebar(ui: ReactElement = <FilesSidebar />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  useUiStore.setState({
    sessions: [],
    activeTabId: null,
    activeDeviceId: null,
    sidebarCollapsed: false,
    authProfileManagerOpen: false,
  });
  useFilesStore.setState({ panes: {} });
  mockedListDevices.mockResolvedValue([device({ id: "vEX1" }), device({ id: "vEX2" })]);
  mockedFilesConnect.mockImplementation(async (deviceId: string) => ({
    session_id: `files-${deviceId}`,
    label: deviceId,
    home: `/home/${deviceId}`,
  }));
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("FilesSidebar", () => {
  it("renders the SAME inventory tree as the SSH sidebar", async () => {
    renderSidebar();
    expect(await screen.findByText("vEX1")).toBeInTheDocument();
    expect(screen.getByText("vEX2")).toBeInTheDocument();
    expect(screen.getByTestId("files-sidebar")).toBeInTheDocument();
  });

  it("names the launch action 'Open file transfer', not 'Connect'", async () => {
    renderSidebar();
    await userEvent.pointer({ keys: "[MouseRight]", target: await screen.findByText("vEX1") });
    expect(await screen.findByText("Open file transfer")).toBeInTheDocument();
    expect(screen.queryByText("Connect")).toBeNull();
  });

  it("launching calls files_connect, opens a kind:'files' tab, and seeds the remote cwd from home", async () => {
    renderSidebar();
    await userEvent.pointer({ keys: "[MouseRight]", target: await screen.findByText("vEX1") });
    await userEvent.click(await screen.findByText("Open file transfer"));

    await waitFor(() => expect(mockedFilesConnect).toHaveBeenCalledWith("vEX1"));
    const tab = useUiStore.getState().sessions.at(-1)!;
    expect(tab.kind).toBe("files");
    expect(tab.sessionId).toBe("files-vEX1");
    expect(tab.deviceId).toBe("vEX1");
    // The server's login directory seeds the pane BEFORE FilesPane mounts,
    // so its first listing is already the right directory.
    expect(useFilesStore.getState().panes["files-vEX1"].remoteCwd).toBe("/home/vEX1");
  });

  it("double-clicking a row launches a file transfer (not an SSH session)", async () => {
    renderSidebar();
    await userEvent.dblClick(await screen.findByText("vEX1"));
    await waitFor(() => expect(mockedFilesConnect).toHaveBeenCalledWith("vEX1"));
  });

  it("multi-select 'Launch all' opens sessions STRICTLY SEQUENTIALLY", async () => {
    // The host-key / weak-crypto responder maps are single-slot `(host,
    // port)` keyed, so two overlapping connects would clobber a pending
    // prompt. Pin the ordering by resolving each connect only after the
    // previous one has been observed.
    const order: string[] = [];
    let inFlight = 0;
    mockedFilesConnect.mockImplementation(async (deviceId: string) => {
      inFlight += 1;
      expect(inFlight).toBe(1); // never two at once
      order.push(deviceId);
      await Promise.resolve();
      inFlight -= 1;
      return { session_id: `files-${deviceId}`, label: deviceId, home: `/home/${deviceId}` };
    });

    renderSidebar();
    const row1 = await screen.findByRole("button", { name: /vEX1/ });
    const row2 = screen.getByRole("button", { name: /vEX2/ });
    fireEvent.click(row1);
    fireEvent.click(row2, { metaKey: true });
    await userEvent.pointer({ keys: "[MouseRight]", target: row2 });
    await userEvent.click(
      await screen.findByRole("menuitem", { name: /launch all \(2 devices\)/i }),
    );

    await waitFor(() => expect(order).toEqual(["vEX1", "vEX2"]));
    await waitFor(() =>
      expect(useUiStore.getState().sessions.filter((t) => t.kind === "files")).toHaveLength(2),
    );
  });

  it("a launch failure surfaces an inline banner and opens no tab", async () => {
    mockedFilesConnect.mockRejectedValue(new Error("device does not run an SFTP server"));
    renderSidebar();
    await userEvent.pointer({ keys: "[MouseRight]", target: await screen.findByText("vEX1") });
    await userEvent.click(await screen.findByText("Open file transfer"));

    expect(await screen.findByText(/does not run an SFTP server/)).toBeInTheDocument();
    expect(useUiStore.getState().sessions).toHaveLength(0);
  });

  it("counts only FILES sessions on the device dot — never SSH terminal tabs", async () => {
    useUiStore.setState({
      sessions: [
        // An SSH tab on vEX1 must NOT light this sidebar's dot...
        { sessionId: "ssh-1", deviceId: "vEX1", ended: false },
        // ...but two Files sessions on vEX2 must show ×2.
        { sessionId: "f1", deviceId: "vEX2", ended: false, kind: "files" },
        { sessionId: "f2", deviceId: "vEX2", ended: false, kind: "files" },
      ],
      activeTabId: "f1",
    });
    renderSidebar();
    await screen.findByText("vEX1");
    // The status text is sr-only on the row; scope by each row's button.
    const rows = screen.getAllByRole("button", { name: /vEX/ });
    const vex1 = rows.find((r) => r.textContent?.includes("vEX1"))!;
    const vex2 = rows.find((r) => r.textContent?.includes("vEX2"))!;
    expect(vex1).toHaveTextContent("not connected");
    expect(vex2).toHaveTextContent("connected · 2 sessions");
    expect(vex2).toHaveTextContent("×2");
  });

  it("shares the group collapse state with the SSH sidebar (same tree, same folds)", async () => {
    mockedListDevices.mockResolvedValue([device({ id: "vEX1", group: "Lab" })]);
    useUiStore.setState((s) => ({
      preferences: { ...s.preferences, collapsedGroups: { Lab: true } },
    }));
    renderSidebar();
    expect(await screen.findByText("Lab")).toBeInTheDocument();
    // Collapsed → the device inside is not rendered.
    expect(screen.queryByText("vEX1")).toBeNull();
  });

  it("collapses to the narrow rail when the sidebar is collapsed", async () => {
    useUiStore.setState({ sidebarCollapsed: true });
    renderSidebar();
    expect(screen.getByTestId("files-sidebar-collapsed")).toBeInTheDocument();
    expect(screen.queryByTestId("files-sidebar")).toBeNull();
  });

  it("shows the '+ New device' CTA on an empty inventory and opens the add dialog (F2)", async () => {
    // Regression: the Files sidebar had inlined a text-only empty state with no
    // button, so a first-run user on this rail couldn't add a device. It now
    // reuses the SSH sidebar's shared EmptyState.
    mockedListDevices.mockResolvedValue([]);
    renderSidebar();
    const cta = await screen.findByRole("button", { name: /\+ new device/i });
    await userEvent.click(cta);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("wires the shared inventory dialogs — a device's Edit opens the edit dialog (Q2)", async () => {
    // Proves the extracted `useInventoryDialogs().treeHandlers` are wired from
    // this sidebar (the dialog set is no longer a fork of Sidebar's).
    renderSidebar();
    await userEvent.pointer({ keys: "[MouseRight]", target: await screen.findByText("vEX1") });
    await userEvent.click(await screen.findByText("Edit device..."));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });
});
