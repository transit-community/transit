import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MainArea } from "@/components/MainArea";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(async () => undefined),
}));

// MainArea hands off to TerminalArea when sessions exist. That
// component pulls in xterm.js, which jsdom doesn't render — stub it.
vi.mock("@/components/TerminalArea", () => ({
  TerminalArea: () => <div data-testid="terminal-area-stub" />,
}));

import { listDevices } from "@/lib/api";

const mockedListDevices = vi.mocked(listDevices);

function renderArea(ui: ReactElement = <MainArea />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  useUiStore.setState({
    activeDeviceId: null,
    sessions: [],
    activeTabId: null,
    sidebarView: "ssh",
  });
  mockedListDevices.mockResolvedValue([]);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("MainArea", () => {
  it("renders TerminalArea when at least one session is open", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    renderArea();
    expect(await screen.findByTestId("terminal-area-stub")).toBeInTheDocument();
    expect(screen.queryByTestId("welcome-panel")).not.toBeInTheDocument();
  });

  it("renders the welcome panel when inventory is empty", async () => {
    mockedListDevices.mockResolvedValue([]);
    renderArea();
    expect(await screen.findByTestId("welcome-panel")).toBeInTheDocument();
    expect(screen.getByTestId("welcome-add-device")).toBeInTheDocument();
    expect(screen.getByTestId("welcome-quickstart-link")).toBeInTheDocument();
  });

  it("renders the broken-inventory panel when listDevices errors", async () => {
    mockedListDevices.mockRejectedValue(new Error("inline secret-shaped value at transit.toml:9"));
    renderArea();
    expect(await screen.findByTestId("broken-inventory-panel")).toBeInTheDocument();
    expect(screen.getByText(/inline secret-shaped value/i)).toBeInTheDocument();
    expect(screen.getByTestId("broken-inventory-copy")).toBeInTheDocument();
  });

  it("renders the select-a-device hint when inventory is non-empty but nothing is selected", async () => {
    mockedListDevices.mockResolvedValue([
      {
        id: "vEX1",
        host: "192.0.2.35",
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
        netbox_id: null,
        jump_via: null,
        forward_agent: null,
      },
    ]);
    renderArea();
    await waitFor(() => expect(mockedListDevices).toHaveBeenCalled());
    expect(await screen.findByText(/Select a device from the sidebar/)).toBeInTheDocument();
  });

  it("renders the right-click hint when an active device is selected", async () => {
    mockedListDevices.mockResolvedValue([
      {
        id: "vEX1",
        host: "192.0.2.35",
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
        netbox_id: null,
        jump_via: null,
        forward_agent: null,
      },
    ]);
    useUiStore.setState({ activeDeviceId: "vEX1" });
    renderArea();
    expect(await screen.findByText("vEX1")).toBeInTheDocument();
    expect(screen.getByText(/Right-click and choose/)).toBeInTheDocument();
  });

  it("welcome panel's Add button synthetic-clicks the sidebar's Add device trigger", async () => {
    mockedListDevices.mockResolvedValue([]);

    const sidebarBtn = document.createElement("button");
    sidebarBtn.setAttribute("aria-label", "Add device");
    const onClick = vi.fn();
    sidebarBtn.addEventListener("click", onClick);
    document.body.appendChild(sidebarBtn);

    renderArea();
    await userEvent.click(await screen.findByTestId("welcome-add-device"));
    expect(onClick).toHaveBeenCalled();

    document.body.removeChild(sidebarBtn);
  });

  describe("Files rail empty state (v5.0.0)", () => {
    const oneDevice = [
      {
        id: "vEX1",
        host: "192.0.2.35",
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
        netbox_id: null,
        jump_via: null,
        forward_agent: null,
      },
    ];

    it("names the file-transfer action instead of the SSH 'Connect' hint", async () => {
      mockedListDevices.mockResolvedValue(oneDevice);
      useUiStore.setState({ sidebarView: "files", activeDeviceId: "vEX1" });
      renderArea();
      expect(await screen.findByTestId("files-empty-state")).toBeInTheDocument();
      expect(screen.queryByText(/Right-click and choose/)).toBeNull();
    });

    it("still yields to the onboarding panel when the inventory is empty (Files rides it)", async () => {
      mockedListDevices.mockResolvedValue([]);
      useUiStore.setState({ sidebarView: "files" });
      renderArea();
      expect(await screen.findByTestId("welcome-panel")).toBeInTheDocument();
      expect(screen.queryByTestId("files-empty-state")).toBeNull();
    });

    it("still yields to the broken-inventory panel", async () => {
      mockedListDevices.mockRejectedValue(new Error("transit.toml is malformed"));
      useUiStore.setState({ sidebarView: "files" });
      renderArea();
      expect(await screen.findByTestId("broken-inventory-panel")).toBeInTheDocument();
      expect(screen.queryByTestId("files-empty-state")).toBeNull();
    });
  });
});
