import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  terminalEnabled: vi.fn().mockResolvedValue(true),
  filesEnabled: vi.fn().mockResolvedValue(true),
}));
vi.mock("@/lib/pcap", () => ({
  pcapEnabled: vi.fn().mockResolvedValue(true),
  usePcapEnabled: () => ({ data: mockPcapEnabled }),
}));

import { filesEnabled, terminalEnabled } from "@/lib/api";
import { useUiStore } from "@/stores/uiStore";

import { PanelSwitcher } from "./PanelSwitcher";

const mockedTerminalEnabled = vi.mocked(terminalEnabled);
const mockedFilesEnabled = vi.mocked(filesEnabled);
// `usePcapEnabled` is a hook, so the mock reads a mutable module-scope
// flag rather than a resolved promise.
let mockPcapEnabled = true;

function renderRail(ui: ReactElement = <PanelSwitcher />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  useUiStore.setState({ sidebarView: "ssh" });
  mockedTerminalEnabled.mockResolvedValue(true);
  mockedFilesEnabled.mockResolvedValue(true);
  mockPcapEnabled = true;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("PanelSwitcher", () => {
  it("renders all five surfaces in rail order", async () => {
    renderRail();
    await waitFor(() => expect(screen.getAllByRole("tab")).toHaveLength(5));
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual([
      "SSH",
      "APIs",
      "Terminal",
      "Files",
      "pcaps",
    ]);
  });

  it("clicking pcaps switches the sidebar view", async () => {
    renderRail();
    await userEvent.click(await screen.findByRole("tab", { name: "pcaps" }));
    expect(useUiStore.getState().sidebarView).toBe("pcaps");
  });

  it("hides the pcaps entry when [pcap] enabled = false (the MDM/DLP off-switch)", async () => {
    mockPcapEnabled = false;
    renderRail();
    // The other gates are independent — Files and Terminal stay.
    await waitFor(() => expect(screen.queryByRole("tab", { name: "pcaps" })).toBeNull());
    expect(screen.getByRole("tab", { name: "Files" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Terminal" })).toBeInTheDocument();
  });

  it("clicking Files switches the sidebar view", async () => {
    renderRail();
    await userEvent.click(await screen.findByRole("tab", { name: "Files" }));
    expect(useUiStore.getState().sidebarView).toBe("files");
  });

  it("hides the Files entry when [files] enabled = false (the MDM/DLP off-switch)", async () => {
    mockedFilesEnabled.mockResolvedValue(false);
    renderRail();
    // Terminal stays — the two gates are independent.
    await waitFor(() => expect(screen.queryByRole("tab", { name: "Files" })).toBeNull());
    expect(screen.getByRole("tab", { name: "Terminal" })).toBeInTheDocument();
  });

  it("hides only Terminal when its own switch is off", async () => {
    mockedTerminalEnabled.mockResolvedValue(false);
    renderRail();
    await waitFor(() => expect(screen.queryByRole("tab", { name: "Terminal" })).toBeNull());
    expect(screen.getByRole("tab", { name: "Files" })).toBeInTheDocument();
  });

  it("marks the active surface as selected", async () => {
    useUiStore.setState({ sidebarView: "files" });
    renderRail();
    const files = await screen.findByRole("tab", { name: "Files" });
    expect(files).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "SSH" })).toHaveAttribute("aria-selected", "false");
  });
});
