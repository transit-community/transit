import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listCaptures: vi.fn(),
  captureCommand: vi.fn(),
  deleteCapture: vi.fn(),
  diffCaptures: vi.fn(),
  runCollection: vi.fn(),
  capturesDirPath: vi
    .fn()
    .mockResolvedValue("/Users/test/Library/Application Support/Transit/captures"),
}));
vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastInfo: vi.fn(),
}));

import { listCaptures } from "@/lib/api";
import { useUiStore } from "@/stores/uiStore";

import { CapturesDialog } from "./CapturesDialog";

const mockedList = vi.mocked(listCaptures);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  mockedList.mockResolvedValue([
    { id: "t1__vEX1", device_id: "vEX1", command: "show run", captured_at: "2026-07-23T10:00:00Z" },
    { id: "t2__vEX2", device_id: "vEX2", command: "show run", captured_at: "2026-07-23T11:00:00Z" },
  ]);
  useUiStore.setState({ capturesDialogOpen: true, sessions: [] });
});

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({ capturesDialogOpen: false });
});

describe("CapturesDialog", () => {
  it("lists saved captures when open", async () => {
    renderWithQuery(<CapturesDialog />);
    await waitFor(() => {
      expect(screen.getByText(/vEX1 · show run/)).toBeInTheDocument();
      expect(screen.getByText(/vEX2 · show run/)).toBeInTheDocument();
    });
  });

  it("defaults the command and disables Capture until a session is picked", async () => {
    renderWithQuery(<CapturesDialog />);
    const input = await screen.findByTestId("capture-command-input");
    expect(input).toHaveValue("show running-config");
    // No live sessions in this test → nothing to capture from.
    expect(screen.getByRole("button", { name: /^capture$/i })).toBeDisabled();
  });

  it("offers only PTY sessions as capture targets (v5.0.0)", async () => {
    useUiStore.setState({
      capturesDialogOpen: true,
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "l1", deviceId: "zsh", ended: false, kind: "local" },
        // Neither has a scrollback ring to capture from.
        { sessionId: "a1", deviceId: "HQ", ended: false, kind: "api" },
        { sessionId: "f1", deviceId: "vEX9", ended: false, kind: "files" },
      ],
    });
    renderWithQuery(<CapturesDialog />);
    // The session picker is the first combobox in the dialog.
    await userEvent.click(screen.getAllByRole("combobox")[0]);

    expect(await screen.findByRole("option", { name: "vEX1" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "zsh" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "HQ" })).toBeNull();
    expect(screen.queryByRole("option", { name: "vEX9" })).toBeNull();
  });
});
