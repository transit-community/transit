import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { QuitConfirmDialog } from "@/components/dialogs/QuitConfirmDialog";
import type { TransferUpdate } from "@/lib/api";
import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

// Capture the `app:confirm-quit` handler the dialog's useEffect registers
// so each test can fire a synthetic veto event.
type QuitHandler = (event: { payload: unknown }) => void;
let registeredHandlers: QuitHandler[] = [];

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: QuitHandler) => {
    if (eventName === "app:confirm-quit") {
      registeredHandlers.push(handler);
    }
    return () => {
      registeredHandlers = registeredHandlers.filter((h) => h !== handler);
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  confirmQuit: vi.fn().mockResolvedValue(undefined),
}));

beforeEach(() => {
  useUiStore.setState({ sessions: [], activeTabId: null });
  // Healthy default: the transfer listener is live, so the quit guard trusts
  // the transfers map (an idle Files tab is NOT counted). The fail-safe path
  // (listener never subscribed) is exercised in its own test below.
  useFilesStore.setState({
    panes: {},
    transfers: new Map(),
    transferTargets: new Map(),
    transferListenerReady: true,
  });
});

/** Put one transfer in the event mirror for `sessionId`. */
function seedTransfer(sessionId: string, id: string, state: TransferUpdate["state"]) {
  useFilesStore.getState().applyTransferUpdate({
    session_id: sessionId,
    id,
    direction: "download",
    state,
    name: "big.log",
    bytes_done: 1,
    bytes_total: 10,
    files_done: 0,
    files_total: null,
    rate_bps: 1,
    skipped: 0,
    warnings: [],
    error: null,
  });
}

afterEach(() => {
  registeredHandlers = [];
  vi.clearAllMocks();
});

function fireConfirmQuit() {
  const handlers = [...registeredHandlers];
  // Wrap the synchronous state update so React flushes before assertions.
  act(() => {
    handlers.forEach((h) => h({ payload: null }));
  });
}

async function renderAndWaitListener() {
  render(<QuitConfirmDialog />);
  await waitFor(() => expect(registeredHandlers.length).toBeGreaterThan(0));
}

describe("QuitConfirmDialog", () => {
  it("renders nothing until app:confirm-quit fires", async () => {
    await renderAndWaitListener();
    expect(screen.queryByText(/Quit Transit\?/i)).not.toBeInTheDocument();
  });

  it("shows the live-session count when a quit is vetoed", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "vEX2", ended: false },
      ],
      activeTabId: "s1",
    });
    await renderAndWaitListener();

    fireConfirmQuit();

    expect(await screen.findByText(/Quit Transit\?/i)).toBeInTheDocument();
    expect(screen.getByText(/2 active sessions are still open/i)).toBeInTheDocument();
    // Nothing confirmed yet — the user must choose.
    expect(vi.mocked(confirmQuit)).not.toHaveBeenCalled();
  });

  it("uses singular copy for exactly one live session", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    await renderAndWaitListener();
    fireConfirmQuit();
    expect(await screen.findByText(/1 active session is still open/i)).toBeInTheDocument();
  });

  it("'Quit anyway' confirms the quit", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    await renderAndWaitListener();
    fireConfirmQuit();

    await userEvent.click(await screen.findByRole("button", { name: /quit anyway/i }));
    expect(vi.mocked(confirmQuit)).toHaveBeenCalledTimes(1);
  });

  it("'Keep working' dismisses without quitting", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false }],
      activeTabId: "s1",
    });
    await renderAndWaitListener();
    fireConfirmQuit();
    await screen.findByText(/Quit Transit\?/i);

    await userEvent.click(screen.getByRole("button", { name: /keep working/i }));
    expect(vi.mocked(confirmQuit)).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByText(/Quit Transit\?/i)).not.toBeInTheDocument());
  });

  it("auto-confirms without a dialog when no session is live", async () => {
    const { confirmQuit } = await import("@/lib/api");
    // Backend held a session (so Rust vetoed + emitted) but it's ended —
    // nothing live to drop, so proceed straight to quit, no prompt.
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true }],
      activeTabId: "s1",
    });
    await renderAndWaitListener();
    fireConfirmQuit();

    await waitFor(() => expect(vi.mocked(confirmQuit)).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/Quit Transit\?/i)).not.toBeInTheDocument();
  });

  it("never counts an IDLE Files tab as live — a browse session must not nag on quit", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" },
        { sessionId: "f2", deviceId: "vEX2", ended: false, kind: "files" },
      ],
      activeTabId: "f1",
    });
    render(<QuitConfirmDialog />);
    await waitFor(() => expect(registeredHandlers.length).toBeGreaterThan(0));
    fireConfirmQuit();

    // Straight to quit, no dialog — nothing in flight to lose.
    expect(screen.queryByText(/Quit Transit\?/i)).not.toBeInTheDocument();
    await waitFor(() => expect(confirmQuit).toHaveBeenCalled());
  });

  it("counts a Files tab as live while a transfer is running or queued", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" },
        { sessionId: "f2", deviceId: "vEX2", ended: false, kind: "files" },
      ],
      activeTabId: "f1",
    });
    // f1 is copying, f2 is idle → exactly one live session.
    seedTransfer("f1", "t1", "running");
    await renderAndWaitListener();
    fireConfirmQuit();

    expect(await screen.findByText(/Quit Transit\?/i)).toBeInTheDocument();
    expect(screen.getByText(/1 active session is still open/)).toBeInTheDocument();
    expect(vi.mocked(confirmQuit)).not.toHaveBeenCalled();
  });

  it("a queued transfer counts too, and a finished one does not", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" }],
      activeTabId: "f1",
    });
    seedTransfer("f1", "t1", "queued");
    await renderAndWaitListener();
    fireConfirmQuit();
    expect(await screen.findByText(/1 active session is still open/)).toBeInTheDocument();

    // Same tab, transfer finished: nothing left to lose.
    seedTransfer("f1", "t1", "done");
    await userEvent.click(screen.getByRole("button", { name: /keep working/i }));
    fireConfirmQuit();
    await waitFor(() => expect(vi.mocked(confirmQuit)).toHaveBeenCalledTimes(1));
  });

  it("fails SAFE: an idle Files tab still confirms when the transfer listener never subscribed (F7)", async () => {
    const { confirmQuit } = await import("@/lib/api");
    // The `files:transfer:update` listener failed to subscribe, so the empty
    // transfers map can't be trusted — a silent quit could drop a running
    // transfer we simply can't see.
    useFilesStore.setState({ transferListenerReady: false });
    useUiStore.setState({
      sessions: [{ sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" }],
      activeTabId: "f1",
    });
    await renderAndWaitListener();
    fireConfirmQuit();

    // The confirm is shown rather than proceeding straight to confirm_quit.
    expect(await screen.findByText(/Quit Transit\?/i)).toBeInTheDocument();
    expect(vi.mocked(confirmQuit)).not.toHaveBeenCalled();
  });

  it("an ENDED Files tab never counts, even with a stale transfer row", async () => {
    const { confirmQuit } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [{ sessionId: "f1", deviceId: "vEX1", ended: true, kind: "files" }],
      activeTabId: "f1",
    });
    // The backend cancels a dead session's transfers, but even a row that
    // hasn't reported yet must not veto a quit for a dead tab.
    seedTransfer("f1", "t1", "running");
    await renderAndWaitListener();
    fireConfirmQuit();

    await waitFor(() => expect(vi.mocked(confirmQuit)).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/Quit Transit\?/i)).not.toBeInTheDocument();
  });

  it("still counts a live SSH tab when a Files tab sits beside it", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "f1", deviceId: "vEX2", ended: false, kind: "files" },
      ],
      activeTabId: "s1",
    });
    render(<QuitConfirmDialog />);
    await waitFor(() => expect(registeredHandlers.length).toBeGreaterThan(0));
    fireConfirmQuit();

    expect(await screen.findByText(/Quit Transit\?/i)).toBeInTheDocument();
    // One live session, not two.
    expect(screen.getByText(/1 active session is still open/)).toBeInTheDocument();
  });
});
