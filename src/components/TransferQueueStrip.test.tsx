import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  filesCancel: vi.fn().mockResolvedValue(undefined),
}));

// Spy on `truncateMiddle` (called exactly once per TransferRow render, with
// the row's name) so the memo test can prove an unrelated update doesn't
// re-render other rows (F3). Real implementations are preserved.
vi.mock("@/lib/fileBrowser", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/fileBrowser")>();
  return { ...actual, truncateMiddle: vi.fn(actual.truncateMiddle) };
});

import { filesCancel, type TransferUpdate } from "@/lib/api";
import { truncateMiddle } from "@/lib/fileBrowser";
import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

import { TransferQueueStrip } from "./TransferQueueStrip";

const mockedCancel = vi.mocked(filesCancel);

function update(partial: Partial<TransferUpdate> & Pick<TransferUpdate, "id">): TransferUpdate {
  return {
    session_id: "f1",
    direction: "download",
    state: "running",
    name: "juniper.conf",
    bytes_done: 0,
    bytes_total: null,
    files_done: 0,
    files_total: null,
    rate_bps: null,
    skipped: 0,
    warnings: [],
    error: null,
    ...partial,
  };
}

/** Seed the event mirror the way the app-global listener would. */
function seed(...updates: TransferUpdate[]) {
  for (const u of updates) useFilesStore.getState().applyTransferUpdate(u);
}

beforeEach(() => {
  useFilesStore.setState({
    panes: {},
    transfers: new Map(),
    transferTargets: new Map(),
    queueCollapsed: false,
  });
  useUiStore.setState({
    sessions: [{ sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" }],
    activeTabId: "f1",
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("TransferQueueStrip", () => {
  it("renders nothing at all when no transfer exists", () => {
    render(<TransferQueueStrip />);
    expect(screen.queryByTestId("transfer-queue")).toBeNull();
  });

  it("shows a running transfer with per-file progress, rate, ETA and the device label", () => {
    seed(
      update({
        id: "t1",
        state: "running",
        name: "big.log",
        bytes_done: 620,
        bytes_total: 1000,
        rate_bps: 100,
      }),
    );
    render(<TransferQueueStrip />);

    const row = screen.getByTestId("transfer-row-t1");
    expect(within(row).getByText("big.log")).toBeInTheDocument();
    // The label matches the tab strip's (computeLabels), not the raw id.
    expect(within(row).getByText("vEX1")).toBeInTheDocument();
    // bytes_done/bytes_total describe the CURRENT FILE.
    expect(screen.getByTestId("transfer-progress-t1")).toHaveAttribute("aria-valuenow", "62");
    expect(within(row).getByText("62%")).toBeInTheDocument();
    expect(within(row).getByText("100 B/s")).toBeInTheDocument();
    // 380 bytes left at 100 B/s.
    expect(within(row).getByText("0:04")).toBeInTheDocument();
    expect(screen.getByTestId("transfer-queue-counts")).toHaveTextContent("(1 running · 0 queued)");
  });

  it("renders an indeterminate bar when the current file has no known total", () => {
    seed(update({ id: "t1", state: "running", bytes_done: 4096, bytes_total: null }));
    render(<TransferQueueStrip />);
    // No percentage invented, and no progressbar role to lie with.
    expect(screen.queryByTestId("transfer-progress-t1")).toBeNull();
    expect(screen.queryByText("%")).toBeNull();
    expect(within(screen.getByTestId("transfer-row-t1")).getByText("4.0 KiB")).toBeInTheDocument();
  });

  it("says which file a recursive directory job is on", () => {
    // A recursive directory job is the one with `files_total === null` (no
    // pre-scan); `files_done + 1` is the file it's on.
    seed(
      update({ id: "t1", state: "running", name: "inner.conf", files_done: 3, files_total: null }),
    );
    render(<TransferQueueStrip />);
    expect(screen.getByTestId("transfer-file-n-t1")).toHaveTextContent("file 4");
  });

  it("does not claim a file number for a plain single-file transfer", () => {
    // The contract: single-file / non-directory jobs carry `files_total === 1`,
    // so no "file N" indicator — NOT the old `files_done >= 1` heuristic, which
    // lit "file 2" the instant the second file of a job started.
    seed(update({ id: "t1", state: "running", files_done: 0, files_total: 1 }));
    render(<TransferQueueStrip />);
    expect(screen.queryByTestId("transfer-file-n-t1")).toBeNull();
  });

  it("shows a file number for a two-file job at its FIRST file (files_total > 1)", () => {
    // The `> 1` half of the contract: a job that DOES carry a known count > 1
    // is recursive-shaped from file 1 — the old heuristic missed this because
    // files_done is still 0.
    seed(update({ id: "t1", state: "running", files_done: 0, files_total: 2 }));
    render(<TransferQueueStrip />);
    expect(screen.getByTestId("transfer-file-n-t1")).toHaveTextContent("file 1");
  });

  it("renders queued / done / cancelled states and an error with its message", () => {
    seed(
      update({ id: "q", state: "queued", name: "q.conf" }),
      update({ id: "ok", state: "done", name: "ok.conf", bytes_done: 100, bytes_total: 100 }),
      update({ id: "bad", state: "error", name: "bad.conf", error: "permission denied" }),
      update({ id: "stop", state: "cancelled", name: "stop.conf" }),
    );
    render(<TransferQueueStrip />);

    expect(within(screen.getByTestId("transfer-row-q")).getByText("Queued")).toBeInTheDocument();
    expect(within(screen.getByTestId("transfer-row-ok")).getByText("Done")).toBeInTheDocument();
    expect(screen.getByTestId("transfer-error-bad")).toHaveTextContent("permission denied");
    expect(
      within(screen.getByTestId("transfer-row-stop")).getByText("Cancelled"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("transfer-queue-counts")).toHaveTextContent("(0 running · 1 queued)");
  });

  it("keeps rows in arrival order, and a progress update does not reorder them", () => {
    seed(
      update({ id: "t1", name: "first.conf" }),
      update({ id: "t2", name: "second.conf" }),
      update({ id: "t3", name: "third.conf" }),
    );
    seed(update({ id: "t1", name: "first.conf", bytes_done: 9 }));
    render(<TransferQueueStrip />);

    const rows = within(screen.getByTestId("transfer-queue-rows")).getAllByText(/\.conf$/);
    expect(rows.map((r) => r.textContent)).toEqual(["first.conf", "second.conf", "third.conf"]);
  });

  it("cancels a queued or running transfer, and offers no cancel on a finished one", async () => {
    seed(
      update({ id: "run", state: "running" }),
      update({ id: "q", state: "queued" }),
      update({ id: "ok", state: "done" }),
      update({ id: "bad", state: "error" }),
    );
    render(<TransferQueueStrip />);

    expect(screen.getByTestId("transfer-cancel-q")).toBeInTheDocument();
    expect(screen.queryByTestId("transfer-cancel-ok")).toBeNull();
    expect(screen.queryByTestId("transfer-cancel-bad")).toBeNull();

    await userEvent.click(screen.getByTestId("transfer-cancel-run"));
    await waitFor(() => expect(mockedCancel).toHaveBeenCalledWith("run"));
  });

  it("Clear finished drops only the terminal rows, and hides itself when none are left", async () => {
    seed(
      update({ id: "run", state: "running" }),
      update({ id: "ok", state: "done" }),
      update({ id: "gone", state: "cancelled" }),
    );
    render(<TransferQueueStrip />);

    await userEvent.click(screen.getByTestId("transfer-queue-clear"));
    expect(screen.getByTestId("transfer-row-run")).toBeInTheDocument();
    expect(screen.queryByTestId("transfer-row-ok")).toBeNull();
    expect(screen.queryByTestId("transfer-row-gone")).toBeNull();
    // Nothing finished to clear → the button is gone.
    expect(screen.queryByTestId("transfer-queue-clear")).toBeNull();
  });

  it("collapse hides the rows but keeps the header counts visible", async () => {
    seed(update({ id: "t1", state: "running" }));
    render(<TransferQueueStrip />);

    await userEvent.click(screen.getByTestId("transfer-queue-collapse"));
    expect(useFilesStore.getState().queueCollapsed).toBe(true);
    expect(screen.queryByTestId("transfer-queue-rows")).toBeNull();
    expect(screen.getByTestId("transfer-queue-counts")).toHaveTextContent("1 running");

    await userEvent.click(screen.getByTestId("transfer-queue-collapse"));
    expect(screen.getByTestId("transfer-queue-rows")).toBeInTheDocument();
  });

  it("surfaces the skipped count with the engine's warnings behind it", async () => {
    seed(
      update({
        id: "t1",
        state: "done",
        skipped: 2,
        warnings: ["skipped symlink etc", "skipped notes.txt (already exists)"],
      }),
    );
    render(<TransferQueueStrip />);

    await userEvent.click(screen.getByTestId("transfer-skipped-t1"));
    expect(await screen.findByText("skipped symlink etc")).toBeInTheDocument();
    expect(screen.getByText("skipped notes.txt (already exists)")).toBeInTheDocument();
  });

  it("notes when the engine capped the warning list at 20", async () => {
    const warnings = Array.from({ length: 20 }, (_, i) => `skipped ${i}`);
    seed(update({ id: "t1", state: "done", skipped: 57, warnings }));
    render(<TransferQueueStrip />);
    await userEvent.click(screen.getByTestId("transfer-skipped-t1"));
    expect(await screen.findByText(/57 skipped \(first 20 shown\)/)).toBeInTheDocument();
  });

  it("shows every session's transfers, not just the visible tab's", () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" },
        { sessionId: "f2", deviceId: "vEX2", ended: false, kind: "files" },
      ],
      activeTabId: "f1",
    });
    seed(
      update({ id: "a", session_id: "f1", name: "a.conf" }),
      update({ id: "b", session_id: "f2", name: "b.conf" }),
    );
    render(<TransferQueueStrip />);

    expect(within(screen.getByTestId("transfer-row-a")).getByText("vEX1")).toBeInTheDocument();
    expect(within(screen.getByTestId("transfer-row-b")).getByText("vEX2")).toBeInTheDocument();
  });

  it("falls back to the enqueue-time label once the session's tab is gone", () => {
    seed(update({ id: "t1", session_id: "closed-session", state: "cancelled" }));
    useFilesStore.getState().recordTransferTargets(["t1"], {
      sessionId: "closed-session",
      side: "local",
      destKey: null,
      deviceLabel: "vEX9",
    });
    render(<TransferQueueStrip />);
    // A finished row outlives its tab, so the row must still name a device.
    expect(within(screen.getByTestId("transfer-row-t1")).getByText("vEX9")).toBeInTheDocument();
  });

  it("memoized rows: a progress event for one transfer doesn't re-render the others (F3)", () => {
    seed(
      update({ id: "t1", name: "a.conf", state: "running" }),
      update({ id: "t2", name: "b.conf", state: "running" }),
    );
    render(<TransferQueueStrip />);
    const callsFor = (name: string) =>
      vi.mocked(truncateMiddle).mock.calls.filter((c) => c[0] === name).length;
    const bBefore = callsFor("b.conf");

    // A progress-only update to t1: its row's props change, t2's don't (same
    // TransferUpdate object reference, same device label).
    act(() => {
      useFilesStore
        .getState()
        .applyTransferUpdate(
          update({ id: "t1", name: "a.conf", state: "running", bytes_done: 99 }),
        );
    });

    // t1 re-rendered (fresh render-time call); t2 is memoized, so it did NOT.
    expect(callsFor("a.conf")).toBeGreaterThan(1);
    expect(callsFor("b.conf")).toBe(bBefore);
  });
});
