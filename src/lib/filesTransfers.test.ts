import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// One captured handler per topic, so a test can fire a synthetic
// `files:transfer:update` the way the backend's forwarder would.
type Handler = (event: { payload: unknown }) => void;
const listeners = new Map<string, Handler[]>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (topic: string, handler: Handler) => {
    listeners.set(topic, [...(listeners.get(topic) ?? []), handler]);
    return () => {
      listeners.set(
        topic,
        (listeners.get(topic) ?? []).filter((h) => h !== handler),
      );
    };
  }),
}));

vi.mock("@/lib/queryClient", () => ({
  queryClient: { invalidateQueries: vi.fn() },
}));

import { listen } from "@tauri-apps/api/event";

import type { TransferUpdate } from "@/lib/api";
import {
  FILES_TRANSFER_TOPIC,
  initFilesTransferListener,
  registerTransferTargets,
} from "@/lib/filesTransfers";
import { queryClient } from "@/lib/queryClient";
import { useFilesStore } from "@/stores/filesStore";

const invalidate = vi.mocked(queryClient.invalidateQueries);
const s = () => useFilesStore.getState();

function update(partial: Partial<TransferUpdate> & Pick<TransferUpdate, "id">): TransferUpdate {
  return {
    session_id: "s1",
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

/** Deliver one event through the real subscriber. */
function fire(payload: TransferUpdate) {
  for (const h of listeners.get(FILES_TRANSFER_TOPIC) ?? []) h({ payload });
}

beforeEach(() => {
  listeners.clear();
  vi.clearAllMocks();
  useFilesStore.setState({
    panes: {},
    transfers: new Map(),
    transferTargets: new Map(),
    queueCollapsed: false,
    // The latch lives in the store precisely so it resets here.
    transferListenerStarted: false,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("filesTransfers — the app-global transfer subscriber", () => {
  it("subscribes to the one shared topic, and only once however often it's called", async () => {
    initFilesTransferListener();
    initFilesTransferListener();
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.get(FILES_TRANSFER_TOPIC)?.length).toBe(1));
    expect(vi.mocked(listen)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(listen).mock.calls[0][0]).toBe("files:transfer:update");
    expect(s().transferListenerStarted).toBe(true);
  });

  it("folds every event into the store mirror", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));

    fire(update({ id: "t1", state: "queued" }));
    fire(update({ id: "t1", state: "running", bytes_done: 10, bytes_total: 100 }));
    fire(update({ id: "t2", state: "queued", session_id: "s2" }));

    expect(Array.from(s().transfers.keys())).toEqual(["t1", "t2"]);
    expect(s().transfers.get("t1")).toMatchObject({ bytes_done: 10, bytes_total: 100 });
    expect(s().activeTransferCount()).toBe(2);
  });

  it("invalidates the DESTINATION listing on done, error, and cancelled — never mid-flight", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));
    // An upload lands in the remote pane of s1, at /var/tmp.
    registerTransferTargets(["up"], {
      sessionId: "s1",
      side: "remote",
      destKey: "/var/tmp",
      deviceLabel: "vEX1",
    });

    fire(update({ id: "up", direction: "upload", state: "running", bytes_done: 5 }));
    expect(invalidate).not.toHaveBeenCalled();

    fire(update({ id: "up", direction: "upload", state: "done" }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesRemoteDir", "s1", "/var/tmp"] });

    // An error and a cancel change the directory too (a partial file was
    // cleaned up), so both refresh it.
    invalidate.mockClear();
    fire(update({ id: "up", direction: "upload", state: "error", error: "disk full" }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesRemoteDir", "s1", "/var/tmp"] });

    invalidate.mockClear();
    fire(update({ id: "up", direction: "upload", state: "cancelled" }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesRemoteDir", "s1", "/var/tmp"] });
  });

  it("invalidates the LOCAL listing for a download, including the null 'home' key", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));
    registerTransferTargets(["d1"], {
      sessionId: "s1",
      side: "local",
      destKey: "/Users/alice",
      deviceLabel: "vEX1",
    });
    registerTransferTargets(["d2"], {
      sessionId: "s1",
      side: "local",
      // The local pane still shows the backend's default home, so its query
      // key is `null` — invalidating the resolved path would MISS it.
      destKey: null,
      deviceLabel: "vEX1",
    });

    fire(update({ id: "d1", state: "done" }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesLocalDir", "/Users/alice"] });

    invalidate.mockClear();
    fire(update({ id: "d2", state: "done" }));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesLocalDir", null] });
  });

  it("a terminal state with no recorded target invalidates nothing (rather than guessing)", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));
    fire(update({ id: "orphan", state: "done" }));
    expect(invalidate).not.toHaveBeenCalled();
    // The row still renders — losing the invalidation must not lose the row.
    expect(s().transfers.get("orphan")?.state).toBe("done");
  });

  it("registerTransferTargets catches up when the transfer already finished before the enqueue response", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));

    // The engine's forwarder is a separate task: a tiny transfer can run to
    // completion while `files_enqueue` is still in flight.
    fire(update({ id: "fast", state: "queued" }));
    fire(update({ id: "fast", state: "done" }));
    expect(invalidate).not.toHaveBeenCalled();

    registerTransferTargets(["fast"], {
      sessionId: "s1",
      side: "remote",
      destKey: "/var/tmp",
      deviceLabel: "vEX1",
    });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["filesRemoteDir", "s1", "/var/tmp"] });
  });

  it("registering a still-running transfer invalidates nothing yet", async () => {
    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.has(FILES_TRANSFER_TOPIC)).toBe(true));
    fire(update({ id: "slow", state: "running" }));
    registerTransferTargets(["slow"], {
      sessionId: "s1",
      side: "remote",
      destKey: "/var/tmp",
      deviceLabel: "vEX1",
    });
    expect(invalidate).not.toHaveBeenCalled();
  });

  it("releases the latch if subscribing fails, so a later mount can retry", async () => {
    vi.mocked(listen).mockRejectedValueOnce(new Error("no event bus"));
    initFilesTransferListener();
    await vi.waitFor(() => expect(s().transferListenerStarted).toBe(false));

    initFilesTransferListener();
    await vi.waitFor(() => expect(listeners.get(FILES_TRANSFER_TOPIC)?.length).toBe(1));
  });
});
