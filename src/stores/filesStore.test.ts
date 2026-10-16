import { beforeEach, describe, expect, it } from "vitest";

import type { TransferUpdate } from "@/lib/api";
import {
  activeFilesTransferCount,
  clearFilesPaneState,
  countActiveTransfers,
  isTerminalTransferState,
  useFilesStore,
} from "@/stores/filesStore";

const s = () => useFilesStore.getState();

beforeEach(() => {
  useFilesStore.setState({
    panes: {},
    transfers: new Map(),
    transferTargets: new Map(),
    queueCollapsed: false,
  });
});

/** One `files:transfer:update` payload — the flattened wire shape. */
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

const ids = () => Array.from(s().transfers.keys());

describe("filesStore", () => {
  it("ensurePane seeds both cwds from the server's home and is idempotent", () => {
    s().ensurePane("sess-1", "/var/home/alice");
    const pane = s().panes["sess-1"];
    expect(pane.remoteCwd).toBe("/var/home/alice");
    expect(pane.remoteHome).toBe("/var/home/alice");
    // The local pane starts at "the backend default" (null → home).
    expect(pane.localCwd).toBeNull();
    expect(pane.remoteSort).toEqual({ key: "name", asc: true });
    expect(pane.localSort).toEqual({ key: "name", asc: true });
    expect(pane.showHiddenRemote).toBe(false);
    expect(pane.showHiddenLocal).toBe(false);

    // A remount must NOT reset the user's navigation.
    s().setCwd("sess-1", "remote", "/etc");
    s().ensurePane("sess-1", "/var/home/alice");
    expect(s().panes["sess-1"].remoteCwd).toBe("/etc");
  });

  it("keeps each session's panes independent", () => {
    s().ensurePane("a", "/home/a");
    s().ensurePane("b", "/home/b");
    s().setCwd("a", "remote", "/tmp");
    expect(s().panes["a"].remoteCwd).toBe("/tmp");
    expect(s().panes["b"].remoteCwd).toBe("/home/b");
  });

  it("setCwd writes each side, and a null remote path falls back to home", () => {
    s().ensurePane("a", "/home/a");
    s().setCwd("a", "local", "/Users/alice/Downloads");
    expect(s().panes["a"].localCwd).toBe("/Users/alice/Downloads");
    // Local "Home" is expressed as null (ask the backend).
    s().setCwd("a", "local", null);
    expect(s().panes["a"].localCwd).toBeNull();
    // The remote side always has a concrete canonical path.
    s().setCwd("a", "remote", "/etc");
    s().setCwd("a", "remote", null);
    expect(s().panes["a"].remoteCwd).toBe("/home/a");
  });

  it("setRemoteHome follows a reconnect's login directory without moving the cwds", () => {
    s().ensurePane("a", "/home/a");
    s().setCwd("a", "remote", "/etc");
    s().setRemoteHome("a", "/home/other");
    expect(s().panes["a"].remoteHome).toBe("/home/other");
    expect(s().panes["a"].remoteCwd).toBe("/etc");
  });

  it("toggleSort flips direction on the same key and restarts ascending on a new one", () => {
    s().ensurePane("a", "/home/a");
    s().toggleSort("a", "remote", "name");
    expect(s().panes["a"].remoteSort).toEqual({ key: "name", asc: false });
    s().toggleSort("a", "remote", "size");
    expect(s().panes["a"].remoteSort).toEqual({ key: "size", asc: true });
    // The other pane's sort is untouched.
    expect(s().panes["a"].localSort).toEqual({ key: "name", asc: true });
  });

  it("toggleHidden is per-side", () => {
    s().ensurePane("a", "/home/a");
    s().toggleHidden("a", "local");
    expect(s().panes["a"].showHiddenLocal).toBe(true);
    expect(s().panes["a"].showHiddenRemote).toBe(false);
    s().toggleHidden("a", "local");
    expect(s().panes["a"].showHiddenLocal).toBe(false);
  });

  it("mutations on an unknown session are inert (no phantom pane)", () => {
    s().setCwd("ghost", "remote", "/etc");
    s().toggleSort("ghost", "remote", "size");
    s().toggleHidden("ghost", "local");
    s().setRemoteHome("ghost", "/x");
    expect(s().panes).toEqual({});
  });

  it("clearFilesPaneState drops one session's state and leaves the rest", () => {
    s().ensurePane("a", "/home/a");
    s().ensurePane("b", "/home/b");
    clearFilesPaneState("a");
    expect(s().panes["a"]).toBeUndefined();
    expect(s().panes["b"]).toBeDefined();
    // Clearing an unknown id is a no-op, not a throw.
    clearFilesPaneState("ghost");
    expect(Object.keys(s().panes)).toEqual(["b"]);
  });
});

describe("filesStore — transfers (v5.0.0 Commit C)", () => {
  it("applyTransferUpdate inserts in arrival order and replaces IN PLACE", () => {
    s().applyTransferUpdate(update({ id: "t1", state: "queued" }));
    s().applyTransferUpdate(update({ id: "t2", state: "queued" }));
    s().applyTransferUpdate(update({ id: "t3", state: "queued" }));
    expect(ids()).toEqual(["t1", "t2", "t3"]);

    // Progress on the FIRST row must not move it to the bottom of the strip.
    s().applyTransferUpdate(update({ id: "t1", state: "running", bytes_done: 42 }));
    expect(ids()).toEqual(["t1", "t2", "t3"]);
    expect(s().transfers.get("t1")).toMatchObject({ state: "running", bytes_done: 42 });
    expect(s().transfers.size).toBe(3);
  });

  it("accepts an update for an id it has never seen (the Queued event can beat the enqueue response)", () => {
    s().applyTransferUpdate(update({ id: "unknown", state: "queued" }));
    expect(s().transfers.get("unknown")?.state).toBe("queued");
    // …and no target yet, which is exactly what registerTransferTargets fixes.
    expect(s().transferTargets.get("unknown")).toBeUndefined();
  });

  it("activeTransferCount counts queued + running, globally and per session", () => {
    s().applyTransferUpdate(update({ id: "a", session_id: "s1", state: "queued" }));
    s().applyTransferUpdate(update({ id: "b", session_id: "s1", state: "running" }));
    s().applyTransferUpdate(update({ id: "c", session_id: "s2", state: "running" }));
    s().applyTransferUpdate(update({ id: "d", session_id: "s1", state: "done" }));
    s().applyTransferUpdate(update({ id: "e", session_id: "s1", state: "error" }));
    s().applyTransferUpdate(update({ id: "f", session_id: "s1", state: "cancelled" }));

    expect(s().activeTransferCount()).toBe(3);
    expect(s().activeTransferCount("s1")).toBe(2);
    expect(s().activeTransferCount("s2")).toBe(1);
    expect(s().activeTransferCount("nobody")).toBe(0);
    // The non-hook accessor the close/quit guards use agrees.
    expect(activeFilesTransferCount("s1")).toBe(2);
    expect(countActiveTransfers(s().transfers)).toBe(3);
  });

  it("clearFinishedTransfers drops terminal rows AND their targets, keeping active work", () => {
    s().applyTransferUpdate(update({ id: "run", state: "running" }));
    s().applyTransferUpdate(update({ id: "q", state: "queued" }));
    s().applyTransferUpdate(update({ id: "ok", state: "done" }));
    s().applyTransferUpdate(update({ id: "bad", state: "error", error: "permission denied" }));
    s().applyTransferUpdate(update({ id: "gone", state: "cancelled" }));
    const target = {
      sessionId: "s1",
      side: "remote" as const,
      destKey: "/tmp",
      deviceLabel: "vEX1",
    };
    s().recordTransferTargets(["run", "q", "ok", "bad", "gone"], target);

    s().clearFinishedTransfers();

    expect(ids()).toEqual(["run", "q"]);
    expect(Array.from(s().transferTargets.keys()).sort()).toEqual(["q", "run"]);

    // Idempotent: a second click with nothing finished is a no-op (and keeps
    // the same object, so no subscriber re-renders).
    const before = s().transfers;
    s().clearFinishedTransfers();
    expect(s().transfers).toBe(before);
  });

  it("recordTransferTargets stores one destination per id and leaves the rows alone", () => {
    s().applyTransferUpdate(update({ id: "t1", state: "queued" }));
    s().recordTransferTargets(["t1", "t2"], {
      sessionId: "s1",
      side: "local",
      destKey: null,
      deviceLabel: "vEX1",
    });
    expect(s().transferTargets.get("t1")).toEqual({
      sessionId: "s1",
      side: "local",
      // `null` = the local pane's "backend default home" query key.
      destKey: null,
      deviceLabel: "vEX1",
    });
    expect(s().transferTargets.get("t2")?.side).toBe("local");
    expect(s().transfers.size).toBe(1);

    // An empty batch is inert.
    const before = s().transferTargets;
    s().recordTransferTargets([], {
      sessionId: "s1",
      side: "local",
      destKey: null,
      deviceLabel: "x",
    });
    expect(s().transferTargets).toBe(before);
  });

  it("isTerminalTransferState matches the engine's definition", () => {
    expect(isTerminalTransferState("done")).toBe(true);
    expect(isTerminalTransferState("error")).toBe(true);
    expect(isTerminalTransferState("cancelled")).toBe(true);
    expect(isTerminalTransferState("queued")).toBe(false);
    expect(isTerminalTransferState("running")).toBe(false);
  });

  it("caps the mirror by forgetting the oldest FINISHED rows, never live work", () => {
    // One row per enqueued item, so a big multi-select can flood the strip
    // (which renders every row it holds).
    s().applyTransferUpdate(update({ id: "old-done", state: "done" }));
    s().applyTransferUpdate(update({ id: "keep-running", state: "running" }));
    s().recordTransferTargets(["old-done"], {
      sessionId: "s1",
      side: "remote",
      destKey: "/tmp",
      deviceLabel: "vEX1",
    });
    for (let i = 0; i < 220; i++) {
      s().applyTransferUpdate(update({ id: `t${i}`, state: "done" }));
    }

    expect(s().transfers.size).toBe(200);
    // The oldest finished row (and its now-pointless target) is gone…
    expect(s().transfers.has("old-done")).toBe(false);
    expect(s().transferTargets.has("old-done")).toBe(false);
    // …the outstanding transfer is not, however old it is.
    expect(s().transfers.get("keep-running")?.state).toBe("running");
    expect(s().activeTransferCount()).toBe(1);
  });

  it("never evicts live rows even when every row is active", () => {
    for (let i = 0; i < 220; i++) {
      s().applyTransferUpdate(update({ id: `t${i}`, state: "queued" }));
    }
    // Nothing is safe to forget, so the cap yields rather than lose work.
    expect(s().transfers.size).toBe(220);
    expect(s().activeTransferCount()).toBe(220);
  });

  it("queue collapse is global (one queue, rendered in every Files tab)", () => {
    expect(s().queueCollapsed).toBe(false);
    s().setQueueCollapsed(true);
    expect(s().queueCollapsed).toBe(true);
  });

  it("closing a tab keeps its transfer rows — the cancelled row is the receipt", () => {
    s().ensurePane("f1", "/home/lab");
    s().applyTransferUpdate(update({ id: "t1", session_id: "f1", state: "cancelled" }));
    clearFilesPaneState("f1");
    expect(s().panes["f1"]).toBeUndefined();
    expect(s().transfers.get("t1")?.state).toBe("cancelled");
  });
});
