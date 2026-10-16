import { create } from "zustand";

import type { TransferUpdate } from "@/lib/api";
import { DEFAULT_SORT, type PaneSort, type SortKey } from "@/lib/fileBrowser";

/**
 * v5.0.0 — per-Files-session pane UI state (cwds, sort, hidden toggles)
 * plus the global transfer-queue mirror.
 *
 * Strictly UI state, per CLAUDE.md §11: the directory LISTINGS are server
 * state and live in TanStack Query (`["filesRemoteDir", sessionId, path]` /
 * `["filesLocalDir", path]`). What lives here is only "where is this pane
 * pointed and how is it ordered" — the equivalent of `uiStore.sessions`
 * for the tab strip. Never persisted: a Files session dies with the app,
 * so restoring a stale remote cwd would be a lie.
 *
 * Keyed by the BACKEND session id, so a reconnect (which keeps the id)
 * preserves both cwds — the pane comes back exactly where it was.
 *
 * The `transfers` map is the one server-shaped thing here, and it is the
 * established event-mirror exception (`uiStore.sessions` /
 * `pendingApprovalByChat` are the precedents): it is built EXCLUSIVELY from
 * `files:transfer:update` events by `lib/filesTransfers.ts`, never fetched,
 * because the backend exposes no "list transfers" query — the event stream
 * IS the state. It is global across sessions (the queue strip shows every
 * Files session's work), so it lives here rather than under `panes`.
 */

/** Which pane of the dual browser. */
export type PaneSide = "local" | "remote";

export interface FilesPaneState {
  /** Canonical remote directory currently listed. Seeded from the
   *  `home` that `files_connect` returned. */
  remoteCwd: string;
  /** The server's login directory — the remote pane's Home button. */
  remoteHome: string;
  /** Canonical local directory, or `null` for "the backend default"
   *  (the user's home — `files_local_list_dir` with no path). */
  localCwd: string | null;
  remoteSort: PaneSort;
  localSort: PaneSort;
  showHiddenRemote: boolean;
  showHiddenLocal: boolean;
}

/**
 * Where a transfer's bytes LAND, recorded at enqueue time.
 *
 * The engine's events are deliberately identity-free beyond
 * `session_id` — a `TransferDescriptor` carries only `{id, direction,
 * name}` — so the destination directory a terminal state must invalidate
 * cannot be recovered from the event stream. The enqueue call is the one
 * place that knows it, so it records it here keyed by transfer id.
 *
 * A discriminated union on `side` so the destination key is typed to the
 * pane it belongs to: the remote pane always has a concrete canonical cwd,
 * while the local pane's cwd is `null` until the user leaves the backend's
 * default home. That distinction is load-bearing — a `string | null`
 * shared field forced `invalidateTransferDestination` into a `destKey ?? ""`
 * that would silently invalidate a nonexistent listing (and skip the real
 * refresh) if a remote target ever went null. The type now makes that
 * unrepresentable.
 */
export type TransferTarget =
  | {
      /** An upload's bytes land in the REMOTE pane. */
      side: "remote";
      sessionId: string;
      /** The canonical remote cwd the destination listing is keyed by. */
      destKey: string;
      /** Tab label at enqueue time — the fallback the queue strip renders
       *  once the tab is gone (a finished row outlives its session). */
      deviceLabel: string;
    }
  | {
      /** A download's bytes land in the LOCAL pane. */
      side: "local";
      sessionId: string;
      /** The local cwd spelling the listing is keyed by; `null` while the
       *  local pane still shows the backend's default home. */
      destKey: string | null;
      deviceLabel: string;
    };

interface FilesState {
  panes: Record<string, FilesPaneState>;
  /**
   * Every transfer we've heard about, newest last (a `Map` for an explicit
   * insertion order the strip renders in). Fed only by
   * `applyTransferUpdate`.
   */
  transfers: Map<string, TransferUpdate>;
  /** Enqueue-time destinations, keyed by transfer id (see
   *  [`TransferTarget`]). */
  transferTargets: Map<string, TransferTarget>;
  /** Queue-strip collapse, global (one queue, shown in every Files tab). */
  queueCollapsed: boolean;
  /** True once the app-global `files:transfer:update` subscription is in
   *  place. The latch lives here rather than in a module variable so it
   *  resets with the rest of the store between tests. */
  transferListenerStarted: boolean;
  /** True once that subscription has actually RESOLVED (the listener is
   *  live). Distinct from `transferListenerStarted`, which flips true
   *  synchronously before the `listen()` promise settles. The quit/close
   *  guards read this to fail SAFE: until it's true — never established, or
   *  the `listen()` rejected — an empty transfers map can't be trusted to
   *  mean "no transfers", so they must assume a Files session may be
   *  mid-transfer rather than allowing a silent quit (F7). */
  transferListenerReady: boolean;
  /** Create the pane state for a session if absent (idempotent — a
   *  remount must not reset a user's cwd). `home` seeds both the remote
   *  cwd and the Home button. */
  ensurePane: (sessionId: string, home: string) => void;
  /** Re-seed the Home target after a reconnect: the server can hand back
   *  a different login directory, and the button must follow it. The cwds
   *  are deliberately left alone. */
  setRemoteHome: (sessionId: string, home: string) => void;
  setCwd: (sessionId: string, side: PaneSide, path: string | null) => void;
  /** Click a column header: same key flips direction, a new key starts
   *  ascending. */
  toggleSort: (sessionId: string, side: PaneSide, key: SortKey) => void;
  toggleHidden: (sessionId: string, side: PaneSide) => void;
  /** Drop a session's pane state (tab closed). Transfers are deliberately
   *  left alone: they're global, and a cancelled row is the receipt that
   *  closing the tab stopped the copy. */
  clearPane: (sessionId: string) => void;

  /** Fold one `files:transfer:update` event into the mirror. Insert-or-
   *  replace by id; an unknown id is inserted (the `Queued` event can beat
   *  the `files_enqueue` response back to us). */
  applyTransferUpdate: (update: TransferUpdate) => void;
  /** Remember where a batch's bytes land, so a terminal state knows which
   *  directory listing to invalidate. */
  recordTransferTargets: (ids: string[], target: TransferTarget) => void;
  /** Drop every finished row (done / error / cancelled) and its target. */
  clearFinishedTransfers: () => void;
  /** Queued + running, optionally scoped to one session — the question the
   *  transfer-aware close and quit guards ask. */
  activeTransferCount: (sessionId?: string) => number;
  setQueueCollapsed: (collapsed: boolean) => void;
  /** See [`FilesState.transferListenerStarted`] — written only by
   *  `lib/filesTransfers.ts`. */
  setTransferListenerStarted: (started: boolean) => void;
  /** See [`FilesState.transferListenerReady`] — written only by
   *  `lib/filesTransfers.ts`. */
  setTransferListenerReady: (ready: boolean) => void;
}

/**
 * How many queue rows to keep. A single "transfer" is one enqueued item, so
 * selecting a thousand files makes a thousand rows — and the strip renders
 * them all (its `max-h` scrolls, it doesn't virtualize). Past the cap the
 * OLDEST FINISHED rows are evicted, so history is what gets forgotten and
 * outstanding work is always visible; "Clear finished" is the manual version
 * of the same rule.
 */
const MAX_TRANSFER_ROWS = 200;

/** Is this state one the engine will never leave? */
export function isTerminalTransferState(state: TransferUpdate["state"]): boolean {
  return state === "done" || state === "error" || state === "cancelled";
}

/**
 * Queued + running transfers, optionally scoped to one session. A pure
 * function so the close/quit guards can ask outside React.
 */
export function countActiveTransfers(
  transfers: Map<string, TransferUpdate>,
  sessionId?: string,
): number {
  let count = 0;
  for (const t of transfers.values()) {
    if (sessionId !== undefined && t.session_id !== sessionId) continue;
    if (t.state === "queued" || t.state === "running") count += 1;
  }
  return count;
}

function initialPane(home: string): FilesPaneState {
  return {
    remoteCwd: home,
    remoteHome: home,
    localCwd: null,
    remoteSort: { ...DEFAULT_SORT },
    localSort: { ...DEFAULT_SORT },
    showHiddenRemote: false,
    showHiddenLocal: false,
  };
}

export const useFilesStore = create<FilesState>((set, get) => ({
  panes: {},
  transfers: new Map(),
  transferTargets: new Map(),
  queueCollapsed: false,
  transferListenerStarted: false,
  transferListenerReady: false,
  ensurePane: (sessionId, home) =>
    set((s) => {
      if (s.panes[sessionId]) return s;
      return { panes: { ...s.panes, [sessionId]: initialPane(home) } };
    }),
  setRemoteHome: (sessionId, home) =>
    set((s) => {
      const pane = s.panes[sessionId];
      if (!pane || pane.remoteHome === home) return s;
      return { panes: { ...s.panes, [sessionId]: { ...pane, remoteHome: home } } };
    }),
  setCwd: (sessionId, side, path) =>
    set((s) => {
      const pane = s.panes[sessionId];
      if (!pane) return s;
      // The remote pane always has a concrete canonical path; only the
      // local pane's null means "ask the backend for home".
      const next =
        side === "remote"
          ? { ...pane, remoteCwd: path ?? pane.remoteHome }
          : { ...pane, localCwd: path };
      return { panes: { ...s.panes, [sessionId]: next } };
    }),
  toggleSort: (sessionId, side, key) =>
    set((s) => {
      const pane = s.panes[sessionId];
      if (!pane) return s;
      const current = side === "remote" ? pane.remoteSort : pane.localSort;
      const sort: PaneSort = current.key === key ? { key, asc: !current.asc } : { key, asc: true };
      const next = side === "remote" ? { ...pane, remoteSort: sort } : { ...pane, localSort: sort };
      return { panes: { ...s.panes, [sessionId]: next } };
    }),
  toggleHidden: (sessionId, side) =>
    set((s) => {
      const pane = s.panes[sessionId];
      if (!pane) return s;
      const next =
        side === "remote"
          ? { ...pane, showHiddenRemote: !pane.showHiddenRemote }
          : { ...pane, showHiddenLocal: !pane.showHiddenLocal };
      return { panes: { ...s.panes, [sessionId]: next } };
    }),
  clearPane: (sessionId) =>
    set((s) => {
      if (!(sessionId in s.panes)) return s;
      const panes = { ...s.panes };
      delete panes[sessionId];
      return { panes };
    }),

  applyTransferUpdate: (update) =>
    set((s) => {
      // `Map.set` on an existing key keeps its original position, so a
      // running transfer's row never jumps around as progress arrives.
      const transfers = new Map(s.transfers);
      transfers.set(update.id, update);
      if (transfers.size <= MAX_TRANSFER_ROWS) return { transfers };
      // Over the cap: forget the oldest FINISHED rows (insertion order),
      // never anything still queued or running.
      const transferTargets = new Map(s.transferTargets);
      for (const [id, t] of transfers) {
        if (transfers.size <= MAX_TRANSFER_ROWS) break;
        if (id === update.id || !isTerminalTransferState(t.state)) continue;
        transfers.delete(id);
        transferTargets.delete(id);
      }
      return { transfers, transferTargets };
    }),

  recordTransferTargets: (ids, target) =>
    set((s) => {
      if (ids.length === 0) return s;
      const transferTargets = new Map(s.transferTargets);
      for (const id of ids) transferTargets.set(id, target);
      return { transferTargets };
    }),

  clearFinishedTransfers: () =>
    set((s) => {
      const transfers = new Map(s.transfers);
      const transferTargets = new Map(s.transferTargets);
      for (const [id, t] of s.transfers) {
        if (isTerminalTransferState(t.state)) {
          transfers.delete(id);
          transferTargets.delete(id);
        }
      }
      if (transfers.size === s.transfers.size) return s;
      return { transfers, transferTargets };
    }),

  activeTransferCount: (sessionId) => countActiveTransfers(get().transfers, sessionId),

  setQueueCollapsed: (collapsed) => set({ queueCollapsed: collapsed }),

  setTransferListenerStarted: (started) => set({ transferListenerStarted: started }),

  setTransferListenerReady: (ready) => set({ transferListenerReady: ready }),
}));

/**
 * Forget a closed session's pane state. A plain function (not a hook) so
 * the tab-close paths in `TerminalArea` can call it inline, the same way
 * `lib/chat.ts`'s thunks are called from event handlers.
 */
export function clearFilesPaneState(sessionId: string): void {
  useFilesStore.getState().clearPane(sessionId);
}

/**
 * Queued + running transfers, read outside React — the transfer-aware
 * close (`TerminalArea`) and quit (`QuitConfirmDialog`) guards both ask
 * this from an event handler, where a hook is not available.
 */
export function activeFilesTransferCount(sessionId?: string): number {
  return countActiveTransfers(useFilesStore.getState().transfers, sessionId);
}

/**
 * Would closing/quitting a Files session risk data loss? True when it has
 * active transfers — OR when the transfer listener isn't confirmed live, in
 * which case an empty transfers map can't be trusted (the listener may have
 * failed to subscribe, F7) and we FAIL SAFE by assuming a transfer might be
 * running. This is what keeps a broken listener from turning a mid-transfer
 * quit into a no-dialog `confirm_quit`. The backend `has_active_session` is
 * the real data-safety authority; this only governs whether the frontend
 * shows the confirm.
 */
export function filesSessionRisksDataLoss(sessionId?: string): boolean {
  const state = useFilesStore.getState();
  if (!state.transferListenerReady) return true;
  return countActiveTransfers(state.transfers, sessionId) > 0;
}
