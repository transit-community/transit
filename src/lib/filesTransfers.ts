import { listen } from "@tauri-apps/api/event";
import { useEffect } from "react";

import type { TransferUpdate } from "@/lib/api";
import { localDirKey, remoteDirKey } from "@/lib/files";
import { queryClient } from "@/lib/queryClient";
import { isTerminalTransferState, useFilesStore, type TransferTarget } from "@/stores/filesStore";

/**
 * v5.0.0 — the app-global `files:transfer:update` subscriber.
 *
 * One topic carries every transfer of every Files session (the backend
 * flattens the engine event beside `session_id`), so the listener belongs at
 * the APP level, not inside `FilesPane`: a transfer keeps running while its
 * tab is backgrounded, the queue strip is global, and the close/quit guards
 * must see transfers even when no Files tab is mounted. Same shape as
 * `ChatNotificationCenter`'s app-global agent listeners and
 * `lib/console.ts`'s `console:plug` subscription.
 *
 * The store holds the mirror; this module owns the two things a mirror
 * can't: subscribing once, and invalidating the destination directory's
 * listing when a transfer stops (`done` — the file is there now; `error` /
 * `cancelled` — the partial `.transitpart` download was cleaned up, or a
 * half-written upload deleted, so the listing changed either way).
 */

/** One topic for all transfers (`files.rs::TRANSFER_TOPIC`). */
export const FILES_TRANSFER_TOPIC = "files:transfer:update";

/**
 * Subscribe to `files:transfer:update` exactly once per app lifetime.
 * Idempotent — the latch (`filesStore.transferListenerStarted`) makes a
 * double mount (React StrictMode, a remount of `App`) safe, where two
 * subscriptions would double-apply every event.
 *
 * Deliberately never unsubscribes: the queue is app-global and outlives
 * every pane, so there is no scope to tear down (the native-menu wiring
 * takes the same view).
 */
export function initFilesTransferListener(): void {
  const store = useFilesStore.getState();
  if (store.transferListenerStarted) return;
  store.setTransferListenerStarted(true);
  void listen<TransferUpdate>(FILES_TRANSFER_TOPIC, (event) => {
    const update = event.payload;
    useFilesStore.getState().applyTransferUpdate(update);
    if (isTerminalTransferState(update.state)) {
      invalidateTransferDestination(update.id);
    }
  })
    .then(() => {
      // The subscription is live: only NOW may the quit/close guards trust
      // an empty transfers map to mean "no transfers" (F7). Until this
      // resolves they fail safe and treat Files tabs as possibly
      // mid-transfer.
      useFilesStore.getState().setTransferListenerReady(true);
    })
    .catch(() => {
      // Release the latch so the next mount can retry rather than leaving the
      // queue permanently blind, and keep `ready` false so the guards stay in
      // their fail-safe (blocking) state rather than silently allowing a quit.
      useFilesStore.getState().setTransferListenerStarted(false);
      useFilesStore.getState().setTransferListenerReady(false);
    });
}

/** Mount hook for `App`. The init is idempotent, so the effect needs no
 *  cleanup and a re-render can't multiply subscriptions. */
export function useFilesTransferListener(): void {
  useEffect(() => {
    initFilesTransferListener();
  }, []);
}

/**
 * Record where a freshly-enqueued batch lands, then catch up on any row that
 * already reached a terminal state.
 *
 * That catch-up is not theoretical: the engine emits `Queued` (and can run
 * the whole job) on its own task while the `files_enqueue` IPC response is
 * still in flight, so a tiny — or immediately failing — transfer can finish
 * before its target is known here. Without this, that transfer's destination
 * listing would keep showing stale contents.
 */
export function registerTransferTargets(ids: string[], target: TransferTarget): void {
  useFilesStore.getState().recordTransferTargets(ids, target);
  const { transfers } = useFilesStore.getState();
  for (const id of ids) {
    const known = transfers.get(id);
    if (known && isTerminalTransferState(known.state)) invalidateTransferDestination(id);
  }
}

/**
 * Invalidate the listing of the directory this transfer wrote into.
 *
 * Both invalidations are spelled out literally (rather than folded into one
 * parameterized helper) for the same reason `lib/files.ts`'s mutation hooks
 * are: react-doctor's `query-mutation-missing-invalidation` rule matches the
 * literal call shape, and a reader can see exactly which listing refreshes.
 */
function invalidateTransferDestination(transferId: string): void {
  const target = useFilesStore.getState().transferTargets.get(transferId);
  if (!target) return;
  if (target.side === "remote") {
    // `destKey` is a concrete remote cwd here — the discriminated union
    // guarantees it (no `?? ""` masking an impossible null that would
    // invalidate a nonexistent listing and skip the real refresh).
    void queryClient.invalidateQueries({
      queryKey: remoteDirKey(target.sessionId, target.destKey),
    });
  } else {
    void queryClient.invalidateQueries({ queryKey: localDirKey(target.destKey) });
  }
}
