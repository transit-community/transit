import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useState } from "react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { confirmQuit } from "@/lib/api";
import { filesSessionRisksDataLoss } from "@/stores/filesStore";
import { isFilesTab, useUiStore } from "@/stores/uiStore";

/**
 * v1.4.0 "warn before quit" — self-managing root dialog.
 *
 * The Rust side (`app_lifecycle::handle_run_event`) vetoes Cmd+Q / window
 * close while the backend still holds sessions and emits `app:confirm-quit`.
 * This component owns the actual decision, because liveness (`ended`) is a
 * frontend concept: it counts the LIVE (non-ended) sessions and either
 * proceeds straight to quit (nothing live to drop) or shows the confirm.
 * "Quit anyway" calls `confirm_quit`, which latches the backend flag and
 * exits, so the re-triggered exit isn't vetoed again.
 */
export function QuitConfirmDialog() {
  // The live-session count to show, or `null` when no prompt is pending.
  const [liveCount, setLiveCount] = useState<number | null>(null);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;

    void listen("app:confirm-quit", () => {
      // A Files tab counts as live ONLY while it risks data loss: with the
      // transfer listener healthy that means queued/running transfers (an idle
      // browse session has nothing to lose and must never nag on quit); if the
      // listener never subscribed, `filesSessionRisksDataLoss` fails SAFE and
      // treats the tab as live rather than presenting a no-dialog quit over a
      // transfer we simply can't see (F7). The Rust `has_active_session` files
      // arm is transfer-aware for the same reason, so the two ends agree on
      // what "active" means (plan §6/§7).
      const live = useUiStore
        .getState()
        .sessions.filter(
          (t) => !t.ended && (!isFilesTab(t) || filesSessionRisksDataLoss(t.sessionId)),
        ).length;
      if (live === 0) {
        // Backend held only ended-but-open tabs — nothing live to drop,
        // so honor the quit immediately without a dialog.
        void confirmQuit();
        return;
      }
      setLiveCount(live);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  const count = liveCount ?? 0;

  return (
    <AlertDialog open={liveCount !== null} onOpenChange={(o) => !o && setLiveCount(null)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Quit Transit?</AlertDialogTitle>
          <AlertDialogDescription>
            {count === 1
              ? "1 active session is still open. Quitting disconnects it."
              : `${count} active sessions are still open. Quitting disconnects them.`}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Keep working</AlertDialogCancel>
          <AlertDialogAction
            onClick={() => {
              setLiveCount(null);
              void confirmQuit();
            }}
          >
            Quit anyway
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
