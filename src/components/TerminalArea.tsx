import {
  DndContext,
  DragOverlay,
  PointerSensor,
  pointerWithin,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { emit, listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { FolderOpen, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { ApiSessionPane } from "@/components/ApiSessionPane";
import { FilesPane } from "@/components/FilesPane";
import { PcapPane } from "@/components/PcapPane";
import { OPEN_CAPTURES_KEY, pcapClose } from "@/lib/pcap";
import { PaneTree } from "@/components/PaneTree";
import { ScrollableTabStrip } from "@/components/ScrollableTabStrip";
import { ExportSessionDialog } from "@/components/dialogs/ExportSessionDialog";
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
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Tabs, TabsContent, TabsTrigger } from "@/components/ui/tabs";
import {
  clearScrollback,
  disconnectSession,
  filesDisconnect,
  listApiSessions,
  listDevices,
  listSessionLogs,
  startSessionLog,
  stopSessionLog,
} from "@/lib/api";
import { deviceColorTint, deviceColorVar } from "@/lib/deviceColors";
import { leaf } from "@/lib/paneTree";
import { toastError } from "@/lib/toast";
import { computeLabels } from "@/lib/sessionLabels";
import { cn } from "@/lib/utils";
import {
  activeFilesTransferCount,
  clearFilesPaneState,
  filesSessionRisksDataLoss,
  useFilesStore,
} from "@/stores/filesStore";
import {
  hasPty,
  isFilesTab,
  isPcapTab,
  resolveActivePaneId,
  type SessionTab,
  useUiStore,
} from "@/stores/uiStore";

/**
 * Phase 3 multi-session host. Reads the `sessions` array from
 * `uiStore` and renders a tab strip + one `TerminalPane` per tab.
 *
 * `forceMount` on every `TabsContent` keeps each pane's xterm.js
 * instance mounted even while the tab is hidden — scrollback +
 * pending PTY output continue to accumulate, and the user sees the
 * latest state when they switch back. Hidden tabs get `display:
 * none` from the Radix `data-state="inactive"` selector via
 * `ui/tabs.tsx`'s class list.
 *
 * Backend was already multi-session-aware since Phase 2b
 * (`SshState.sessions: HashMap<String, SessionEntry>`). This
 * component is the frontend lift to expose that capability.
 */
export function TerminalArea() {
  const sessions = useUiStore((s) => s.sessions);
  const activeTabId = useUiStore((s) => s.activeTabId);
  // Read live (not via getState) so flipping the setting applies to the
  // very next close without a remount. Must sit up here with the other
  // hooks — this component has early returns further down, and calling it
  // below one of them is a rules-of-hooks error (react-doctor catches it).
  const warnOnSessionClose = useUiStore((s) => s.preferences.warnOnSessionClose);
  const setActiveTab = useUiStore((s) => s.setActiveTab);
  const removeSession = useUiStore((s) => s.removeSession);
  const clearAllSessions = useUiStore((s) => s.clearAllSessions);
  const sortSessionsByLabel = useUiStore((s) => s.sortSessionsByLabel);
  const moveSession = useUiStore((s) => s.moveSession);
  const movePaneInto = useUiStore((s) => s.movePaneInto);
  const movePaneOut = useUiStore((s) => s.movePaneOut);
  // v6.4.0 — which pane of the active tab is focused. Subscribed (not read via
  // getState) so the ring re-renders the moment focus moves between panes.
  const activePaneId = useUiStore((s) => s.activePaneId);
  const lastPaneByTab = useUiStore((s) => s.lastPaneByTab);
  const openCaptures = useUiStore((s) => s.openCaptures);
  // Transfer liveness for the Files close guards. Deliberately a NUMBER, not
  // the transfers map: a running transfer emits progress at ~10 Hz, and
  // subscribing to the map would re-render every pane in the strip that
  // often. Only a change in how much work is outstanding matters here — and
  // any such change re-renders this component, so the per-session reads in
  // `needsCloseConfirm` (live `getState`) stay in step.
  const activeTransfers = useFilesStore((s) => s.activeTransferCount());

  // v4.1.0 draggable tabs. A 5px activation distance means a plain click
  // still activates the tab (Radix) — only a real drag starts a reorder,
  // matching the sidebar DeviceTree's dnd. `draggingId` drives the overlay.
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }));
  const [draggingId, setDraggingId] = useState<string | null>(null);
  // Grabbing a tab chip activates that tab (Radix), which would make the
  // DRAGGED tab the only visible pane — and you can't tile a pane onto itself
  // (the whole point is to drop it onto ANOTHER tab's view). So we record the
  // tab that was visible just before the grab (captured in the pointerdown
  // CAPTURE phase, before Radix switches) and restore it when the drag starts,
  // keeping it the drop target while the grabbed tab tiles into it.
  const activeBeforeDragRef = useRef<string | null>(null);

  // Tab close confirmation: target sessionId. `null` = no dialog.
  const [pendingClose, setPendingClose] = useState<string | null>(null);
  // v2.3.4 "Close all tabs" confirmation (user request — dozens of
  // switch sessions open at once made one-at-a-time closing painful).
  const [pendingCloseAll, setPendingCloseAll] = useState(false);
  const [pendingExport, setPendingExport] = useState<SessionTab | null>(null);

  // Phase 3 — session logging. The set of currently-logging sessions drives
  // the per-tab recording dot; the backend owns the state, so this is a
  // TanStack query invalidated on start/stop + on the `session-log:changed`
  // event a logger emits when its session ends. These hooks (and the two
  // effects) MUST stay ABOVE the `sessions.length === 0` early return below —
  // Rules of Hooks: hook order must be identical on every render, and a hook
  // placed after the return would be skipped on an empty-session render.
  const queryClient = useQueryClient();
  const sessionLogsQuery = useQuery({ queryKey: ["sessionLogs"], queryFn: listSessionLogs });

  useEffect(() => {
    const unlisten = listen("session-log:changed", () => {
      void queryClient.invalidateQueries({ queryKey: ["sessionLogs"] });
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, [queryClient]);

  // Console auto-reconnect: the backend re-opened a dropped console session
  // under the same id on cable replug — un-end its tab so the pane resumes.
  useEffect(() => {
    const unlisten = listen<string>("console:reconnected", (e) => {
      useUiStore.getState().markSessionReconnected(e.payload);
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  if (sessions.length === 0) return null;

  // Top-level tabs only — right-pane sessions live inside their
  // primary's TabsContent and are not addressable via the tab strip.
  const topLevelSessions = sessions.filter((t) => !t.splitWith);
  const labels = computeLabels(topLevelSessions);

  // All sessions belonging to a tab: its primary + every pane whose splitWith
  // points at it (v4.4.0 tiling — a tab can hold >2 panes). Close / disconnect
  // act on all of them.
  const panesOf = (tab: SessionTab): SessionTab[] =>
    sessions.filter((t) => t.sessionId === tab.sessionId || t.splitWith === tab.sessionId);

  // v6.4.0 — the focused pane of the ACTIVE tab, resolved once here and handed
  // down. Resolving (rather than reading `activePaneId` raw) is what makes a
  // stale hint harmless: it falls back to the tab's primary, which is the
  // pre-tiling behaviour.
  const focusedPaneId = resolveActivePaneId({
    sessions,
    activeTabId,
    activePaneId,
    lastPaneByTab,
  });

  // What warrants a confirm before closing: a live PTY session, or a Files
  // session that risks data loss (transfers queued/running — closing cancels
  // them — OR the transfer listener isn't confirmed live, in which case
  // `filesSessionRisksDataLoss` fails safe rather than trusting an empty map;
  // F7). An API tab holds no connection, and an IDLE Files tab with a healthy
  // listener has nothing to lose, so both close without a prompt.
  const needsCloseConfirm = (tab: SessionTab) =>
    isFilesTab(tab)
      ? !tab.ended && filesSessionRisksDataLoss(tab.sessionId)
      : hasPty(tab) && !tab.ended;

  // Tear down whichever backend a tab actually owns. Files sessions live in
  // the DISJOINT `files_*` namespace: `disconnect_session` has no files arm
  // (plan decision 7), so routing one there would leak the SFTP session and
  // its SSH connection. Pane-state cleanup is deliberately NOT here — see
  // `dropTab`.
  const teardown = (tab: SessionTab): Promise<void> => {
    if (isFilesTab(tab)) return filesDisconnect(tab.sessionId);
    // v6.0.0 — a capture closes through the equally-disjoint `pcap_*`
    // namespace. `disconnect_session` has no pcap arm either, so routing
    // one there would leave the index (and its memory) resident forever.
    if (isPcapTab(tab)) return pcapClose(tab.sessionId);
    return disconnectSession(tab.sessionId);
  };

  // Drop a tab's UI state once its backend is (being) torn down. `removeSession`
  // unmounts the pane; for a Files tab the pane state is cleared in the SAME
  // synchronous tick (both are store writes → one batched re-render), so the
  // pane never re-renders cwd-less. Clearing it EARLIER — e.g. inside `teardown`
  // before the awaited `filesDisconnect` — left the still-mounted pane with no
  // cwd, snapping it to "." and firing a fresh listing at the closing session
  // (F8).
  const dropTab = (tab: SessionTab) => {
    removeSession(tab.sessionId);
    if (isFilesTab(tab)) clearFilesPaneState(tab.sessionId);
  };

  const requestClose = async (tab: SessionTab) => {
    // API tabs have no backend session — just drop the tab (no confirm).
    if (tab.kind === "api") {
      removeSession(tab.sessionId);
      return;
    }
    // A capture holds no connection and nothing in flight, so there is
    // nothing to lose by closing it — no confirm, just release the index.
    if (isPcapTab(tab)) {
      await pcapClose(tab.sessionId).catch(() => {});
      removeSession(tab.sessionId);
      // The sidebar's capture list is the set of OPEN captures, so it has
      // to hear about this — otherwise the row survives its capture and
      // clicking it reopens a tab onto an id the backend has forgotten.
      void queryClient.invalidateQueries({ queryKey: OPEN_CAPTURES_KEY });
      return;
    }
    if (isFilesTab(tab)) {
      // Transfers in flight → confirm; idle → close silently (see
      // `needsCloseConfirm`). `files_disconnect` cancels the session's
      // transfers backend-side, so the confirm path needs no separate
      // cancel call — each parked transfer reports `cancelled` and the
      // queue row says so.
      if (needsCloseConfirm(tab)) {
        setPendingClose(tab.sessionId);
        return;
      }
      // `allSettled` semantics via catch: a session the backend already
      // dropped is fine for the user's "close" intent. `dropTab` clears the
      // pane state AFTER the disconnect completes (F8).
      await teardown(tab).catch(() => {});
      dropTab(tab);
      return;
    }
    const panes = panesOf(tab);
    // User opt-out (2026-09-02): with the confirm turned off, the X
    // just closes. Scoped to the PTY path on purpose — the Files branch
    // above warns about losing in-flight transfers, which is a different
    // risk from "you will disconnect", and this preference does not
    // silently discard a user's work.
    if (!warnOnSessionClose || panes.every((p) => p.ended)) {
      // Every pane already closed remotely — skip the confirm dialog, but
      // still tell the backend so no dead session lingers in
      // SshState.sessions (the agent's `list_open_sessions` must not surface
      // dead entries on the next chat turn). `allSettled` — a backend that
      // already tore a session down is fine.
      await Promise.allSettled(panes.map((p) => teardown(p)));
      dropTab(tab);
      return;
    }
    setPendingClose(tab.sessionId);
  };

  const confirmClose = async () => {
    if (pendingClose === null) return;
    const tab = sessions.find((t) => t.sessionId === pendingClose);
    setPendingClose(null);
    if (!tab) return;
    // Disconnect EVERY pane of the tab, THEN drop the UI (primary + all its
    // panes + any Files pane state). `allSettled`: a session torn down by a
    // remote race is not an error for the user's "close" intent.
    await Promise.allSettled(panesOf(tab).map((p) => teardown(p)));
    dropTab(tab);
  };

  // v2.3.4 — close every tab (and right pane) at once. Same contract
  // as the single-tab path: still-connected sessions get one combined
  // confirm dialog; if everything already ended we skip the dialog but
  // still disconnect backend-side so SshState.sessions is cleaned
  // (agent's `list_open_sessions` must not surface dead entries).
  const confirmCloseAll = async () => {
    setPendingCloseAll(false);
    // Snapshot before the store empties. Disconnect EVERY backend
    // session — right panes included; the store cascade only covers UI
    // state. API tabs have no backend session (synthetic id), so they
    // are dropped from the store only.
    const all = [...sessions];
    await Promise.allSettled(all.filter((t) => t.kind !== "api").map((t) => teardown(t)));
    // Unmount every pane, THEN drop the Files pane state — same tick, so no
    // Files pane re-renders cwd-less at a closing session (F8).
    clearAllSessions();
    for (const t of all) if (isFilesTab(t)) clearFilesPaneState(t.sessionId);
    // `teardown` already closed each capture backend-side, so the sidebar
    // list has to re-fetch or it keeps rows for captures that no longer
    // exist — the same stale-row bug the single-tab close path guards
    // against, which this path would otherwise reintroduce in bulk.
    if (all.some(isPcapTab)) {
      void queryClient.invalidateQueries({ queryKey: OPEN_CAPTURES_KEY });
    }
  };

  const requestCloseAll = () => {
    // Only a live PTY session warrants the confirm — so an all-API,
    // all-Files, or all-ended strip closes without prompting (but is still
    // torn down backend-side by `confirmCloseAll`).
    if (!sessions.some(needsCloseConfirm)) {
      void confirmCloseAll();
      return;
    }
    setPendingCloseAll(true);
  };

  // v1.4.0 "Clear terminal" — wipe BOTH the backend scrollback ring
  // (so the agent's read_scrollback can't resurface cleared output) and
  // the visible xterm (via the per-session ui event the pane listens
  // for). Fire both; a not-found ring (just-closed session) is harmless.
  const requestClear = (tab: SessionTab) => {
    void clearScrollback(tab.sessionId).catch(() => {});
    void emit(`ui:clear-terminal:${tab.sessionId}`);
  };

  // Currently-logging session ids → the per-tab recording dot. Derived from
  // `sessionLogsQuery` (hoisted above the early return); not a hook, so its
  // position here is free.
  const loggingIds = new Set((sessionLogsQuery.data ?? []).map((l) => l.session_id));

  const startLog = async (tab: SessionTab) => {
    const label = tab.customLabel || tab.deviceId || "session";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const destination = await save({
      title: "Log session to file",
      defaultPath: `${label}-${stamp}.log`,
      filters: [{ name: "Log file", extensions: ["log", "txt"] }],
    });
    if (!destination) return; // user cancelled the native dialog
    try {
      await startSessionLog(tab.sessionId, destination, true);
      void queryClient.invalidateQueries({ queryKey: ["sessionLogs"] });
    } catch (e) {
      toastError(`Could not start logging: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const stopLog = async (tab: SessionTab) => {
    await stopSessionLog(tab.sessionId).catch(() => {});
    void queryClient.invalidateQueries({ queryKey: ["sessionLogs"] });
  };

  // The session matching `pendingClose` for the dialog body.
  const pendingTab = sessions.find((t) => t.sessionId === pendingClose);
  const pendingTabIsFiles = pendingTab !== undefined && isFilesTab(pendingTab);
  const pendingTabTransfers = pendingTab ? activeFilesTransferCount(pendingTab.sessionId) : 0;

  return (
    <div className="flex h-full w-full flex-col">
      <Tabs
        // Keep the controlled value a string: `?? ""` (not `undefined`) so
        // closing the last tab doesn't flip Radix Tabs to uncontrolled (#18).
        value={activeTabId ?? ""}
        onValueChange={setActiveTab}
        className="flex h-full w-full flex-col"
      >
        <DndContext
          sensors={sensors}
          // Pointer-based collision so a tab dropped anywhere resolves by where
          // the cursor is — over another tab → reorder; over a pane's edge zone
          // → tile in. `rectIntersection` (the default) would fight the small
          // overlaid edge droppables.
          collisionDetection={pointerWithin}
          onDragStart={(e: DragStartEvent) => {
            const id = String(e.active.id);
            setDraggingId(id);
            // Re-show the pre-grab tab so its panes are the drop target (see
            // activeBeforeDragRef). Skip if the grabbed tab was already the
            // visible one — dropping it on its own pane is a no-op anyway.
            const before = activeBeforeDragRef.current;
            if (before && before !== id) setActiveTab(before);
          }}
          onDragEnd={(e: DragEndEvent) => {
            setDraggingId(null);
            const { active, over } = e;
            if (!over) return;
            const activeId = String(active.id);
            const overId = String(over.id);
            // Drop on a pane edge zone: "split|<paneId>|<edge>" → tile the
            // dragged tab into that pane. (Session ids carry no "|".)
            if (overId.startsWith("split|")) {
              const parts = overId.split("|");
              const paneId = parts[1];
              const edge = parts[2];
              const dir = edge === "left" || edge === "right" ? "row" : "col";
              const before = edge === "left" || edge === "top";
              movePaneInto(activeId, paneId, dir, before);
              return;
            }
            // Otherwise a strip reorder (drop over another tab).
            if (activeId !== overId) moveSession(activeId, overId);
          }}
          onDragCancel={() => setDraggingId(null)}
        >
          <ScrollableTabStrip activeTabId={activeTabId}>
            {topLevelSessions.map((tab, i) => (
              <TabTrigger
                key={tab.sessionId}
                tab={tab}
                label={labels[i]}
                // Capture the visible tab BEFORE this grab switches it (runs in
                // the pointerdown capture phase, ahead of Radix's activation).
                onGrabCapture={() => {
                  activeBeforeDragRef.current = useUiStore.getState().activeTabId;
                }}
                onRequestClose={() => requestClose(tab)}
                onRequestCloseAll={requestCloseAll}
                onSortTabs={sortSessionsByLabel}
                onRequestExport={() => setPendingExport(tab)}
                onCompareCaptures={() => openCaptures(tab.sessionId)}
                onRequestClear={() => requestClear(tab)}
                logging={loggingIds.has(tab.sessionId)}
                onStartLog={() => void startLog(tab)}
                onStopLog={() => void stopLog(tab)}
              />
            ))}
          </ScrollableTabStrip>
          {/* Floating drag preview (portal) so reordering doesn't disturb
              the strip's own horizontal scroll layout. */}
          <DragOverlay>
            {draggingId ? (
              <div className="rounded bg-background px-2 py-1 font-mono text-sm shadow-md ring-1 ring-border">
                {labels[topLevelSessions.findIndex((t) => t.sessionId === draggingId)] ?? ""}
              </div>
            ) : null}
          </DragOverlay>

          {/* Panes live INSIDE the DndContext so their `PaneDropZones`
              droppables share it with the draggable tabs. */}
          {topLevelSessions.map((tab) => (
            <TabsContent
              key={tab.sessionId}
              value={tab.sessionId}
              forceMount
              // Override the default `mt-2` so the terminal hugs the tab strip
              // and fills the vertical space. `min-h-0` lets the flex-1 content
              // shrink below the fitted xterm height so the v1.4.0 button-bar
              // row below always gets its slot.
              className="m-0 flex-1 min-h-0 data-[state=inactive]:hidden"
            >
              {tab.kind === "api" ? (
                <ApiSessionPane
                  apiSessionId={tab.apiSessionId ?? ""}
                  sessionId={tab.sessionId}
                  active={tab.sessionId === activeTabId}
                />
              ) : isPcapTab(tab) ? (
                // Like Files, MUST precede the PaneTree fallthrough: a
                // PaneTree leaf hardcodes `TerminalPane`, and a capture has
                // no PTY at all.
                <PcapPane captureId={tab.sessionId} active={tab.sessionId === activeTabId} />
              ) : isFilesTab(tab) ? (
                // MUST precede the PaneTree fallthrough: a PaneTree leaf
                // hardcodes `TerminalPane`, and a Files session has no PTY.
                <FilesPane
                  sessionId={tab.sessionId}
                  deviceId={tab.deviceId}
                  ended={tab.ended}
                  active={tab.sessionId === activeTabId}
                />
              ) : (
                // Every SSH/console/local tab renders through PaneTree — even a
                // single-pane tab (`leaf`) — so its pane hosts the drag-to-split
                // drop zones and a tab can be tiled onto a not-yet-split pane.
                <PaneTree
                  node={tab.layout ?? leaf(tab.sessionId)}
                  sessions={sessions}
                  tabActive={tab.sessionId === activeTabId}
                  // Focus is only meaningful for the visible tab; passing null
                  // for the others keeps a background tab from drawing a ring.
                  activePaneId={tab.sessionId === activeTabId ? focusedPaneId : null}
                  paneTotal={panesOf(tab).length}
                  onMovePaneOut={movePaneOut}
                />
              )}
            </TabsContent>
          ))}
        </DndContext>
      </Tabs>

      <AlertDialog open={pendingClose !== null} onOpenChange={(o) => !o && setPendingClose(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingTabIsFiles ? "Cancel transfers and close?" : "Close session?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pendingTabIsFiles ? (
                pendingTabTransfers > 0 ? (
                  <>
                    <b>{pendingTabTransfers}</b>{" "}
                    {pendingTabTransfers === 1 ? "transfer is" : "transfers are"} still in progress
                    to <span className="font-mono">{pendingTab?.deviceId ?? "(unknown)"}</span>.
                    Closing this tab cancels {pendingTabTransfers === 1 ? "it" : "them"}; partly
                    copied files are cleaned up.
                  </>
                ) : (
                  // Fail-safe path: the transfer listener isn't confirmed live,
                  // so we can't be sure the session is idle (F7).
                  <>
                    Transfers to{" "}
                    <span className="font-mono">{pendingTab?.deviceId ?? "(unknown)"}</span> may
                    still be in progress. Closing this tab cancels any that are; partly copied files
                    are cleaned up.
                  </>
                )
              ) : pendingTab?.layout ? (
                <>
                  Closing this tab disconnects <b>all</b> panes for{" "}
                  <span className="font-mono">{pendingTab.deviceId}</span>.
                </>
              ) : (
                <>
                  The connection to{" "}
                  <span className="font-mono">{pendingTab?.deviceId ?? "(unknown)"}</span> is still
                  open. Closing this tab disconnects its session.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep open</AlertDialogCancel>
            <AlertDialogAction onClick={confirmClose}>Close</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* v2.3.4 — close-all confirmation. One dialog for the whole
          strip; the per-tab dialog above keeps its own copy. */}
      <AlertDialog open={pendingCloseAll} onOpenChange={(o) => !o && setPendingCloseAll(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Close all sessions?</AlertDialogTitle>
            <AlertDialogDescription>
              {(() => {
                const live = sessions.filter(needsCloseConfirm).length;
                return (
                  <>
                    <b>{live}</b> of <b>{sessions.length}</b>{" "}
                    {sessions.length === 1 ? "session" : "sessions"} {live === 1 ? "is" : "are"}{" "}
                    still connected. Closing disconnects every open session and removes all tabs.
                    {activeTransfers > 0 && (
                      <>
                        {" "}
                        Closing also cancels <b>{activeTransfers}</b> file{" "}
                        {activeTransfers === 1 ? "transfer" : "transfers"} in progress.
                      </>
                    )}
                  </>
                );
              })()}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep open</AlertDialogCancel>
            <AlertDialogAction onClick={() => void confirmCloseAll()}>Close all</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Phase 8b — session-export modal. Single instance mounted at
          the TerminalArea root; pendingExport carries the SessionTab
          whose scrollback the user is exporting. */}
      <ExportSessionDialog
        open={pendingExport !== null}
        onOpenChange={(o) => !o && setPendingExport(null)}
        sessionId={pendingExport?.sessionId ?? ""}
        label={pendingExport?.customLabel || pendingExport?.deviceId || "session"}
      />
    </div>
  );
}

/**
 * Custom tab trigger: the device-id label, an "ended" pill if the
 * remote disconnected, and a small X close button. The X is a
 * sibling, NOT a nested button — Radix's TabsTrigger forbids
 * descendants of role="button" because it's a button itself.
 *
 * Phase 7a C9 — right-click opens a context menu with Rename + Close.
 * Rename swaps the label for an inline input; Enter commits, Esc
 * cancels, blank reverts to the auto-generated label.
 */
function TabTrigger({
  tab,
  label,
  onGrabCapture,
  onRequestClose,
  onRequestCloseAll,
  onSortTabs,
  onRequestExport,
  onCompareCaptures,
  onRequestClear,
  logging,
  onStartLog,
  onStopLog,
}: {
  tab: SessionTab;
  label: string;
  onGrabCapture: () => void;
  onRequestClose: () => void;
  onRequestCloseAll: () => void;
  onSortTabs: () => void;
  onRequestExport: () => void;
  onCompareCaptures: () => void;
  onRequestClear: () => void;
  logging: boolean;
  onStartLog: () => void;
  onStopLog: () => void;
}) {
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const devices = devicesQuery.data ?? [];
  // API and Files tabs are different actors with no scrollback/PTY — the
  // terminal-only context actions (export, log, compare, clear) don't apply,
  // so their menu shows only rename + close. `hasPty` is the one predicate
  // for that, so a future kind can't silently inherit those items.
  const isApi = tab.kind === "api";
  const isFiles = isFilesTab(tab);
  const ptyTab = hasPty(tab);
  // Per-device accent (Phase 1): tint this tab's left edge to match the
  // device's sidebar row + pane. v4.1.0 — `bold_color` upgrades the subtle
  // edge to a louder background tint (a stronger "am I on prod?" cue).
  const tabDevice = devices.find((d) => d.id === tab.deviceId);
  // #16 — API tabs get the same accent banner as SSH, from the controller's
  // color (looked up from list_api_sessions). bold_color parity is a follow-up.
  const apiSessionsQuery = useQuery({
    queryKey: ["apiSessions"],
    queryFn: listApiSessions,
    enabled: isApi,
  });
  const tabColor = isApi
    ? apiSessionsQuery.data?.find((s) => s.id === tab.apiSessionId)?.color
    : tabDevice?.color;
  const accent = deviceColorVar(tabColor ?? undefined);
  const boldTint = tabDevice?.bold_color ? deviceColorTint(tabDevice.color) : undefined;
  const setSessionLabel = useUiStore((s) => s.setSessionLabel);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(label);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // v4.1.0 — the whole tab chip is a drag handle AND a drop target.
  // Only `listeners` (pointer) are spread — not dnd's `attributes`, which
  // would put role="button"/tabIndex on a wrapper around the Radix tab.
  const { setNodeRef: setDragRef, listeners, isDragging } = useDraggable({ id: tab.sessionId });
  const { setNodeRef: setDropRef, isOver } = useDroppable({ id: tab.sessionId });
  const setDndRef = useCallback(
    (node: HTMLElement | null) => {
      setDragRef(node);
      setDropRef(node);
    },
    [setDragRef, setDropRef],
  );

  useEffect(() => {
    if (editing) {
      // Defer focus + select to the next microtask so the input is
      // mounted before we try to grab it.
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    }
  }, [editing]);

  const startRename = () => {
    setDraft(tab.customLabel ?? label);
    setEditing(true);
  };

  const commit = () => {
    const trimmed = draft.trim();
    setSessionLabel(tab.sessionId, trimmed.length === 0 ? null : trimmed);
    setEditing(false);
  };

  const cancel = () => {
    setDraft(label);
    setEditing(false);
  };

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <div
          ref={setDndRef}
          {...listeners}
          // Capture-phase: record the currently-visible tab BEFORE Radix's
          // activation switches to this one, so a drag can restore it.
          onPointerDownCapture={onGrabCapture}
          style={{
            ...(accent ? { borderLeft: `2px solid ${accent}` } : {}),
            ...(boldTint ? { backgroundColor: boldTint.backgroundColor } : {}),
            opacity: isDragging ? 0.4 : undefined,
          }}
          className={cn(
            "group flex items-center gap-1 rounded transition-all",
            // Match TabsTrigger's `data-[state=active]` background by
            // checking the trigger's data-state. Lifted via a CSS
            // sibling selector so the close button sits outside the
            // trigger but participates in the active styling.
            "[&:has([data-state=active])]:bg-background [&:has([data-state=active])]:shadow",
            // Drop-target cue while another tab is dragged over this one.
            isOver && "ring-2 ring-ring",
          )}
        >
          <TabsTrigger
            value={tab.sessionId}
            // Strip the default background — the wrapping div owns the
            // active-state styling now (see comment above).
            className="bg-transparent shadow-none data-[state=active]:bg-transparent data-[state=active]:shadow-none"
            onDoubleClick={(e) => {
              e.preventDefault();
              startRename();
            }}
          >
            {/* A Files tab and an SSH tab on the same device share the label
                namespace ("vEX1 (2)"); the folder glyph is what tells them
                apart (plan veto #5). */}
            {isFiles && (
              <FolderOpen
                className="mr-1 h-3 w-3 shrink-0 text-muted-foreground"
                data-testid={`tab-files-glyph-${tab.sessionId}`}
                aria-hidden
              />
            )}
            {editing ? (
              <input
                ref={inputRef}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    commit();
                  } else if (e.key === "Escape") {
                    e.preventDefault();
                    cancel();
                  }
                  // Stop the Tabs root from intercepting arrow keys
                  // for tab navigation while we're typing.
                  e.stopPropagation();
                }}
                onBlur={commit}
                onClick={(e) => e.stopPropagation()}
                className="w-24 bg-transparent font-mono text-sm outline-none ring-1 ring-ring rounded px-1"
                data-testid={`tab-rename-input-${tab.sessionId}`}
                aria-label="Tab name"
              />
            ) : (
              <span className="font-mono">{label}</span>
            )}
            {tab.ended && (
              <span
                className="ml-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-1 text-[10px] font-normal text-amber-700 dark:text-amber-400"
                title="Remote disconnected"
              >
                ended
              </span>
            )}
            {logging && (
              <span
                className="ml-1.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-red-500"
                title="Logging this session to a file"
                data-testid="tab-logging-dot"
              />
            )}
          </TabsTrigger>
          <button
            type="button"
            aria-label={`Close ${label}`}
            onClick={(e) => {
              e.stopPropagation();
              onRequestClose();
            }}
            className="mr-1 flex h-4 w-4 items-center justify-center rounded text-muted-foreground opacity-60 hover:bg-accent hover:text-foreground hover:opacity-100"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </ContextMenuTrigger>
      <ContextMenuContent
        // Radix's default is to restore focus to the trigger element
        // when the menu closes. That collides with our rename-input
        // useEffect — the menu's focus restoration runs AFTER our
        // requestAnimationFrame, blurs the input, fires the commit
        // path, and collapses edit mode. preventDefault hands focus
        // back to us; the rename effect (or the natural click target)
        // claims it next.
        onCloseAutoFocus={(e) => e.preventDefault()}
      >
        <ContextMenuItem onSelect={startRename}>Rename...</ContextMenuItem>
        {tab.customLabel && (
          <ContextMenuItem onSelect={() => setSessionLabel(tab.sessionId, null)}>
            Reset to default name
          </ContextMenuItem>
        )}
        {ptyTab && (
          <>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={onRequestExport}>Export scrollback...</ContextMenuItem>
            <ContextMenuItem onSelect={logging ? onStopLog : onStartLog}>
              {logging ? "Stop logging" : "Log session to file..."}
            </ContextMenuItem>
            <ContextMenuItem onSelect={onCompareCaptures}>
              Compare captures / diff output...
            </ContextMenuItem>
            <ContextMenuItem onSelect={onRequestClear}>Clear terminal</ContextMenuItem>
          </>
        )}
        <ContextMenuSeparator />
        {/* v6.1.0 — a ONE-SHOT reorder, not a sticky mode: new tabs
            still append. Lives next to "Close all tabs" because this is
            where someone with thirty sessions already right-clicks. */}
        <ContextMenuItem onSelect={onSortTabs} data-testid="tab-sort">
          Sort tabs alphabetically
        </ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem
          onSelect={onRequestClose}
          className="text-destructive focus:text-destructive"
        >
          Close tab
        </ContextMenuItem>
        <ContextMenuItem
          onSelect={onRequestCloseAll}
          className="text-destructive focus:text-destructive"
          data-testid="tab-close-all"
        >
          Close all tabs
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

// `computeLabels` moved to `@/lib/sessionLabels` (shared with the command
// palette and the propose_command approval modal so all three name a
// session identically). Re-exported here so existing importers — and the
// `TerminalArea.test.tsx` suite — keep importing it from this module.
export { computeLabels };
