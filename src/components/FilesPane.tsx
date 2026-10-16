import { useQueryClient } from "@tanstack/react-query";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { FolderOpen, Unplug, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

import { FileListPane } from "@/components/FileListPane";
import { TransferQueueStrip } from "@/components/TransferQueueStrip";
import { DeleteConfirmDialog } from "@/components/dialogs/DeleteConfirmDialog";
import { FileNameDialog, type FileNameDialogState } from "@/components/dialogs/FileNameDialog";
import { OverwriteConfirmDialog } from "@/components/dialogs/OverwriteConfirmDialog";
import { Button } from "@/components/ui/button";
import {
  filesCheckConflicts,
  filesEnqueue,
  type FileEntry,
  type OverwritePolicy,
  type TransferDirection,
  type TransferItem,
} from "@/lib/api";
import type { FilesDragPayload } from "@/lib/fileDnd";
import { DEFAULT_SORT, joinChildPath, type SortKey } from "@/lib/fileBrowser";
import {
  localDirKey,
  remoteDirKey,
  useFilesReconnectSession,
  useLocalDelete,
  useLocalDir,
  useLocalMkdir,
  useLocalRename,
  useLocalRoots,
  useRemoteDelete,
  useRemoteDir,
  useRemoteMkdir,
  useRemoteRename,
} from "@/lib/files";
import { registerTransferTargets } from "@/lib/filesTransfers";
import { toastError, toastInfo } from "@/lib/toast";
import { useFilesStore, type PaneSide, type TransferTarget } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

/** Fallback seed for the remote pane when the pane state is missing (a
 *  hot-reload, or a tab that outlived its launch mutation). The backend
 *  canonicalizes `"."` to the login directory, so this resolves to exactly
 *  what `files_connect` would have handed us. */
const REMOTE_CWD_FALLBACK = ".";

type DeleteDialogState =
  { kind: "none" } | { kind: "delete"; side: PaneSide; entries: FileEntry[] };

/** A resolved, ready-to-enqueue batch: every item shares one direction and
 *  one destination directory, which is what makes a single batch overwrite
 *  decision meaningful. */
interface TransferPlan {
  direction: TransferDirection;
  /** The pane the bytes land in (upload → remote, download → local). */
  destSide: PaneSide;
  /** The cwd spelling the destination pane's query key is built from, so a
   *  terminal transfer state can invalidate the right listing. */
  destKey: string | null;
  items: TransferItem[];
}

/** The plan is parked here while the batch overwrite dialog is up. */
interface PendingTransfer extends TransferPlan {
  /** Full destination paths that already exist (`files_check_conflicts`). */
  conflicts: string[];
}

const otherSide = (side: PaneSide): PaneSide => (side === "local" ? "remote" : "local");

/**
 * Is a webview drag position inside `el`'s box?
 *
 * Tauri's `onDragDropEvent` is a WINDOW-level event, so its position must be
 * hit-tested against the pane to honor the "drop over the pane" intent —
 * otherwise a file dropped on the sidebar, chat input, or an open modal would
 * still upload to the device (F1). Tauri reports the position in PHYSICAL
 * pixels; `getBoundingClientRect` is in CSS pixels, so divide by
 * `devicePixelRatio` before comparing. `null` element / position → outside.
 */
function pointInElement(
  el: HTMLElement | null,
  position: { x: number; y: number } | undefined,
): boolean {
  if (!el || !position) return false;
  const rect = el.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const x = position.x / dpr;
  const y = position.y / dpr;
  return x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
}

/**
 * v5.0.0 — the dual-pane file browser for one Files (SFTP) session:
 * LOCAL on the left, REMOTE on the right, in a resizable `PanelGroup`, with
 * the global transfer queue below.
 *
 * Rendered as the third arm of `TerminalArea`'s tab dispatch — BEFORE the
 * `PaneTree` fallthrough, because a `PaneTree` leaf hardcodes
 * `TerminalPane` and would mount a real xterm against a session that has
 * no PTY. Files tabs are excluded from tiling in v1 (plan decision 6), so
 * this component is always the whole tab.
 *
 * **Human input, not an agent surface.** Nothing here is reachable by the
 * AI agent: `FilesState` is passed to no agent-side seam and the
 * `transit_files` crate is banned outside `transit_app` at the dependency
 * -graph level (plan §2, threat model T43). An upload is Transit's first
 * structured human write path to a device — it is deliberately NOT policy
 * gated, because the gate governs the *agent*.
 *
 * Owns its own listener lifecycle (the `TerminalPane` pattern): the
 * synthesized `files:{id}:closed` signal — the backend's watch on the SFTP
 * stream, so a dead socket can't masquerade as a live browser — ends the
 * tab and raises the reconnect banner. The transfer-event subscription is
 * deliberately NOT here: it is app-global (`lib/filesTransfers.ts`), since
 * transfers outlive both the pane and the tab.
 *
 * Three ways to start a transfer, all landing in `beginTransfer`:
 * double-click a file, the toolbar / context-menu action for the selection,
 * or drag rows onto the other pane. OS file drags (Finder / Explorer) are
 * intercepted by Tauri before the DOM sees them, so they arrive through
 * `onDragDropEvent` and upload to the remote cwd.
 */
export function FilesPane({
  sessionId,
  deviceId,
  ended,
  active,
}: {
  sessionId: string;
  deviceId: string;
  ended: boolean;
  active: boolean;
}) {
  const queryClient = useQueryClient();
  const markSessionEnded = useUiStore((s) => s.markSessionEnded);

  // The pane root — an OS file drop is hit-tested against its box so a drop
  // outside the pane (sidebar / chat / a modal) is ignored (F1).
  const rootRef = useRef<HTMLDivElement | null>(null);

  const pane = useFilesStore((s) => s.panes[sessionId]);
  const ensurePane = useFilesStore((s) => s.ensurePane);
  const setCwd = useFilesStore((s) => s.setCwd);
  const toggleSort = useFilesStore((s) => s.toggleSort);
  const toggleHidden = useFilesStore((s) => s.toggleHidden);

  const [nameDialog, setNameDialog] = useState<FileNameDialogState>({ kind: "none" });
  const [deleteDialog, setDeleteDialog] = useState<DeleteDialogState>({ kind: "none" });
  const [pendingTransfer, setPendingTransfer] = useState<PendingTransfer | null>(null);
  /** Which pane a row drag started in (`null` = no drag) — the other pane
   *  uses it to decide whether it may accept the drop. */
  const [dragSide, setDragSide] = useState<PaneSide | null>(null);
  // The internal row-drag payload, stashed at drag-start. This — not
  // `dataTransfer` — is the source of truth for an in-app drag: on macOS wry
  // intercepts the whole drag session (OS copy cursor + `onDragDropEvent` +
  // it consumes the drop), so the webview's DOM `dragover`/`drop` never reach
  // the panes. The native drop handler completes the transfer from this ref.
  // It also lets that handler tell an internal drag from an external Finder
  // drop in the same tick (a React state read there would be stale).
  const internalDragRef = useRef<FilesDragPayload | null>(null);
  // One transfer per drag: whichever trigger fires first (the `dragend`
  // below, or a native/DOM drop) consumes the drag; the rest no-op.
  const dropHandledRef = useRef(false);
  // Pointer is inside the pane during an internal drag. State drives the
  // drop-ring on the opposite pane (from the native drag event — the DOM
  // `dragover` that would normally light it never fires under wry); the ref
  // twin is read synchronously by `dragend`, which is where the transfer
  // actually fires (see `handleDragChange`).
  const [dragInsideRoot, setDragInsideRoot] = useState(false);
  const dragInsideRef = useRef(false);
  const setInside = (v: boolean) => {
    dragInsideRef.current = v;
    setDragInsideRoot(v);
  };
  /** An OS file drag is hovering this tab. */
  const [osDropActive, setOsDropActive] = useState(false);
  // True only between a real OS-file `enter` (one carrying paths) and its
  // drop/leave. Gates the overlay so a trailing native echo of an in-app drag
  // — which can arrive after `dragend` and has no paths — can't raise it.
  const osDragActiveRef = useRef(false);

  // Idempotent: the launch mutation normally seeds this with the server's
  // real login directory before the pane ever mounts, and `ensurePane`
  // no-ops when it did.
  useEffect(() => {
    ensurePane(sessionId, REMOTE_CWD_FALLBACK);
  }, [sessionId, ensurePane]);

  const remoteCwd = pane?.remoteCwd ?? REMOTE_CWD_FALLBACK;
  const localCwd = pane?.localCwd ?? null;

  const remote = useRemoteDir(sessionId, remoteCwd, !ended);
  const local = useLocalDir(localCwd);
  const roots = useLocalRoots();

  const reconnect = useFilesReconnectSession();
  const remoteMkdir = useRemoteMkdir();
  const remoteRename = useRemoteRename();
  const remoteDelete = useRemoteDelete();
  const localMkdir = useLocalMkdir();
  const localRename = useLocalRename();
  const localDelete = useLocalDelete();

  // The backend's synthesized closed signal (plan §4): russh-sftp swallows
  // EOF internally, so without this the pane would show a live browser over
  // a dead socket. Cancelled-flag cleanup so a fast unmount can't leak the
  // listener (the TerminalPane pattern).
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    void listen(`files:${sessionId}:closed`, () => {
      markSessionEnded(sessionId);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [sessionId, markSessionEnded]);

  // The listing's `path` is authoritative: the backend canonicalizes what
  // the user typed (and resolves `..` / symlinks / trailing slashes), so
  // store that spelling. Everything then agrees on one path — the bar, the
  // child-path arithmetic, and the query key the mutations invalidate.
  // Converges in one extra fetch and cannot loop: the canonical path
  // canonicalizes to itself.
  const remotePath = remote.data?.path;
  useEffect(() => {
    if (remotePath && remotePath !== remoteCwd) setCwd(sessionId, "remote", remotePath);
  }, [remotePath, remoteCwd, sessionId, setCwd]);

  const localPath = local.data?.path;
  useEffect(() => {
    if (localPath && localPath !== localCwd) setCwd(sessionId, "local", localPath);
  }, [localPath, localCwd, sessionId, setCwd]);

  /** The directory a mutation acts in, per side: the canonical path if a
   *  listing has resolved, else the requested one. */
  const dirOf = (side: PaneSide): string =>
    side === "remote" ? (remote.data?.path ?? remoteCwd) : (local.data?.path ?? localCwd ?? "");

  const refresh = (side: PaneSide) => {
    if (side === "remote") {
      void queryClient.invalidateQueries({ queryKey: remoteDirKey(sessionId, remoteCwd) });
    } else {
      void queryClient.invalidateQueries({ queryKey: localDirKey(localCwd) });
    }
  };

  // -------------------------------------------------------------------
  // Transfers
  // -------------------------------------------------------------------

  /** Build a batch from absolute source paths on `sourceSide`, aimed at the
   *  other pane's current directory. `null` when either end is unknown. */
  const planFrom = (sourceSide: PaneSide, sourcePaths: string[]): TransferPlan | null => {
    if (sourcePaths.length === 0) return null;
    // EVERY transfer has the remote session at one end, so a dead session
    // rules out both directions — not just downloads.
    if (ended) return null;
    const destSide = otherSide(sourceSide);
    const destDir = dirOf(destSide);
    if (destDir.length === 0) return null;
    return {
      direction: sourceSide === "local" ? "upload" : "download",
      destSide,
      destKey: destSide === "remote" ? remoteCwd : localCwd,
      items: sourcePaths.map((source_path) => ({ source_path, dest_dir: destDir })),
    };
  };

  /**
   * Pre-flight, then either ask once or queue.
   *
   * The overwrite decision is per BATCH and taken up front (plan §7 /
   * decision 8): `files_check_conflicts` reports the TOP-LEVEL destinations
   * that already exist, and only those raise the dialog. With no top-level
   * collision nothing exists to overwrite, so the policy is inert for the
   * items themselves and governs only per-file collisions a recursive
   * directory walk might meet — `overwrite` is the right default there,
   * because silently skipping files inside a folder the user just dragged
   * would be a lie about what was copied.
   */
  const beginTransfer = async (plan: TransferPlan | null) => {
    if (!plan) return;
    // `pendingTransfer` is a single slot: a second batch that raised conflicts
    // while the overwrite dialog is already up would silently overwrite (and
    // discard) the parked plan. Refuse the second one with a nudge instead of
    // dropping the first (F1).
    if (pendingTransfer) {
      toastInfo("Finish the current transfer prompt first");
      return;
    }
    try {
      const conflicts = await filesCheckConflicts({
        session_id: sessionId,
        direction: plan.direction,
        items: plan.items,
      });
      if (conflicts.length > 0) {
        setPendingTransfer({ ...plan, conflicts });
        return;
      }
      await runEnqueue(plan, "overwrite");
    } catch (err) {
      toastError("Couldn't start the transfer", {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const runEnqueue = async (plan: TransferPlan, policy: OverwritePolicy) => {
    try {
      const descriptors = await filesEnqueue({
        session_id: sessionId,
        direction: plan.direction,
        policy,
        items: plan.items,
      });
      // The engine's events carry no destination, so the enqueue call is the
      // only place that can tell the queue mirror which listing a finished
      // transfer changed. Built per side so the discriminated `TransferTarget`
      // gets a concrete key for remote (never null) and the local pane's
      // nullable "backend default home" key for local.
      const target: TransferTarget =
        plan.destSide === "remote"
          ? { side: "remote", sessionId, destKey: plan.destKey ?? remoteCwd, deviceLabel: deviceId }
          : { side: "local", sessionId, destKey: plan.destKey, deviceLabel: deviceId };
      registerTransferTargets(
        descriptors.map((d) => d.id),
        target,
      );
    } catch (err) {
      toastError("Couldn't start the transfer", {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  };

  /** Toolbar / context menu / double-click: transfer selected ROWS. */
  const transferEntries = (sourceSide: PaneSide, entries: FileEntry[]) => {
    // Every transfer has the remote session at one end, so a dead session
    // rules out BOTH directions. The remote pane's toolbar is already
    // disabled, and the local Transfer button is disabled via
    // `transferDisabled`, but a LOCAL file double-click still lands here — so
    // surface a toast rather than a silent no-op (the OS-drop path already
    // does this; F4).
    if (ended) {
      toastError("Reconnect before transferring — this file transfer session is closed.");
      return;
    }
    const dir = dirOf(sourceSide);
    if (dir.length === 0) return;
    void beginTransfer(
      planFrom(
        sourceSide,
        entries.map((e) => joinChildPath(dir, e.name)),
      ),
    );
  };

  /** Complete an internal row drag onto `dropSide`, consuming the stashed
   *  payload. Idempotent (the first trigger to fire wins — `dragend`, the
   *  native drop, or the DOM drop). Same-side drops and — defensively —
   *  cross-session payloads are inert: a same-side drop's paths are already
   *  where they are, and each pane instance holds its own drag ref so a
   *  cross-session drop can't normally arise. */
  const performInternalDrop = (dropSide: PaneSide) => {
    if (dropHandledRef.current) return;
    const payload = internalDragRef.current;
    dropHandledRef.current = true;
    internalDragRef.current = null;
    setInside(false);
    if (!payload || payload.sessionId !== sessionId || payload.side === dropSide) return;
    void beginTransfer(planFrom(payload.side, payload.paths));
  };
  // Freshness ref for the native drag handler (its effect deps are `[active]`,
  // so a direct call would capture a stale closure) — same pattern as
  // `osUploadRef` below.
  const performInternalDropRef = useRef(performInternalDrop);
  useEffect(() => {
    performInternalDropRef.current = performInternalDrop;
  });

  /** Row-drag lifecycle from a pane. A non-null payload is a drag START
   *  (stash it); `null` is the drag END.
   *
   *  **The transfer fires on `dragend`, not on a drop event.** `dragend` is a
   *  synchronous WebKit event on the drag source and fires reliably; the DOM
   *  `drop` on the target never fires under wry (it intercepts the session),
   *  and the native drop event arrives asynchronously — *after* this
   *  `dragend` has already ended the drag. So if the pointer was over the
   *  pane at release (`dragInsideRef`, tracked from the native over/leave),
   *  transfer to the opposite side here. Two panes → the target is always the
   *  side opposite the source. Releasing outside the pane cancels. */
  const handleDragChange = (payload: FilesDragPayload | null) => {
    if (payload) {
      internalDragRef.current = payload;
      dropHandledRef.current = false;
      setDragSide(payload.side);
      return;
    }
    const dragged = internalDragRef.current;
    if (dragged && dragInsideRef.current) {
      performInternalDrop(dragged.side === "local" ? "remote" : "local");
    } else {
      internalDragRef.current = null;
    }
    setDragSide(null);
    setInside(false);
  };

  // OS file drop (Finder / Explorer → upload). Tauri's `dragDropEnabled`
  // intercepts native file drags, so HTML5 drop events never fire for them —
  // the webview event is the only way to see them. It is WINDOW-scoped, so a
  // drop is only accepted when its position falls inside THIS pane's box
  // (`pointInElement`): a drop on the sidebar / chat / a modal must not upload
  // to the device (F1). Accepted drops upload to the REMOTE cwd.
  //
  // The handler lives behind a ref so the subscription depends only on
  // `active` — re-subscribing on every cwd change would drop events
  // mid-drag (the TerminalPane latest-ref pattern).
  const osUploadRef = useRef<(paths: string[]) => void>(() => {});
  useEffect(() => {
    osUploadRef.current = (paths: string[]) => {
      if (ended) {
        toastError("Reconnect before uploading — this file transfer session is closed.");
        return;
      }
      void beginTransfer(planFrom("local", paths));
    };
  });

  useEffect(() => {
    // ONLY the visible Files tab reacts: every mounted pane would otherwise
    // receive the same webview event and enqueue the same files N times.
    if (!active) return;
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    // `getCurrentWebview()` throws synchronously where Tauri's internals are
    // absent, so the whole subscription is guarded: no OS-drop support must
    // degrade to "dragging between the panes still works", never to a pane
    // that fails to mount.
    try {
      void getCurrentWebview()
        .onDragDropEvent((event) => {
          const payload = event.payload;
          // An internal row drag (files dragged between the two panes) is a
          // WebKit DOM drag, but on macOS wry intercepts the whole session and
          // consumes the drop, so the DOM `dragover`/`drop` never reach the
          // panes (no ring, no transfer from the DOM path). Drive BOTH from
          // here using the payload stashed at drag-start; never show the OS
          // "Drop to upload" overlay for our own drag. There are exactly two
          // panes, so the target is always the side opposite the source.
          if (internalDragRef.current) {
            if (payload.type === "leave") {
              setInside(false);
              return;
            }
            const inside = pointInElement(rootRef.current, payload.position);
            if (payload.type === "drop") {
              // A secondary trigger: on most platforms `dragend` (which fires
              // first) has already completed the transfer, so this is deduped.
              // It's the sole trigger only if a platform withholds `dragend`.
              if (inside) {
                const target = internalDragRef.current.side === "local" ? "remote" : "local";
                performInternalDropRef.current(target);
              }
            } else {
              // enter / over — track the pointer for the `dragend` transfer and
              // light the drop-ring on the opposite pane.
              setInside(inside);
            }
            return;
          }
          // A REAL OS file drag is identified by an `enter` carrying file
          // paths. An internal row drag's native echoes (empty paths on
          // enter/drop, none on over) — which can arrive AFTER `dragend`
          // cleared the internal state — must never drive this overlay.
          if (payload.type === "leave") {
            // Tauri 2 has no separate "cancel" variant, and a leave carries
            // no position.
            osDragActiveRef.current = false;
            setOsDropActive(false);
            return;
          }
          if (payload.type === "enter") {
            if (payload.paths.length === 0) return; // internal echo, not OS files
            osDragActiveRef.current = true;
            // Only light up while the pointer is over THIS pane (F1).
            setOsDropActive(pointInElement(rootRef.current, payload.position));
            return;
          }
          if (payload.type === "over") {
            // Only sustain an already-active OS drag; a stray `over` (which
            // carries no paths) can't start the overlay.
            if (osDragActiveRef.current) {
              setOsDropActive(pointInElement(rootRef.current, payload.position));
            }
            return;
          }
          // drop
          osDragActiveRef.current = false;
          setOsDropActive(false);
          if (payload.paths.length === 0) return; // internal echo, not OS files
          if (pointInElement(rootRef.current, payload.position)) {
            osUploadRef.current(payload.paths);
          }
        })
        .then((fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        })
        .catch(() => {});
    } catch {
      // No webview available.
    }
    return () => {
      cancelled = true;
      osDragActiveRef.current = false;
      setOsDropActive(false);
      unlisten?.();
    };
  }, [active]);

  const submitName = async (name: string) => {
    if (nameDialog.kind === "none") return;
    const side = nameDialog.side;
    const dir = dirOf(side);
    if (dir.length === 0) return;
    const target = joinChildPath(dir, name);

    if (nameDialog.kind === "newFolder") {
      if (side === "remote") {
        await remoteMkdir.mutateAsync({ sessionId, dir: remoteCwd, path: target });
      } else {
        await localMkdir.mutateAsync({ dir: localCwd, path: target });
      }
      return;
    }

    const from = joinChildPath(dir, nameDialog.entry.name);
    if (from === target) return; // unchanged name — nothing to do
    if (side === "remote") {
      await remoteRename.mutateAsync({
        sessionId,
        from,
        to: target,
        fromDir: remoteCwd,
        toDir: remoteCwd,
      });
    } else {
      await localRename.mutateAsync({ from, to: target, fromDir: localCwd, toDir: localCwd });
    }
  };

  const confirmDelete = async () => {
    if (deleteDialog.kind === "none") return;
    const { side, entries } = deleteDialog;
    const dir = dirOf(side);
    if (dir.length === 0) return;
    // Sequential, so a mid-batch failure surfaces in the dialog with the
    // earlier deletes already applied — the same honesty as the bulk
    // connect loop, rather than a partial success reported as a failure.
    for (const entry of entries) {
      const path = joinChildPath(dir, entry.name);
      const recursive = entry.kind === "dir";
      if (side === "remote") {
        await remoteDelete.mutateAsync({ sessionId, path, dir: remoteCwd, recursive });
      } else {
        await localDelete.mutateAsync({ path, dir: localCwd, recursive });
      }
    }
  };

  const namePending =
    remoteMkdir.isPending ||
    remoteRename.isPending ||
    localMkdir.isPending ||
    localRename.isPending;

  return (
    <div
      ref={rootRef}
      className="flex h-full w-full flex-col"
      data-testid={`files-pane-${sessionId}`}
    >
      <header className="flex shrink-0 items-center gap-2 border-b border-border bg-muted/20 px-3 py-1.5">
        <FolderOpen className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span className="truncate font-mono text-sm">{deviceId}</span>
        <span className="shrink-0 text-xs text-muted-foreground">SFTP file transfer</span>
      </header>

      {ended && (
        <div
          className="flex shrink-0 items-center gap-2 border-b border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-400"
          role="alert"
          data-testid="files-ended-banner"
        >
          <Unplug className="h-3.5 w-3.5 shrink-0" />
          <span className="min-w-0 flex-1">
            The file transfer connection closed. Reconnecting keeps this tab and both folders.
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-6 shrink-0"
            disabled={reconnect.isPending}
            onClick={() => reconnect.mutate(sessionId)}
            data-testid="files-reconnect"
          >
            {reconnect.isPending ? "Reconnecting…" : "Reconnect"}
          </Button>
        </div>
      )}

      <div className="relative min-h-0 flex-1">
        <PanelGroup direction="horizontal" className="min-h-0 w-full">
          <Panel id={`${sessionId}-local`} order={0} minSize={20} className="min-h-0 min-w-0">
            <FileListPane
              side="local"
              sessionId={sessionId}
              title="Local"
              path={local.data?.path ?? localCwd ?? ""}
              listing={local.data}
              isLoading={local.isLoading}
              error={local.error}
              sort={pane?.localSort ?? DEFAULT_SORT}
              showHidden={pane?.showHiddenLocal ?? false}
              active={active}
              // Browsing local files needs no session, but a transfer does —
              // an ended session has nowhere for an upload to land (F4).
              transferDisabled={ended}
              roots={roots.data}
              onNavigate={(path) => setCwd(sessionId, "local", path)}
              onHome={() => setCwd(sessionId, "local", null)}
              onRefresh={() => refresh("local")}
              onToggleHidden={() => toggleHidden(sessionId, "local")}
              onSort={(key: SortKey) => toggleSort(sessionId, "local", key)}
              onNewFolder={() => setNameDialog({ kind: "newFolder", side: "local" })}
              onRename={(entry) => setNameDialog({ kind: "rename", side: "local", entry })}
              onDelete={(entries) => setDeleteDialog({ kind: "delete", side: "local", entries })}
              onTransfer={(entries) => transferEntries("local", entries)}
              transferVerb="Upload"
              canAcceptDrop={dragSide === "remote" && !ended}
              dropRingActive={dragInsideRoot}
              onDragChange={handleDragChange}
              onDropRows={() => performInternalDrop("local")}
            />
          </Panel>
          <PanelResizeHandle
            className="w-1 shrink-0 cursor-col-resize bg-border hover:bg-primary/30 data-[resize-handle-state=drag]:bg-primary/50"
            data-testid="files-resize-handle"
          />
          <Panel id={`${sessionId}-remote`} order={1} minSize={20} className="min-h-0 min-w-0">
            <FileListPane
              side="remote"
              sessionId={sessionId}
              title={deviceId}
              path={remote.data?.path ?? remoteCwd}
              listing={remote.data}
              isLoading={remote.isLoading && !ended}
              error={remote.error}
              sort={pane?.remoteSort ?? DEFAULT_SORT}
              showHidden={pane?.showHiddenRemote ?? false}
              active={active}
              disabled={ended}
              transferDisabled={ended}
              onNavigate={(path) => setCwd(sessionId, "remote", path)}
              onHome={() => setCwd(sessionId, "remote", pane?.remoteHome ?? REMOTE_CWD_FALLBACK)}
              onRefresh={() => refresh("remote")}
              onToggleHidden={() => toggleHidden(sessionId, "remote")}
              onSort={(key: SortKey) => toggleSort(sessionId, "remote", key)}
              onNewFolder={() => setNameDialog({ kind: "newFolder", side: "remote" })}
              onRename={(entry) => setNameDialog({ kind: "rename", side: "remote", entry })}
              onDelete={(entries) => setDeleteDialog({ kind: "delete", side: "remote", entries })}
              onTransfer={(entries) => transferEntries("remote", entries)}
              transferVerb="Download"
              canAcceptDrop={dragSide === "local"}
              dropRingActive={dragInsideRoot}
              onDragChange={handleDragChange}
              onDropRows={() => performInternalDrop("remote")}
            />
          </Panel>
        </PanelGroup>

        {osDropActive && (
          <div
            className="pointer-events-none absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 border-2 border-dashed border-primary bg-background/85"
            data-testid="files-os-drop-overlay"
          >
            <Upload className="h-8 w-8 text-primary" />
            <span className="text-sm font-medium">Drop to upload to {deviceId}</span>
            <span className="font-mono text-xs text-muted-foreground">{dirOf("remote")}</span>
          </div>
        )}
      </div>

      <TransferQueueStrip />

      <FileNameDialog
        state={nameDialog}
        pending={namePending}
        onClose={() => setNameDialog({ kind: "none" })}
        onSubmit={submitName}
      />

      {deleteDialog.kind === "delete" && (
        <DeleteConfirmDialog
          open
          onOpenChange={(o) => !o && setDeleteDialog({ kind: "none" })}
          title={deleteTitle(deleteDialog.entries)}
          description={deleteDescription(deleteDialog.entries, deleteDialog.side)}
          onConfirm={confirmDelete}
        />
      )}

      {pendingTransfer && (
        <OverwriteConfirmDialog
          open
          conflicts={pendingTransfer.conflicts}
          destinationLabel={pendingTransfer.destSide === "remote" ? deviceId : "this computer"}
          onCancel={() => setPendingTransfer(null)}
          onChoose={(policy) => {
            const plan = pendingTransfer;
            setPendingTransfer(null);
            void runEnqueue(plan, policy);
          }}
        />
      )}
    </div>
  );
}

function deleteTitle(entries: FileEntry[]): string {
  if (entries.length === 1) return `Delete "${entries[0].name}"?`;
  return `Delete ${entries.length} items?`;
}

/** Deletes are PERMANENT in v1 (no trash), and a directory delete is
 *  recursive — so the confirm names the entry and spells out the blast
 *  radius (plan decision 9 / veto #3). */
function deleteDescription(entries: FileEntry[], side: PaneSide): string {
  const where = side === "remote" ? "on the device" : "on this computer";
  const dirs = entries.filter((e) => e.kind === "dir");
  if (entries.length === 1) {
    const entry = entries[0];
    return entry.kind === "dir"
      ? `Permanently deletes the folder "${entry.name}" and all its contents ${where}. This cannot be undone.`
      : `Permanently deletes "${entry.name}" ${where}. This cannot be undone.`;
  }
  const folderNote =
    dirs.length > 0
      ? ` ${dirs.length} of them ${dirs.length === 1 ? "is a folder" : "are folders"} and will be deleted with all their contents.`
      : "";
  return `Permanently deletes ${entries.length} items ${where}.${folderNote} This cannot be undone.`;
}
