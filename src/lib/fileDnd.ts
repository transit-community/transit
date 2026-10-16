import type { PaneSide } from "@/stores/filesStore";

/**
 * v5.0.0 — the drag payload for dragging rows between the two Files panes.
 *
 * **Plain HTML5 drag-and-drop, deliberately.** `FilesPane` renders inside
 * `TerminalArea`'s dnd-kit `DndContext` (tab reorder + drag-to-split), and
 * file rows are NOT dnd-kit draggables — so the two systems never interact,
 * and `TerminalPane`'s text-drop handling is untouched. Do not "unify" these
 * onto dnd-kit: that would put every file row into the tab-drag collision
 * graph.
 *
 * OS file drags (Finder / Explorer) never reach this code: Tauri's
 * `dragDropEnabled` intercepts them before the webview sees a DOM event, so
 * they arrive through `getCurrentWebview().onDragDropEvent` instead
 * (`FilesPane`'s upload overlay).
 */

/** Custom MIME type. Its mere presence in `dataTransfer.types` is what a
 *  dragover handler can check — the payload itself is unreadable until the
 *  drop, by design in every browser. */
export const FILES_DND_MIME = "application/x-transit-files";

export interface FilesDragPayload {
  /** The pane the rows were dragged FROM. A drop on the same side is a
   *  no-op (there is nothing to copy). */
  side: PaneSide;
  /** The Files session the drag started in — a drop is only honored inside
   *  the same session, so a payload can't be replayed against another
   *  device's pane. */
  sessionId: string;
  /** Absolute source paths (already joined against the source pane's
   *  canonical cwd). */
  paths: string[];
}

export function serializeFilesDrag(payload: FilesDragPayload): string {
  return JSON.stringify(payload);
}

/**
 * Parse a dropped payload defensively: anything that isn't our exact shape
 * yields `null` and the drop is ignored. `dataTransfer` content is attacker-
 * adjacent input (any page/app can claim a MIME type), and a drop handler
 * must never throw.
 */
export function parseFilesDragPayload(raw: string | null | undefined): FilesDragPayload | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const { side, sessionId, paths } = parsed as Record<string, unknown>;
  if (side !== "local" && side !== "remote") return null;
  if (typeof sessionId !== "string" || sessionId.length === 0) return null;
  if (!Array.isArray(paths)) return null;
  const clean = paths.filter((p): p is string => typeof p === "string" && p.length > 0);
  if (clean.length === 0) return null;
  return { side, sessionId, paths: clean };
}
