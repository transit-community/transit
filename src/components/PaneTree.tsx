import { useDndContext, useDroppable } from "@dnd-kit/core";
import { Fragment } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

import { TerminalPane } from "@/components/TerminalPane";
import { paneIds, type PaneNode } from "@/lib/paneTree";
import { cn } from "@/lib/utils";
import type { SessionTab } from "@/stores/uiStore";

/**
 * v4.4.0 tiling — render a tab's `PaneNode` layout as a nested, resizable
 * grid of `TerminalPane`s (`react-resizable-panels`). A `leaf` resolves to
 * one terminal; a `split` becomes a `PanelGroup` (`row` → horizontal,
 * `col` → vertical) whose children recurse.
 *
 * `tabActive` is passed straight through as each pane's `active`: while the
 * tab is visible, ALL its panes are "active" (visible → they must fit).
 * `activePaneId` (v6.4.0) is the separate, narrower concept — which ONE of
 * those panes has keyboard focus, and therefore which one the button bar and
 * View → Clear Terminal target. The two are deliberately distinct props: every
 * pane of a visible tab is `active`, exactly one is focused, and collapsing
 * them would stop unfocused panes re-fitting.
 *
 * Stable React keys + Panel ids come from each subtree's FIRST pane id, so a
 * split/close elsewhere in the tree never remounts an untouched pane's xterm
 * (which would drop its scrollback). This depends on `removeLeaf` NOT
 * collapsing single-child splits: keeping the split node stable means the
 * element type React renders at each position never flips between
 * `<PanelGroup>` and `<TerminalPane>` on a close, so a surviving pane keeps its
 * mount. (The one unavoidable remount is a tab's FIRST split — an unsplit tab
 * renders a bare `<TerminalPane>`, and wrapping it in the panel grid is a new
 * position; this pre-dates tiling and only ever touches that tab's primary.)
 *
 * Each leaf also hosts `PaneDropZones` (v4.4.0 drag-to-split): during a tab
 * drag, four edge droppables light up so a tab dropped on an edge tiles into
 * that pane (`movePaneInto`) instead of only reordering the strip.
 */
export function PaneTree({
  node,
  sessions,
  tabActive,
  activePaneId,
  paneTotal,
  onMovePaneOut,
}: {
  node: PaneNode;
  sessions: SessionTab[];
  tabActive: boolean;
  /** v6.4.0 — the focused pane of this tab (already resolved by the caller). */
  activePaneId: string | null;
  /** v6.4.0 — pane count for the WHOLE tab, not this subtree: the focus ring
   *  and "Own tab" button are about whether the tab is split at all, so the
   *  count has to come from the root and be threaded down unchanged. */
  paneTotal: number;
  onMovePaneOut: (sessionId: string) => void;
}) {
  if (node.type === "leaf") {
    const tab = sessions.find((t) => t.sessionId === node.sessionId);
    if (!tab) return null; // pane's session was removed
    const inSplit = paneTotal > 1;
    // Ring only in a split, and only on the visible tab: a lone pane has
    // nothing to disambiguate, and a background tab has no focus to show.
    const showFocusRing = inSplit && tabActive && tab.sessionId === activePaneId;
    return (
      <div
        className={cn(
          "relative h-full w-full",
          // `ring-inset` so the ring sits inside the pane's box and doesn't
          // overlap the resize handle or the neighbouring pane. Distinct from
          // the drop-zone highlight below, which is only up mid-drag.
          showFocusRing && "ring-2 ring-inset ring-primary/70",
        )}
        data-testid={showFocusRing ? "pane-focused" : undefined}
      >
        <TerminalPane
          sessionId={tab.sessionId}
          deviceId={tab.deviceId}
          ended={tab.ended}
          active={tabActive}
          inSplit={inSplit}
          onMoveOut={() => onMovePaneOut(tab.sessionId)}
          isLocal={tab.kind === "local"}
        />
        {/* Only the visible tab's panes measure (inactive tabs are
            display:none), so these drop zones are live only where they should
            be. */}
        {tabActive && <PaneDropZones paneId={tab.sessionId} />}
      </div>
    );
  }

  const direction = node.dir === "row" ? "horizontal" : "vertical";
  const handleClass =
    direction === "horizontal"
      ? "w-1 shrink-0 cursor-col-resize bg-border hover:bg-primary/30 data-[resize-handle-state=drag]:bg-primary/50"
      : "h-1 shrink-0 cursor-row-resize bg-border hover:bg-primary/30 data-[resize-handle-state=drag]:bg-primary/50";

  return (
    <PanelGroup direction={direction} className="h-full w-full">
      {node.children.map((child, i) => {
        // First pane id of this subtree: stable across inner splits, so the
        // wrapping Panel (and react-resizable-panels' size for it) survives a
        // change elsewhere in the group without a remount.
        const key = paneIds(child)[0] ?? `pane-${i}`;
        return (
          <Fragment key={key}>
            {i > 0 && (
              <PanelResizeHandle className={handleClass} data-testid="pane-resize-handle" />
            )}
            <Panel id={key} order={i} minSize={10} className="min-h-0 min-w-0">
              <PaneTree
                node={child}
                sessions={sessions}
                tabActive={tabActive}
                activePaneId={activePaneId}
                paneTotal={paneTotal}
                onMovePaneOut={onMovePaneOut}
              />
            </Panel>
          </Fragment>
        );
      })}
    </PanelGroup>
  );
}

/**
 * The four edge drop-zones overlaid on a leaf pane. Rendered only while a tab
 * drag is in flight (`useDndContext().active`). Each is a `@dnd-kit` droppable
 * keyed `split|<paneId>|<edge>`; `TerminalArea`'s `onDragEnd` parses the id and
 * calls `movePaneInto`. Center (56%×56%) is deliberately uncovered — a drop
 * there is a no-op, so you split by aiming at an edge. The overlay is
 * `pointer-events-none` (collision is pointer-coordinate based, not DOM
 * hit-testing), so it never interferes with xterm mouse handling.
 */
const EDGE_ZONES = [
  { edge: "left", className: "left-0 top-0 h-full w-[22%]" },
  { edge: "right", className: "right-0 top-0 h-full w-[22%]" },
  { edge: "top", className: "left-0 top-0 h-[22%] w-full" },
  { edge: "bottom", className: "bottom-0 left-0 h-[22%] w-full" },
] as const;

function PaneDropZones({ paneId }: { paneId: string }) {
  const { active } = useDndContext();
  if (!active) return null; // only while a tab is being dragged
  return (
    <div className="pointer-events-none absolute inset-0 z-20">
      {EDGE_ZONES.map((z) => (
        <PaneDropZone key={z.edge} paneId={paneId} edge={z.edge} className={z.className} />
      ))}
    </div>
  );
}

function PaneDropZone({
  paneId,
  edge,
  className,
}: {
  paneId: string;
  edge: string;
  className: string;
}) {
  const { setNodeRef, isOver } = useDroppable({ id: `split|${paneId}|${edge}` });
  return (
    <div
      ref={setNodeRef}
      data-testid={`pane-drop-${edge}`}
      className={cn(
        "absolute transition-colors",
        // Faint outline on every zone during a drag (discoverability), strong
        // fill on the one under the pointer (the split you'd get on release).
        isOver
          ? "bg-primary/30 ring-2 ring-inset ring-primary"
          : "bg-primary/5 ring-1 ring-inset ring-primary/20",
        className,
      )}
    />
  );
}
