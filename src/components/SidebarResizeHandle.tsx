import { useDragResize } from "@/lib/useDragResize";
import { useUiStore } from "@/stores/uiStore";

/** The pre-v6.5.2 fixed rail width. Kept as the default so an existing
 *  install's layout is byte-identical until the user drags. */
export const SIDEBAR_DEFAULT_WIDTH = 280;
/** Floor. Narrow enough to be a mostly-icons rail without becoming the
 *  collapsed (`w-10`) state, which is a separate affordance. */
export const SIDEBAR_MIN_WIDTH = 180;
/** Ceiling as a fraction of the viewport. Half the window is generous for
 *  a deeply nested inventory and still leaves a usable terminal — the
 *  point of widening the rail is to read device names, not to work in it. */
export const SIDEBAR_MAX_WIDTH_PCT = 0.5;

/**
 * v6.5.2 — the resolved sidebar width, in CSS pixels.
 *
 * ONE width shared by all five sidebar views (SSH / Terminal / Files /
 * APIs / PCaps). Each view's `<aside>` spreads this into an inline
 * `style.width` and renders a `<SidebarResizeHandle />`.
 */
export function useSidebarWidth(): number {
  const persisted = useUiStore((s) => s.preferences.sidebarWidth);
  return persisted ?? SIDEBAR_DEFAULT_WIDTH;
}

/**
 * Drag handle for the left sidebar's right edge.
 *
 * Absolutely positioned so it takes no layout space, which is why the
 * host `<aside>` must be `relative`. The 8px hit area straddles the
 * sidebar's 1px border — comfortable to grab without visually widening
 * the border, since the strip is transparent until hovered.
 *
 * Deliberately duplicated per view rather than wrapped in a shared
 * `<SidebarShell>`: the five asides differ in their inner structure and
 * their collapsed variants, and a wrapper that took all of that as props
 * would be harder to read than five two-line insertions.
 */
export function SidebarResizeHandle() {
  const width = useSidebarWidth();
  const setSidebarWidth = useUiStore((s) => s.setSidebarWidth);
  const { onMouseDown, onDoubleClick, onKeyDown } = useDragResize({
    edge: "right",
    min: SIDEBAR_MIN_WIDTH,
    maxPct: SIDEBAR_MAX_WIDTH_PCT,
    onWidth: setSidebarWidth,
    defaultWidth: SIDEBAR_DEFAULT_WIDTH,
  });

  return (
    <div
      role="separator"
      aria-label="Resize sidebar"
      aria-orientation="vertical"
      aria-valuenow={width}
      aria-valuemin={SIDEBAR_MIN_WIDTH}
      tabIndex={0}
      data-testid="sidebar-resize-handle"
      title="Drag to resize · double-click to reset"
      onMouseDown={onMouseDown}
      onDoubleClick={onDoubleClick}
      onKeyDown={(e) => onKeyDown(e, width)}
      className="absolute -right-1 top-0 z-10 h-full w-2 cursor-col-resize hover:bg-primary/20 focus-visible:bg-primary/30 active:bg-primary/30 focus-visible:outline-none"
    />
  );
}
