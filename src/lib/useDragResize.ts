import { useCallback, useRef } from "react";

/** Which edge of the panel the handle sits on. Determines how a pointer
 *  position becomes a width: a panel anchored on the RIGHT of the shell
 *  (the chat panel) is dragged by its LEFT edge, so its width grows as
 *  the cursor moves toward x=0; a panel anchored on the LEFT (the
 *  sidebars) is dragged by its RIGHT edge and its width IS the cursor's
 *  x position. */
/** Applied to `document.body` while a drag is in flight — see the hook's
 *  doc comment. Written as literals in this file so Tailwind's scanner
 *  emits both utilities. */
const DRAG_BODY_CLASSES = ["cursor-col-resize", "select-none"] as const;

type ResizeEdge = "left" | "right";

interface DragResizeOptions {
  /** Handle edge — see {@link ResizeEdge}. */
  edge: ResizeEdge;
  /** Floor, in CSS pixels. */
  min: number;
  /** Ceiling as a fraction of the viewport width (0–1). Relative rather
   *  than absolute so a panel can never eat the whole window on a small
   *  display, and so the clamp follows a window resize. */
  maxPct: number;
  /** Receives every clamped width during the drag. Callers persist it
   *  (the store writes through to localStorage on each set, so a drag
   *  survives an app restart without needing a mouseup commit). */
  onWidth: (px: number) => void;
  /** Width to restore on a double-click of the handle. */
  defaultWidth: number;
}

/**
 * v6.5.2 — shared drag-to-resize for the shell's side panels.
 *
 * Extracted from ChatPanel when the left sidebars became resizable
 * (deeply nested inventory truncated device names at the old fixed
 * 280px). Both consumers get identical drag feel, and there is one
 * place to fix a drag bug.
 *
 * Listeners live on `window`, not the handle: the hit area is a couple
 * of pixels wide and a fast drag outsprints it every time — binding to
 * the element loses the pointer mid-gesture.
 *
 * For the duration of the drag, `document.body` carries two utility
 * classes: `cursor-col-resize` so the resize cursor holds while the
 * pointer is over a pane that sets its own cursor (the terminal does),
 * and `select-none` so dragging across the app doesn't select text. One
 * classList write rather than two inline `style` assignments — same
 * effect, one style recalculation.
 */
export function useDragResize({ edge, min, maxPct, onWidth, defaultWidth }: DragResizeOptions) {
  const draggingRef = useRef(false);

  const clamp = useCallback(
    (proposed: number) => {
      const max = Math.floor(window.innerWidth * maxPct);
      // min wins a min > max collision (a very narrow window): a panel
      // that has to overflow should overflow at its usable width rather
      // than collapse to something unreadable.
      return Math.max(min, Math.min(max, proposed));
    },
    [min, maxPct],
  );

  const onMouseDown = useCallback(
    (e: React.MouseEvent<HTMLElement>) => {
      e.preventDefault();
      draggingRef.current = true;
      document.body.classList.add(...DRAG_BODY_CLASSES);

      const onMove = (move: MouseEvent) => {
        if (!draggingRef.current) return;
        const proposed = edge === "left" ? window.innerWidth - move.clientX : move.clientX;
        onWidth(clamp(proposed));
      };
      const onUp = () => {
        draggingRef.current = false;
        document.body.classList.remove(...DRAG_BODY_CLASSES);
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
      };
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    },
    [clamp, edge, onWidth],
  );

  /** Double-click resets to the default width — the standard escape
   *  hatch from a drag that went somewhere unhelpful. */
  const onDoubleClick = useCallback(() => {
    onWidth(clamp(defaultWidth));
  }, [clamp, defaultWidth, onWidth]);

  /** Keyboard resize, so the handle is not pointer-only. Arrow keys step
   *  by 16px (Shift → 64px); Home restores the default. The handle is
   *  focusable via `tabIndex={0}` on the consumer's separator. */
  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLElement>, current: number) => {
      const step = e.shiftKey ? 64 : 16;
      // "Wider" is the same key in both orientations — the separator's
      // own outward direction, not a screen direction.
      const grow = edge === "left" ? "ArrowLeft" : "ArrowRight";
      const shrink = edge === "left" ? "ArrowRight" : "ArrowLeft";
      if (e.key === grow) {
        e.preventDefault();
        onWidth(clamp(current + step));
      } else if (e.key === shrink) {
        e.preventDefault();
        onWidth(clamp(current - step));
      } else if (e.key === "Home") {
        e.preventDefault();
        onWidth(clamp(defaultWidth));
      }
    },
    [clamp, defaultWidth, edge, onWidth],
  );

  return { onMouseDown, onDoubleClick, onKeyDown };
}
