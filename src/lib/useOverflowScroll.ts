import { useCallback, useEffect, useRef, useState } from "react";

/**
 * v2.3.4 — shared horizontal-overflow scrolling for strip UIs (the
 * session tab strip and the button bar). Tracks whether the referenced
 * element can scroll left/right, re-measuring on element resize, child
 * mutations (strip items mounting/unmounting/renaming), and scroll.
 *
 * The consumer renders chevron buttons only while `overflowing` and
 * attaches `update` as the element's onScroll handler — the hook can't
 * own that binding because React's synthetic onScroll on the element
 * also needs to belong to the consumer's JSX.
 */
export function useOverflowScroll<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [canLeft, setCanLeft] = useState(false);
  const [canRight, setCanRight] = useState(false);

  const update = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    // ±1px tolerance: fractional layout widths make exact comparisons
    // flicker at the ends of the scroll range.
    setCanLeft(el.scrollLeft > 1);
    setCanRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 1);
  }, []);

  useEffect(() => {
    update();
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(update);
    ro.observe(el);
    const mo = new MutationObserver(update);
    mo.observe(el, { childList: true, subtree: true });
    return () => {
      ro.disconnect();
      mo.disconnect();
    };
  }, [update]);

  /** Page ~60% of the visible width (min 120px) in `dir`. */
  const scrollByStep = useCallback(
    (dir: -1 | 1) => {
      const el = ref.current;
      if (!el) return;
      const step = dir * Math.max(120, el.clientWidth * 0.6);
      if (typeof el.scrollBy === "function") {
        el.scrollBy({ left: step, behavior: "smooth" });
      } else {
        // jsdom (tests) has no scrollBy.
        el.scrollLeft += step;
      }
      update();
    },
    [update],
  );

  return { ref, canLeft, canRight, overflowing: canLeft || canRight, update, scrollByStep };
}
