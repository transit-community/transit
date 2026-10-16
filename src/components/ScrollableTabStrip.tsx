import { useEffect, type ReactNode } from "react";

import { ScrollChevron } from "@/components/ScrollChevron";
import { TabsList } from "@/components/ui/tabs";
import { useOverflowScroll } from "@/lib/useOverflowScroll";

/**
 * v2.3.4 — horizontally scrollable tab strip (MTPuTTY-style). When the
 * strip overflows its container the native scrollbar is hidden (it steals
 * vertical space and looks heavy over a tab row), and chevron buttons
 * appear at the ends. Trackpad/shift-wheel horizontal scrolling still
 * works via `overflow-x-auto`, and activating a tab scrolls it into view.
 *
 * Renders a Radix `<TabsList>`, so it MUST live inside a `<Tabs>` context
 * (the terminal session tabs and the v2.5.0 AI chat tabs both provide
 * one). Extracted from `TerminalArea` so both surfaces share it.
 */
export function ScrollableTabStrip({
  activeTabId,
  children,
}: {
  activeTabId: string | null;
  children: ReactNode;
}) {
  const { ref, canLeft, canRight, overflowing, update, scrollByStep } =
    useOverflowScroll<HTMLDivElement>();

  // Keep the active tab visible when it changes (new tab opened, tab
  // clicked while partially clipped, keyboard tab-switch).
  //
  // We scroll ONLY the strip element — NOT `element.scrollIntoView()`,
  // which scrolls EVERY scrollable ancestor to reveal the target. The
  // app-shell containers are `overflow-hidden`, but a hidden box is still
  // *programmatically* scrollable, so a stray pixel of horizontal overflow
  // + scrollIntoView shifted the WHOLE app left (the v2.3.6 regression).
  // Adjusting the strip's own scrollLeft confines all scrolling to the strip.
  useEffect(() => {
    if (!activeTabId) return;
    const strip = ref.current;
    const active = strip?.querySelector<HTMLElement>('[data-state="active"]');
    if (!strip || !active) return;
    const stripBox = strip.getBoundingClientRect();
    const activeBox = active.getBoundingClientRect();
    if (activeBox.left < stripBox.left) {
      strip.scrollLeft -= stripBox.left - activeBox.left;
    } else if (activeBox.right > stripBox.right) {
      strip.scrollLeft += activeBox.right - stripBox.right;
    }
  }, [activeTabId, ref]);

  return (
    <div className="mx-2 mt-2 flex max-w-full items-center gap-0.5 self-start">
      {overflowing && (
        <ScrollChevron
          dir="left"
          enabled={canLeft}
          onClick={() => scrollByStep(-1)}
          label="Scroll tabs left"
        />
      )}
      <TabsList
        ref={ref}
        onScroll={update}
        className="max-w-full min-w-0 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        {children}
      </TabsList>
      {overflowing && (
        <ScrollChevron
          dir="right"
          enabled={canRight}
          onClick={() => scrollByStep(1)}
          label="Scroll tabs right"
        />
      )}
    </div>
  );
}
