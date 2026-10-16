import { ChevronLeft, ChevronRight } from "lucide-react";

/**
 * v2.3.4 — chevron button for horizontally scrollable strips (session
 * tab strip, button bar). Rendered only while the strip overflows;
 * disabled at the end of its scroll direction. MTPuTTY-style, per a
 * user running dozens of concurrent switch sessions.
 */
export function ScrollChevron({
  dir,
  enabled,
  onClick,
  label,
}: {
  dir: "left" | "right";
  enabled: boolean;
  onClick: () => void;
  label: string;
}) {
  const Icon = dir === "left" ? ChevronLeft : ChevronRight;
  return (
    <button
      type="button"
      aria-label={label}
      disabled={!enabled}
      onClick={onClick}
      className="flex h-7 w-5 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-30"
    >
      <Icon className="h-4 w-4" />
    </button>
  );
}
