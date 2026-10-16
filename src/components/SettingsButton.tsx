import { Settings } from "lucide-react";

import { useUiStore } from "@/stores/uiStore";

/** Standalone Settings gear in every sidebar's footer, so Settings is
 *  reachable in one click from any rail. */
export function SettingsButton() {
  const openSettingsDialog = useUiStore((s) => s.openSettingsDialog);
  return (
    <button
      type="button"
      onClick={() => openSettingsDialog()}
      aria-label="Settings"
      title="Settings"
      className="flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-md border bg-background text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
    >
      <Settings className="h-4 w-4" />
    </button>
  );
}

/** The footer's left-hand label. There is no account in this edition —
 *  the chat runs on the user's own provider key or a local model — so
 *  the slot the account chip used to fill names the edition instead. */
export function EditionChip() {
  return (
    <div
      data-testid="edition-chip"
      className="flex w-full items-center rounded-md border bg-background px-2 py-1.5 text-xs text-muted-foreground"
    >
      <span className="truncate">Community Edition</span>
    </div>
  );
}
