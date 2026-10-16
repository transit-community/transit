import { PauseCircle, Play, Square } from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatTokens } from "@/lib/utils";

/**
 * Inline "paused at a checkpoint" card, rendered in the chat thread
 * when a long autonomous run pauses for a one-click Continue.
 *
 * Deliberately soft styling (NOT the destructive-red error banner) —
 * a checkpoint is normal, not a failure. One click resumes; "Stop"
 * just dismisses the card (the loop already ended, so there is
 * nothing to cancel). The card labels itself with rounds + tokens and
 * NEVER shows a dollar amount.
 */
export function CheckpointCard({
  rounds,
  tokens,
  onContinue,
  onDismiss,
}: {
  rounds: number;
  tokens: number;
  onContinue: () => void;
  onDismiss: () => void;
}) {
  const commands = `${rounds} command${rounds === 1 ? "" : "s"}`;
  return (
    <div
      className="space-y-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2"
      data-testid="checkpoint-card"
    >
      <div className="flex items-center gap-2 text-xs font-medium">
        <PauseCircle className="h-4 w-4 text-primary" />
        Paused after {commands} ({formatTokens(tokens)} tokens).
      </div>
      <p className="text-[11px] text-muted-foreground">
        The investigation is still going. Continue to let it keep working, or stop here.
      </p>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          className="h-7 gap-1 px-2"
          onClick={onContinue}
          data-testid="checkpoint-continue"
        >
          <Play className="h-3 w-3" />
          Continue
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 gap-1 px-2"
          onClick={onDismiss}
          data-testid="checkpoint-stop"
        >
          <Square className="h-3 w-3" />
          Stop
        </Button>
      </div>
    </div>
  );
}
