import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { OverwritePolicy } from "@/lib/api";
import { baseName } from "@/lib/fileBrowser";

/** How many conflicting names to spell out before summarizing the rest. */
const MAX_LISTED = 8;

/**
 * v5.0.0 — the batch overwrite decision.
 *
 * Conflicts are resolved **pre-flight for the whole batch**, from this one
 * dialog (plan §7 / decision 8) — never per file mid-transfer, which is the
 * modal-fatigue trap that makes people click through prompts. The backend's
 * `files_check_conflicts` pre-flight decides whether it opens at all: no
 * top-level collision, no dialog.
 *
 * Three outcomes, no dismiss-to-guess: **Overwrite all** (`overwrite`),
 * **Skip existing** (`skip` — the skipped names come back as queue warnings
 * so the user learns what didn't move), **Cancel** (nothing is queued).
 */
export function OverwriteConfirmDialog({
  open,
  conflicts,
  destinationLabel,
  onCancel,
  onChoose,
}: {
  open: boolean;
  /** Full destination paths from `files_check_conflicts`. */
  conflicts: string[];
  /** Where the batch is headed, for the prose ("the device" / "this
   *  computer"). */
  destinationLabel: string;
  onCancel: () => void;
  onChoose: (policy: OverwritePolicy) => void;
}) {
  const listed = conflicts.slice(0, MAX_LISTED);
  const extra = conflicts.length - listed.length;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="sm:max-w-md" data-testid="files-overwrite-dialog">
        <DialogHeader>
          <DialogTitle>
            {conflicts.length === 1
              ? "1 item already exists"
              : `${conflicts.length} items already exist`}
          </DialogTitle>
          <DialogDescription>
            {conflicts.length === 1 ? "This name is" : "These names are"} already in use on{" "}
            {destinationLabel}. Choose once for the whole transfer.
          </DialogDescription>
        </DialogHeader>

        <ul className="max-h-40 overflow-y-auto rounded border border-border bg-muted/30 px-2 py-1.5 font-mono text-xs">
          {listed.map((path) => (
            // Remote-supplied names render as text nodes, never markup (T43).
            <li key={path} className="truncate" title={path}>
              {baseName(path)}
            </li>
          ))}
          {extra > 0 && (
            <li className="pt-0.5 font-sans text-muted-foreground">and {extra} more</li>
          )}
        </ul>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={onCancel}
            data-testid="files-overwrite-cancel"
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => onChoose("skip")}
            data-testid="files-overwrite-skip"
          >
            Skip existing
          </Button>
          <Button
            type="button"
            onClick={() => onChoose("overwrite")}
            data-testid="files-overwrite-all"
          >
            Overwrite all
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
