import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { FileEntry } from "@/lib/api";
import { validateEntryName } from "@/lib/fileBrowser";
import type { PaneSide } from "@/stores/filesStore";

/**
 * Open state, owned by the parent `FilesPane` (the `ButtonBarNameDialog` /
 * `MapButtonDialog` pattern). `side` tells the parent which pane — and so
 * which IPC namespace, local or remote — the submitted name belongs to.
 * The DIRECTORY is deliberately absent: the parent resolves it at submit
 * time from the live pane state, so a listing that moved while the dialog
 * was open can't strand the operation in a stale directory.
 */
export type FileNameDialogState =
  | { kind: "none" }
  | { kind: "newFolder"; side: PaneSide }
  | { kind: "rename"; side: PaneSide; entry: FileEntry };

/**
 * v5.0.0 — the one-field name prompt behind both "New folder" and
 * "Rename". One component because the two are the same interaction with
 * the same validation; only the title, prefill, and verb differ.
 */
export function FileNameDialog({
  state,
  pending,
  onClose,
  onSubmit,
}: {
  state: FileNameDialogState;
  pending: boolean;
  onClose: () => void;
  /** Rejects with the backend's message on failure; the dialog stays open
   *  and shows it, so a permission error is visible where it happened. */
  onSubmit: (name: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Reset-on-open (a prop change, not a user event — same as
  // ButtonBarNameDialog).
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (state.kind === "none") return;
    setName(state.kind === "rename" ? state.entry.name : "");
    setError(null);
  }, [state]);

  const isRename = state.kind === "rename";

  const save = async () => {
    const invalid = validateEntryName(name);
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    try {
      await onSubmit(name.trim());
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Dialog
      open={state.kind !== "none"}
      onOpenChange={(o) => {
        if (!o && !pending) onClose();
      }}
    >
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{isRename ? "Rename" : "New folder"}</DialogTitle>
          <DialogDescription>
            {isRename
              ? "Renaming happens in place, in the same directory."
              : "Creates the folder in the directory this pane is showing."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="file-name-input">Name</Label>
          <Input
            id="file-name-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            data-testid="file-name-input"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                void save();
              }
            }}
          />
        </div>
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void save()}
            disabled={pending}
            data-testid="file-name-save"
          >
            {isRename ? "Rename" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
