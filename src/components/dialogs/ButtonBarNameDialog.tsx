import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BAR_NAME_MAX_LEN, type ButtonBar, useUiStore } from "@/stores/uiStore";

/** Open state for the bar-name dialog, owned by the parent ButtonBar. */
export type ButtonBarNameState =
  { kind: "none" } | { kind: "new" } | { kind: "rename"; bar: ButtonBar };

/**
 * v2.7.0 — create/rename a named button bar. Mirrors MapButtonDialog's
 * parent-owned open-state pattern; the store trims/caps the name and a
 * freshly-created bar becomes active (`addBar`).
 */
export function ButtonBarNameDialog({
  state,
  onClose,
}: {
  state: ButtonBarNameState;
  onClose: () => void;
}) {
  const addBar = useUiStore((s) => s.addBar);
  const renameBar = useUiStore((s) => s.renameBar);

  const [name, setName] = useState("");

  // Reset-on-open (prop change, not a user event — mirrors MapButtonDialog).
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (state.kind === "rename") setName(state.bar.name);
    else if (state.kind === "new") setName("");
  }, [state]);

  const canSave = name.trim().length > 0;

  const save = () => {
    if (!canSave) return;
    if (state.kind === "rename") renameBar(state.bar.id, name);
    else addBar(name);
    onClose();
  };

  return (
    <Dialog open={state.kind !== "none"} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{state.kind === "rename" ? "Rename bar" : "New button bar"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="button-bar-name">Name</Label>
          <Input
            id="button-bar-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={BAR_NAME_MAX_LEN}
            placeholder="Routers"
            autoFocus
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                save();
              }
            }}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save} disabled={!canSave} data-testid="button-bar-name-save">
            OK
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
