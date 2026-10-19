import { useEffect, useState } from "react";

import { DeviceColorPicker } from "@/components/dialogs/DeviceColorPicker";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { type ButtonBarButton, useUiStore } from "@/stores/uiStore";

/** Open state for the Map Button dialog, owned by the parent ButtonBar. */
export type MapButtonState =
  { kind: "none" } | { kind: "new" } | { kind: "edit"; button: ButtonBarButton };

/**
 * "Map Button" dialog. v1 ships the single **Send String**
 * function (the dropdown is present to leave room for future functions). The String accepts the escape codes the executor
 * understands (`\r \n \p \v \e \### \\`).
 */
export function MapButtonDialog({
  state,
  onClose,
}: {
  state: MapButtonState;
  onClose: () => void;
}) {
  const addButton = useUiStore((s) => s.addButton);
  const updateButton = useUiStore((s) => s.updateButton);

  const [label, setLabel] = useState("");
  const [value, setValue] = useState("");
  // "" = no shade; otherwise a palette token (deviceColors.ts).
  const [color, setColor] = useState("");
  // v6.1.0 — where the button's text goes. Defaults to the terminal so
  // every existing button keeps behaving exactly as before.
  const [target, setTarget] = useState<"session" | "agent">("session");

  // Reset-on-open: sync the draft to the edited button (or blank for a new
  // one) each time the dialog opens. A prop change, not a user event, so the
  // react-doctor event-handler rule doesn't apply (mirrors RenameGroupDialog).
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (state.kind === "edit") {
      setLabel(state.button.label);
      setValue(state.button.value);
      setColor(state.button.color ?? "");
      setTarget(state.button.target === "agent" ? "agent" : "session");
    } else if (state.kind === "new") {
      setLabel("");
      setValue("");
      setColor("");
      setTarget("session");
    }
  }, [state]);

  const editing = state.kind === "edit";
  const canSave = label.trim().length > 0 && value.length > 0;

  const save = () => {
    if (!canSave) return;
    if (state.kind === "edit") {
      updateButton(state.button.id, { label: label.trim(), value, color, target });
    } else {
      addButton({ label: label.trim(), value, color, target });
    }
    onClose();
  };

  return (
    <Dialog open={state.kind !== "none"} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit button" : "Map button"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label>Function</Label>
            <Select defaultValue="send_string">
              <SelectTrigger data-testid="map-button-function">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="send_string">Send String</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="map-button-label">Label</Label>
            <Input
              id="map-button-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="show ver"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  save();
                }
              }}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="map-button-string">String</Label>
            <Input
              id="map-button-string"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="show version\r"
              spellCheck={false}
              autoCapitalize="none"
              autoCorrect="off"
            />
            <p className="text-xs leading-relaxed text-muted-foreground">
              <span className="font-mono">\r</span> Enter · <span className="font-mono">\n</span>{" "}
              newline · <span className="font-mono">\p</span> 1s delay ·{" "}
              <span className="font-mono">\v</span> paste clipboard ·{" "}
              <span className="font-mono">\e</span>/<span className="font-mono">\###</span>{" "}
              ESC/octal · <span className="font-mono">\\</span> backslash
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="button-target">Send to</Label>
            <Select
              value={target}
              onValueChange={(v) => setTarget(v === "agent" ? "agent" : "session")}
            >
              <SelectTrigger id="button-target" data-testid="button-target-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="session">Terminal — send to the device</SelectItem>
                <SelectItem value="agent">AI prompt — fill the chat box</SelectItem>
              </SelectContent>
            </Select>
            {target === "agent" && (
              <p className="text-xs leading-relaxed text-muted-foreground">
                The text is placed in the AI composer for you to review and send — the escape codes
                above don&apos;t apply. Anything the assistant then proposes still needs the usual
                approval.
              </p>
            )}
          </div>
          <div className="grid gap-1.5">
            <Label>Color</Label>
            <DeviceColorPicker value={color} onChange={setColor} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save} disabled={!canSave} data-testid="map-button-save">
            OK
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
