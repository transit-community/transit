import { useEffect, useState } from "react";

import { save } from "@tauri-apps/plugin-dialog";
import { AlertTriangle, Lock } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { exportSession, type ExportEncryption } from "@/lib/api";
import { toastError, toastSuccess } from "@/lib/toast";

export interface ExportSessionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sessionId: string;
  /** Human label for the tab — used to seed the default filename. */
  label: string;
}

/**
 * Phase 8b — session export modal. Two-step flow:
 *
 *   1. User picks encryption (None | Age passphrase). If passphrase,
 *      types the passphrase here.
 *   2. Click Export → native Save dialog opens for destination path.
 *   3. Backend writes the redacted (and optionally age-encrypted)
 *      bytes atomically.
 *
 * The dialog opens, runs the native save dialog ONCE per user click
 * on Export; if the user cancels the native dialog we stay in the
 * modal (so they can amend encryption choice / passphrase without
 * re-opening from scratch).
 */
export function ExportSessionDialog({
  open,
  onOpenChange,
  sessionId,
  label,
}: ExportSessionDialogProps) {
  const [encrypt, setEncrypt] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setEncrypt(false);
      setPassphrase("");
      setConfirm("");
      setBusy(false);
      setError(null);
    }
  }, [open]);

  const passphraseMismatch =
    encrypt && passphrase.length > 0 && confirm.length > 0 && passphrase !== confirm;
  const canSubmit = !busy && (!encrypt || (passphrase.length >= 8 && passphrase === confirm));

  async function onExport(): Promise<void> {
    setError(null);
    setBusy(true);
    try {
      const ext = encrypt ? "age" : "txt";
      const safeLabel = label.replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 40) || "session";
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const defaultPath = `transit-${safeLabel}-${stamp}.${ext}`;

      const destination = await save({
        title: encrypt ? "Save encrypted scrollback" : "Save scrollback",
        defaultPath,
        filters: encrypt
          ? [{ name: "Age-encrypted file", extensions: ["age"] }]
          : [{ name: "Text file", extensions: ["txt"] }],
      });
      if (!destination) {
        setBusy(false);
        return; // user cancelled the native dialog — stay in modal
      }

      const encryption: ExportEncryption = encrypt
        ? { kind: "age_passphrase", passphrase }
        : { kind: "none" };
      const result = await exportSession({
        session_id: sessionId,
        destination,
        encryption,
      });
      toastSuccess("Scrollback exported", {
        description: `${result.bytes_written.toLocaleString()} bytes written to ${result.path}`,
      });
      onOpenChange(false);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toastError("Export failed", { description: msg });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-emerald-500" />
            Export scrollback
          </DialogTitle>
          <DialogDescription>
            Saves this session's scrollback to disk. The redaction filter runs again on the bytes
            before writing — PEM blocks, passwords, and cloud credentials are stripped.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Session:</span>{" "}
            <span className="font-mono font-medium">{label}</span>
          </div>

          <div className="flex items-start gap-2">
            <Checkbox
              id="export-encrypt"
              checked={encrypt}
              onCheckedChange={(c) => setEncrypt(c === true)}
              disabled={busy}
            />
            <div className="grid gap-0.5">
              <Label htmlFor="export-encrypt" className="cursor-pointer">
                Encrypt with a passphrase (age)
              </Label>
              <p className="text-xs text-muted-foreground">
                Decrypt later with <code className="font-mono">age -d file.age</code> from the CLI.
              </p>
            </div>
          </div>

          {encrypt && (
            <div className="grid gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2">
              <div className="flex items-start gap-2 text-xs text-amber-200">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  Transit cannot recover this file if you lose the passphrase. Store it somewhere
                  safe.
                </span>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="export-passphrase" className="text-xs">
                  Passphrase (min 8 chars)
                </Label>
                <Input
                  id="export-passphrase"
                  type="password"
                  autoComplete="new-password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  disabled={busy}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="export-passphrase-confirm" className="text-xs">
                  Confirm passphrase
                </Label>
                <Input
                  id="export-passphrase-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  disabled={busy}
                />
                {passphraseMismatch && (
                  <p className="text-xs text-destructive" role="alert">
                    Passphrases don't match.
                  </p>
                )}
              </div>
            </div>
          )}

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button type="button" onClick={() => void onExport()} disabled={!canSubmit}>
            {busy ? "Exporting..." : "Export"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
