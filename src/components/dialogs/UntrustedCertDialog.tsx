import { AlertTriangle } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/** Colon-separate a 64-char hex fingerprint into byte pairs, for readability. */
function prettyFingerprint(hex: string): string {
  return hex.replace(/(.{2})(?=.)/g, "$1:").toUpperCase();
}

/**
 * Untrusted-certificate TOFU confirm for a self-signed API controller
 * (v4.3.0, threat-model T40). Prop-driven and owned by `ApiSessionPane`:
 * when a send fails at the TLS handshake, the pane fetches the rejected
 * cert's fingerprint (`api_pending_cert`) and shows it here. Trusting pins
 * this exact leaf for this controller (`api_trust_cert`), mirroring the SSH
 * host-key flow — the user must VERIFY the fingerprint out-of-band, and no
 * dismissal silently trusts anything.
 */
export function UntrustedCertDialog({
  fingerprint,
  host,
  busy,
  onTrust,
  onCancel,
}: {
  /** The rejected cert's SHA-256 hex, or null when the dialog is closed. */
  fingerprint: string | null;
  /** The controller host, shown for context. */
  host?: string;
  /** True while the trust + retry round-trip is in flight. */
  busy?: boolean;
  onTrust: () => void;
  onCancel: () => void;
}) {
  return (
    <Dialog
      open={fingerprint !== null}
      onOpenChange={(open) => {
        if (!open) onCancel();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Untrusted certificate
          </DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-3 text-sm text-foreground">
              <p>
                {host ? <span className="font-medium">{host}</span> : "This controller"} presented a
                certificate your system doesn&apos;t trust — typically a self-signed controller
                cert.
              </p>
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2">
                <div className="text-xs font-medium text-muted-foreground">SHA-256 fingerprint</div>
                <div className="mt-1 font-mono text-xs break-all">
                  {fingerprint ? prettyFingerprint(fingerprint) : ""}
                </div>
              </div>
              <p>
                <strong>Verify this fingerprint out-of-band</strong> (from the controller itself)
                before trusting it. Trusting pins this exact certificate for this controller; if it
                ever changes, you&apos;ll be asked again.
              </p>
            </div>
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={onTrust} disabled={busy}>
            {busy ? "Trusting…" : "Trust & connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
