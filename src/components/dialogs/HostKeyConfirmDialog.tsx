import { useEffect, useState } from "react";

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { ShieldAlert } from "lucide-react";

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
import { verifyHostKey, type HostKeyConfirmPayload } from "@/lib/api";

/**
 * Self-managing host-key prompt. Mounted once at the App root;
 * subscribes to `host-key:confirm` events and renders a modal when
 * one fires — the plain first-contact TOFU prompt, or the loud
 * changed-key WARNING variant when the payload carries
 * `previous_fingerprint` (the pinned fingerprint the server no
 * longer matches).
 *
 * The dialog cannot be dismissed by clicking outside or pressing
 * Escape, and no close X is rendered (`hideClose`) — only the
 * explicit buttons reply to the backend. This is intentional defense
 * against social-engineering "just dismiss the warning" muscle
 * memory: the user must consciously choose.
 *
 * The changed-key variant adds friction on top (threat model T11): a
 * key change is how a MITM looks, so both fingerprints render side
 * by side, "Replace & connect" is destructive-styled and stays
 * disabled until the user ticks a separate "I've verified this key
 * change is legitimate" checkbox, and there is deliberately no
 * remember/always-allow affordance — every key change is confirmed
 * per-event. The backend rewrites the pin only after the connection
 * also authenticates.
 */
export function HostKeyConfirmDialog() {
  const [pending, setPending] = useState<HostKeyConfirmPayload | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [verifiedChange, setVerifiedChange] = useState(false);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    listen<HostKeyConfirmPayload>("host-key:confirm", (event) => {
      setPending(event.payload);
      // Each prompt demands a fresh verification — never inherit a
      // tick from a previous key change.
      setVerifiedChange(false);
    }).then((fn) => {
      if (cancelled) {
        fn();
      } else {
        unlisten = fn;
      }
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  async function respond(trust: boolean) {
    if (!pending) return;
    setSubmitting(true);
    try {
      await verifyHostKey(pending.device_id, pending.host, pending.port, trust);
    } catch {
      // The backend reported the responder was already consumed (rare —
      // the connect attempt timed out or was aborted before the user
      // clicked). Clear the dialog either way; nothing the user can
      // do, and the connect failure surfaces in the sidebar banner.
    } finally {
      setPending(null);
      setSubmitting(false);
      setVerifiedChange(false);
    }
  }

  const changed = pending?.previous_fingerprint != null;

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(open) => {
        if (!open && pending) {
          // Defense-in-depth: no close X is rendered (`hideClose`)
          // and Escape/outside-click are intercepted below, so this
          // should be unreachable. If a future Radix version grows a
          // new close path, treat it as a decline so the backend's
          // connect attempt fails cleanly instead of hanging.
          void respond(false);
        }
      }}
    >
      <DialogContent
        onEscapeKeyDown={(e) => e.preventDefault()}
        onPointerDownOutside={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
        hideClose
        data-testid="host-key-dialog"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className={`h-5 w-5 ${changed ? "text-destructive" : "text-amber-500"}`} />
            {changed ? "Warning: host key changed!" : "Verify host key"}
          </DialogTitle>
          <DialogDescription>
            {changed
              ? "This device presented a different SSH host key than the one Transit pinned " +
                "when you first connected. Review carefully! A key changes legitimately when " +
                "a device is re-imaged, replaced, or re-keys during an upgrade — but it can " +
                "also mean the connection is being intercepted. Verify the new fingerprint " +
                "with whoever manages the device before replacing the pin."
              : "Transit hasn't connected to this host before. Confirm the SSH host-key " +
                "fingerprint with someone who manages the device, then click Trust to record " +
                "it. Transit will warn loudly if this host's key ever changes."}
          </DialogDescription>
        </DialogHeader>

        {pending && (
          <div className="space-y-2 rounded-md border bg-muted/30 px-3 py-2 font-mono text-xs">
            {/* Device first, address second. With per-device pins two
                sites can both sit at 192.168.1.1, so the address on
                its own does not say what is being trusted — and this
                dialog is the moment that distinction matters most. */}
            <div>
              <span className="text-muted-foreground">Device:</span>{" "}
              <span className="font-medium" data-testid="host-key-device">
                {pending.device_id}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Address:</span>{" "}
              <span className="font-medium">
                {pending.host}:{pending.port}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Algorithm:</span>{" "}
              <span>{pending.algorithm}</span>
            </div>
            {pending.previous_fingerprint != null ? (
              <>
                <div className="break-all">
                  <span className="text-muted-foreground">Pinned fingerprint:</span>{" "}
                  <span className="opacity-75">{pending.previous_fingerprint}</span>
                </div>
                <div className="break-all">
                  <span className="text-muted-foreground">New fingerprint:</span>{" "}
                  <span className="font-medium">{pending.fingerprint}</span>
                </div>
              </>
            ) : (
              <div className="break-all">
                <span className="text-muted-foreground">Fingerprint:</span>{" "}
                <span className="font-medium">{pending.fingerprint}</span>
              </div>
            )}
          </div>
        )}

        {changed && (
          <div className="flex items-start gap-2 px-1 pt-1">
            <Checkbox
              id="host-key-verified"
              data-testid="host-key-verified"
              checked={verifiedChange}
              onCheckedChange={(checked) => setVerifiedChange(checked === true)}
              disabled={submitting}
            />
            <label
              htmlFor="host-key-verified"
              className="text-xs leading-tight text-muted-foreground"
            >
              I&apos;ve verified this key change is legitimate — I checked the new fingerprint on
              the device itself or with whoever re-keyed it.
            </label>
          </div>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={submitting}
            onClick={() => void respond(false)}
          >
            {changed ? "Don’t connect" : "Cancel"}
          </Button>
          {changed ? (
            <Button
              type="button"
              data-testid="host-key-replace"
              variant="destructive"
              disabled={submitting || !verifiedChange}
              onClick={() => void respond(true)}
            >
              Replace &amp; connect
            </Button>
          ) : (
            <Button type="button" disabled={submitting} onClick={() => void respond(true)}>
              Trust
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
