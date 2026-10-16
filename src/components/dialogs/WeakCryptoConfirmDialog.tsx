import { useEffect, useState } from "react";

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { AlertTriangle } from "lucide-react";

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
import { weakCryptoDecision, type WeakCryptoConfirmPayload } from "@/lib/api";
import { toastInfo } from "@/lib/toast";

/**
 * Self-managing weak-crypto warning. Mounted once at App root.
 * Mirrors `HostKeyConfirmDialog` structurally: subscribe to a Tauri
 * event, render a modal, reply via IPC, no dismissal without an
 * explicit button click.
 *
 * Threat model — T_WEAK_CRYPTO_OPTIN. Cisco IOS-XE (vIOS, CSR1000v)
 * and older Junos ship with SHA1-only KEX defaults; supporting them
 * means letting users opt into negotiating with crypto below
 * Transit's strict floor. The risk:
 *
 *   - SHA1 KEX (`diffie-hellman-group14-sha1`, `*-group-exchange-sha1`)
 *     is theoretically downgrade-attackable by a sufficiently-funded
 *     MITM; SHA1's collision resistance is broken.
 *   - CBC ciphers are AEAD-less; padding-oracle classes of attack
 *     have historically applied.
 *   - ssh-rsa host-key signatures use SHA1 over the exchange hash;
 *     NIST deprecated this for SSH in 2022.
 *
 * The mitigation isn't "refuse the connection" — that strands users
 * on legacy gear they own. It's "make sure they know what they're
 * opting into, per device, and don't let muscle memory grant the
 * downgrade." Hence:
 *
 *   - The dialog cannot be dismissed via Escape or click-outside,
 *     and no close X is rendered (`hideClose`); only the explicit
 *     Connect Anyway / Cancel buttons reply to the backend.
 *   - "Remember for this device" is a separate checkbox the user
 *     must consciously tick — never one click away from Connect.
 *   - The offered algorithms are rendered verbatim so the user can
 *     reason about *what* is being negotiated down to (a server
 *     offering ONLY ssh-rsa is a different risk than one offering
 *     ssh-rsa alongside ed25519, etc).
 */
export function WeakCryptoConfirmDialog() {
  const [pending, setPending] = useState<WeakCryptoConfirmPayload | null>(null);
  const [remember, setRemember] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    listen<WeakCryptoConfirmPayload>("weak-crypto:confirm", (event) => {
      setPending(event.payload);
      setRemember(false);
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

  async function respond(accept: boolean) {
    if (!pending) return;
    setSubmitting(true);
    const persisted = accept && remember;
    try {
      await weakCryptoDecision(pending.host, pending.port, accept, persisted);
      if (persisted) {
        toastInfo("Weak crypto remembered for this device", {
          description: `${pending.host}:${pending.port} will skip the prompt on future connects.`,
        });
      }
    } catch {
      // Responder was already consumed (rare — e.g. the connect
      // attempt timed out). Clear the dialog either way; the
      // connect failure surfaces in the sidebar banner.
    } finally {
      setPending(null);
      setSubmitting(false);
      setRemember(false);
    }
  }

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(open) => {
        if (!open && pending) {
          // Defense-in-depth: no close X is rendered (`hideClose`)
          // and Escape/outside-click are intercepted below, so this
          // should be unreachable. If a future Radix version grows a
          // new close path, treat it as Cancel so the backend's
          // connect attempt fails cleanly instead of hanging.
          void respond(false);
        }
      }}
    >
      <DialogContent
        data-testid="weak-crypto-dialog"
        onEscapeKeyDown={(e) => e.preventDefault()}
        onPointerDownOutside={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
        hideClose
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Weak crypto required
          </DialogTitle>
          <DialogDescription>
            The server below requires SSH algorithms Transit considers weak — or it closed the
            handshake before agreeing on modern ones (common on legacy switches). Connecting means
            negotiating with SHA-1, CBC ciphers, or ssh-rsa signatures, which a sufficiently capable
            attacker on the network path could exploit. Continue only if you trust the path between
            your machine and this device.
          </DialogDescription>
        </DialogHeader>

        {pending && (
          <div className="space-y-2 rounded-md border bg-muted/30 px-3 py-2 font-mono text-xs">
            <div>
              <span className="text-muted-foreground">Host:</span>{" "}
              <span className="font-medium">
                {pending.host}:{pending.port}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Slot:</span> <span>{pending.kind}</span>
            </div>
            <div className="break-all">
              <span className="text-muted-foreground">Offered:</span>{" "}
              <span data-testid="weak-crypto-offered">
                {pending.offered.length > 0
                  ? pending.offered.join(", ")
                  : "(server closed the handshake before advertising its algorithms)"}
              </span>
            </div>
          </div>
        )}

        <div className="flex items-start gap-2 px-1 pt-1">
          <Checkbox
            id="weak-crypto-remember"
            data-testid="weak-crypto-remember"
            checked={remember}
            onCheckedChange={(checked) => setRemember(checked === true)}
            disabled={submitting}
          />
          <label
            htmlFor="weak-crypto-remember"
            className="text-xs leading-tight text-muted-foreground"
          >
            Remember for this device. Future connects to{" "}
            <span className="font-medium">
              {pending?.host}:{pending?.port}
            </span>{" "}
            will skip this prompt and negotiate weak crypto directly.
          </label>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={submitting}
            onClick={() => void respond(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            data-testid="weak-crypto-accept"
            variant="destructive"
            disabled={submitting}
            onClick={() => void respond(true)}
          >
            Connect anyway
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
