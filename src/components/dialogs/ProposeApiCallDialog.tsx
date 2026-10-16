import { useEffect, useState } from "react";

import { Globe } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { chatSetAutoApproveGets, respondProposeCommand } from "@/lib/api";
import { sessionDisplayLabel } from "@/lib/sessionLabels";
import { useUiStore } from "@/stores/uiStore";

/**
 * Per-call approval modal for the v4.0.0 `propose_api_call` tool — the
 * GET-only controller path. Mounted once at the App root as a sibling of
 * {@link ProposeCommandDialog}; store-driven, rendering ONLY the active
 * chat's pending API call (a background chat surfaces as a notification
 * card + tab dot instead of stealing the modal).
 *
 * Inviolable Rule 3 (CLAUDE.md §3), UI half: the agent's request already
 * passed the GET+confine gate (a GET can't mutate; the host is pinned and
 * the path confined) — this is the second-of-two checks. The dialog is
 * undismissable except via an explicit Approve / Deny click (no Escape,
 * click-outside, or window-X).
 *
 * There is deliberately NO auto-approve affordance: a controller is a
 * custom-vendor session with no shipped read-only floor, so every agent
 * GET is a per-call decision — the same reason the command dialog hides
 * auto-approve for custom / unrestricted vendors. Approve / Deny reply
 * through the SAME `respond_propose_command` IPC (shared `pending_approvals`
 * map) as the command modal.
 */
function isResponderGoneError(message: string): boolean {
  return message.includes("responder consumed") || message.includes("no pending approval");
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function ProposeApiCallDialog() {
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // Opt-in: auto-approve the agent's read-only GETs for the rest of this
  // chat. A separate, deliberate checkbox (never one Approve-click) — the
  // command dialog's T18 posture, though the risk is far lower here since a
  // GET can't mutate. The GET+confine gate STILL runs on every call.
  const [autoApprove, setAutoApprove] = useState(false);
  const sessions = useUiStore((s) => s.sessions);
  // Render ONLY the active chat's pending API call (store-driven). A
  // background chat's request lives in the store too, but surfaces as a
  // tab dot + notification card, not a modal.
  const pending = useUiStore((s) =>
    s.activeChatId ? (s.pendingApiCallByChat[s.activeChatId] ?? null) : null,
  );
  const setChatPendingApiCall = useUiStore((s) => s.setChatPendingApiCall);
  // Resolve the backend session_id to the friendly controller name.
  const sessionTab = pending ? sessionDisplayLabel(sessions, pending.session_id) : null;

  useEffect(() => {
    setSubmitError(null);
    setSubmitting(false);
    setAutoApprove(false);
  }, [pending?.request_id]);

  async function reply(verdict: { kind: "approve" } | { kind: "deny" }): Promise<void> {
    if (!pending) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      // Opt into auto-approving future GETs BEFORE approving this one, so a
      // later GET in the same chat skips the modal. The gate still runs.
      if (verdict.kind === "approve" && autoApprove) {
        await chatSetAutoApproveGets(pending.chat_id, true);
        // Mirror it into the store so the chat header shows the state + an
        // off-toggle (M1 — otherwise the modal stops firing and there's no
        // way to revoke).
        useUiStore.getState().setChatAutoApproveGets(pending.chat_id, true);
      }
      await respondProposeCommand({ request_id: pending.request_id, verdict });
    } catch (e) {
      const message = errorMessage(e);
      if (!isResponderGoneError(message)) {
        // Still pending backend-side — keep the dialog open + show why.
        setSubmitError(message);
        setSubmitting(false);
        return;
      }
      // "responder consumed" / "no pending approval" — chat cancelled
      // mid-flight. Dismiss.
    }
    setChatPendingApiCall(pending.chat_id, null);
    setSubmitting(false);
  }

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(open) => {
        if (!open && pending) {
          // No-op — Rule 3: only an explicit Approve / Deny click closes
          // it. The preventDefault handlers below intercept Escape /
          // click-outside, and `hideClose` removes the X.
        }
      }}
    >
      <DialogContent
        onEscapeKeyDown={(e) => e.preventDefault()}
        onPointerDownOutside={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
        hideClose
        data-testid="propose-api-call-dialog"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-emerald-500" />
            Approve API request?
          </DialogTitle>
          <DialogDescription>
            The agent wants to send a read-only <span className="font-mono">GET</span> to a
            controller. It cannot change anything — GET-only, host-pinned, path-confined — and this
            is the second-of-two checks. Read the path before approving.
          </DialogDescription>
        </DialogHeader>

        {pending && (
          <div className="space-y-2 rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <div>
              <span className="text-muted-foreground">Controller:</span>{" "}
              <span
                className={sessionTab?.resolved ? "font-medium" : "font-mono font-medium"}
                title={pending.session_id}
              >
                {sessionTab?.label ?? pending.session_id}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">Method:</span>{" "}
              <span className="font-mono font-medium text-emerald-500">GET</span>
            </div>
            {/* `whitespace-pre-wrap break-all` so the path renders
                byte-faithfully — the modal can't approve something other
                than what it displays. */}
            <div className="whitespace-pre-wrap break-all rounded bg-background px-2 py-1.5 font-mono text-sm">
              {pending.path}
            </div>
          </div>
        )}

        {pending && (
          <label className="flex cursor-pointer items-start gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={autoApprove}
              onChange={(e) => setAutoApprove(e.target.checked)}
              data-testid="propose-api-call-auto-approve"
            />
            <span>
              Auto-approve read-only GETs for the rest of this chat — the agent won&apos;t ask again
              for GET requests. It still can&apos;t write or reach any other host, and the gate runs
              on every call.
            </span>
          </label>
        )}

        {submitError && (
          <p
            className="text-xs text-destructive"
            role="alert"
            data-testid="propose-api-call-submit-error"
          >
            {submitError}
          </p>
        )}

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={submitting}
            onClick={() => void reply({ kind: "deny" })}
            data-testid="propose-api-call-deny"
          >
            Deny
          </Button>
          <Button
            type="button"
            disabled={submitting}
            onClick={() => void reply({ kind: "approve" })}
            data-testid="propose-api-call-approve"
          >
            Approve
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
