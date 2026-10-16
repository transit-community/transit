import { useEffect, useState } from "react";

import { AlertTriangle, ShieldCheck } from "lucide-react";

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
import { respondProposeCommand } from "@/lib/api";
import { sessionDisplayLabel } from "@/lib/sessionLabels";
import { useUiStore } from "@/stores/uiStore";

/**
 * Self-managing per-step approval modal for Phase 6's
 * `propose_command` tool. Mounted once at the App root; subscribes
 * to `propose-command:request` events and renders the dialog when
 * one fires.
 *
 * Inviolable Rule 3 (CLAUDE.md §3) enforced UI-side:
 *   - Cannot be dismissed via Escape, click-outside, or the
 *     window-X chrome. The only way to reply is via the explicit
 *     Approve / Deny / "Auto-approve matching" buttons.
 *   - Auto-approve is a SEPARATE action behind a collapsed
 *     disclosure (a `<details>` panel with a clear "Auto-approve …?
 *     Expand here" summary) plus its own dedicated button — never the
 *     primary Approve. Collapsed-by-default + a distinct click
 *     mitigates the modal-fatigue threat (T18 / T_MODAL_FATIGUE)
 *     where a user habituates to clicking Approve and accidentally
 *     arms a wide allowlist. The regex field is pre-filled with
 *     `^show` (read-only commands) as a sensible, editable default.
 *     Shown only when the payload's `allow_auto_approve` is true
 *     (hidden for unrestricted Linux + custom BYOP vendors).
 *
 * The `(chat_id, session_id)` regex allowlist is dispatcher-side
 * state owned by the chat session — this component just sends the
 * regex with the verdict; the dispatcher compiles + stores it. The
 * allowlist persists for the life of the chat and clears when the
 * chat closes.
 *
 * v2.5.0 multi-chat: the modal is STORE-DRIVEN. `ChatNotificationCenter`
 * (App root) owns the `propose-command:request`/`:cancel` listeners and
 * writes each request into `pendingApprovalByChat[chat_id]`. This dialog
 * renders only the ACTIVE chat's pending approval — a background chat's
 * request shows as a tab dot + notification card instead of stealing a
 * modal, and two concurrent chats can no longer clobber one shared slot.
 * Answering clears the active chat's store entry.
 */
/**
 * True for the backend errors that mean the pending approval no
 * longer exists (chat cancelled / responder already drained) — the
 * only errors where dismissing the dialog without a verdict is
 * correct. Anything else (e.g. `invalid regex: …` from Rust's regex
 * dialect rejecting a JS-valid pattern) left the approval pending
 * and answerable, so the dialog must stay open and show the reason.
 */
function isResponderGoneError(message: string): boolean {
  return message.includes("responder consumed") || message.includes("no pending approval");
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function ProposeCommandDialog() {
  const [submitting, setSubmitting] = useState(false);
  const [rememberOpen, setRememberOpen] = useState(false);
  // Pre-filled with a sensible, editable default — `^show` matches the
  // read-only show/display commands that dominate investigations.
  const [regex, setRegex] = useState("^show");
  const [regexError, setRegexError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const sessions = useUiStore((s) => s.sessions);
  // Render ONLY the active chat's pending approval (store-driven). A
  // background chat's request lives in the store too, but surfaces as a
  // tab dot + notification card, not a modal.
  const pending = useUiStore((s) =>
    s.activeChatId ? (s.pendingApprovalByChat[s.activeChatId] ?? null) : null,
  );
  const setChatPendingApproval = useUiStore((s) => s.setChatPendingApproval);
  // Resolve the backend session_id to the friendly tab name the user
  // sees, so the modal says WHICH session ("vEX1") — not an opaque UUID
  // they can't place — the agent wants to run in. Falls back to the raw
  // id if the session isn't a known tab.
  const sessionTab = pending ? sessionDisplayLabel(sessions, pending.session_id) : null;

  // Reset transient UI state whenever the surfaced request changes (a
  // new approval, or switching to a different chat's pending one) so
  // nothing leaks across rounds/chats.
  useEffect(() => {
    setRememberOpen(false);
    setRegex("^show");
    setRegexError(null);
    setSubmitError(null);
    setSubmitting(false);
  }, [pending?.request_id]);

  async function reply(verdict: { kind: "approve" } | { kind: "deny" }): Promise<void> {
    if (!pending) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      await respondProposeCommand({ request_id: pending.request_id, verdict });
    } catch (e) {
      const message = errorMessage(e);
      if (!isResponderGoneError(message)) {
        // The approval is still pending backend-side — silently
        // dismissing would strand it. Keep the dialog open and
        // surface the reason so the user can act.
        setSubmitError(message);
        setSubmitting(false);
        return;
      }
      // "responder consumed" / "no pending approval" — typical when
      // the chat was cancelled mid-flight. Dismiss.
    }
    setChatPendingApproval(pending.chat_id, null);
    setSubmitting(false);
  }

  async function approveAndRemember(): Promise<void> {
    if (!pending) return;
    // Compile the regex client-side first so a syntactically
    // bogus pattern surfaces inline rather than in a backend
    // error string the user can't act on.
    try {
      new RegExp(regex);
    } catch (e) {
      setRegexError(errorMessage(e));
      return;
    }
    setRegexError(null);
    setSubmitError(null);
    setSubmitting(true);
    try {
      await respondProposeCommand({
        request_id: pending.request_id,
        verdict: { kind: "always_allow_regex", regex },
      });
    } catch (e) {
      const message = errorMessage(e);
      if (!isResponderGoneError(message)) {
        // The backend validates the regex BEFORE consuming the
        // pending approval, so a Rust-side rejection (`invalid
        // regex: …` — its dialect refuses look-around etc. that
        // JS accepts) leaves the modal answerable. Show the error
        // inline next to the pattern input and keep `pending` so
        // the user can fix the regex or fall back to plain
        // Approve / Deny.
        setRegexError(message);
        setSubmitting(false);
        return;
      }
      // Responder gone (chat cancelled mid-flight) — dismiss, same
      // as plain reply().
    }
    setChatPendingApproval(pending.chat_id, null);
    setSubmitting(false);
    setRememberOpen(false);
    setRegex("^show");
  }

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(open) => {
        // Closing via click-outside / Escape DOES NOT count as a
        // verdict — Rule 3 requires explicit user action. We
        // intercept those paths via DialogContent's preventDefault
        // handlers below (and `hideClose` removes the X entirely);
        // this onOpenChange handler exists only to satisfy Radix's
        // controlled-state contract.
        if (!open && pending) {
          // No-op. The dialog stays mounted via the `open` prop
          // until the user clicks Approve / Deny / Remember.
        }
      }}
    >
      <DialogContent
        onEscapeKeyDown={(e) => e.preventDefault()}
        onPointerDownOutside={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
        // No close X in the rendered tree (`hideClose`) — the only
        // way out of this dialog is an explicit Approve / Deny /
        // Remember click, and there's no focusable X for an
        // accidental Enter to land on.
        hideClose
        data-testid="propose-command-dialog"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {pending?.unrestricted ? (
              <AlertTriangle className="h-5 w-5 text-amber-500" />
            ) : (
              <ShieldCheck className="h-5 w-5 text-emerald-500" />
            )}
            Approve command?
          </DialogTitle>
          <DialogDescription>
            {pending?.unrestricted
              ? "The agent wants to run a command in an open session. This device has no policy gate — verify the command yourself before approving."
              : "The agent wants to run a command in an open session. The per-vendor policy gate already said yes; this is the second-of-two checks. Read the command before approving."}
          </DialogDescription>
        </DialogHeader>

        {pending && (
          <div className="space-y-3">
            {pending.unrestricted && pending.warning && (
              <div
                className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                role="alert"
                data-testid="propose-command-unrestricted-warning"
              >
                <div className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div className="whitespace-pre-line leading-snug">{pending.warning}</div>
                </div>
              </div>
            )}
            <div className="space-y-2 rounded-md border bg-muted/30 px-3 py-2 text-xs">
              <div>
                <span className="text-muted-foreground">Session:</span>{" "}
                <span
                  className={sessionTab?.resolved ? "font-medium" : "font-mono font-medium"}
                  title={pending.session_id}
                >
                  {sessionTab?.label ?? pending.session_id}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Gate:</span>{" "}
                <span className="font-mono">{pending.gate_decision}</span>
              </div>
              {/* `whitespace-pre-wrap break-all` so the command renders
                  byte-faithfully: an embedded newline must show as two
                  lines, never collapse to a space — the modal can't
                  approve something other than what it displays. (The
                  backend also rejects control chars; this is the
                  display half of that defense.) */}
              <div className="whitespace-pre-wrap break-all rounded bg-background px-2 py-1.5 font-mono text-sm">
                {pending.command}
              </div>
            </div>

            {/* Auto-approve is gated on `allow_auto_approve` — false for
                unrestricted (Linux) AND custom (BYOP) vendors, which have
                no shipped read-only floor and so require a per-command
                click with no regex shortcut. It lives behind a
                collapsed-by-default disclosure with its own dedicated
                button — never one Approve-click away — to preserve the
                T18 modal-fatigue mitigation. The regex is pre-filled with
                `^show` (read-only default; editable). The dispatcher also
                refuses any regex verdict on a no-floor vendor, defending
                in depth. */}
            {pending.allow_auto_approve && (
              <details
                open={rememberOpen}
                onToggle={(e) => setRememberOpen((e.target as HTMLDetailsElement).open)}
                className="rounded-md border px-3 py-2 text-xs"
                data-testid="propose-command-auto-approve"
              >
                <summary className="cursor-pointer font-bold text-foreground">
                  Auto-approve matching commands? Expand here
                </summary>
                <div className="mt-2 space-y-2">
                  <label
                    htmlFor="propose-command-regex-input"
                    className="block text-muted-foreground"
                  >
                    Auto-approve commands matching
                  </label>
                  <Input
                    id="propose-command-regex-input"
                    type="text"
                    placeholder="^show "
                    value={regex}
                    onChange={(e) => {
                      setRegex(e.target.value);
                      setRegexError(null);
                    }}
                    className="h-7 font-mono text-xs"
                    autoComplete="off"
                    spellCheck={false}
                    data-testid="propose-command-regex-input"
                  />
                  <p className="text-muted-foreground leading-snug">
                    for the rest of this chat — the policy gate still runs every time. The allowlist
                    clears when this chat closes.
                  </p>
                  {regexError && (
                    <p className="text-destructive" role="alert">
                      {regexError}
                    </p>
                  )}
                  <div className="flex justify-end">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs"
                      disabled={submitting || regex.trim().length === 0}
                      onClick={() => void approveAndRemember()}
                      data-testid="propose-command-approve-remember"
                    >
                      Auto-approve matching
                    </Button>
                  </div>
                </div>
              </details>
            )}
          </div>
        )}

        {submitError && (
          <p
            className="text-xs text-destructive"
            role="alert"
            data-testid="propose-command-submit-error"
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
            data-testid="propose-command-deny"
          >
            Deny
          </Button>
          <Button
            type="button"
            disabled={submitting}
            onClick={() => void reply({ kind: "approve" })}
            data-testid="propose-command-approve"
          >
            Approve
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
