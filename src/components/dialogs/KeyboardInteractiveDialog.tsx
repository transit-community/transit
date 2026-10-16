import { useEffect, useRef, useState } from "react";

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { KeyRound } from "lucide-react";

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
import { cancelKbi, submitKbiAnswers, type KbiPromptPayload } from "@/lib/api";
import { toastError } from "@/lib/toast";

/**
 * Interactive (keyboard-interactive) authentication prompt — v6.1.0.
 * Mounted once at App root, self-managing, mirroring
 * `WeakCryptoConfirmDialog` / `HostKeyConfirmDialog`.
 *
 * This is the UI half of the only credential path in the product that
 * doesn't go through enrollment: the user types a password / OTP / menu
 * choice at connect time and nothing is ever stored. See
 * the interactive keyboard auth design notes (not included in this repository) and threat-model T46.
 *
 * ## Two things here are load-bearing, not styling
 *
 * 1. **The prompt text belongs to the server, and the server may be
 *    hostile (T46.1).** Whoever runs the host chooses `name`,
 *    `instruction`, and every prompt label. It is sanitized backend-side
 *    (printable ASCII, length-capped, control characters stripped), but
 *    sanitizing only makes it *inert* — it does not make it *true*. A
 *    host can still send "Enter your Anthropic API key:". So the
 *    dialog states whose question this is in Transit's own voice, names
 *    the exact `user@host:port` being answered, and renders every
 *    server-authored string inside a visually distinct quoted block.
 *    **Never render server text as the dialog's title, description, or
 *    button label** — those are Transit's voice and must stay ours.
 *
 * 2. **`echo` decides masking, not the label text.** RFC 4256 marks each
 *    prompt echo-on or echo-off; a password is echo-off, an account-menu
 *    selection is echo-on. Guessing from the label ("does it contain the
 *    word password?") would mask menu choices and — far worse — echo a
 *    credential whose label we failed to recognize.
 *
 * Answers are held in component state only for as long as the dialog is
 * open, cleared on every close path, and never logged.
 */
export function KeyboardInteractiveDialog() {
  // A QUEUE, not a single slot. Two connects can be awaiting a prompt at
  // once (the user starts one MFA device, then another before answering),
  // and the backend parks each attempt on its own responder with the
  // connect deadline PAUSED while it waits. A single slot would let the
  // second event overwrite the first, stranding that connect until
  // something else dropped its responder. Queueing answers them in
  // arrival order and leaves nothing parked.
  const [queue, setQueue] = useState<KbiPromptPayload[]>([]);
  const [answers, setAnswers] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const firstFieldRef = useRef<HTMLInputElement>(null);
  const pending = queue[0] ?? null;

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    listen<KbiPromptPayload>("auth:kbi:request", (event) => {
      setQueue((prev) => [...prev, event.payload]);
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

  // Reset the fields whenever the head of the queue changes — including
  // when one challenge is answered and the next takes its place. One
  // empty answer per prompt: the array LENGTH is the contract with the
  // backend, which refuses a mismatched count rather than answering the
  // wrong prompt.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    setAnswers(pending ? pending.prompts.map(() => "") : []);
    setSubmitting(false);
  }, [pending]);

  /** Drop the head of the queue and wipe what was typed into it. */
  function done() {
    setAnswers([]);
    setSubmitting(false);
    setQueue((prev) => prev.slice(1));
  }

  async function submit() {
    if (!pending || submitting) return;
    setSubmitting(true);
    try {
      await submitKbiAnswers(pending.host, pending.port, answers);
    } catch (e) {
      toastError("Authentication failed", { description: String(e) });
    } finally {
      // `done()` in `finally` so the typed answers are wiped on every
      // path — a thrown IPC error must not leave them in component state.
      done();
    }
  }

  async function cancel() {
    if (!pending) return;
    const { host, port } = pending;
    done();
    try {
      await cancelKbi(host, port);
    } catch {
      // The attempt may have already torn down; nothing to surface.
    }
  }

  if (!pending) return null;

  const target = `${pending.username}@${pending.host}:${pending.port}`;

  return (
    <Dialog
      open
      onOpenChange={(next) => {
        // Closing by any means is a cancel — the backend must be told,
        // or the connect stays parked until its deadline.
        if (!next) void cancel();
      }}
    >
      <DialogContent
        hideClose
        onEscapeKeyDown={(e) => {
          e.preventDefault();
          void cancel();
        }}
        onInteractOutside={(e) => e.preventDefault()}
        onOpenAutoFocus={(e) => {
          e.preventDefault();
          firstFieldRef.current?.focus();
        }}
        className="sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            Sign in to {pending.host}
          </DialogTitle>
          {/* Transit's voice. Never the server's. */}
          <DialogDescription>
            <span className="font-mono text-xs">{target}</span> is asking for credentials. Transit
            does not store what you type here — it is used once for this connection.
          </DialogDescription>
        </DialogHeader>

        {/* TRANSIT-authored. Rendered ABOVE and visually distinct from the
            server block below, because the two must never be confusable:
            this explains why Transit is asking, the other is text a host
            operator chose (T46.1). */}
        {pending.notice && (
          <p className="px-1 text-sm text-muted-foreground" data-testid="kbi-notice">
            {pending.notice}
          </p>
        )}

        {/* Everything below is SERVER-AUTHORED text, quoted and
            attributed so it can't pass for Transit's own copy. */}
        {(pending.name || pending.instruction) && (
          <div className="rounded-md border border-border bg-muted/40 p-3">
            <p className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">
              Message from the server
            </p>
            {pending.name && (
              <p className="text-sm font-medium whitespace-pre-wrap break-words">{pending.name}</p>
            )}
            {pending.instruction && (
              <p className="text-sm whitespace-pre-wrap break-words text-muted-foreground">
                {pending.instruction}
              </p>
            )}
          </div>
        )}

        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {pending.prompts.map((prompt, i) => (
            // Keyed on position AND text: position is the semantic
            // identity (answers map positionally), while including the
            // text gives a new round with different prompts fresh inputs
            // rather than reusing the previous round's.
            <div key={`${i}-${prompt.text}`} className="space-y-1.5">
              <Label htmlFor={`kbi-${i}`} className="break-words">
                {/* Server-authored label, quoted. */}
                <span className="text-muted-foreground">“</span>
                {prompt.text}
                <span className="text-muted-foreground">”</span>
              </Label>
              <Input
                id={`kbi-${i}`}
                ref={i === 0 ? firstFieldRef : undefined}
                // The server's echo flag decides this — never the label.
                type={prompt.echo ? "text" : "password"}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                value={answers[i] ?? ""}
                onChange={(e) =>
                  setAnswers((prev) => {
                    const next = [...prev];
                    next[i] = e.target.value;
                    return next;
                  })
                }
              />
            </div>
          ))}
          {/* Submit lives inside the form so Enter works from any field. */}
          <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
        </form>

        <DialogFooter>
          <Button variant="outline" onClick={() => void cancel()} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={submitting}>
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
