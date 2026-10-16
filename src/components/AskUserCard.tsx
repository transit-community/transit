import { useEffect, useState } from "react";

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { MessageCircleQuestion, Send, ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { respondAskUser, type AskUserRequestPayload } from "@/lib/api";
import { composerPlaceholder, composerSendKey } from "@/lib/chatComposer";
import { useUiStore } from "@/stores/uiStore";

/**
 * Inline card for Phase 6's `ask_user` tool. Listens for
 * `ask-user:request` events scoped to the active chat, renders the
 * question + a fixed "don't type secrets" warning + a small
 * textarea, and dispatches the user's typed answer back via
 * `respond_ask_user`.
 *
 * The secret-warning banner is structural — not an opt-in nag. The
 * `ask_user` tool is the only path where the AI can elicit free-form
 * input from the user mid-chat; without a salient warning a tired
 * user could type a credential into a question like "what's the BGP
 * MD5 key for vEX1?". The AcceptableUseGuard tells the model not to
 * recite credentials it sees, but a model asking the user to TYPE
 * one bypasses the redaction filter entirely. The warning is the
 * defensive UX layer that closes that loop.
 *
 * Dismissal:
 *   - Submitting an answer dismisses the card.
 *   - A `chat:{id}:completed` event for the active chat dismisses
 *     the card silently (the loop ended; the dispatcher already
 *     dropped the responder via `cancel_chat_approvals`).
 *
 * Filtering: every request is keyed by `chat_id` in the payload.
 * A stale event from a destroyed chat (or a sibling chat in a
 * future multi-chat world) is ignored.
 */
export function AskUserCard({ chatId }: { chatId: string | null }) {
  const [pending, setPending] = useState<AskUserRequestPayload | null>(null);
  const [answer, setAnswer] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const sendOnEnter = useUiStore((s) => s.preferences.chatSendOnEnter);

  useEffect(() => {
    if (!chatId) return;
    let unlistenReq: UnlistenFn | undefined;
    let unlistenCompleted: UnlistenFn | undefined;
    let cancelled = false;

    listen<AskUserRequestPayload>("ask-user:request", (event) => {
      if (event.payload.chat_id !== chatId) return;
      setPending(event.payload);
      setAnswer("");
      setSubmitting(false);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenReq = fn;
    });

    listen(`chat:${chatId}:completed`, () => {
      // Loop ended (any stop_reason). Backend already dropped the
      // responder via cancel_chat_approvals — mirror here so the
      // user doesn't see an orphan card after their final message.
      setPending(null);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenCompleted = fn;
    });

    return () => {
      cancelled = true;
      unlistenReq?.();
      unlistenCompleted?.();
    };
  }, [chatId]);

  async function handleSend(): Promise<void> {
    if (!pending || submitting) return;
    const trimmed = answer.trim();
    if (!trimmed) return;
    setSubmitting(true);
    try {
      await respondAskUser(pending.request_id, trimmed);
    } catch {
      // Backend reported "responder consumed" — chat was cancelled
      // mid-flight. Dismiss either way.
    } finally {
      setPending(null);
      setAnswer("");
      setSubmitting(false);
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>): void {
    // Same send-key contract as the main composer (v6.3.0) — this card
    // sits in the same thread, autofocused, right after a placeholder
    // that told the user "↵ to send"; diverging here left the agent loop
    // looking hung when an Enter answer only inserted a newline.
    if (!composerSendKey(e, sendOnEnter)) return;
    if (submitting || answer.trim().length === 0) {
      if (e.metaKey || e.ctrlKey) e.preventDefault();
      return;
    }
    e.preventDefault();
    void handleSend();
  }

  if (!pending) return null;

  return (
    <div
      data-testid="ask-user-card"
      className="rounded-md border border-primary/40 bg-primary/5 p-3"
      role="region"
      aria-label="AI question"
    >
      <div className="mb-2 flex items-start gap-2">
        <MessageCircleQuestion className="mt-0.5 h-4 w-4 flex-shrink-0 text-primary" />
        <p className="text-sm font-medium leading-relaxed">{pending.question}</p>
      </div>

      <div
        role="alert"
        data-testid="ask-user-secret-warning"
        className="mb-2 flex items-center gap-2 rounded-sm border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-700 dark:text-amber-300"
      >
        <ShieldAlert className="h-3.5 w-3.5 flex-shrink-0" />
        <span>
          Don&apos;t type passwords, keys, or other secrets — your answer is sent to the AI.
        </span>
      </div>

      <textarea
        value={answer}
        onChange={(e) => setAnswer(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder={composerPlaceholder("Type your answer", sendOnEnter)}
        rows={2}
        autoFocus
        disabled={submitting}
        className="w-full resize-none rounded-sm border border-input bg-background px-2 py-1.5 text-sm outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
        data-testid="ask-user-input"
      />

      <div className="mt-2 flex justify-end">
        <Button
          type="button"
          size="sm"
          disabled={answer.trim().length === 0 || submitting}
          onClick={() => void handleSend()}
          data-testid="ask-user-send"
        >
          <Send className="mr-1 h-3 w-3" />
          Send answer
        </Button>
      </div>
    </div>
  );
}
