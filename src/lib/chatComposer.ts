import type { KeyboardEvent } from "react";

/**
 * The one send-key contract for every composer on the AI chat surface —
 * the main composer AND the ask_user answer card. They render in the same
 * thread and must agree, or Enter sends in one textarea and newlines in
 * the other (v6.3.0 review finding: the card kept the old binding, so an
 * agent question looked hung when the user answered it with Enter).
 *
 * Returns true when this keydown asks to SEND. The caller still gates on
 * its own send-ability (streaming, empty draft, pending state) BEFORE
 * calling preventDefault — claiming the key and then not sending swallows
 * Enter entirely, which is worse than either sending or newlining.
 *
 * Rules: Cmd/Ctrl+Enter always asks to send (the original binding, kept
 * for muscle memory). With `sendOnEnter` on (default since v6.3.0), bare
 * Enter asks too; Shift+Enter always falls through to a newline. An Enter
 * that confirms an IME composition (CJK input) never sends — the user is
 * picking a candidate, not submitting.
 */
export function composerSendKey(
  e: KeyboardEvent<HTMLTextAreaElement>,
  sendOnEnter: boolean,
): boolean {
  if (e.key !== "Enter") return false;
  if (e.nativeEvent.isComposing) return false;
  if (e.metaKey || e.ctrlKey) return true;
  return sendOnEnter && !e.shiftKey && !e.altKey;
}

/** Placeholder hint matching the active send-key mode. */
export function composerPlaceholder(prefix: string, sendOnEnter: boolean): string {
  return sendOnEnter
    ? `${prefix} (↵ to send, Shift+↵ for a new line)`
    : `${prefix} (⌘/Ctrl + ↵ to send)`;
}
