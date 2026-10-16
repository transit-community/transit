import { ShieldCheck } from "lucide-react";

import { chatSetAutoApproveGets } from "@/lib/api";
import { type ChatTab, useUiStore } from "@/stores/uiStore";

/**
 * v4.0.0 — the indicator + off-switch for a chat's auto-approve-GET opt-in
 * (adversarial-review M1). Renders ONLY when the chat is auto-approving the
 * agent's read-only GETs (turned on from the propose-api-call modal's
 * checkbox). Without it, once a chat opts in the approval modal stops firing
 * and there is no way to revoke — the user loses control.
 *
 * Clicking it turns auto-approve OFF — restoring the per-call approval
 * modal — via the `chat_set_auto_approve_gets` IPC. It updates the store
 * mirror only AFTER the backend confirms, so the badge never advertises
 * "per-call approval" while the backend is still auto-approving (the honest
 * direction; same posture as `setChatScope`).
 */
export function ChatAutoApproveToggle({ chat }: { chat: ChatTab }) {
  const setMirror = useUiStore((s) => s.setChatAutoApproveGets);
  if (!chat.autoApproveGets) return null;

  async function turnOff() {
    try {
      await chatSetAutoApproveGets(chat.chatId, false);
      setMirror(chat.chatId, false);
    } catch {
      // Backend still auto-approving — keep the badge (don't claim per-call
      // approval the backend isn't enforcing).
    }
  }

  return (
    <button
      type="button"
      onClick={() => void turnOff()}
      title="Auto-approving the agent's read-only GETs — click to require per-call approval again"
      data-testid="chat-auto-approve-toggle"
      className="flex shrink-0 items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-300"
    >
      <ShieldCheck className="h-3 w-3" />
      Auto-GET
    </button>
  );
}
