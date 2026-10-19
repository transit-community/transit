import { RadioTower, X } from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { sendInput } from "@/lib/api";
import { computeLabels } from "@/lib/sessionLabels";
import { encodeBytesToBase64 } from "@/lib/terminal/bytes";
import { hasPty, useUiStore } from "@/stores/uiStore";

/**
 * v2.4.0 broadcast input bar. A strip below the button bar,
 * shown when `preferences.showBroadcastBar` (View → Broadcast Input). You
 * type ONE line and it's sent — with a trailing `\r` — to every targeted
 * LIVE session at once via the existing `send_input` PTY path.
 *
 * Like the button bar, this is **human input** — identical to typing, so it
 * is NOT policy-gated (the agent policy gate is agent-only, Inviolable Rule
 * 3). The only new risk is blast radius (one keystroke → many devices), and
 * because the gate can't help here the safety is entirely UX visibility: the
 * bar is an always-present Transit-blue strip (v3.2.0 — recolored from red
 * for brand consistency) with a live `Sending to N of M` device count as the
 * primary indicator; the destructive Interrupt-all button keeps a red accent
 * as a blast-radius cue. No per-command confirm — it's an efficiency tool users know
 * from other apps (decision 2026-07-06). The one retained gate is the app's
 * existing multi-line-paste confirm, which lives on the terminal pane; the
 * broadcast input itself is single-line (Enter sends).
 *
 * Targets default to ALL live sessions (top-level tabs AND split right panes
 * — every open connection); the target popover lets you exclude individual
 * sessions (e.g. a prod box) before sending. Ended sessions are never
 * targets. Exclusions are ephemeral local state — closing the bar resets
 * them (a persisted target set across restarts would itself be a footgun).
 *
 * Interrupt-all (`^C`) is a MOUSE-ONLY button, never a key chord: normal
 * Ctrl+C in a terminal pane stays per-session. The only broadcast triggers
 * are Enter-in-the-input and clicking Interrupt-all.
 */
export function BroadcastBar() {
  const showBroadcastBar = useUiStore((s) => s.preferences.showBroadcastBar);
  const setShowBroadcastBar = useUiStore((s) => s.setShowBroadcastBar);
  const sessions = useUiStore((s) => s.sessions);

  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [text, setText] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Live sessions only — a dead tab can't receive input. Labels computed
  // over the full session list so disambiguation ("vEX1 (2)") matches the
  // tab strip, then filtered to live for display.
  //
  // Targets are PTY tabs MINUS local shells. `hasPty` drops what can't take
  // `send_input` at all: an API tab (no PTY — it was latently counted here
  // before v5.0.0) and a Files tab (SFTP, no PTY). Local shells DO have a
  // PTY but are excluded on purpose: "send to all" is a fleet tool for
  // network gear, and typing `show version` into the user's own zsh is
  // noise that would also inflate the "Sending to N of M" safety count.
  const labels = useMemo(() => computeLabels(sessions), [sessions]);
  const liveSessions = useMemo(
    () =>
      sessions
        .map((tab, i) => ({ tab, label: labels[i] }))
        .filter(({ tab }) => !tab.ended && hasPty(tab) && tab.kind !== "local"),
    [sessions, labels],
  );

  if (!showBroadcastBar) return null;

  const targets = liveSessions.filter(({ tab }) => !excluded.has(tab.sessionId));

  const broadcast = (bytes: Uint8Array) => {
    const b64 = encodeBytesToBase64(bytes);
    for (const { tab } of targets) {
      void sendInput(tab.sessionId, b64).catch(() => {
        // A session that died between render and send folds silently —
        // the same non-actionable failure the button bar / keystroke
        // paths swallow.
      });
    }
  };

  const sendLine = () => {
    if (targets.length === 0) return;
    // Enter appends CR — one command executed on every targeted shell.
    broadcast(new TextEncoder().encode(`${text}\r`));
    setText("");
    // Stay in the bar: the user is about to send another line (unlike the
    // button bar, which hands focus back to the terminal).
    inputRef.current?.focus();
  };

  const interruptAll = () => {
    // Ctrl-C (0x03) to every target. Mouse-only — see the component doc.
    broadcast(new Uint8Array([0x03]));
    inputRef.current?.focus();
  };

  const toggleExcluded = (sessionId: string) => {
    setExcluded((prev) => {
      const next = new Set(prev);
      if (next.has(sessionId)) next.delete(sessionId);
      else next.add(sessionId);
      return next;
    });
  };

  return (
    <div
      className="flex shrink-0 items-center gap-2 border-t border-blue-500/50 bg-blue-500/15 px-2 py-1.5"
      data-testid="broadcast-bar"
    >
      <div className="flex shrink-0 items-center gap-1.5 text-blue-700 dark:text-blue-400">
        <RadioTower className="h-4 w-4" />
        <span className="text-xs font-semibold uppercase tracking-wide">Broadcast</span>
      </div>

      <form
        className="flex min-w-0 flex-1 items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          sendLine();
        }}
      >
        <input
          ref={inputRef}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={
            targets.length === 0
              ? "No live sessions to broadcast to"
              : `Send to ${targets.length} session${targets.length === 1 ? "" : "s"}…`
          }
          disabled={targets.length === 0}
          aria-label="Broadcast command to all targeted sessions"
          data-testid="broadcast-input"
          className="min-w-0 flex-1 rounded border border-blue-500/40 bg-background/60 px-2 py-1 font-mono text-sm outline-none focus:ring-1 focus:ring-blue-500/60 disabled:opacity-50"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
      </form>

      {/* Live device count + target selector. The count is the primary
          safety indicator (decision 2026-07-06: the bar + count is
          sufficient — no per-command confirm). */}
      <Popover>
        <PopoverTrigger asChild>
          <button
            type="button"
            data-testid="broadcast-targets"
            className="shrink-0 whitespace-nowrap rounded px-2 py-1 text-xs font-medium text-blue-700 hover:bg-blue-500/20 dark:text-blue-300"
          >
            Sending to {targets.length} of {liveSessions.length} ▾
          </button>
        </PopoverTrigger>
        <PopoverContent align="end" className="w-64 p-2">
          <div className="px-1 pb-1.5 text-xs font-medium text-muted-foreground">
            Broadcast targets
          </div>
          {liveSessions.length === 0 ? (
            <div className="px-1 py-2 text-xs text-muted-foreground">No live sessions.</div>
          ) : (
            <ScrollArea className="max-h-64">
              <div className="flex flex-col gap-0.5">
                {liveSessions.map(({ tab, label }) => (
                  <label
                    key={tab.sessionId}
                    className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-sm hover:bg-accent"
                  >
                    <Checkbox
                      checked={!excluded.has(tab.sessionId)}
                      onCheckedChange={() => toggleExcluded(tab.sessionId)}
                      data-testid={`broadcast-target-${tab.sessionId}`}
                    />
                    <span className="truncate font-mono">{label}</span>
                  </label>
                ))}
              </div>
            </ScrollArea>
          )}
        </PopoverContent>
      </Popover>

      <Button
        type="button"
        size="sm"
        variant="outline"
        className="h-7 shrink-0 border-red-500/40"
        onClick={interruptAll}
        disabled={targets.length === 0}
        title="Send Ctrl-C to every targeted session"
        data-testid="broadcast-interrupt-all"
      >
        ^C&nbsp;Interrupt all
      </Button>

      <button
        type="button"
        aria-label="Close broadcast bar"
        onClick={() => setShowBroadcastBar(false)}
        className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-blue-700/80 hover:bg-blue-500/20 hover:text-blue-700 dark:text-blue-300/80 dark:hover:text-blue-300"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
