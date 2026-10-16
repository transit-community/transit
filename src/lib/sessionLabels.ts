import { type SessionTab } from "@/stores/uiStore";

/**
 * Compute display labels for the open session tabs. First occurrence of
 * a deviceId is the bare id; subsequent occurrences get " (N)" where N
 * counts among same-deviceId in array order. Tabs with a user-set
 * `customLabel` (Phase 7a C9) bypass the dedupe counter entirely and
 * render their custom label verbatim.
 *
 * Stable across the lifetime of the tabs in question — the suffix for a
 * given tab only changes when an earlier same-deviceId tab is added or
 * removed, and that's the right behavior: the *visual* order matches the
 * *temporal* order of opens.
 *
 * Lives here (not in `TerminalArea`) so the tab strip, the command
 * palette, and the `propose_command` approval modal all name a session
 * identically — without the modal pulling in the terminal/xterm module.
 */
export function computeLabels(sessions: SessionTab[]): string[] {
  const counts = new Map<string, number>();
  return sessions.map((s) => {
    if (s.customLabel && s.customLabel.length > 0) return s.customLabel;
    const next = (counts.get(s.deviceId) ?? 0) + 1;
    counts.set(s.deviceId, next);
    return next === 1 ? s.deviceId : `${s.deviceId} (${next})`;
  });
}

/**
 * Resolve a backend `session_id` to the human label shown on its
 * terminal tab — the user's rename, else the disambiguated device name
 * ("vEX1", "vEX1 (2)"). Falls back to the raw id (and reports
 * `resolved: false`) when the session isn't in the UI's tab list — e.g.
 * it already closed, or a transport the tab strip doesn't track — so a
 * caller never renders an empty Session field.
 */
export function sessionDisplayLabel(
  sessions: SessionTab[],
  sessionId: string,
): { label: string; resolved: boolean } {
  const idx = sessions.findIndex((s) => s.sessionId === sessionId);
  if (idx < 0) return { label: sessionId, resolved: false };
  return { label: computeLabels(sessions)[idx] ?? sessionId, resolved: true };
}
