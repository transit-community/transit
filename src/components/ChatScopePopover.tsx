import { useMemo } from "react";

import { MonitorSmartphone } from "lucide-react";

import { Checkbox } from "@/components/ui/checkbox";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { setChatScope } from "@/lib/chat";
import { isFilesTab, type ChatTab, useUiStore } from "@/stores/uiStore";

/**
 * v2.7.0 — per-chat device scope picker (T31). A checkbox popover in
 * the chat header, cloned from the BroadcastBar target popover: it
 * restricts THIS chat's agent to the checked devices. Enforcement is
 * backend-side (the scoped wrappers in `scoped_session_view.rs`); this
 * component only edits intent via the `setChatScope` thunk, which
 * awaits the IPC and reverts on failure — the trigger badge never
 * advertises a scope the backend isn't enforcing.
 *
 * The device universe = distinct agent-visible device ids of LIVE
 * sessions (a dead tab can't be an agent target) ∪ ids already in the
 * chat's scope — so a scoped-but-disconnected device stays visible
 * (and uncheckable) instead of silently vanishing from the list.
 * Agent-visible id = `agentDeviceId ?? deviceId` (console tabs carry a
 * `console-` display prefix the backend doesn't know).
 *
 * Semantics: `null` = "All devices" — an OPEN scope where sessions to
 * new devices auto-join the chat's view. An explicit list (even one
 * covering every current device) stays closed to newcomers; the
 * **All devices** quick action is the way back to the open mode.
 * Scope keys on the connection name as opened — renaming a device in
 * the inventory and reconnecting makes the old entry visible-but-dead
 * here (union rendering keeps that state honest rather than silent).
 */
export function ChatScopePopover({ chat }: { chat: ChatTab }) {
  const sessions = useUiStore((s) => s.sessions);
  const scope = chat.scopedDeviceIds;

  // Distinct live agent-visible device ids, insertion-ordered by tab. Local
  // shells (`kind === "local"`, T42) and Files/SFTP sessions
  // (`kind === "files"`, T43) are deliberately EXCLUDED: the agent is blind to
  // both surfaces (neither transport is ever wired into the agent's session
  // source — for Files, `transit_files` is banned outside `transit_app` at the
  // dependency-graph level), so listing one here as a "device this chat's AI
  // can see" would misrepresent that. Either is inert even if listed (the
  // backend scoped view has no such session to expose), but the picker must
  // not claim otherwise.
  const liveDevices = useMemo(() => {
    const out: string[] = [];
    for (const tab of sessions) {
      if (tab.ended || tab.kind === "local" || isFilesTab(tab)) continue;
      const id = tab.agentDeviceId ?? tab.deviceId;
      if (!out.includes(id)) out.push(id);
    }
    return out;
  }, [sessions]);

  const universe = useMemo(() => {
    const out = [...liveDevices];
    for (const id of scope ?? []) {
      if (!out.includes(id)) out.push(id);
    }
    return out;
  }, [liveDevices, scope]);

  const isChecked = (id: string) => scope === null || scope.includes(id);

  const toggle = (id: string) => {
    // Unchecking while unscoped materializes the open scope into an
    // explicit allowlist of everything else currently known.
    const next =
      scope === null
        ? universe.filter((d) => d !== id)
        : isChecked(id)
          ? scope.filter((d) => d !== id)
          : [...scope, id];
    void setChatScope(chat.chatId, next);
  };

  const label = scope === null ? "All devices" : `${scope.length} of ${universe.length} devices`;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          data-testid="chat-scope-trigger"
          title="Devices this chat's AI can see and act on"
          className="flex h-7 shrink-0 items-center gap-1 rounded px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <MonitorSmartphone className="h-3.5 w-3.5" />
          {label}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 p-2">
        <div className="px-1 pb-1.5 text-xs font-medium text-muted-foreground">
          Devices in this chat
        </div>
        {universe.length === 0 ? (
          <div className="px-1 py-2 text-xs text-muted-foreground">
            No connected devices — open a session first.
          </div>
        ) : (
          <ScrollArea className="max-h-64">
            <div className="flex flex-col gap-0.5">
              {universe.map((id) => (
                <label
                  key={id}
                  className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-sm hover:bg-accent"
                >
                  <Checkbox
                    checked={isChecked(id)}
                    onCheckedChange={() => toggle(id)}
                    data-testid={`chat-scope-device-${id}`}
                  />
                  <span className="truncate font-mono">{id}</span>
                  {!liveDevices.includes(id) && (
                    <span className="ml-auto shrink-0 text-[10px] uppercase tracking-wide text-muted-foreground">
                      disconnected
                    </span>
                  )}
                </label>
              ))}
            </div>
          </ScrollArea>
        )}
        {scope !== null && scope.length === 0 && (
          <div
            data-testid="chat-scope-empty-warning"
            className="mt-1.5 rounded border border-amber-500/50 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-400"
          >
            The AI can't see any sessions in this chat.
          </div>
        )}
        <div className="mt-1.5 flex items-center gap-1 border-t pt-1.5">
          <button
            type="button"
            data-testid="chat-scope-all"
            onClick={() => void setChatScope(chat.chatId, null)}
            className="rounded px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            All devices
          </button>
          <button
            type="button"
            data-testid="chat-scope-none"
            onClick={() => void setChatScope(chat.chatId, [])}
            className="rounded px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            None
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
