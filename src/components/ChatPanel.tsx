import { useEffect, useMemo, useRef, useState } from "react";

import { MessageSquare, Plus, Send, Square, X } from "lucide-react";

import { AskUserCard } from "@/components/AskUserCard";
import { ChatBubble } from "@/components/ChatBubble";
import { ChatAutoApproveToggle } from "@/components/ChatAutoApproveToggle";
import { ChatScopePopover } from "@/components/ChatScopePopover";
import { CheckpointCard } from "@/components/CheckpointCard";
import { ScrollableTabStrip } from "@/components/ScrollableTabStrip";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsTrigger } from "@/components/ui/tabs";
import { useQuery } from "@tanstack/react-query";

import {
  AGENT_CHAT_SETTINGS_QUERY_KEY,
  chatList,
  getAgentChatSettings,
  providerForModel,
  providerKeysStatus,
  type ChatUsage,
} from "@/lib/api";
import {
  applyBackendChats,
  BACKEND_CHATS_QUERY_KEY,
  changeChatModel,
  closeChat,
  createChat,
  newChat,
  useChat,
} from "@/lib/chat";
import { composerPlaceholder, composerSendKey } from "@/lib/chatComposer";
import { isLocalModelId, useLocalModelsSettings, useLocalToolModels } from "@/lib/localModels";
import { useChatGptStatus } from "@/lib/chatgpt";
import {
  offeredProviderModels,
  pickDefaultModel,
  useProviderModels,
  type PickerLevel,
  type PickerModel,
} from "@/lib/providerModels";
import { toastInfo } from "@/lib/toast";
import { useDragResize } from "@/lib/useDragResize";
import { cn, formatTokens } from "@/lib/utils";
import { CHAT_FONT_SIZE_DEFAULT, CHAT_TABS_MAX, type ChatTab, useUiStore } from "@/stores/uiStore";

/** Display label for a chat tab: the user's rename, else "Chat N". */
function chatLabel(chat: ChatTab): string {
  const custom = chat.customLabel?.trim();
  return custom && custom.length > 0 ? custom : `Chat ${chat.seq}`;
}

/**
 * Right-hand chat panel — Phase 5d.A5.
 *
 * Layout (Cursor-matching):
 *
 *   ┌────────────────────────────────────────┐
 *   │  Chat   model ▾                  [×]   │  header
 *   ├────────────────────────────────────────┤
 *   │  ...message bubbles...                  │  scroll-area
 *   ├────────────────────────────────────────┤
 *   │  ┌─ textarea (auto-grow) ─┐             │  input
 *   │  │ Type a message...       │             │
 *   │  └─────────────────────────┘             │
 *   │  N input · M out · K% used      [Send]  │  usage line + send/stop
 *   └────────────────────────────────────────┘
 *
 * Gating: the AI can serve when at least one provider key is enrolled
 * (Settings → API keys) OR local models are on and offering a
 * tools-capable model. With neither, the panel shows a setup empty
 * state — never a sign-in, never an upsell (this edition has no
 * account).
 *
 * Phase 6: chat_send_message drives the AgentLoop end-to-end —
 * read-only tools (list_open_sessions, read_scrollback) execute
 * silently, propose_command surfaces the ProposeCommandDialog
 * approval modal, ask_user emits inline questions. Tool rounds
 * appear in the thread as chevron-collapsed cards via
 * `ChatBubble`'s ToolUseBubble variant; useChat wires the
 * `chat:{id}:tool-use-{begin,end}` events into the message log.
 * Stop aborts the loop via the per-session `Arc<Notify>` plumbed
 * through `ChatSession.cancel`.
 */
const CHAT_PANEL_MIN_WIDTH = 320;
const CHAT_PANEL_MAX_WIDTH_PCT = 0.7;
const CHAT_PANEL_DEFAULT_WIDTH = 420;

/** Query key for the provider-key status (shared with Settings → API keys
 *  so a Save there refreshes the picker here). */
export const PROVIDER_KEYS_QUERY_KEY = ["provider-keys", "status"] as const;

const LEVEL_ORDER: ReadonlyArray<PickerLevel> = ["easy", "medium", "advanced", "other"];

const LEVEL_LABELS: Readonly<Record<PickerLevel, string>> = {
  easy: "Easy — fast & cheap",
  medium: "Medium — balanced",
  advanced: "Advanced — deep reasoning",
  other: "Other",
};

function groupModels(offered: ReadonlyArray<PickerModel>): Record<PickerLevel, PickerModel[]> {
  const groups: Record<PickerLevel, PickerModel[]> = {
    easy: [],
    medium: [],
    advanced: [],
    other: [],
  };
  for (const m of offered) groups[m.level].push(m);
  return groups;
}

/** Backend error markers (`provider_error_kind` in chat.rs) that the user
 *  fixes in Settings → AI providers, so the banner offers the shortcut. */
const CREDENTIAL_ERROR_KINDS: ReadonlySet<string> = new Set([
  "missing_provider_key",
  "provider_key_rejected",
  "plan_cap_reached",
  "plan_not_eligible",
  "plan_reauth_required",
]);

export function ChatPanel() {
  const open = useUiStore((s) => s.chatPanelOpen);
  const toggle = useUiStore((s) => s.toggleChatPanel);
  const persistedWidth = useUiStore((s) => s.preferences.chatPanelWidth);
  const setChatPanelWidth = useUiStore((s) => s.setChatPanelWidth);

  const width = persistedWidth ?? CHAT_PANEL_DEFAULT_WIDTH;

  // Drag-to-resize from the panel's left edge. v6.5.2 — the mechanics
  // moved to the shared `useDragResize` hook when the left sidebars
  // became resizable too; the clamp is still [320px, 70% of viewport],
  // and the store persists each step so a drag survives an app restart.
  const {
    onMouseDown: onResizeStart,
    onDoubleClick: onResizeReset,
    onKeyDown: onResizeKey,
  } = useDragResize({
    edge: "left",
    min: CHAT_PANEL_MIN_WIDTH,
    maxPct: CHAT_PANEL_MAX_WIDTH_PCT,
    onWidth: setChatPanelWidth,
    defaultWidth: CHAT_PANEL_DEFAULT_WIDTH,
  });

  if (!open) {
    return (
      <aside
        data-testid="chat-panel-closed"
        className="flex h-full w-10 flex-col items-center border-l border-border bg-background py-2"
        aria-label="Chat (closed)"
      >
        <button
          type="button"
          onClick={toggle}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Open chat panel"
          title="Open chat (⌘/Ctrl+J)"
        >
          <MessageSquare className="h-4 w-4" />
        </button>
      </aside>
    );
  }

  return (
    <aside
      data-testid="chat-panel"
      className="relative flex h-full flex-col border-l border-border bg-background"
      style={{ width: `${width}px` }}
      aria-label="Assistant chat"
    >
      {/* Drag handle — a 4px-wide vertical strip on the panel's left
          edge. Sits absolutely so it doesn't take layout space; the
          larger hit area (8px) bleeds into the main pane by 4px,
          which is fine since that's the chat-panel border. */}
      <div
        role="separator"
        aria-label="Resize chat panel"
        aria-orientation="vertical"
        data-testid="chat-panel-resize-handle"
        aria-valuenow={width}
        aria-valuemin={CHAT_PANEL_MIN_WIDTH}
        tabIndex={0}
        title="Drag to resize · double-click to reset"
        onMouseDown={onResizeStart}
        onDoubleClick={onResizeReset}
        onKeyDown={(e) => onResizeKey(e, width)}
        className="absolute -left-1 top-0 z-10 h-full w-2 cursor-col-resize hover:bg-primary/20 focus-visible:bg-primary/30 active:bg-primary/30 focus-visible:outline-none"
      />
      <ChatPanelInner onClose={toggle} />
    </aside>
  );
}

function ChatPanelInner({ onClose }: { onClose: () => void }) {
  // Which providers have a key enrolled (booleans only — Rule 1). The
  // Settings → API keys tab invalidates this key on Save/Clear so the
  // picker updates without a reload.
  const { data: keys, isLoading: keysLoading } = useQuery({
    queryKey: PROVIDER_KEYS_QUERY_KEY,
    queryFn: providerKeysStatus,
    staleTime: 0,
    retry: false,
  });
  const customModelIds = useUiStore((s) => s.preferences.customModelIds);
  const cachedModels = useUiStore((s) => s.preferences.cachedModels);
  // The OpenAI side is "usable" through whichever method is selected: an
  // enrolled key, or a ChatGPT plan sign-in (preview). The effective key
  // status feeds the same offered-models logic either way.
  const chatgpt = useChatGptStatus();
  const planActive = chatgpt.data?.method === "chatgpt";
  const effectiveKeys = useMemo(() => {
    if (!keys) return undefined;
    const openaiUsable = planActive ? chatgpt.data?.signed_in === true : keys.openai;
    return { anthropic: keys.anthropic, openai: openaiUsable };
  }, [keys, planActive, chatgpt.data?.signed_in]);
  // Live discovery per usable provider (24 h stale, mirrored into the
  // cache above by the hook). A failed fetch falls back to the cache, then
  // to a short static list — never an empty picker while a provider can
  // serve.
  const anthropicModels = useProviderModels("anthropic", effectiveKeys?.anthropic === true);
  const openaiModels = useProviderModels("openai", effectiveKeys?.openai === true);
  const offered = useMemo(
    () =>
      offeredProviderModels(
        effectiveKeys,
        { anthropic: anthropicModels.data, openai: openaiModels.data },
        cachedModels,
        customModelIds,
      ),
    [effectiveKeys, anthropicModels.data, openaiModels.data, cachedModels, customModelIds],
  );
  const providerModelIds = useMemo(() => offered.map((m) => m.id), [offered]);
  const displayNameFor = (id: string) => offered.find((m) => m.id === id)?.displayName ?? id;
  const groupedModels = useMemo(() => groupModels(offered), [offered]);

  const chats = useUiStore((s) => s.chats);
  const activeChatId = useUiStore((s) => s.activeChatId);
  const setActiveChat = useUiStore((s) => s.setActiveChat);
  const setDefaultChatModel = useUiStore((s) => s.setDefaultChatModel);

  // ---- BYOM local models -----------------------------------------
  // Free in this edition: usable = feature enabled AND a tools-capable
  // model is actually offered.
  const localSettings = useLocalModelsSettings();
  const localFeatureOn = localSettings.data?.enabled === true;
  const { models: localModels, statusLoaded: localStatusLoaded } =
    useLocalToolModels(localFeatureOn);
  const localUsable = localFeatureOn && localModels.length > 0;

  // The AI is gated only when NEITHER a provider key nor a local model
  // can serve. Gating wraps ALL tabs: no tab strip or tab content
  // renders while gated.
  const providerUsable = offered.length > 0;
  const gated = !providerUsable && !localUsable;
  // Still resolving the key status (and, if local is on, the local
  // lists) — don't flash the setup empty state over a usable setup.
  const loading = keysLoading || (localFeatureOn && !localStatusLoaded && !providerUsable);

  // Publish the default new-chat model so the `newChat()` thunk (invoked
  // from the "+", Cmd/Ctrl+T, or the palette — none of which see the key
  // status) can create at the right model even while the panel is
  // collapsed. Provider first (preferred id, else newest), else the first
  // local.
  const defaultModel = pickDefaultModel(offered) ?? localModels[0]?.id ?? null;
  useEffect(() => {
    if (defaultModel) setDefaultChatModel(defaultModel);
  }, [defaultModel, setDefaultChatModel]);

  // v6.3.0 — sync the tab strip against the backend's chat list once per
  // panel mount. The backend lazily restores opt-in persisted history on
  // this call, and the sync also heals webview-reload orphans; create/
  // close keep the cache truthful (BACKEND_CHATS_QUERY_KEY maintenance
  // in lib/chat.ts), and the Settings history toggle invalidates it.
  // Query owns the fetch (server state, §11).
  const backendChats = useQuery({
    queryKey: BACKEND_CHATS_QUERY_KEY,
    queryFn: chatList,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  // v6.3.0 — the Save-on-code-blocks gate, ONE observer for all tabs
  // (ChatBubble stays provider-free for its XSS tests; the key is the
  // exported const so the Settings toggle's invalidation reaches this).
  const agentChatSettings = useQuery({
    queryKey: AGENT_CHAT_SETTINGS_QUERY_KEY,
    queryFn: getAgentChatSettings,
  });
  const canSaveSnippets = agentChatSettings.data?.save_to_file === true;
  // ONE effect for apply + first-run create, sequential in one function —
  // an earlier draft split them across two effects coordinated by
  // same-commit ordering plus a live store re-read, which review flagged
  // as exactly the shape a future exhaustive-deps cleanup silently
  // breaks. Ref-guarded against StrictMode's double-invoke + the create
  // round-trip.
  // Store-driven, not an event handler — react-doctor's rule doesn't fit.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  const creatingRef = useRef(false);
  // An errored list reads as empty — a transient chat_list failure must
  // not block the first-run auto-create forever.
  const backendList = backendChats.data ?? (backendChats.isError ? [] : undefined);
  useEffect(() => {
    if (!backendList) return;
    applyBackendChats(backendList);
    if (gated || creatingRef.current || !defaultModel) return;
    // Live read guards only PRE-EXISTING tabs now (apply just ran
    // synchronously above); restored tabs are already in the store.
    if (useUiStore.getState().chats.length > 0) return;
    creatingRef.current = true;
    void createChat(defaultModel).finally(() => {
      creatingRef.current = false;
    });
  }, [backendList, gated, defaultModel]);

  const activeChat = chats.find((c) => c.chatId === activeChatId) ?? null;

  // Reconcile a selection that's no longer offered:
  //  - a provider model whose key was cleared (or a custom id removed);
  //  - a local model that disappeared (Ollama stopped, model removed,
  //    endpoint deleted) — but only once the local lists have LOADED,
  //    so a transient fetch never thrashes the selection.
  useEffect(() => {
    if (!activeChat || effectiveKeys === undefined) return;
    if (!isLocalModelId(activeChat.model) && !providerModelIds.includes(activeChat.model)) {
      // Fall back to another provider model (a mixed-provider user
      // clearing one key must land on the other provider's model, not
      // strand), else a loaded local one. No fallback at all → leave the
      // selection: the panel is about to gate anyway, and the model is
      // restored the moment the key comes back.
      const provider = providerForModel(activeChat.model) === "anthropic" ? "Anthropic" : "OpenAI";
      const fallback =
        pickDefaultModel(offered) ?? (localStatusLoaded ? localModels[0]?.id : undefined);
      if (fallback && fallback !== activeChat.model) {
        const fallbackName =
          localModels.find((m) => m.id === fallback)?.label ?? displayNameFor(fallback);
        changeChatModel(activeChat.chatId, fallback);
        toastInfo(
          `${displayNameFor(activeChat.model)} needs your ${provider} key. Switched to ${fallbackName}.`,
        );
      }
      return;
    }
    if (
      isLocalModelId(activeChat.model) &&
      localStatusLoaded &&
      !localModels.some((m) => m.id === activeChat.model) &&
      defaultModel &&
      defaultModel !== activeChat.model
    ) {
      changeChatModel(activeChat.chatId, defaultModel);
      toastInfo("That local model isn't available right now. Switched models.");
    }
  }, [
    activeChat,
    effectiveKeys,
    offered,
    providerModelIds,
    localModels,
    localStatusLoaded,
    defaultModel,
  ]);

  return (
    <Tabs
      // Keep the controlled value a string: `?? ""` (not `undefined`) so the
      // pre-first-chat state doesn't flip Radix Tabs to uncontrolled (#18).
      value={activeChatId ?? ""}
      onValueChange={setActiveChat}
      className="flex min-h-0 flex-1 flex-col"
    >
      <header className="flex h-12 items-center gap-2 border-b border-border px-3">
        <MessageSquare className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold tracking-wide">Chat</h2>
        {!gated && activeChat && (
          <Select
            value={activeChat.model}
            onValueChange={(m) => changeChatModel(activeChat.chatId, m)}
          >
            <SelectTrigger
              data-testid="chat-model-picker"
              className="ml-2 h-7 w-auto border-none bg-transparent px-2 text-xs text-muted-foreground hover:bg-accent focus:ring-0"
            >
              <SelectValue placeholder="Model" />
            </SelectTrigger>
            <SelectContent>
              {/* Provider groups render only while a key can serve them —
                  hidden (not disabled) in local-only mode, which is
                  simpler and truthful. */}
              {providerUsable && planActive && effectiveKeys?.openai && (
                <SelectGroup data-testid="chat-model-source">
                  <SelectLabel className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
                    OpenAI models bill your ChatGPT plan
                  </SelectLabel>
                </SelectGroup>
              )}
              {providerUsable &&
                LEVEL_ORDER.map((level) => {
                  const models = groupedModels[level];
                  if (models.length === 0) return null;
                  return (
                    <SelectGroup key={level} data-testid={`chat-model-group-${level}`}>
                      <SelectLabel className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
                        {LEVEL_LABELS[level]}
                      </SelectLabel>
                      {models.map((m) => (
                        <SelectItem key={m.id} value={m.id} className="text-xs">
                          {m.displayName}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  );
                })}
              {/* BYOM (v3.0.0): tools-capable local models. Labels
                  carry the source (`· local` / `· <endpoint name>`);
                  unverified tool support (OpenAI-compat endpoints) is
                  flagged rather than hidden. */}
              {localUsable && (
                <SelectGroup data-testid="chat-model-group-local">
                  <SelectLabel className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
                    Local — your hardware
                  </SelectLabel>
                  {localModels.map((m) => (
                    <SelectItem key={m.id} value={m.id} className="text-xs">
                      {m.label}
                      {m.toolsVerified ? "" : " (tools unverified)"}
                    </SelectItem>
                  ))}
                </SelectGroup>
              )}
            </SelectContent>
          </Select>
        )}
        {/* v2.7.0 — per-chat device scope (T31). Same gating as the
            model picker; scopes THIS chat's agent to checked devices. */}
        {!gated && activeChat && <ChatScopePopover chat={activeChat} />}
        {/* v4.0.0 — auto-approve-GET indicator + off-switch (M1). Renders
            only when this chat is auto-approving the agent's read-only GETs. */}
        {!gated && activeChat && <ChatAutoApproveToggle chat={activeChat} />}
        <div className="flex-1" />
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Close chat panel"
          title="Close (⌘/Ctrl+J)"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      {gated && loading ? (
        <LoadingState />
      ) : gated ? (
        <NoModelsState />
      ) : (
        <>
          <ChatTabStrip chats={chats} activeChatId={activeChatId} />
          {chats.map((c) => (
            <TabsContent
              key={c.chatId}
              value={c.chatId}
              forceMount
              // Every chat stays mounted (its useChat keeps streaming);
              // inactive ones are display:none'd. Mirrors the terminal
              // pane's forceMount + hidden pattern so switching tabs
              // never drops an in-flight stream.
              className="m-0 flex-1 min-h-0 data-[state=inactive]:hidden"
            >
              <ChatTabContent chatId={c.chatId} canSaveSnippets={canSaveSnippets} />
            </TabsContent>
          ))}
        </>
      )}
    </Tabs>
  );
}

/** The chat tab strip: scrollable row of chat tabs + a "+" new-chat
 *  button. Reuses the terminal's `ScrollableTabStrip`. */
function ChatTabStrip({ chats, activeChatId }: { chats: ChatTab[]; activeChatId: string | null }) {
  const atCap = chats.length >= CHAT_TABS_MAX;
  return (
    <div className="flex items-center border-b border-border pr-1.5">
      <ScrollableTabStrip activeTabId={activeChatId}>
        {chats.map((c) => (
          <ChatTabTrigger key={c.chatId} chat={c} active={c.chatId === activeChatId} />
        ))}
      </ScrollableTabStrip>
      <button
        type="button"
        onClick={() => newChat()}
        disabled={atCap}
        aria-label="New chat"
        title={atCap ? `Chat limit reached (${CHAT_TABS_MAX})` : "New chat (⌘/Ctrl+T)"}
        data-testid="chat-new-tab"
        className="ml-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-40"
      >
        <Plus className="h-4 w-4" />
      </button>
    </div>
  );
}

/** A single chat tab: label (double-click to rename) + a status dot
 *  (yellow = pending approval, green = completed while unfocused) + an X
 *  to close. Mirrors the terminal `TabTrigger`. */
function ChatTabTrigger({ chat, active }: { chat: ChatTab; active: boolean }) {
  const setChatLabel = useUiStore((s) => s.setChatLabel);
  const pending = useUiStore((s) => !!s.pendingApprovalByChat[chat.chatId]);
  const completed = useUiStore((s) => !!s.completedUnfocusedByChat[chat.chatId]);
  const label = chatLabel(chat);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(label);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing) {
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    }
  }, [editing]);

  const startRename = () => {
    setDraft(chat.customLabel ?? label);
    setEditing(true);
  };
  const commit = () => {
    const trimmed = draft.trim();
    setChatLabel(chat.chatId, trimmed.length === 0 ? null : trimmed);
    setEditing(false);
  };

  return (
    <div className="group flex items-center gap-1 rounded [&:has([data-state=active])]:bg-background [&:has([data-state=active])]:shadow">
      <TabsTrigger
        value={chat.chatId}
        data-testid={`chat-tab-${chat.chatId}`}
        className="bg-transparent shadow-none data-[state=active]:bg-transparent data-[state=active]:shadow-none"
        onDoubleClick={(e) => {
          e.preventDefault();
          startRename();
        }}
      >
        {editing ? (
          <input
            ref={inputRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                commit();
              } else if (e.key === "Escape") {
                e.preventDefault();
                setEditing(false);
              }
              e.stopPropagation();
            }}
            onBlur={commit}
            onClick={(e) => e.stopPropagation()}
            className="w-20 bg-transparent text-xs outline-none ring-1 ring-ring rounded px-1"
            data-testid={`chat-tab-rename-${chat.chatId}`}
            aria-label="Chat name"
          />
        ) : (
          <span className="max-w-[10rem] truncate text-xs">{label}</span>
        )}
        {/* Status dot — only for a NON-active tab. Yellow (pending
            approval) wins over green (completed while unfocused). */}
        {!active && pending && (
          <span
            data-testid={`chat-dot-pending-${chat.chatId}`}
            title="Needs command approval"
            className="ml-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500"
          />
        )}
        {!active && !pending && completed && (
          <span
            data-testid={`chat-dot-done-${chat.chatId}`}
            title="Task complete"
            className="ml-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500"
          />
        )}
      </TabsTrigger>
      <button
        type="button"
        aria-label={`Close ${label}`}
        onClick={(e) => {
          e.stopPropagation();
          closeChat(chat.chatId);
        }}
        className="mr-1 flex h-4 w-4 items-center justify-center rounded text-muted-foreground opacity-60 hover:bg-accent hover:text-foreground hover:opacity-100"
      >
        <X className="h-3 w-3" />
      </button>
    </div>
  );
}

/** Hosts one chat's `useChat` + `ChatBody`. One instance per tab stays
 *  mounted (see the `forceMount` TabsContent) so a backgrounded chat's
 *  stream survives tab switches. */
function ChatTabContent({ chatId, canSaveSnippets }: { chatId: string; canSaveSnippets: boolean }) {
  const chat = useChat(chatId);
  return (
    <div className={cn("flex h-full min-h-0 flex-col")}>
      <ChatBody chatId={chatId} canSaveSnippets={canSaveSnippets} {...chat} />
    </div>
  );
}

function ChatBody({
  chatId,
  messages,
  streamingText,
  isStreaming,
  lastUsage,
  error,
  errorKind,
  clearError,
  send,
  cancel,
  canSaveSnippets,
  rounds,
  liveTokens,
  streamStartedAt,
  pausedAtCheckpoint,
  continueRun,
  dismissCheckpoint,
}: {
  chatId: string | null;
  /** v6.3.0 — Save-on-code-blocks gate, hoisted to ChatPanelInner (ONE
   *  query observer instead of one per forceMounted tab). The backend
   *  command re-checks on every
   *  save regardless; this only shows/hides the button. */
  canSaveSnippets: boolean;
  messages: ReturnType<typeof useChat>["messages"];
  streamingText: string;
  isStreaming: boolean;
  lastUsage: ChatUsage | null;
  error: string | null;
  errorKind: string | null;
  clearError: () => void;
  send: (text: string) => Promise<void>;
  cancel: () => Promise<void>;
  rounds: number;
  liveTokens: number;
  streamStartedAt: number | null;
  pausedAtCheckpoint: { rounds: number; tokens: number } | null;
  continueRun: () => Promise<void>;
  dismissCheckpoint: () => void;
}) {
  const [input, setInput] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  // v6.1.0 — a button-bar macro whose target is "agent" parks its text in
  // the store; the composer picks it up here. FILL, not send: the user
  // reads it and presses Enter, so a saved prompt stays one glance from
  // being edited for the case at hand.
  //
  // Appends to whatever is already typed rather than clobbering it — a
  // half-written question is the user's work, and losing it to a stray
  // click would be worse than the macro not firing.
  const pendingAgentPrompt = useUiStore((s) => s.pendingAgentPrompt);
  const consumeAgentPrompt = useUiStore((s) => s.consumeAgentPrompt);
  const openSettingsDialog = useUiStore((s) => s.openSettingsDialog);
  // ⚠️ EVERY chat tab mounts its own ChatBody (the TabsContent above uses
  // `forceMount` so backgrounded streams keep running), so this effect
  // runs in all of them at once. Without the active-chat guard they would
  // race to consume the queued text and it could land in a hidden tab —
  // a click that appears to do nothing.
  const isActiveChat = useUiStore((s) => s.activeChatId) === chatId;
  // Store-driven, not an event handler — react-doctor's rule doesn't fit.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (!isActiveChat || pendingAgentPrompt === null) return;
    const text = consumeAgentPrompt();
    if (!text) return;
    setInput((prev) => (prev.trim().length > 0 ? `${prev.trimEnd()} ${text}` : text));
    textareaRef.current?.focus();
  }, [isActiveChat, pendingAgentPrompt, consumeAgentPrompt]);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const userScrolledUp = useRef(false);
  const chatFontSize = useUiStore((s) => s.preferences.chatFontSize) ?? CHAT_FONT_SIZE_DEFAULT;
  const sendOnEnter = useUiStore((s) => s.preferences.chatSendOnEnter);

  // Auto-scroll on new content unless the user has scrolled up to
  // re-read history. 20px tolerance for "at the bottom".
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (userScrolledUp.current) return;
    el.scrollTop = el.scrollHeight;
  }, [messages, streamingText]);

  function onScroll(e: React.UIEvent<HTMLDivElement>) {
    const el = e.currentTarget;
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    userScrolledUp.current = distFromBottom > 20;
  }

  async function handleSend() {
    if (isStreaming) return;
    const text = input.trim();
    if (!text) return;
    setInput("");
    requestAnimationFrame(() => {
      if (textareaRef.current) {
        textareaRef.current.style.height = "auto";
      }
    });
    await send(text);
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (!composerSendKey(e, sendOnEnter)) return;
    // Claim the key ONLY when a send will actually happen. The composer
    // stays enabled during a stream on purpose, so a bare Enter that
    // can't send (mid-stream, or an empty draft) must fall through to
    // the newline — preventDefault-then-no-op would swallow the
    // keystroke entirely (v6.3.0 review finding). Cmd/Ctrl+Enter keeps
    // its historic claim-and-drop on an unsendable draft.
    if (isStreaming || input.trim().length === 0) {
      if (e.metaKey || e.ctrlKey) e.preventDefault();
      return;
    }
    e.preventDefault();
    void handleSend();
  }

  function autosize(e: React.ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value);
    if (error) clearError();
    const el = e.target;
    el.style.height = "auto";
    // Cap at ~6 lines so a long paste doesn't push the chat
    // off-screen — internal scroll takes over past the cap.
    el.style.height = `${Math.min(el.scrollHeight, 144)}px`;
  }

  return (
    <>
      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="flex-1 space-y-4 overflow-y-auto p-3"
        style={{ fontSize: `${chatFontSize}px` }}
        data-testid="chat-scrollarea"
      >
        {messages.length === 0 && !isStreaming && (
          <p className="text-center text-xs text-muted-foreground">
            Ask anything about your open sessions. Commands the agent proposes run only after your
            explicit approval.
          </p>
        )}
        {messages.map((m) => (
          <ChatBubble key={m._key} message={m} canSaveSnippets={canSaveSnippets} />
        ))}
        {isStreaming && streamingText.length > 0 && (
          <ChatBubble
            key="__streaming"
            message={{ role: "assistant", text: streamingText }}
            streaming
          />
        )}
        {error && (
          <div
            className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
            role="alert"
          >
            {error}
            {errorKind !== null && CREDENTIAL_ERROR_KINDS.has(errorKind) && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="ml-2 h-6 px-2 text-[11px]"
                data-testid="chat-error-open-settings"
                onClick={() => openSettingsDialog("api-keys")}
              >
                Open Settings → AI providers
              </Button>
            )}
          </div>
        )}
        <AskUserCard chatId={chatId} />
        {pausedAtCheckpoint && !isStreaming && (
          <CheckpointCard
            rounds={pausedAtCheckpoint.rounds}
            tokens={pausedAtCheckpoint.tokens}
            onContinue={() => void continueRun()}
            onDismiss={dismissCheckpoint}
          />
        )}
      </div>

      {isStreaming && (
        <ActivityLine rounds={rounds} tokens={liveTokens} streamStartedAt={streamStartedAt} />
      )}

      <div className="border-t border-border p-3">
        <div className="rounded-md border border-input bg-background focus-within:ring-1 focus-within:ring-ring">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={autosize}
            onKeyDown={onKeyDown}
            placeholder={composerPlaceholder("Ask anything", sendOnEnter)}
            rows={1}
            className="w-full resize-none bg-transparent px-3 py-2 text-sm outline-none placeholder:text-muted-foreground"
            data-testid="chat-input"
          />
          <div className="flex items-center justify-between gap-2 border-t border-border px-2 py-1">
            <UsageLine usage={lastUsage} />
            {isStreaming ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 gap-1 px-2"
                onClick={() => void cancel()}
              >
                <Square className="h-3 w-3" />
                Stop
              </Button>
            ) : (
              <Button
                type="button"
                size="sm"
                className="h-7 gap-1 px-2"
                disabled={input.trim().length === 0}
                onClick={() => void handleSend()}
              >
                <Send className="h-3 w-3" />
                Send
              </Button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

function UsageLine({ usage }: { usage: ChatUsage | null }) {
  const inputTotal = usage
    ? usage.input_uncached + usage.input_cache_read + usage.input_cache_write
    : 0;
  return (
    <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
      {usage ? (
        <span>
          {inputTotal} in · {usage.output} out
        </span>
      ) : (
        <span className="text-muted-foreground/60">no usage yet</span>
      )}
    </div>
  );
}

/**
 * Live activity readout shown while a run streams: a pulsing dot plus
 * `running · N commands · 1m24s · 18.2k tokens`. Tokens + elapsed
 * time only — NO dollar/cost figure is ever displayed (product
 * requirement). The 1Hz elapsed ticker lives here so the chat hook
 * stays timer-free.
 */
function ActivityLine({
  rounds,
  tokens,
  streamStartedAt,
}: {
  rounds: number;
  tokens: number;
  streamStartedAt: number | null;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (streamStartedAt === null) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [streamStartedAt]);
  const elapsedMs = streamStartedAt === null ? 0 : Math.max(0, now - streamStartedAt);
  const commands = rounds > 0 ? `${rounds} command${rounds === 1 ? "" : "s"} · ` : "";
  return (
    <div
      className="flex items-center gap-2 px-3 pb-1 text-[11px] text-muted-foreground"
      data-testid="chat-activity-line"
    >
      <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
      <span>
        running · {commands}
        {formatElapsed(elapsedMs)} · {formatTokens(tokens)} tokens
      </span>
    </div>
  );
}

function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return m > 0 ? `${m}m${s.toString().padStart(2, "0")}s` : `${s}s`;
}

function NoModelsState() {
  const openSettingsDialog = useUiStore((s) => s.openSettingsDialog);
  return (
    <div
      data-testid="chat-no-models-state"
      className="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center"
    >
      <p className="text-sm font-medium">Choose how the assistant runs</p>
      <p className="text-xs text-muted-foreground">
        Add your own Anthropic or OpenAI API key — it is stored in your OS keychain and sent only to
        that provider — or run models on your own hardware with Ollama or a self-hosted endpoint.
        Either way, proposed commands still require your explicit approval.
      </p>
      <div className="flex gap-2">
        <Button
          type="button"
          size="sm"
          data-testid="chat-setup-api-keys"
          onClick={() => openSettingsDialog("api-keys")}
        >
          Add an API key
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          data-testid="chat-setup-local"
          onClick={() => openSettingsDialog("local-models")}
        >
          Set up local models
        </Button>
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="flex flex-1 items-center justify-center text-xs text-muted-foreground">
      Loading…
    </div>
  );
}
