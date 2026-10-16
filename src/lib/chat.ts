import { useCallback, useEffect, useRef, useState } from "react";

import { useQueryClient } from "@tanstack/react-query";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import {
  chatCancel,
  chatCreate,
  chatDestroy,
  chatMessages as chatMessagesIpc,
  chatSendMessage,
  chatSetModel,
  chatSetScope,
  type ChatListEntry,
  type ChatMessage,
  type ChatUsage,
} from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { toastError, toastInfo } from "@/lib/toast";
import { CHAT_TABS_MAX, useUiStore } from "@/stores/uiStore";

/** The backend chat-list query key (restore + reload-heal sync). The
 *  thunks below keep its never-stale cache truthful on create/close;
 *  Settings invalidates it when history is toggled. */
export const BACKEND_CHATS_QUERY_KEY = ["chats", "backend"] as const;

/**
 * Friendly label for a backend `stop_reason` (snake_case on the
 * wire). `end_turn` is the happy path and never toasts; `checkpoint`
 * is rendered by the inline Continue card, not a toast. The rest get
 * user-visible copy.
 */
function stopReasonLabel(reason: string): string {
  switch (reason) {
    case "stream_timeout":
      return "The model's response timed out";
    case "user_aborted":
      return "Investigation stopped";
    default:
      return `Investigation stopped (${reason})`;
  }
}

function stopReasonDescription(reason: string): string | undefined {
  switch (reason) {
    case "stream_timeout":
      return "Continue to retry from where it left off.";
    default:
      return undefined;
  }
}

/** Total tokens consumed across all buckets (input + output). */
function usageToTokens(u: ChatUsage): number {
  return u.input_uncached + u.input_cache_write + u.input_cache_read + u.output;
}

/**
 * Wire-shape `ChatMessage` augmented with a client-only stable id
 * for React keys. Backend doesn't care; we generate a uuid per
 * message at render time.
 */
export type ChatMessageView = ChatMessage & { _key: string };

function withKey(m: ChatMessage): ChatMessageView {
  return { ...m, _key: crypto.randomUUID() };
}

/**
 * `useChat(chatId)` — drives one chat session against the Rust
 * backend over Tauri commands + events.
 *
 * Lifecycle:
 *   - On chatId change → fetch the persisted message log via
 *     `chat_messages`, subscribe to that chat's event topics.
 *   - `send(text)` appends a user message + spawns a stream;
 *     deltas accumulate in `streamingText` until a `completed`
 *     event flushes them into `messages` as an Assistant entry.
 *   - `cancel()` aborts the in-flight stream (Rust side drops
 *     the reqwest body); we discard the partial text. Cursor's
 *     "stop the LLM mid-thought" UX expects the partial to vanish
 *     since the agent loop hasn't finalized it.
 */
export interface UseChatResult {
  messages: ChatMessageView[];
  /** Live-streaming assistant text (not yet committed to `messages`). */
  streamingText: string;
  /** True between send → completed/error/cancel. */
  isStreaming: boolean;
  /** Last-completed turn's token counts; null until first turn settles. */
  lastUsage: ChatUsage | null;
  /** Last error from the stream; null on success or if the user retries. */
  error: string | null;
  /** The backend's stable error marker for the last error (e.g.
   *  `missing_provider_key`, `plan_reauth_required`); null when unknown. */
  errorKind: string | null;
  /** Send a user message and start a stream. */
  send: (text: string) => Promise<void>;
  /** Stop the in-flight stream. */
  cancel: () => Promise<void>;
  /** Clear the displayed error (e.g. when the user starts typing again). */
  clearError: () => void;
  /** Tool-rounds completed in the current/last run (live activity). */
  rounds: number;
  /** Tokens consumed in the current run (live activity; never $). */
  liveTokens: number;
  /** `Date.now()` when the current stream started; null when idle. */
  streamStartedAt: number | null;
  /** Set when a run paused at a checkpoint; drives the Continue card. */
  pausedAtCheckpoint: { rounds: number; tokens: number } | null;
  /** One-click resume from a checkpoint pause. */
  continueRun: () => Promise<void>;
  /** Dismiss the checkpoint card without resuming (loop already ended). */
  dismissCheckpoint: () => void;
}

export function useChat(chatId: string | null): UseChatResult {
  const [messages, setMessages] = useState<ChatMessageView[]>([]);
  const [streamingText, setStreamingText] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [lastUsage, setLastUsage] = useState<ChatUsage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorKind, setErrorKind] = useState<string | null>(null);

  // Live activity readout (tokens + time + rounds — never dollars).
  const [rounds, setRounds] = useState(0);
  const [liveTokens, setLiveTokens] = useState(0);
  const [streamStartedAt, setStreamStartedAt] = useState<number | null>(null);
  // Set when a run pauses at a checkpoint; drives the one-click
  // Continue card. Tokens/rounds label the card — NO cost.
  const [pausedAtCheckpoint, setPausedAtCheckpoint] = useState<{
    rounds: number;
    tokens: number;
  } | null>(null);

  const queryClient = useQueryClient();

  // Accumulate deltas in a ref to avoid stale-closure bugs when
  // many text-delta events fire in quick succession. The ref is
  // the source of truth; `streamingText` is the rendered mirror.
  const streamingRef = useRef("");

  // Reset state when chatId changes.
  useEffect(() => {
    setRounds(0);
    setLiveTokens(0);
    setStreamStartedAt(null);
    setPausedAtCheckpoint(null);
    if (!chatId) {
      setMessages([]);
      setStreamingText("");
      setIsStreaming(false);
      setLastUsage(null);
      setError(null);
      streamingRef.current = "";
      return;
    }
    let cancelled = false;
    chatMessagesIpc(chatId)
      .then((m) => {
        if (!cancelled) setMessages(m.map(withKey));
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [chatId]);

  // Subscribe to per-chat events.
  useEffect(() => {
    if (!chatId) return;
    let unlistens: UnlistenFn[] = [];
    let cancelled = false;

    // Phase 6: cache the tool's name + `input` from the
    // tool-use-begin event so the matching tool-use-end can
    // include both in the ChatMessage. The end event only carries
    // the textual output + is_error flag.
    const pendingTools = new Map<string, { name: string; input: unknown }>();

    const subscribe = async () => {
      const deltaTopic = `chat:${chatId}:text-delta`;
      const completedTopic = `chat:${chatId}:completed`;
      const errorTopic = `chat:${chatId}:error`;
      const toolBeginTopic = `chat:${chatId}:tool-use-begin`;
      const toolEndTopic = `chat:${chatId}:tool-use-end`;
      const iterationTopic = `chat:${chatId}:iteration`;

      // Subscriptions are independent — race them in parallel rather
      // than waterfalling sequential awaits.
      const [
        unListenDelta,
        unListenCompleted,
        unListenError,
        unListenToolBegin,
        unListenToolEnd,
        unListenIteration,
      ] = await Promise.all([
        listen<{ delta: string }>(deltaTopic, (event) => {
          streamingRef.current += event.payload.delta;
          setStreamingText(streamingRef.current);
        }),
        listen<{ usage: ChatUsage; stop_reason: string; rounds: number }>(
          completedTopic,
          (event) => {
            const finalText = streamingRef.current;
            streamingRef.current = "";
            setStreamingText("");
            // Skip empty assistant bubbles — when a turn ended with
            // only tool calls and no final prose, the streaming
            // buffer is empty and an empty assistant message would
            // surface as a blank bubble in the chat thread.
            if (finalText.length > 0) {
              setMessages((prev) => [...prev, withKey({ role: "assistant", text: finalText })]);
            }
            setLastUsage(event.payload.usage);
            setIsStreaming(false);

            const reason = event.payload.stop_reason;
            if (reason === "checkpoint") {
              // Pause for a one-click Continue. The card labels
              // itself with rounds + tokens — never a dollar amount.
              setPausedAtCheckpoint({
                rounds: event.payload.rounds,
                tokens: usageToTokens(event.payload.usage),
              });
            } else if (reason === "user_aborted" || reason === "stream_timeout") {
              // Recoverable, non-error reasons get a brief toast.
              // (provider_error is surfaced via the error topic's
              // banner, so we don't double-toast it here.)
              toastInfo(stopReasonLabel(reason), {
                description: stopReasonDescription(reason),
              });
            }
          },
        ),
        listen<{ message: string; kind?: string }>(errorTopic, (event) => {
          streamingRef.current = "";
          setStreamingText("");
          setIsStreaming(false);
          if (
            event.payload.kind === "provider_overloaded" ||
            event.payload.kind === "rate_limited"
          ) {
            // Transient on the provider's side, not a failure of ours.
            // Show a soft, recoverable notice — no red inline error
            // banner — since a resend shortly almost always works.
            toastInfo("AI provider busy", { description: event.payload.message });
            return;
          }
          setError(event.payload.message);
          setErrorKind(event.payload.kind ?? null);
          toastError("Chat error", { description: event.payload.message });
        }),
        listen<{ id: string; call: { tool: string; [k: string]: unknown } }>(
          toolBeginTopic,
          (event) => {
            // The `call` payload is the ToolCall serialized
            // with `serde(tag = "tool")`, so the input fields
            // sit alongside `tool`. Pull the name out + stash
            // the rest as the input shape the model emitted.
            const { tool, ...input } = event.payload.call;
            pendingTools.set(event.payload.id, { name: tool, input });
          },
        ),
        listen<{ id: string; output: string; is_error: boolean }>(toolEndTopic, (event) => {
          const pending = pendingTools.get(event.payload.id);
          pendingTools.delete(event.payload.id);
          // Flush any in-flight assistant prose into its own
          // message before the tool-use card so the thread
          // reads in order: the model's "let me check" text
          // first, then the tool round.
          const inflightText = streamingRef.current;
          if (inflightText.length > 0) {
            streamingRef.current = "";
            setStreamingText("");
            setMessages((prev) => [...prev, withKey({ role: "assistant", text: inflightText })]);
          }
          setMessages((prev) => [
            ...prev,
            withKey({
              role: "tool_use",
              id: event.payload.id,
              name: pending?.name ?? "tool",
              input: pending?.input ?? null,
              output: event.payload.output,
              is_error: event.payload.is_error,
            }),
          ]);
        }),
        listen<{ iteration: number; cumulative_usage: ChatUsage }>(iterationTopic, (event) => {
          // Live activity: rounds run + tokens consumed this run.
          // (No cost — spend is never surfaced.)
          setRounds(event.payload.iteration);
          setLiveTokens(usageToTokens(event.payload.cumulative_usage));
        }),
      ]);

      if (cancelled) {
        unListenDelta();
        unListenCompleted();
        unListenError();
        unListenToolBegin();
        unListenToolEnd();
        unListenIteration();
        return;
      }
      unlistens = [
        unListenDelta,
        unListenCompleted,
        unListenError,
        unListenToolBegin,
        unListenToolEnd,
        unListenIteration,
      ];
    };

    void subscribe();
    return () => {
      cancelled = true;
      unlistens.forEach((fn) => fn());
    };
  }, [chatId, queryClient]);

  const send = useCallback(
    async (text: string) => {
      if (!chatId) return;
      const trimmed = text.trim();
      if (!trimmed) return;
      // Optimistically append the user message — backend appends
      // synchronously inside chat_send_message before spawning, so
      // the orderings agree by the time the next chat_messages fetch
      // runs.
      setMessages((prev) => [...prev, withKey({ role: "user", text: trimmed })]);
      streamingRef.current = "";
      setStreamingText("");
      setError(null);
      setRounds(0);
      setLiveTokens(0);
      setStreamStartedAt(Date.now());
      setPausedAtCheckpoint(null);
      setIsStreaming(true);
      try {
        await chatSendMessage(chatId, trimmed);
      } catch (err: unknown) {
        // The backend rejected the call (e.g. chat not found, or a
        // sync IPC-layer error). The stream task never spawned; clear
        // streaming state so the UI doesn't appear stuck.
        setError(err instanceof Error ? err.message : String(err));
        setIsStreaming(false);
      }
    },
    [chatId],
  );

  const cancel = useCallback(async () => {
    if (!chatId) return;
    try {
      await chatCancel(chatId);
    } catch {
      // Cancel-of-nothing is harmless; ignore.
    }
    streamingRef.current = "";
    setStreamingText("");
    setIsStreaming(false);
  }, [chatId]);

  const continueRun = useCallback(async () => {
    // One-click resume from a checkpoint pause. Reuses the per-turn
    // replay (history is preserved); a fresh round/token budget is
    // intended — the human is back in the loop.
    setPausedAtCheckpoint(null);
    await send("continue");
  }, [send]);

  const dismissCheckpoint = useCallback(() => setPausedAtCheckpoint(null), []);

  const clearError = useCallback(() => {
    setError(null);
    setErrorKind(null);
  }, []);

  return {
    messages,
    streamingText,
    isStreaming,
    lastUsage,
    error,
    errorKind,
    send,
    cancel,
    clearError,
    rounds,
    liveTokens,
    streamStartedAt,
    pausedAtCheckpoint,
    continueRun,
    dismissCheckpoint,
  };
}

// ---------------------------------------------------------------------
// Chat lifecycle thunks (v2.5.0 multi-chat).
//
// These replace the single-chat `useEnsureChat`: create/close/switch is
// now explicit and store-driven, so N concurrent chats can coexist.
// Message/stream state stays in `useChat(chatId)` (one instance per
// mounted tab); these only touch the backend + the uiStore `chats` slice.
// Because creation is now an explicit user action (not a mount effect),
// the old StrictMode create-race teardown is no longer needed.
// ---------------------------------------------------------------------

/**
 * v6.3.0 — apply the backend's chat list to the tab strip. ADD-only:
 * missing tabs are added (`addChat` no-ops duplicates and respects the
 * cap); existing tabs are never removed or re-modeled — the backend owns
 * existence, the frontend owns focus. Covers two cases with one code
 * path: restoring opt-in persisted history on launch, and healing
 * webview-reload orphans (backend sessions that lost their tabs).
 * Applies persisted custom labels to tabs it adds, then prunes the label
 * map to live ids so it never accumulates. Returns how many were added.
 */
export function applyBackendChats(entries: ChatListEntry[]): number {
  const store = useUiStore.getState();
  let added = 0;
  for (const entry of entries) {
    if (useUiStore.getState().chats.some((c) => c.chatId === entry.chat_id)) continue;
    store.addChat(entry.chat_id, entry.model);
    if (useUiStore.getState().chats.some((c) => c.chatId === entry.chat_id)) added += 1;
  }
  // ONE preferences write for labels + prune (a per-label localStorage
  // stringify at panel-paint time was measurable waste), and the action
  // itself refuses to prune on an empty live set — a transiently-empty
  // backend list (feature off, resolver error) must not wipe the label
  // map (review finding).
  const state = useUiStore.getState();
  state.applyRestoredChatLabels(state.preferences.chatLabelsById, [
    ...entries.map((e) => e.chat_id),
    ...state.chats.map((c) => c.chatId),
  ]);
  return added;
}

/** Create a backend chat, add its tab, and focus it. Capped at
 *  CHAT_TABS_MAX (the "+" is disabled at the cap; this is belt-and-braces
 *  and also destroys an orphan if the last slot fills during the await). */
export async function createChat(model: string): Promise<void> {
  if (useUiStore.getState().chats.length >= CHAT_TABS_MAX) return;
  let chatId: string;
  try {
    chatId = await chatCreate(model);
  } catch (err) {
    toastError("Couldn't start a chat session", {
      description: err instanceof Error ? err.message : String(err),
    });
    return;
  }
  useUiStore.getState().addChat(chatId, model);
  // addChat no-ops if the cap filled during the await — destroy the orphan
  // so a rejected tab doesn't strand a ChatSession in the Rust-side map.
  if (!useUiStore.getState().chats.some((c) => c.chatId === chatId)) {
    void chatDestroy(chatId).catch(() => {});
    return;
  }
  // Mirror the create into the backend-list cache (same truthfulness
  // contract as closeChat's filter above).
  queryClient.setQueryData<ChatListEntry[]>(BACKEND_CHATS_QUERY_KEY, (old) =>
    old ? [...old, { chat_id: chatId, model }] : old,
  );
}

/** Close a chat tab: update the store immediately (instant UI close +
 *  neighbor focus) then fire-and-forget destroy the backend session. The
 *  backend tolerates unknown ids, so racing a concurrent cancel/destroy
 *  is harmless. `chat_destroy` also scope-cancels that chat's pending
 *  approvals (Phase 5) so closing a chat mid-approval frees its loop. */
export function closeChat(chatId: string): void {
  useUiStore.getState().removeChat(chatId);
  // Keep the never-stale backend-list cache truthful: without this, a
  // panel remount inside gcTime replays the stale list and resurrects
  // this chat as a ghost tab over a destroyed session — stealing focus
  // and erroring "chat not found" on every send (review finding).
  queryClient.setQueryData<ChatListEntry[]>(BACKEND_CHATS_QUERY_KEY, (old) =>
    old?.filter((e) => e.chat_id !== chatId),
  );
  void chatDestroy(chatId).catch(() => {});
}

/** Change a chat's model in both the store and the backend session. */
export function changeChatModel(chatId: string, model: string): void {
  useUiStore.getState().setChatModel(chatId, model);
  void chatSetModel(chatId, model).catch(() => {});
}

/** v2.7.0 — set a chat's device scope (T31). Deliberately NOT the
 *  fire-and-forget pattern of `changeChatModel`: scope is a
 *  security-presenting control, and a dropped IPC would leave the UI
 *  claiming "2 of 5 devices" while the backend runs unscoped. So:
 *  optimistic store update → await the backend → on failure REVERT
 *  the store and toast. The UI must never advertise a scope the
 *  backend isn't enforcing. */
export async function setChatScope(chatId: string, deviceIds: string[] | null): Promise<void> {
  const prev =
    useUiStore.getState().chats.find((c) => c.chatId === chatId)?.scopedDeviceIds ?? null;
  useUiStore.getState().setChatScope(chatId, deviceIds);
  try {
    await chatSetScope(chatId, deviceIds);
  } catch (err) {
    useUiStore.getState().setChatScope(chatId, prev);
    toastError("Couldn't update the chat's device scope", {
      description: err instanceof Error ? err.message : String(err),
    });
  }
}

/** Open a new chat at the default model — the single entry point for the
 *  "+" button, the Cmd/Ctrl+T hotkey, and the command palette. Opens the
 *  chat panel first (so the new tab is visible + so ChatPanel is mounted),
 *  then creates. No-op until the key/local status has resolved a default model, in which
 *  case opening the empty panel triggers ChatPanel's first-run auto-create
 *  instead — so the user still ends up in a fresh chat. */
export function newChat(): void {
  const st = useUiStore.getState();
  if (!st.chatPanelOpen) st.toggleChatPanel();
  if (st.defaultChatModel) void createChat(st.defaultChatModel);
}
