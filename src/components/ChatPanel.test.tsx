import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ChatPanel } from "@/components/ChatPanel";
import { useUiStore } from "@/stores/uiStore";

// ---- Tauri event listener capture ----
type Handler = (event: { payload: unknown }) => void;
const handlers = new Map<string, Set<Handler>>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: Handler) => {
    if (!handlers.has(eventName)) handlers.set(eventName, new Set());
    handlers.get(eventName)!.add(handler);
    return () => {
      handlers.get(eventName)?.delete(handler);
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  AGENT_CHAT_SETTINGS_QUERY_KEY: ["agentChat", "settings"],
  // Which providers have a key enrolled. Default: none — the panel
  // shows its setup empty state until a test enrolls one.
  providerKeysStatus: vi.fn(async () => ({ anthropic: false, openai: false })),
  providerForModel: (id: string) => (id.includes("claude") ? "anthropic" : "openai"),
  // Sign in with ChatGPT (preview): default = API-key method, signed out.
  chatgptStatus: vi.fn(async () => ({ signed_in: false, email: null, method: "api_key" })),
  chatgptSigninStart: vi.fn(async () => undefined),
  chatgptSigninCancel: vi.fn(async () => undefined),
  chatgptSignout: vi.fn(async () => ({ revoked: true })),
  providerOpenaiMethodSet: vi.fn(async () => undefined),
  // Live model discovery per key. Fixtures are the real wire shape; the
  // registry no longer exists, so these ARE the picker's contents.
  providerModelsList: vi.fn(async (provider: "anthropic" | "openai") =>
    provider === "anthropic"
      ? [
          {
            id: "claude-opus-5-5",
            display_name: "Claude Opus 5.5",
            created: 1_788_220_800,
            level: "advanced",
            context_window: 1_000_000,
          },
          {
            id: "claude-sonnet-5-5",
            display_name: "Claude Sonnet 5.5",
            created: 1_785_542_400,
            level: "medium",
            context_window: 1_000_000,
          },
          {
            id: "claude-haiku-4-5",
            display_name: "Claude Haiku 4.5",
            created: 1_759_276_800,
            level: "easy",
            context_window: 200_000,
          },
        ]
      : [
          {
            id: "gpt-5.6-sol",
            display_name: "GPT-5.6 Sol",
            created: 1_790_000_000,
            level: "advanced",
            context_window: null,
          },
          {
            id: "gpt-5.6-terra",
            display_name: "GPT-5.6 Terra",
            created: 1_789_000_000,
            level: "medium",
            context_window: null,
          },
          {
            id: "gpt-5.6-luna",
            display_name: "GPT-5.6 Luna",
            created: 1_788_000_000,
            level: "easy",
            context_window: null,
          },
        ],
  ),
  chatCreate: vi.fn(async (_model: string) => "chat-1"),
  chatDestroy: vi.fn(async () => undefined),
  chatMessages: vi.fn(async () => []),
  // v6.3.0 — the backend chat list (restore + reload-heal sync). Empty by
  // default so the first-run effect creates its usual fresh chat.
  chatList: vi.fn(async () => []),
  // v6.3.0 — Agent Chat settings gate for the code-block Save button.
  getAgentChatSettings: vi.fn(async () => ({
    persist_history: false,
    history_dir: "/tmp/chats",
    history_dir_configured: null,
    persist_history_env_override: false,
    history_dir_env_override: false,
    save_to_file: false,
    save_dir: "/tmp/snippets",
    save_dir_configured: null,
    save_to_file_env_override: false,
    save_dir_env_override: false,
  })),
  saveChatSnippet: vi.fn(async () => null),
  // Must return a promise — `changeChatModel` chains `.catch()` on it
  // (a bare vi.fn() returns undefined and detonates the reconcile
  // effect the moment any test exercises it).
  chatSetModel: vi.fn(async () => undefined),
  chatSetScope: vi.fn(async () => undefined),
  chatSendMessage: vi.fn(async () => undefined),
  chatCancel: vi.fn(),
  // v3.0.0 BYOM — defaults keep local models fully OFF so the legacy
  // gating paths stay byte-identical; the BYOM tests override these.
  getLocalModelsSettings: vi.fn(async () => ({
    enabled: false,
    base_url: "http://127.0.0.1:11434",
    num_ctx: 16384,
    keep_alive: "15m",
    env_override: false,
    warning: null,
  })),
  localModelsStatus: vi.fn(async () => ({
    enabled: false,
    reachable: false,
    base_url: "http://127.0.0.1:11434",
    version: null,
    version_supported: null,
    models: [],
    hidden_cloud_models: [],
    error: null,
    warning: null,
  })),
  localEndpointsStatus: vi.fn(async () => []),
}));

// `useEnsureChat` toasts chat_create failures (no console.* allowed);
// mock the toast surface so the failure path is assertable.
vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(async () => undefined),
}));

vi.mock("@/lib/toast", () => ({
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastInfo: vi.fn(),
  toastPromise: vi.fn(<T,>(p: Promise<T>) => p),
}));

function fireEvent(name: string, payload: unknown) {
  act(() => {
    handlers.get(name)?.forEach((h) => h({ payload }));
  });
}

function makeQc(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderPanel(qc?: QueryClient) {
  const client = qc ?? makeQc();
  return render(
    <QueryClientProvider client={client}>
      <ChatPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  useUiStore.setState({
    chatPanelOpen: false,
    // Reset the v2.5.0 chat slice so chats don't leak across tests.
    chats: [],
    activeChatId: null,
    chatSeq: 0,
    pendingApprovalByChat: {},
    completedUnfocusedByChat: {},
    defaultChatModel: null,
  });
  handlers.clear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("ChatPanel — closed", () => {
  it("renders the closed gutter when chatPanelOpen is false", () => {
    renderPanel();
    expect(screen.getByTestId("chat-panel-closed")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-panel")).not.toBeInTheDocument();
  });

  it("clicking the open button flips chatPanelOpen", async () => {
    renderPanel();
    await userEvent.click(screen.getByRole("button", { name: /open chat panel/i }));
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });
});

describe("ChatPanel — resize handle (Phase 7a)", () => {
  beforeEach(() => {
    useUiStore.setState({
      chatPanelOpen: true,
      preferences: {
        themeId: null,
        chatPanelWidth: null,
        sidebarWidth: null,
        chatPanelOpen: null,
        terminalFontSize: null,
        terminalFontFamily: null,
        chatFontSize: null,
        customModelIds: [],
        cachedModels: {},
        collapsedGroups: {},
        showButtonBar: false,
        buttonBars: [{ id: "bar-1", name: "Default", buttons: [] }],
        activeButtonBarId: "bar-1",
        showBroadcastBar: false,
        notifyOnUnfocusedComplete: true,
        chatSendOnEnter: true,
        chatLabelsById: {},
        warnOnSessionClose: true,
      },
    });
    // jsdom default innerWidth is 1024.
    Object.defineProperty(window, "innerWidth", { value: 1200, configurable: true });
  });

  it("renders a drag handle on the open panel", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    renderPanel();
    expect(await screen.findByTestId("chat-panel-resize-handle")).toBeInTheDocument();
  });

  it("mousedown + mousemove updates preferences.chatPanelWidth", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    renderPanel();
    const handle = await screen.findByTestId("chat-panel-resize-handle");

    act(() => {
      handle.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, clientX: 780 }));
    });
    act(() => {
      window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 600 }));
    });
    // 1200 - 600 = 600px requested → clamped into [320, 1200*0.7=840].
    expect(useUiStore.getState().preferences.chatPanelWidth).toBe(600);

    act(() => {
      window.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    });
  });

  it("clamps below the minimum (320px)", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    renderPanel();
    const handle = await screen.findByTestId("chat-panel-resize-handle");

    act(() => {
      handle.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    act(() => {
      // 1200 - 1190 = 10px → clamped to 320.
      window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 1190 }));
    });
    expect(useUiStore.getState().preferences.chatPanelWidth).toBe(320);

    act(() => {
      window.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    });
  });

  it("clamps above the maximum (70% of innerWidth)", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    renderPanel();
    const handle = await screen.findByTestId("chat-panel-resize-handle");

    act(() => {
      handle.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    act(() => {
      // 1200 - 0 = 1200px requested → clamped to floor(1200*0.7)=840.
      window.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, clientX: 0 }));
    });
    expect(useUiStore.getState().preferences.chatPanelWidth).toBe(840);

    act(() => {
      window.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    });
  });
});

describe("ChatPanel — a provider key is enrolled", () => {
  const anthropicKey = { anthropic: true, openai: false };

  it("renders the input area + usage bar; default model is the preferred discovered model", async () => {
    const { providerKeysStatus, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    expect(await screen.findByTestId("chat-input")).toBeInTheDocument();
    // Never a budget/plan readout — there is no plan.
    expect(screen.queryByText(/of budget/i)).not.toBeInTheDocument();
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("claude-sonnet-5-5"));
  });

  it("Send → chatSendMessage; appends user bubble; streams deltas; completed flushes assistant", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    const qc = makeQc();
    const invalidate = vi.spyOn(qc, "invalidateQueries");
    renderPanel(qc);

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "hello");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    await waitFor(() => expect(chatSendMessage).toHaveBeenCalledWith("chat-1", "hello"));
    expect(await screen.findByText("hello")).toBeInTheDocument();

    fireEvent("chat:chat-1:text-delta", { delta: "Hi" });
    fireEvent("chat:chat-1:text-delta", { delta: " there" });
    expect(await screen.findByText(/Hi there/i)).toBeInTheDocument();

    fireEvent("chat:chat-1:completed", {
      usage: { input_uncached: 5, input_cache_write: 0, input_cache_read: 0, output: 2 },
    });

    expect(await screen.findByText(/Hi there/i)).toBeInTheDocument();
    expect(await screen.findByText(/5 in · 2 out/i)).toBeInTheDocument();
    // No account query exists to refresh.
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ["cloud", "me"] });
  });

  it("restored backend chats populate the tab strip and suppress the auto-create (v6.3.0)", async () => {
    const { providerKeysStatus, chatList, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    // Once-scoped: the factory default (empty list) must return for
    // every later test or they'd all inherit these restored tabs.
    vi.mocked(chatList).mockResolvedValueOnce([
      { chat_id: "chat-r1", model: "claude-opus-4-7" },
      { chat_id: "chat-r2", model: "claude-sonnet-4-6" },
    ]);
    act(() => useUiStore.getState().setChatLabel("chat-r2", "Core lab")); // persisted label
    useUiStore.setState({ chatPanelOpen: true, chats: [], activeChatId: null });
    renderPanel();

    await waitFor(() => expect(useUiStore.getState().chats).toHaveLength(2));
    const chats = useUiStore.getState().chats;
    expect(chats.map((c) => c.chatId)).toEqual(["chat-r1", "chat-r2"]);
    expect(chats[1].customLabel).toBe("Core lab");
    // The first-run effect must NOT stack an extra empty chat on top of
    // the restored ones.
    expect(chatCreate).not.toHaveBeenCalled();
  });

  it("plain Enter sends by default; Shift+Enter inserts a newline (v6.3.0)", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "first line");
    await userEvent.type(input, "{Shift>}{Enter}{/Shift}second line");
    expect(chatSendMessage).not.toHaveBeenCalled();
    await userEvent.type(input, "{Enter}");
    await waitFor(() => expect(chatSendMessage).toHaveBeenCalled());
    const [, sent] = vi.mocked(chatSendMessage).mock.calls[0];
    expect(sent).toContain("first line");
    expect(sent).toContain("second line");
  });

  it("Cmd+Enter still sends when Enter-to-send is on (muscle memory)", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "hello");
    await userEvent.keyboard("{Meta>}{Enter}{/Meta}");
    await waitFor(() => expect(chatSendMessage).toHaveBeenCalled());
    const [, sent] = vi.mocked(chatSendMessage).mock.calls[0];
    expect(sent).toBe("hello");
  });

  it("Enter during a stream falls through to a newline, never swallowed (v6.3.0)", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "first question{Enter}");
    await waitFor(() => expect(chatSendMessage).toHaveBeenCalledTimes(1));

    // Mid-stream the composer stays enabled on purpose — drafting a
    // follow-up with a line break must neither send nor vanish.
    await userEvent.type(input, "draft line one{Enter}draft line two");
    expect(chatSendMessage).toHaveBeenCalledTimes(1);
    expect((input as HTMLTextAreaElement).value).toBe("draft line one\ndraft line two");
  });

  it("Enter on an empty composer inserts a newline (not swallowed)", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "{Enter}hello");
    expect(chatSendMessage).not.toHaveBeenCalled();
    expect((input as HTMLTextAreaElement).value).toBe("\nhello");
  });

  it("with Enter-to-send off, plain Enter is a newline and Cmd+Enter sends (legacy mode)", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    act(() => useUiStore.getState().setChatSendOnEnter(false));
    try {
      useUiStore.setState({ chatPanelOpen: true });
      renderPanel();

      const input = await screen.findByTestId("chat-input");
      await userEvent.type(input, "first line");
      await userEvent.type(input, "{Enter}second line");
      expect(chatSendMessage).not.toHaveBeenCalled();
      input.focus();
      await userEvent.keyboard("{Meta>}{Enter}{/Meta}");
      await waitFor(() => expect(chatSendMessage).toHaveBeenCalled());
      const [, sent] = vi.mocked(chatSendMessage).mock.calls[0];
      expect(sent).toContain("first line");
      expect(sent).toContain("second line");
    } finally {
      act(() => useUiStore.getState().setChatSendOnEnter(true));
    }
  });

  it("Stop button calls chatCancel and clears streaming state", async () => {
    const { providerKeysStatus, chatCancel } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "hello");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:text-delta", { delta: "Hi" });
    const stopBtn = await screen.findByRole("button", { name: /^stop$/i });
    await userEvent.click(stopBtn);
    await waitFor(() => expect(chatCancel).toHaveBeenCalledWith("chat-1"));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /^stop$/i })).not.toBeInTheDocument(),
    );
  });

  it("Surfaces stream errors as a destructive banner", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "hello");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:error", { message: "provider returned malformed SSE: details" });

    expect(await screen.findByText(/provider returned malformed SSE/i)).toBeInTheDocument();
  });

  it("a provider_overloaded error is a soft toast, not a red banner", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    const { toastInfo, toastError } = await import("@/lib/toast");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "hello");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:error", {
      kind: "provider_overloaded",
      message: "The AI provider had a brief hiccup — resend to continue.",
    });

    // Soft info toast, no scary red "Chat error", no raw-JSON banner.
    await waitFor(() =>
      expect(vi.mocked(toastInfo)).toHaveBeenCalledWith(
        "AI provider busy",
        expect.objectContaining({ description: expect.stringMatching(/resend to continue/i) }),
      ),
    );
    expect(vi.mocked(toastError)).not.toHaveBeenCalled();
    expect(screen.queryByText(/Cloud returned status 502/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/provider_auth_error/i)).not.toBeInTheDocument();
  });

  it("activity line shows rounds + tokens (never a dollar amount) on :iteration", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "parse the logs");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:iteration", {
      iteration: 3,
      cumulative_usage: {
        input_uncached: 18000,
        input_cache_write: 0,
        input_cache_read: 0,
        output: 243,
      },
    });

    const line = await screen.findByTestId("chat-activity-line");
    expect(line.textContent).toMatch(/3 commands/);
    expect(line.textContent).toMatch(/18\.2k tokens/);
    expect(line.textContent).not.toContain("$");
  });

  it("activity line omits the commands clause before the first round", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "go");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:iteration", {
      iteration: 0,
      cumulative_usage: {
        input_uncached: 10,
        input_cache_write: 0,
        input_cache_read: 0,
        output: 0,
      },
    });

    const line = await screen.findByTestId("chat-activity-line");
    expect(line.textContent).toMatch(/running/);
    expect(line.textContent).not.toMatch(/command/);
  });

  it("checkpoint completion renders a soft Continue card (not an error, no $)", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "dig deep");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));

    fireEvent("chat:chat-1:completed", {
      usage: { input_uncached: 5000, input_cache_write: 0, input_cache_read: 0, output: 200 },
      stop_reason: "checkpoint",
      rounds: 12,
    });

    const card = await screen.findByTestId("checkpoint-card");
    expect(screen.getByTestId("checkpoint-continue")).toBeInTheDocument();
    expect(card.textContent).toMatch(/Paused after 12 commands/i);
    // Soft card, not the destructive error banner.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // Product rule: never a dollar figure on the card.
    expect(card.textContent).not.toContain("$");
  });

  it("Continue on the checkpoint card sends 'continue' and clears the card", async () => {
    const { providerKeysStatus, chatSendMessage } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "dig deep");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));
    fireEvent("chat:chat-1:completed", {
      usage: { input_uncached: 5000, input_cache_write: 0, input_cache_read: 0, output: 200 },
      stop_reason: "checkpoint",
      rounds: 12,
    });

    await userEvent.click(await screen.findByTestId("checkpoint-continue"));
    await waitFor(() => expect(chatSendMessage).toHaveBeenLastCalledWith("chat-1", "continue"));
    await waitFor(() => expect(screen.queryByTestId("checkpoint-card")).not.toBeInTheDocument());
  });

  it("Stop on the checkpoint card dismisses it WITHOUT calling chatCancel", async () => {
    const { providerKeysStatus, chatCancel } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    const input = await screen.findByTestId("chat-input");
    await userEvent.type(input, "dig deep");
    await userEvent.click(screen.getByRole("button", { name: /^send$/i }));
    fireEvent("chat:chat-1:completed", {
      usage: { input_uncached: 5000, input_cache_write: 0, input_cache_read: 0, output: 200 },
      stop_reason: "checkpoint",
      rounds: 12,
    });

    await userEvent.click(await screen.findByTestId("checkpoint-stop"));
    await waitFor(() => expect(screen.queryByTestId("checkpoint-card")).not.toBeInTheDocument());
    expect(chatCancel).not.toHaveBeenCalled();
  });

  it("keeps the backend chat alive when the panel collapses (v2.5.0 — background loops keep running)", async () => {
    const { providerKeysStatus, chatCreate, chatDestroy } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    vi.mocked(chatDestroy).mockClear();
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    await waitFor(() => expect(chatCreate).toHaveBeenCalled());
    expect(useUiStore.getState().chats.length).toBe(1);

    // Collapsing the panel must NOT destroy the chat — multi-chat runs
    // background agent loops that keep going while the panel is closed.
    // Chats are only torn down on explicit close (X) or app teardown.
    act(() => useUiStore.setState({ chatPanelOpen: false }));
    await new Promise((r) => setTimeout(r, 0));
    expect(chatDestroy).not.toHaveBeenCalled();
    expect(useUiStore.getState().chats.length).toBe(1);
  });

  it("surfaces a chat_create failure via toast instead of swallowing it", async () => {
    const { providerKeysStatus, chatCreate } = await import("@/lib/api");
    const { toastError } = await import("@/lib/toast");
    vi.mocked(providerKeysStatus).mockResolvedValue(anthropicKey);
    vi.mocked(chatCreate).mockRejectedValueOnce("cloud unreachable");
    useUiStore.setState({ chatPanelOpen: true });
    renderPanel();

    await waitFor(() =>
      expect(vi.mocked(toastError)).toHaveBeenCalledWith(
        "Couldn't start a chat session",
        expect.objectContaining({ description: "cloud unreachable" }),
      ),
    );
  });
});

describe("ChatPanel — device scope popover (v2.7.0, T31)", () => {
  async function renderSignedInPanel() {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    renderPanel();
    // The panel auto-creates its first chat ("chat-1" via the mocked
    // chatCreate) once the key status resolves.
    return await screen.findByTestId("chat-scope-trigger");
  }

  beforeEach(() => {
    useUiStore.setState({
      chatPanelOpen: true,
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "core1", ended: false },
        // A console tab: display id is prefixed, the agent sees the
        // bare label — the popover must list "FTDI FT232R".
        {
          sessionId: "s3",
          deviceId: "console-FTDI FT232R",
          agentDeviceId: "FTDI FT232R",
          ended: false,
        },
        // Ended sessions are never scope targets.
        { sessionId: "s4", deviceId: "dead1", ended: true },
      ],
    });
  });

  afterEach(() => {
    useUiStore.setState({ sessions: [], activeTabId: null });
  });

  it("lists live devices (agent-visible ids), not ended ones; trigger reads All devices", async () => {
    const trigger = await renderSignedInPanel();
    expect(trigger).toHaveTextContent("All devices");
    await userEvent.click(trigger);

    expect(await screen.findByTestId("chat-scope-device-vEX1")).toBeInTheDocument();
    expect(screen.getByTestId("chat-scope-device-core1")).toBeInTheDocument();
    expect(screen.getByTestId("chat-scope-device-FTDI FT232R")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-scope-device-dead1")).not.toBeInTheDocument();
    // Console entries appear under the BACKEND's vocabulary.
    expect(screen.queryByTestId("chat-scope-device-console-FTDI FT232R")).not.toBeInTheDocument();
  });

  it("unchecking one device materializes an allowlist of the others and calls chat_set_scope", async () => {
    const { chatSetScope } = await import("@/lib/api");
    const trigger = await renderSignedInPanel();
    await userEvent.click(trigger);

    await userEvent.click(await screen.findByTestId("chat-scope-device-core1"));
    await waitFor(() =>
      expect(vi.mocked(chatSetScope)).toHaveBeenCalledWith("chat-1", ["vEX1", "FTDI FT232R"]),
    );
    expect(trigger).toHaveTextContent("2 of 3 devices");
    // Store mirror updated (drives the badge + checkbox state).
    const chat = useUiStore.getState().chats.find((c) => c.chatId === "chat-1");
    expect(chat?.scopedDeviceIds).toEqual(["vEX1", "FTDI FT232R"]);
  });

  it("None empties the scope and shows the loud warning; All devices restores null", async () => {
    const { chatSetScope } = await import("@/lib/api");
    const trigger = await renderSignedInPanel();
    await userEvent.click(trigger);

    await userEvent.click(await screen.findByTestId("chat-scope-none"));
    await waitFor(() => expect(vi.mocked(chatSetScope)).toHaveBeenCalledWith("chat-1", []));
    expect(await screen.findByTestId("chat-scope-empty-warning")).toBeInTheDocument();
    expect(trigger).toHaveTextContent("0 of 3 devices");

    await userEvent.click(screen.getByTestId("chat-scope-all"));
    await waitFor(() => expect(vi.mocked(chatSetScope)).toHaveBeenCalledWith("chat-1", null));
    expect(trigger).toHaveTextContent("All devices");
    expect(screen.queryByTestId("chat-scope-empty-warning")).not.toBeInTheDocument();
  });

  it("a scoped-but-disconnected device stays visible with a disconnected hint", async () => {
    const trigger = await renderSignedInPanel();
    // Scope to a device, then simulate its sessions all closing.
    await userEvent.click(trigger);
    await userEvent.click(await screen.findByTestId("chat-scope-device-vEX1"));
    await waitFor(() =>
      expect(
        useUiStore.getState().chats.find((c) => c.chatId === "chat-1")?.scopedDeviceIds,
      ).toEqual(["core1", "FTDI FT232R"]),
    );
    act(() => {
      useUiStore.setState((s) => ({
        sessions: s.sessions.map((t) => (t.deviceId === "core1" ? { ...t, ended: true } : t)),
      }));
    });
    // core1 is still in the scope set → still listed, flagged.
    const row = await screen.findByTestId("chat-scope-device-core1");
    expect(row).toBeInTheDocument();
    expect(screen.getByText(/disconnected/i)).toBeInTheDocument();
  });

  it("reverts the store and toasts when the backend rejects the scope change", async () => {
    const { chatSetScope } = await import("@/lib/api");
    const { toastError } = await import("@/lib/toast");
    vi.mocked(chatSetScope).mockRejectedValueOnce(new Error("chat not found"));
    const trigger = await renderSignedInPanel();
    await userEvent.click(trigger);

    await userEvent.click(await screen.findByTestId("chat-scope-none"));
    // The optimistic update must roll back — the UI never advertises a
    // scope the backend isn't enforcing.
    await waitFor(() => expect(vi.mocked(toastError)).toHaveBeenCalled());
    expect(
      useUiStore.getState().chats.find((c) => c.chatId === "chat-1")?.scopedDeviceIds,
    ).toBeNull();
    expect(trigger).toHaveTextContent("All devices");
  });
});

describe("ChatPanel — gating on keys + local models", () => {
  function localOff() {
    return {
      enabled: false,
      base_url: "http://127.0.0.1:11434",
      num_ctx: 16384,
      keep_alive: "15m",
      env_override: false,
      warning: null,
    };
  }
  async function mockLocalOn() {
    const { getLocalModelsSettings, localModelsStatus } = await import("@/lib/api");
    vi.mocked(getLocalModelsSettings).mockResolvedValue({ ...localOff(), enabled: true });
    vi.mocked(localModelsStatus).mockResolvedValue({
      enabled: true,
      reachable: true,
      base_url: "http://127.0.0.1:11434",
      version: "0.32.1",
      version_supported: true,
      models: [
        { id: "ollama:qwen3:8b", name: "qwen3:8b", size_bytes: 5_000_000_000, tools_capable: true },
        // Non-tool models never reach the picker.
        { id: "ollama:gemma-notools", name: "gemma-notools", size_bytes: 1, tools_capable: false },
      ],
      hidden_cloud_models: [],
      error: null,
      warning: null,
    });
  }

  beforeEach(async () => {
    // clearAllMocks clears CALLS, not implementations — re-pin defaults.
    const api = await import("@/lib/api");
    vi.mocked(api.providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    vi.mocked(api.getLocalModelsSettings).mockResolvedValue(localOff());
    useUiStore.getState().setCachedModels("anthropic", []);
    useUiStore.getState().setCachedModels("openai", []);
    vi.mocked(api.localEndpointsStatus).mockResolvedValue([]);
    useUiStore.setState({ chatPanelOpen: true });
  });

  it("no key + local off → setup empty state with BOTH CTAs; no picker, no input", async () => {
    const { chatCreate } = await import("@/lib/api");
    renderPanel();
    expect(await screen.findByTestId("chat-no-models-state")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-input")).not.toBeInTheDocument();
    expect(screen.queryByTestId("chat-model-picker")).not.toBeInTheDocument();
    // Never a sign-in, never an upsell.
    expect(screen.queryByText(/sign in/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/subscri|plan|tier/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByTestId("chat-setup-api-keys"));
    expect(useUiStore.getState().settingsDialogOpen).toBe(true);
    expect(useUiStore.getState().settingsInitialTab).toBe("api-keys");
    expect(chatCreate).not.toHaveBeenCalled();
  });

  it("Anthropic key only → only discovered claude models render, grouped by level; default is Sonnet 5.5", async () => {
    const { providerKeysStatus, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    renderPanel();
    const picker = await screen.findByTestId("chat-model-picker");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("claude-sonnet-5-5"));
    await userEvent.click(picker);
    expect(await screen.findByTestId("chat-model-group-medium")).toBeInTheDocument();
    expect(screen.getByTestId("chat-model-group-easy")).toBeInTheDocument();
    expect(screen.getByTestId("chat-model-group-advanced")).toBeInTheDocument();
    // Display names come from the provider, minus the leading family word.
    expect(screen.getByRole("option", { name: "Sonnet 5.5" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Opus 5.5" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /GPT/ })).not.toBeInTheDocument();
  });

  it("OpenAI key only → only GPT models render; default is GPT-5.6 Terra", async () => {
    const { providerKeysStatus, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: true });
    renderPanel();
    await screen.findByTestId("chat-model-picker");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("gpt-5.6-terra"));
  });

  it("a custom model id renders under Other, routed to the provider its id names", async () => {
    const { providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    useUiStore.getState().setCustomModelIds(["claude-opus-6", "gpt-7-nova"]);
    renderPanel();
    await userEvent.click(await screen.findByTestId("chat-model-picker"));
    const other = await screen.findByTestId("chat-model-group-other");
    expect(other).toHaveTextContent("claude-opus-6");
    // The OpenAI custom id has no key behind it → not offered.
    expect(other).not.toHaveTextContent("gpt-7-nova");
    useUiStore.getState().setCustomModelIds([]);
  });

  it("ChatGPT plan signed in (no key) → OpenAI models are offered with the plan note", async () => {
    const { providerKeysStatus, chatgptStatus, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    vi.mocked(chatgptStatus).mockResolvedValue({
      signed_in: true,
      email: "alice@example.com",
      method: "chatgpt",
    });
    renderPanel();
    await screen.findByTestId("chat-model-picker");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("gpt-5.6-terra"));
    await userEvent.click(screen.getByTestId("chat-model-picker"));
    expect(await screen.findByTestId("chat-model-source")).toHaveTextContent(/ChatGPT plan/);
    expect(screen.queryByRole("option", { name: /Sonnet/ })).not.toBeInTheDocument();
    vi.mocked(chatgptStatus).mockResolvedValue({
      signed_in: false,
      email: null,
      method: "api_key",
    });
  });

  it("ChatGPT method selected but signed out → gated like no key", async () => {
    const { providerKeysStatus, chatgptStatus } = await import("@/lib/api");
    // A stale API key must NOT serve while the method is "chatgpt".
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: true });
    vi.mocked(chatgptStatus).mockResolvedValue({
      signed_in: false,
      email: null,
      method: "chatgpt",
    });
    renderPanel();
    expect(await screen.findByTestId("chat-no-models-state")).toBeInTheDocument();
    vi.mocked(chatgptStatus).mockResolvedValue({
      signed_in: false,
      email: null,
      method: "api_key",
    });
  });

  it("discovery failure falls back to the cached list, then to a static default list", async () => {
    const { providerKeysStatus, providerModelsList, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    vi.mocked(providerModelsList).mockRejectedValue("HTTP transport error: offline");
    // Cached from an earlier run: an id the static fallback does not know.
    useUiStore.getState().setCachedModels("anthropic", [
      {
        id: "claude-opus-6",
        display_name: "Claude Opus 6",
        created: 1_800_000_000,
        level: "advanced",
        context_window: null,
      },
    ]);
    renderPanel();
    await screen.findByTestId("chat-model-picker");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("claude-opus-6"));
    await userEvent.click(screen.getByTestId("chat-model-picker"));
    expect(await screen.findByRole("option", { name: "Opus 6" })).toBeInTheDocument();
    useUiStore.getState().setCachedModels("anthropic", []);
  });

  it("no key + Ollama running → chat renders with a local default and only the Local group", async () => {
    const { chatCreate } = await import("@/lib/api");
    await mockLocalOn();
    renderPanel();
    await screen.findByTestId("chat-input");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("ollama:qwen3:8b"));
    await userEvent.click(screen.getByTestId("chat-model-picker"));
    expect(await screen.findByTestId("chat-model-group-local")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-model-group-medium")).not.toBeInTheDocument();
  });

  it("key + Ollama → provider default wins, local group is also offered", async () => {
    const { providerKeysStatus, chatCreate } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    await mockLocalOn();
    renderPanel();
    await screen.findByTestId("chat-input");
    await waitFor(() => expect(chatCreate).toHaveBeenCalledWith("claude-sonnet-5-5"));
    await userEvent.click(screen.getByTestId("chat-model-picker"));
    expect(await screen.findByTestId("chat-model-group-local")).toBeInTheDocument();
    expect(screen.getByTestId("chat-model-group-medium")).toBeInTheDocument();
  });

  it("clearing the key behind the selected model falls back to a local model with a toast", async () => {
    const { providerKeysStatus, chatSetModel } = await import("@/lib/api");
    const { toastInfo } = await import("@/lib/toast");
    await mockLocalOn();
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    const qc = makeQc();
    renderPanel(qc);
    await screen.findByTestId("chat-input");
    await waitFor(() => expect(useUiStore.getState().chats[0]?.model).toBe("claude-sonnet-5-5"));
    // Key cleared elsewhere → status refetch.
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: false, openai: false });
    await act(async () => {
      await qc.invalidateQueries({ queryKey: ["provider-keys", "status"] });
    });
    await waitFor(() => expect(chatSetModel).toHaveBeenCalledWith("chat-1", "ollama:qwen3:8b"));
    expect(vi.mocked(toastInfo)).toHaveBeenCalledWith(expect.stringMatching(/Anthropic key/));
  });
});
