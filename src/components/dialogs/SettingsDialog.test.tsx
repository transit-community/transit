import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { SettingsDialog } from "@/components/dialogs/SettingsDialog";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  AGENT_CHAT_SETTINGS_QUERY_KEY: ["agentChat", "settings"],
  providerKeySet: vi.fn(async () => undefined),
  providerKeyClear: vi.fn(async () => undefined),
  providerKeysStatus: vi.fn(async () => ({ anthropic: false, openai: false })),
  providerForModel: (id: string) => (id.includes("claude") ? "anthropic" : "openai"),
  // Sign in with ChatGPT (preview): default = API-key method, signed out.
  chatgptStatus: vi.fn(async () => ({ signed_in: false, email: null, method: "api_key" })),
  chatgptSigninStart: vi.fn(async () => undefined),
  chatgptSigninCancel: vi.fn(async () => undefined),
  chatgptSignout: vi.fn(async () => ({ revoked: true })),
  providerOpenaiMethodSet: vi.fn(async () => undefined),
  providerModelsList: vi.fn(async () => [
    {
      id: "claude-opus-5-5",
      display_name: "Claude Opus 5.5",
      created: 1,
      level: "advanced",
      context_window: null,
    },
    {
      id: "claude-sonnet-5-5",
      display_name: "Claude Sonnet 5.5",
      created: 1,
      level: "medium",
      context_window: null,
    },
    {
      id: "claude-haiku-4-5",
      display_name: "Claude Haiku 4.5",
      created: 1,
      level: "easy",
      context_window: null,
    },
  ]),
  getPolicySettings: vi.fn(async () => ({
    user_dir: null,
    env_override: false,
    vendors: ["fortios", "junos"],
    warnings: [],
  })),
  // v6.3.0 — Settings → Agent Chat.
  getAgentChatSettings: vi.fn(async () => ({
    persist_history: false,
    history_dir: "/home/alice/.local/share/Transit/chats",
    history_dir_configured: null,
    persist_history_env_override: false,
    history_dir_env_override: false,
    save_to_file: false,
    save_dir: "/home/alice/Downloads",
    save_dir_configured: null,
    save_to_file_env_override: false,
    save_dir_env_override: false,
  })),
  setAgentChatSettings: vi.fn(async () => undefined),
  setUserPoliciesDir: vi.fn(async () => undefined),
  listMonospaceFonts: vi.fn(async () => ["Fira Code", "JetBrains Mono"]),
  // v3.0.0 BYOM — defaults keep local models fully OFF so the legacy
  // tabs render unchanged; the local-models tests override these.
  getLocalModelsSettings: vi.fn(async () => ({
    enabled: false,
    base_url: "http://127.0.0.1:11434",
    num_ctx: 16384,
    keep_alive: "15m",
    env_override: false,
    warning: null,
  })),
  setLocalModelsSettings: vi.fn(async () => undefined),
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
  localEndpointsList: vi.fn(async () => []),
  localEndpointsStatus: vi.fn(async () => []),
  localEndpointUpsert: vi.fn(async () => undefined),
  localEndpointDelete: vi.fn(async () => undefined),
  localEndpointSetToken: vi.fn(async () => undefined),
  localEndpointClearToken: vi.fn(async () => undefined),
}));

// Tauri's opener plugin and app.getVersion are unreachable in jsdom;
// mock them so the About tab renders.
vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(async () => undefined),
}));
vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn(async () => "0.0.1"),
}));

function makeQc(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderDialog(qc?: QueryClient) {
  const client = qc ?? makeQc();
  return render(
    <QueryClientProvider client={client}>
      <SettingsDialog />
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  useUiStore.setState({ settingsDialogOpen: false });
  // The ChatGPT status mock is re-pointed by the sign-in tests; restore
  // the default (API-key method, signed out) so it never leaks across.
  const { chatgptStatus } = await import("@/lib/api");
  vi.mocked(chatgptStatus).mockResolvedValue({ signed_in: false, email: null, method: "api_key" });
});

// Radix Select drives pointer capture + scrollIntoView, none of
// which jsdom implements — stub them so the font picker can open.
beforeAll(() => {
  Object.assign(window.HTMLElement.prototype, {
    scrollIntoView: vi.fn(),
    hasPointerCapture: vi.fn(() => false),
    setPointerCapture: vi.fn(),
    releasePointerCapture: vi.fn(),
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("SettingsDialog", () => {
  it("renders nothing when settingsDialogOpen is false", () => {
    renderDialog();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens when the store flag flips, shows General tab", async () => {
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /general/i })).toBeInTheDocument();
    // v3.0.1: LEFT NAV RAIL. At nine tabs a horizontal strip's nowrap
    // min-content overflows the dialog and (via the grid's
    // min-width:auto) drags every row's controls past the clipped edge
    // — the vertical orientation is the load-bearing fix, not styling.
    expect(screen.getByRole("tablist")).toHaveAttribute("aria-orientation", "vertical");
  });

  it("Policies tab lists loaded vendors and saves a directory (then refetches)", async () => {
    const { getPolicySettings, setUserPoliciesDir } = await import("@/lib/api");
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    // The Policies tab is always present (BYOP needs no subscription).
    await userEvent.click(await screen.findByRole("tab", { name: /policies/i }));
    const panel = await screen.findByTestId("policies-tab");
    // Loaded vendors (incl. a custom one) surface so the user can
    // confirm their policy took.
    expect(panel).toHaveTextContent("fortios, junos");

    const input = screen.getByPlaceholderText(/transit-policies/i);
    await userEvent.type(input, "/Volumes/nas/pol");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(vi.mocked(setUserPoliciesDir)).toHaveBeenCalledWith("/Volumes/nas/pol");
    });
    // Saving refetches the settings (restart-to-apply state).
    await waitFor(() => {
      expect(vi.mocked(getPolicySettings).mock.calls.length).toBeGreaterThan(1);
    });
  });

  it("Policies tab is read-only when the dir is set by env var", async () => {
    const { getPolicySettings } = await import("@/lib/api");
    vi.mocked(getPolicySettings).mockResolvedValueOnce({
      user_dir: "/env/controlled/policies",
      env_override: true,
      vendors: ["junos"],
      warnings: [],
    });
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");
    await userEvent.click(await screen.findByRole("tab", { name: /policies/i }));
    const panel = await screen.findByTestId("policies-tab");
    expect(panel).toHaveTextContent("TRANSIT_USER_POLICIES");
    expect(panel).toHaveTextContent("/env/controlled/policies");
    // No editable path input / Save button on the env-override path.
    expect(screen.queryByPlaceholderText(/transit-policies/i)).not.toBeInTheDocument();
  });

  it("General tab renders the real theme picker and no telemetry card", async () => {
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");
    // Theme picker is real (C5); scrollback remains a placeholder until
    // its backend lands.
    expect(screen.getByTestId("general-theme-row")).toBeInTheDocument();
    expect(screen.getByTestId("general-theme-select")).toBeInTheDocument();
    expect(screen.getByTestId("general-placeholder-scrollback size")).toBeInTheDocument();
    // Transit collects NO telemetry, so there is no card promising a
    // future opt-in toggle for it (v6.1.0). Advertising a setting for
    // data we don't gather invites the question it was meant to answer.
    expect(screen.queryByTestId("general-placeholder-telemetry")).not.toBeInTheDocument();
  });

  it("font picker lists detected fonts and picking one persists", async () => {
    act(() => useUiStore.getState().setTerminalFontFamily(null));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    const user = userEvent.setup({ pointerEventsCheck: 0 });
    await user.click(screen.getByTestId("general-font-family-select"));
    await user.click(await screen.findByRole("option", { name: "JetBrains Mono" }));
    expect(useUiStore.getState().preferences.terminalFontFamily).toBe("JetBrains Mono");
    // A listed pick never shows the custom free-text input.
    expect(screen.queryByTestId("general-font-family-input")).not.toBeInTheDocument();
  });

  it("font picker System default clears the family", async () => {
    act(() => useUiStore.getState().setTerminalFontFamily("Fira Code"));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    const user = userEvent.setup({ pointerEventsCheck: 0 });
    await user.click(screen.getByTestId("general-font-family-select"));
    await user.click(await screen.findByRole("option", { name: "System default" }));
    expect(useUiStore.getState().preferences.terminalFontFamily).toBeNull();
  });

  it("font picker Custom… reveals the free-text input and Enter commits it", async () => {
    act(() => useUiStore.getState().setTerminalFontFamily(null));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    const user = userEvent.setup({ pointerEventsCheck: 0 });
    await user.click(screen.getByTestId("general-font-family-select"));
    await user.click(await screen.findByRole("option", { name: /custom/i }));
    const input = await screen.findByTestId("general-font-family-input");
    await user.type(input, "Berkeley Mono, Menlo{Enter}");
    expect(useUiStore.getState().preferences.terminalFontFamily).toBe("Berkeley Mono, Menlo");
  });

  it("a stored family missing from the detected list surfaces as Custom, input prefilled", async () => {
    act(() => useUiStore.getState().setTerminalFontFamily("Comic Mono"));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    // The fonts query resolves to a list without "Comic Mono" —
    // the row flips to Custom and preserves the value for editing.
    const input = await screen.findByTestId("general-font-family-input");
    expect((input as HTMLInputElement).value).toBe("Comic Mono");
  });

  it("chat font-size control grows, shrinks, and resets the persisted size", async () => {
    act(() => useUiStore.getState().setChatFontSize(null));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    const user = userEvent.setup({ pointerEventsCheck: 0 });
    // Default (null → 14). Reset starts disabled; grow bumps to 15.
    expect(screen.getByTestId("general-chat-font-size-value")).toHaveTextContent("14 px");
    expect(screen.getByTestId("general-chat-font-size-reset")).toBeDisabled();
    await user.click(screen.getByTestId("general-chat-font-size-grow"));
    expect(useUiStore.getState().preferences.chatFontSize).toBe(15);
    expect(screen.getByTestId("general-chat-font-size-value")).toHaveTextContent("15 px");

    await user.click(screen.getByTestId("general-chat-font-size-shrink"));
    expect(useUiStore.getState().preferences.chatFontSize).toBe(14);

    // After a non-default value, Reset is enabled and clears to null.
    await user.click(screen.getByTestId("general-chat-font-size-grow"));
    await user.click(screen.getByTestId("general-chat-font-size-reset"));
    expect(useUiStore.getState().preferences.chatFontSize).toBeNull();
  });

  it("API keys tab is always present and renders both provider rows + the custom-ids row", async () => {
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    expect(await screen.findByTestId("provider-key-row-anthropic")).toBeInTheDocument();
    expect(screen.getByTestId("provider-key-row-openai")).toBeInTheDocument();
    expect(screen.getByTestId("custom-models-row")).toBeInTheDocument();
    // No account, billing, updates, or BYOK-mode toggle anywhere.
    expect(
      screen.queryByRole("tab", { name: /account|billing|updates|byok/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/monthly budget/)).not.toBeInTheDocument();
  });

  it("Save calls providerKeySet with the typed value, then refetches status", async () => {
    const { providerKeySet, providerKeysStatus } = await import("@/lib/api");
    vi.mocked(providerKeysStatus)
      .mockResolvedValueOnce({ anthropic: false, openai: false })
      .mockResolvedValue({ anthropic: true, openai: false });
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    const input = await screen.findByTestId("provider-key-input-anthropic");
    await userEvent.type(input, "sk-ant-test");
    await userEvent.click(screen.getAllByRole("button", { name: /^save$/i })[0]);
    await waitFor(() => expect(providerKeySet).toHaveBeenCalledWith("anthropic", "sk-ant-test"));
    await waitFor(() => expect(vi.mocked(providerKeysStatus).mock.calls.length).toBeGreaterThan(1));
    expect(await screen.findByText("Configured")).toBeInTheDocument();
  });

  it("OpenAI card: switching to Sign in with ChatGPT persists the method and offers sign-in", async () => {
    const { providerOpenaiMethodSet, chatgptStatus, chatgptSigninStart } =
      await import("@/lib/api");
    vi.mocked(chatgptStatus)
      .mockResolvedValueOnce({ signed_in: false, email: null, method: "api_key" })
      .mockResolvedValue({ signed_in: false, email: null, method: "chatgpt" });
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    // API-key method by default: the key row is there, the plan row is not.
    expect(await screen.findByTestId("provider-key-row-openai")).toBeInTheDocument();
    expect(screen.queryByTestId("chatgpt-plan-row")).not.toBeInTheDocument();
    await userEvent.click(screen.getByTestId("openai-method-chatgpt"));
    await waitFor(() => expect(providerOpenaiMethodSet).toHaveBeenCalledWith("chatgpt"));
    expect(await screen.findByTestId("chatgpt-plan-row")).toBeInTheDocument();
    expect(screen.queryByTestId("provider-key-row-openai")).not.toBeInTheDocument();
    expect(screen.getByText(/Preview/)).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("chatgpt-signin"));
    await waitFor(() => expect(chatgptSigninStart).toHaveBeenCalled());
    expect(await screen.findByText(/Waiting for the browser/)).toBeInTheDocument();
    // Cancel is available while waiting.
    expect(screen.getByTestId("chatgpt-cancel")).toBeInTheDocument();
  });

  it("OpenAI card: signed in shows the account and Sign out clears it", async () => {
    const { chatgptStatus, chatgptSignout } = await import("@/lib/api");
    vi.mocked(chatgptStatus).mockResolvedValue({
      signed_in: true,
      email: "alice@example.com",
      method: "chatgpt",
    });
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    expect(await screen.findByTestId("chatgpt-account")).toHaveTextContent("alice@example.com");
    await userEvent.click(screen.getByTestId("chatgpt-signout"));
    await waitFor(() => expect(chatgptSignout).toHaveBeenCalled());
  });

  it("an enrolled key shows the discovered model count and Refresh re-lists", async () => {
    const { providerKeysStatus, providerModelsList } = await import("@/lib/api");
    vi.mocked(providerKeysStatus).mockResolvedValue({ anthropic: true, openai: false });
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    const count = await screen.findByTestId("provider-models-count-anthropic");
    await waitFor(() => expect(count).toHaveTextContent(/3 models/));
    expect(screen.queryByTestId("provider-models-row-openai")).not.toBeInTheDocument();
    const calls = vi.mocked(providerModelsList).mock.calls.length;
    await userEvent.click(screen.getByTestId("provider-models-refresh-anthropic"));
    await waitFor(() => expect(vi.mocked(providerModelsList).mock.calls.length).toBe(calls + 1));
    // The list is mirrored into preferences for offline launches.
    expect(useUiStore.getState().preferences.cachedModels.anthropic?.length).toBe(3);
  });

  it("does not allow saving an empty key (Save button disabled)", async () => {
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    await screen.findByTestId("provider-key-row-anthropic");
    for (const b of screen.getAllByRole("button", { name: /^save$/i })) {
      expect(b).toBeDisabled();
    }
  });

  it("custom model ids persist to preferences and can be removed", async () => {
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /ai providers/i }));
    const input = await screen.findByTestId("custom-model-input");
    await userEvent.type(input, "claude-opus-6{Enter}");
    expect(useUiStore.getState().preferences.customModelIds).toEqual(["claude-opus-6"]);
    expect(screen.getByTestId("custom-model-list")).toHaveTextContent("Anthropic");
    await userEvent.click(screen.getByRole("button", { name: /remove claude-opus-6/i }));
    expect(useUiStore.getState().preferences.customModelIds).toEqual([]);
  });

  it("Local models tab is always present (no entitlement)", async () => {
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /local models/i }));
    expect(await screen.findByTestId("local-models-tab")).toBeInTheDocument();
    expect(screen.queryByText(/subscription|sign-in|offline pass/i)).not.toBeInTheDocument();
  });

  it("About tab renders the app version, the license, and the repo links", async () => {
    act(() => useUiStore.setState({ settingsDialogOpen: true }));
    renderDialog();
    await userEvent.click(await screen.findByRole("tab", { name: /about/i }));
    expect(await screen.findByText("0.0.1")).toBeInTheDocument();
    expect(screen.getByText("Apache-2.0")).toBeInTheDocument();
    expect(screen.getByTestId("about-repo-link")).toBeInTheDocument();
    expect(screen.getByTestId("about-issues-link")).toBeInTheDocument();
    expect(screen.queryByText(/proprietary/i)).not.toBeInTheDocument();
  });
});

describe("SettingsDialog — Agent Chat tab (v6.3.0)", () => {
  it("Enter-to-send toggle reflects and flips the persisted pref", async () => {
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    renderDialog();
    act(() => useUiStore.getState().openSettingsDialog());
    await screen.findByRole("dialog");

    const user = userEvent.setup({ pointerEventsCheck: 0 });
    await user.click(screen.getByRole("tab", { name: /agent chat/i }));

    const toggle = await screen.findByTestId("agent-chat-send-on-enter");
    expect(toggle).toHaveAttribute("aria-checked", "true");
    expect(toggle).toHaveTextContent("On");

    await user.click(toggle);
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(false);
    expect(toggle).toHaveAttribute("aria-checked", "false");
    expect(toggle).toHaveTextContent("Off");

    await user.click(toggle);
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(true);
  });
});
