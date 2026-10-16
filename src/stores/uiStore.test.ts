import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { leaf, type PaneNode } from "@/lib/paneTree";

const PREFERENCES_KEY = "transit.preferences";

const split = (dir: "row" | "col", children: PaneNode[]): PaneNode => ({
  type: "split",
  dir,
  children,
});

describe("uiStore chat panel persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    // The store reads localStorage at module-init time. Tests force a
    // fresh evaluation by importing dynamically after seeding the
    // storage. Reset the module cache between scenarios.
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults chatPanelOpen to true when localStorage has no preferences (first launch)", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });

  it("defaults chatPanelOpen to true when stored preferences exist but chatPanelOpen is absent", async () => {
    // Older clients that wrote preferences before this feature shipped
    // will have a preferences blob without chatPanelOpen. Treat that
    // as "never explicitly set" and apply the first-launch default.
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ themeId: "dracula", chatPanelWidth: 500 }),
    );
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });

  it("honors a persisted chatPanelOpen=false across reloads", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ themeId: null, chatPanelWidth: null, chatPanelOpen: false }),
    );
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().chatPanelOpen).toBe(false);
  });

  it("honors a persisted chatPanelOpen=true across reloads", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ themeId: null, chatPanelWidth: null, chatPanelOpen: true }),
    );
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });

  it("toggleChatPanel flips state AND persists the new value", async () => {
    const { useUiStore } = await import("./uiStore");
    // Start state: true (first-launch default)
    expect(useUiStore.getState().chatPanelOpen).toBe(true);

    useUiStore.getState().toggleChatPanel();
    expect(useUiStore.getState().chatPanelOpen).toBe(false);

    const persistedAfterClose = JSON.parse(localStorage.getItem(PREFERENCES_KEY)!);
    expect(persistedAfterClose.chatPanelOpen).toBe(false);

    useUiStore.getState().toggleChatPanel();
    expect(useUiStore.getState().chatPanelOpen).toBe(true);

    const persistedAfterReopen = JSON.parse(localStorage.getItem(PREFERENCES_KEY)!);
    expect(persistedAfterReopen.chatPanelOpen).toBe(true);
  });

  it("preserves other persisted preferences when chatPanelOpen toggles", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ themeId: "dracula", chatPanelWidth: 500, chatPanelOpen: true }),
    );
    const { useUiStore } = await import("./uiStore");

    useUiStore.getState().toggleChatPanel();
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY)!);
    expect(persisted.themeId).toBe("dracula");
    expect(persisted.chatPanelWidth).toBe(500);
    expect(persisted.chatPanelOpen).toBe(false);
  });

  it("ignores a malformed chatPanelOpen value in storage and applies first-launch default", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ themeId: null, chatPanelWidth: null, chatPanelOpen: "not a boolean" }),
    );
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });
});

describe("uiStore session-close warning (user request)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults to ON — a misclick must not drop a live session", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.warnOnSessionClose).toBe(true);
  });

  it("defaults to ON for an install that predates the setting", async () => {
    // A stored blob with no such key is an OLDER install, which HAD the
    // warning. Absence must not read as "the user turned it off".
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ themeId: "dracula" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.warnOnSessionClose).toBe(true);
  });

  it("persists an explicit OFF across reloads", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setWarnOnSessionClose(false);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.warnOnSessionClose).toBe(false);
  });

  it("honors a persisted false", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ warnOnSessionClose: false }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.warnOnSessionClose).toBe(false);
  });

  it("ignores a non-boolean and falls back to ON", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ warnOnSessionClose: "no thanks" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.warnOnSessionClose).toBe(true);
  });
});

describe("uiStore sidebar width (v6.5.2)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults sidebarWidth to null (the component applies SIDEBAR_DEFAULT_WIDTH)", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.sidebarWidth).toBeNull();
  });

  it("persists a set width to localStorage", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setSidebarWidth(420);
    expect(useUiStore.getState().preferences.sidebarWidth).toBe(420);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.sidebarWidth).toBe(420);
  });

  it("honors a persisted width across reloads", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ sidebarWidth: 360 }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.sidebarWidth).toBe(360);
  });

  it("ignores a non-numeric persisted width", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ sidebarWidth: "wide" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.sidebarWidth).toBeNull();
  });

  it("ignores a non-finite persisted width", async () => {
    // JSON.stringify turns Infinity into null, so the hostile shape a
    // hand-edited blob can actually carry is a string like "Infinity".
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ sidebarWidth: "Infinity" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.sidebarWidth).toBeNull();
  });

  it("is one shared width, not per sidebar view", async () => {
    // The rail is one conceptual column: switching views must not
    // change its width (see SidebarResizeHandle's useSidebarWidth).
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setSidebarWidth(400);
    useUiStore.getState().setSidebarView("files");
    expect(useUiStore.getState().preferences.sidebarWidth).toBe(400);
    useUiStore.getState().setSidebarView("pcaps");
    expect(useUiStore.getState().preferences.sidebarWidth).toBe(400);
  });
});

describe("uiStore chat font size", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults chatFontSize to null (= CHAT_FONT_SIZE_DEFAULT) on first launch", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.chatFontSize).toBeNull();
  });

  it("setChatFontSize clamps above the max and persists the clamped value", async () => {
    const { useUiStore, CHAT_FONT_SIZE_MAX } = await import("./uiStore");
    useUiStore.getState().setChatFontSize(999);
    expect(useUiStore.getState().preferences.chatFontSize).toBe(CHAT_FONT_SIZE_MAX);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.chatFontSize).toBe(CHAT_FONT_SIZE_MAX);
  });

  it("setChatFontSize clamps below the min", async () => {
    const { useUiStore, CHAT_FONT_SIZE_MIN } = await import("./uiStore");
    useUiStore.getState().setChatFontSize(1);
    expect(useUiStore.getState().preferences.chatFontSize).toBe(CHAT_FONT_SIZE_MIN);
  });

  it("setChatFontSize(null) resets to default and a non-finite value is rejected by the loader", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setChatFontSize(18);
    expect(useUiStore.getState().preferences.chatFontSize).toBe(18);
    useUiStore.getState().setChatFontSize(null);
    expect(useUiStore.getState().preferences.chatFontSize).toBeNull();
  });

  it("honors a persisted chatFontSize across reloads (clamped on read)", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ chatFontSize: 20 }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.chatFontSize).toBe(20);
  });

  it("ignores a malformed chatFontSize in storage", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ chatFontSize: "huge" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.chatFontSize).toBeNull();
  });
});

describe("uiStore group collapse", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults to an empty collapsed map (all groups open)", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.collapsedGroups).toEqual({});
  });

  it("toggleGroupCollapsed flips a path on/off and persists", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().toggleGroupCollapsed("Lab/Junos");
    expect(useUiStore.getState().preferences.collapsedGroups).toEqual({ "Lab/Junos": true });
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.collapsedGroups).toEqual({ "Lab/Junos": true });

    // Toggling again removes the key (back to expanded).
    useUiStore.getState().toggleGroupCollapsed("Lab/Junos");
    expect(useUiStore.getState().preferences.collapsedGroups).toEqual({});
  });

  it("honors a persisted collapsed map across reloads and drops non-true values", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({ collapsedGroups: { Lab: true, Prod: false, Bad: "x" } }),
    );
    const { useUiStore } = await import("./uiStore");
    // Only the genuine `true` entry survives sanitization.
    expect(useUiStore.getState().preferences.collapsedGroups).toEqual({ Lab: true });
  });
});

describe("uiStore button bar (v1.4.0 core + v2.7.0 multi-bar)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  /** The active bar's buttons (post-v2.7.0, buttons live per-bar). */
  async function activeButtons() {
    const { useUiStore } = await import("./uiStore");
    const p = useUiStore.getState().preferences;
    return (p.buttonBars.find((b) => b.id === p.activeButtonBarId) ?? p.buttonBars[0]).buttons;
  }

  it("defaults to hidden with a single empty Default bar", async () => {
    const { useUiStore } = await import("./uiStore");
    const p = useUiStore.getState().preferences;
    expect(p.showButtonBar).toBe(false);
    expect(p.buttonBars).toHaveLength(1);
    expect(p.buttonBars[0].name).toBe("Default");
    expect(p.buttonBars[0].buttons).toEqual([]);
    expect(p.activeButtonBarId).toBe(p.buttonBars[0].id);
  });

  it("setShowButtonBar toggles + persists", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setShowButtonBar(true);
    expect(useUiStore.getState().preferences.showButtonBar).toBe(true);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.showButtonBar).toBe(true);
  });

  it("addButton appends to the active bar with a generated id + persists", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().addButton({ label: "ver", value: "show version\\r" });
    const buttons = await activeButtons();
    expect(buttons).toHaveLength(1);
    expect(buttons[0]).toMatchObject({ label: "ver", value: "show version\\r" });
    expect(buttons[0].id.length).toBeGreaterThan(0);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.buttonBars[0].buttons).toHaveLength(1);
  });

  it("updateButton replaces label + value by id; removeButton deletes by id", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().addButton({ label: "a", value: "x" });
    const id = (await activeButtons())[0].id;
    useUiStore.getState().updateButton(id, { label: "b", value: "y" });
    expect((await activeButtons())[0]).toMatchObject({ id, label: "b", value: "y" });
    useUiStore.getState().removeButton(id);
    expect(await activeButtons()).toEqual([]);
  });

  it("addButton stores a valid color; updateButton changes then clears it (Jeff Kish)", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addButton({ label: "voip", value: "x", color: "blue" });
    const btn = (await activeButtons())[0];
    expect(btn.color).toBe("blue");
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.buttonBars[0].buttons[0].color).toBe("blue");

    s().updateButton(btn.id, { label: "voip", value: "x", color: "green" });
    expect((await activeButtons())[0].color).toBe("green");

    // "None" (or anything not a palette token) removes the shade.
    s().updateButton(btn.id, { label: "voip", value: "x", color: "" });
    expect((await activeButtons())[0].color).toBeUndefined();
  });

  it("addButton drops an unknown color token (no arbitrary CSS in state)", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().addButton({ label: "x", value: "y", color: "chartreuse" });
    expect((await activeButtons())[0].color).toBeUndefined();
  });

  it("addButton accepts a strict #rrggbb hex but nothing CSS-shaped (v6.3.0)", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().addButton({ label: "hex", value: "y", color: "#ffaa00" });
    useUiStore.getState().addButton({ label: "short", value: "y", color: "#fff" });
    useUiStore.getState().addButton({ label: "css", value: "y", color: "url(red)" });
    // Case-insensitive accept, canonical lowercase store — equality on
    // stored values must never depend on input casing.
    useUiStore.getState().addButton({ label: "upper", value: "y", color: "#FFAA00" });
    const buttons = await activeButtons();
    expect(buttons[0].color).toBe("#ffaa00");
    expect(buttons[1].color).toBeUndefined();
    expect(buttons[2].color).toBeUndefined();
    expect(buttons[3].color).toBe("#ffaa00");
  });

  it("sanitizeButtons keeps a valid color and drops a bogus one on rehydration", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({
        buttonBars: [
          {
            id: "bar-1",
            name: "Default",
            buttons: [
              { id: "b1", label: "ok", value: "v", color: "purple" },
              { id: "b2", label: "bad", value: "v", color: "javascript:alert(1)" },
              { id: "b3", label: "hex", value: "v", color: "#00ff7f" },
              { id: "b4", label: "hex8", value: "v", color: "#00ff7fcc" },
            ],
          },
        ],
        activeButtonBarId: "bar-1",
      }),
    );
    const { useUiStore } = await import("./uiStore");
    const buttons = useUiStore.getState().preferences.buttonBars[0].buttons;
    expect(buttons[0].color).toBe("purple");
    expect(buttons[1].color).toBeUndefined();
    // v6.3.0: a strict #rrggbb survives rehydration; an 8-digit form
    // (or any other non-canonical shape) is dropped like hostile CSS.
    expect(buttons[2].color).toBe("#00ff7f");
    expect(buttons[3].color).toBeUndefined();
  });

  it("addButton caps label + value length and stops at the per-bar max count", async () => {
    const { useUiStore, BUTTON_LABEL_MAX_LEN, BUTTON_VALUE_MAX_LEN, BUTTON_BAR_MAX_BUTTONS } =
      await import("./uiStore");
    useUiStore.getState().addButton({ label: "L".repeat(200), value: "V".repeat(5000) });
    const first = (await activeButtons())[0];
    expect(first.label.length).toBe(BUTTON_LABEL_MAX_LEN);
    expect(first.value.length).toBe(BUTTON_VALUE_MAX_LEN);

    for (let i = 0; i < BUTTON_BAR_MAX_BUTTONS + 5; i += 1) {
      useUiStore.getState().addButton({ label: `b${i}`, value: "x" });
    }
    expect(await activeButtons()).toHaveLength(BUTTON_BAR_MAX_BUTTONS);
    // The cap is PER BAR — a second bar starts fresh.
    useUiStore.getState().addBar("Overflow");
    useUiStore.getState().addButton({ label: "more", value: "x" });
    expect(await activeButtons()).toHaveLength(1);
  });

  it("migrates a legacy v1.4.0 buttonBarButtons blob into a single Default bar", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({
        buttonBarButtons: [
          { id: "ok", label: "good", value: "v" },
          { id: "noLabel", value: "v" }, // missing label → dropped
          { label: "noId", value: "v" }, // missing id → dropped
          { id: "blank", label: "   ", value: "v" }, // empty label → dropped
          "garbage", // non-object → dropped
        ],
      }),
    );
    const { useUiStore } = await import("./uiStore");
    const p = useUiStore.getState().preferences;
    expect(p.buttonBars).toHaveLength(1);
    expect(p.buttonBars[0].name).toBe("Default");
    expect(p.buttonBars[0].buttons).toEqual([{ id: "ok", label: "good", value: "v" }]);
    expect(p.activeButtonBarId).toBe(p.buttonBars[0].id);
  });

  it("sanitizes a persisted v2.7.0 buttonBars blob (drops malformed bars, resolves active id)", async () => {
    localStorage.setItem(
      PREFERENCES_KEY,
      JSON.stringify({
        buttonBars: [
          { id: "b1", name: "  VOIP  ", buttons: [{ id: "x", label: "mute", value: "m" }] },
          { id: "", name: "no-id", buttons: [] }, // empty id → dropped
          { name: "missing-id", buttons: [] }, // missing id → dropped
          { id: "b2", name: 42, buttons: "junk" }, // coerced: name→Default, buttons→[]
        ],
        activeButtonBarId: "not-a-real-bar",
      }),
    );
    const { useUiStore } = await import("./uiStore");
    const p = useUiStore.getState().preferences;
    expect(p.buttonBars.map((b) => b.id)).toEqual(["b1", "b2"]);
    expect(p.buttonBars[0].name).toBe("VOIP"); // trimmed
    expect(p.buttonBars[1]).toMatchObject({ name: "Default", buttons: [] });
    // Unknown active id falls back to the first bar.
    expect(p.activeButtonBarId).toBe("b1");
  });

  it("a fully-malformed buttonBars blob collapses to one empty Default bar", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ buttonBars: "garbage" }));
    const { useUiStore } = await import("./uiStore");
    const p = useUiStore.getState().preferences;
    expect(p.buttonBars).toHaveLength(1);
    expect(p.buttonBars[0]).toMatchObject({ name: "Default", buttons: [] });
  });

  it("addBar activates the new bar, caps the count, and trims names", async () => {
    const { useUiStore, BUTTON_BAR_MAX_BARS, BAR_NAME_MAX_LEN } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addBar(`  ${"N".repeat(100)}  `);
    expect(s().preferences.buttonBars).toHaveLength(2);
    const added = s().preferences.buttonBars[1];
    expect(added.name.length).toBe(BAR_NAME_MAX_LEN);
    expect(s().preferences.activeButtonBarId).toBe(added.id);
    // Whitespace-only names collapse to Default.
    s().addBar("   ");
    expect(s().preferences.buttonBars[2].name).toBe("Default");
    // Cap.
    for (let i = s().preferences.buttonBars.length; i < BUTTON_BAR_MAX_BARS + 3; i += 1) {
      s().addBar(`bar-${i}`);
    }
    expect(s().preferences.buttonBars).toHaveLength(BUTTON_BAR_MAX_BARS);
  });

  it("cycleBar wraps in both directions; setActiveBar no-ops on unknown ids", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addBar("Two"); // active
    s().addBar("Three"); // active
    const [one, two, three] = s().preferences.buttonBars;
    expect(s().preferences.activeButtonBarId).toBe(three.id);
    s().cycleBar(1); // wraps to the first
    expect(s().preferences.activeButtonBarId).toBe(one.id);
    s().cycleBar(-1); // wraps back to the last
    expect(s().preferences.activeButtonBarId).toBe(three.id);
    s().setActiveBar("nope");
    expect(s().preferences.activeButtonBarId).toBe(three.id);
    s().setActiveBar(two.id);
    expect(s().preferences.activeButtonBarId).toBe(two.id);
  });

  it("removeBar refuses the last bar and neighbor-focuses when the active bar dies", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    const only = s().preferences.buttonBars[0];
    s().removeBar(only.id); // last bar → no-op
    expect(s().preferences.buttonBars).toHaveLength(1);

    s().addBar("Two");
    s().addBar("Three");
    const [one, two, three] = s().preferences.buttonBars;
    s().setActiveBar(two.id);
    s().removeBar(two.id); // active dies → next bar (same index) takes over
    expect(s().preferences.buttonBars.map((b) => b.id)).toEqual([one.id, three.id]);
    expect(s().preferences.activeButtonBarId).toBe(three.id);
    s().removeBar(three.id); // active again, no next → previous
    expect(s().preferences.activeButtonBarId).toBe(one.id);
  });

  it("renameBar trims + caps; an empty rename keeps the old name", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    const bar = s().preferences.buttonBars[0];
    s().renameBar(bar.id, "  Routers  ");
    expect(s().preferences.buttonBars[0].name).toBe("Routers");
    s().renameBar(bar.id, "   ");
    expect(s().preferences.buttonBars[0].name).toBe("Routers");
  });
});

describe("uiStore broadcast bar (v2.4.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("defaults to hidden", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.showBroadcastBar).toBe(false);
  });

  it("setShowBroadcastBar toggles + persists", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().setShowBroadcastBar(true);
    expect(useUiStore.getState().preferences.showBroadcastBar).toBe(true);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.showBroadcastBar).toBe(true);
  });

  it("loads a persisted true value", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ showBroadcastBar: true }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.showBroadcastBar).toBe(true);
  });
});

describe("uiStore multi-chat tabs (v2.5.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  const P = (chatId: string) => ({
    request_id: `req-${chatId}`,
    chat_id: chatId,
    session_id: "s",
    command: "show version",
    gate_decision: "allow",
    allow_auto_approve: true,
  });

  it("addChat appends with a stable seq and focuses it; cap at CHAT_TABS_MAX", async () => {
    const { useUiStore, CHAT_TABS_MAX } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m1");
    s().addChat("b", "m2");
    expect(s().chats.map((c) => c.chatId)).toEqual(["a", "b"]);
    expect(s().chats.map((c) => c.seq)).toEqual([1, 2]);
    expect(s().activeChatId).toBe("b");
    // Fill to the cap; further adds no-op.
    for (let i = s().chats.length; i < CHAT_TABS_MAX; i += 1) s().addChat(`x${i}`, "m");
    expect(s().chats.length).toBe(CHAT_TABS_MAX);
    s().addChat("overflow", "m");
    expect(s().chats.length).toBe(CHAT_TABS_MAX);
    expect(s().chats.some((c) => c.chatId === "overflow")).toBe(false);
  });

  it("seq is stable — closing an earlier tab doesn't renumber survivors", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m"); // seq 1
    s().addChat("b", "m"); // seq 2
    s().addChat("c", "m"); // seq 3
    s().removeChat("b");
    expect(s().chats.find((c) => c.chatId === "c")?.seq).toBe(3);
    s().addChat("d", "m"); // seq 4, never reuses 2
    expect(s().chats.find((c) => c.chatId === "d")?.seq).toBe(4);
  });

  it("removeChat focuses the neighbor (next → prev → null) and purges attention", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().addChat("b", "m");
    s().addChat("c", "m");
    s().setActiveChat("b");
    s().setChatPendingApproval("b", P("b"));
    s().removeChat("b");
    // Neighbor at the removed index (c) takes focus.
    expect(s().activeChatId).toBe("c");
    expect(s().pendingApprovalByChat.b).toBeUndefined();
    // Remove the last remaining, focus falls to prev then null.
    s().removeChat("c");
    s().removeChat("a");
    expect(s().activeChatId).toBeNull();
  });

  it("setActiveChat clears the focused chat's green dot but keeps its pending approval", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().addChat("b", "m"); // active = b
    // A completion + a pending approval land on the (currently inactive) a.
    s().markChatCompleted("a");
    s().setChatPendingApproval("a", P("a"));
    expect(s().completedUnfocusedByChat.a).toBe(true);
    s().setActiveChat("a");
    // Green dot cleared on focus; pending approval retained for the modal.
    expect(s().completedUnfocusedByChat.a).toBeUndefined();
    expect(s().pendingApprovalByChat.a).toBeDefined();
  });

  it("markChatCompleted is a no-op for the active chat", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m"); // active = a
    s().markChatCompleted("a");
    expect(s().completedUnfocusedByChat.a).toBeUndefined();
  });

  it("setChatModel + setChatLabel + clearAllChats", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m1");
    s().setChatModel("a", "m2");
    expect(s().chats[0].model).toBe("m2");
    // The caller (ChatTabTrigger) trims before calling; the action stores
    // a non-empty label verbatim and treats empty as "revert to auto".
    s().setChatLabel("a", "Core lab");
    expect(s().chats[0].customLabel).toBe("Core lab");
    s().setChatLabel("a", "");
    expect(s().chats[0].customLabel).toBeNull();
    s().clearAllChats();
    expect(s().chats).toEqual([]);
    expect(s().activeChatId).toBeNull();
  });

  it("notifyOnUnfocusedComplete defaults on, toggles + persists", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.notifyOnUnfocusedComplete).toBe(true);
    useUiStore.getState().setNotifyOnUnfocusedComplete(false);
    expect(useUiStore.getState().preferences.notifyOnUnfocusedComplete).toBe(false);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.notifyOnUnfocusedComplete).toBe(false);
  });
});

describe("uiStore chat composer send key (v6.3.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("chatSendOnEnter defaults on (fresh install + absent key)", async () => {
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(true);
  });

  it("toggles + persists, and an existing blob without the key stays default-on", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ showButtonBar: true }));
    const { useUiStore } = await import("./uiStore");
    // Pre-v6.3.0 blob: key absent → default ON, siblings honored.
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(true);
    expect(useUiStore.getState().preferences.showButtonBar).toBe(true);
    useUiStore.getState().setChatSendOnEnter(false);
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(false);
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.chatSendOnEnter).toBe(false);
    expect(persisted.showButtonBar).toBe(true);
  });

  it("a malformed persisted value coerces back to the default (on)", async () => {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ chatSendOnEnter: "yes please" }));
    const { useUiStore } = await import("./uiStore");
    expect(useUiStore.getState().preferences.chatSendOnEnter).toBe(true);
  });
});

describe("uiStore chat labels (v6.3.0 persistence)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("setChatLabel persists to the label map; closing the chat prunes it", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().setChatLabel("a", "Core lab");
    expect(s().preferences.chatLabelsById.a).toBe("Core lab");
    let persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.chatLabelsById.a).toBe("Core lab");
    s().removeChat("a");
    expect(s().preferences.chatLabelsById.a).toBeUndefined();
    persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.chatLabelsById?.a).toBeUndefined();
  });

  it("the label map is capped AT WRITE TIME, not only at next load", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    // 20 renames in one session: the merged map must stay at the cap and
    // keep the NEWEST entries (the loader cap alone truncated newest-first
    // at next launch — review finding).
    for (let i = 0; i < 20; i++) {
      s().setChatLabel(`chat-${i}`, `Label ${i}`);
    }
    const ids = Object.keys(s().preferences.chatLabelsById);
    expect(ids.length).toBe(16);
    expect(s().preferences.chatLabelsById["chat-19"]).toBe("Label 19");
    expect(s().preferences.chatLabelsById["chat-0"]).toBeUndefined();
  });

  it("applyRestoredChatLabels applies to unnamed tabs and prunes dead ids in one write", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().setChatLabel("dead", "Old chat"); // no live tab — should prune
    s().addChat("live", "m");
    s().applyRestoredChatLabels({ live: "Restored name" }, ["live"]);
    expect(s().chats[0].customLabel).toBe("Restored name");
    expect(s().preferences.chatLabelsById.dead).toBeUndefined();
    const persisted = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "{}");
    expect(persisted.chatLabelsById?.dead).toBeUndefined();
  });

  it("applyRestoredChatLabels never overwrites a user-set label", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().setChatLabel("a", "My name");
    s().applyRestoredChatLabels({ a: "Stale restored name" }, ["a"]);
    expect(s().chats[0].customLabel).toBe("My name");
  });

  it("an EMPTY live set never wipes the label map (transient backend miss)", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().setChatLabel("a", "Keep me");
    s().applyRestoredChatLabels({}, []);
    expect(s().preferences.chatLabelsById.a).toBe("Keep me");
  });
});

describe("uiStore chat scope (v2.7.0, T31)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("addChat defaults scopedDeviceIds to null (unscoped) — never undefined", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.getState().addChat("a", "m");
    const chat = useUiStore.getState().chats[0];
    // Explicit null, not absent: null vs undefined would be a silent
    // third scope state the popover/thunk can't reason about.
    expect(chat.scopedDeviceIds).toBeNull();
    expect("scopedDeviceIds" in chat).toBe(true);
  });

  it("setChatScope stores a device list per chat and null restores all-devices", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().addChat("b", "m");
    s().setChatScope("a", ["vEX1", "core1"]);
    expect(s().chats.find((c) => c.chatId === "a")?.scopedDeviceIds).toEqual(["vEX1", "core1"]);
    // Per-chat: b is untouched.
    expect(s().chats.find((c) => c.chatId === "b")?.scopedDeviceIds).toBeNull();
    s().setChatScope("a", []);
    expect(s().chats.find((c) => c.chatId === "a")?.scopedDeviceIds).toEqual([]);
    s().setChatScope("a", null);
    expect(s().chats.find((c) => c.chatId === "a")?.scopedDeviceIds).toBeNull();
  });

  it("scope is chat-tab state — removeChat drops it with the tab", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().setChatScope("a", ["vEX1"]);
    s().removeChat("a");
    s().addChat("a", "m"); // same id re-added → fresh unscoped tab
    expect(s().chats.find((c) => c.chatId === "a")?.scopedDeviceIds).toBeNull();
  });

  it("addSession stores agentDeviceId only when it differs and falls back to deviceId", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    // SSH tab: agent id == display id → not stored (fallback covers it).
    s().addSession("s1", "vEX1", "vEX1");
    // Console tab: display id is prefixed; the agent-visible id rides along.
    s().addSession("s2", "console-FTDI FT232R", "FTDI FT232R");
    const [ssh, console_] = s().sessions;
    expect(ssh.agentDeviceId).toBeUndefined();
    expect(console_.agentDeviceId).toBe("FTDI FT232R");
    expect(console_.deviceId).toBe("console-FTDI FT232R");
  });
});

describe("uiStore API tabs + sidebar view (v4.0.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("sidebarView defaults to 'ssh' and setSidebarView flips it", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    expect(s().sidebarView).toBe("ssh");
    s().setSidebarView("apis");
    expect(s().sidebarView).toBe("apis");
    s().setSidebarView("terminal");
    expect(s().sidebarView).toBe("terminal");
    s().setSidebarView("files");
    expect(s().sidebarView).toBe("files");
  });

  it("openShellTab adds a kind:'local' tab keyed by the real backend id and focuses it (v4.4.0)", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openShellTab("sess-abc", "zsh");
    const tab = s().sessions.at(-1)!;
    expect(tab.kind).toBe("local");
    // Local shells carry a REAL backend session id (not a synthetic api: id).
    expect(tab.sessionId).toBe("sess-abc");
    expect(tab.deviceId).toBe("zsh"); // drives computeLabels
    expect(tab.ended).toBe(false);
    expect(tab.apiSessionId).toBeUndefined();
    expect(s().activeTabId).toBe("sess-abc");
  });

  it("openApiTab adds a kind:'api' tab, labels it with the controller name, and focuses it", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openApiTab("ctrl-1", "HQ Controller");
    const tab = s().sessions.at(-1)!;
    expect(tab.kind).toBe("api");
    expect(tab.apiSessionId).toBe("ctrl-1");
    expect(tab.deviceId).toBe("HQ Controller"); // drives computeLabels
    expect(tab.ended).toBe(false);
    // Synthetic id namespaced so it can never collide with a backend session id.
    expect(tab.sessionId.startsWith("api:ctrl-1:")).toBe(true);
    expect(s().activeTabId).toBe(tab.sessionId);
  });

  it("two tabs off the same controller get distinct synthetic ids", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openApiTab("ctrl-1", "HQ Controller");
    s().openApiTab("ctrl-1", "HQ Controller");
    const ids = s().sessions.map((t) => t.sessionId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("removeSession drops an API tab with no backend call", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openApiTab("ctrl-1", "HQ Controller");
    const id = s().sessions.at(-1)!.sessionId;
    s().removeSession(id);
    expect(s().sessions.find((t) => t.sessionId === id)).toBeUndefined();
  });

  it("launchApiRequest opens a tab, focuses it, and stashes the template for that tab", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    const tmpl = {
      id: "r1",
      name: "List sites",
      method: "GET",
      path: "/v1/sites",
      headers: [],
      body: null,
      destructive: false,
    };
    s().launchApiRequest("ctrl-1", "HQ Controller", tmpl);
    const tab = s().sessions.at(-1)!;
    expect(tab.kind).toBe("api");
    expect(tab.apiSessionId).toBe("ctrl-1");
    expect(s().activeTabId).toBe(tab.sessionId);
    expect(s().pendingApiLoad[tab.sessionId]).toEqual(tmpl);
  });

  it("launchApiRequest reuses the controller's existing tab (no duplicate)", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    const t = (path: string) => ({
      id: path,
      name: path,
      method: "GET",
      path,
      headers: [],
      body: null,
      destructive: false,
    });
    s().launchApiRequest("ctrl-1", "HQ", t("/v1/sites"));
    const first = s().sessions.at(-1)!.sessionId;
    s().launchApiRequest("ctrl-1", "HQ", t("/v1/devices"));
    const apiTabs = s().sessions.filter((x) => x.apiSessionId === "ctrl-1");
    expect(apiTabs).toHaveLength(1);
    // The newer template replaces the pending one on the same tab.
    expect(s().pendingApiLoad[first]?.path).toBe("/v1/devices");
  });

  it("openFilesTab adds a kind:'files' tab keyed by the real backend id and focuses it (v5.0.0)", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openFilesTab("files-sess-1", "vEX1");
    const tab = s().sessions.at(-1)!;
    expect(tab.kind).toBe("files");
    // A REAL backend session id (files_connect), not a synthetic api: id.
    expect(tab.sessionId).toBe("files-sess-1");
    // The INVENTORY id — so the per-host tab accent and computeLabels work.
    expect(tab.deviceId).toBe("vEX1");
    expect(tab.ended).toBe(false);
    expect(tab.apiSessionId).toBeUndefined();
    expect(s().activeTabId).toBe("files-sess-1");
  });

  it("openFilesTab always opens a NEW tab, even for the same device", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openFilesTab("f1", "vEX1");
    s().openFilesTab("f2", "vEX1");
    expect(s().sessions.filter((t) => t.kind === "files")).toHaveLength(2);
    expect(s().activeTabId).toBe("f2");
  });

  it("consumeApiLoad clears a tab's pending template", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().launchApiRequest("ctrl-1", "HQ", {
      id: "r",
      name: "r",
      method: "GET",
      path: "/v1/sites",
      headers: [],
      body: null,
      destructive: false,
    });
    const id = s().sessions.at(-1)!.sessionId;
    s().consumeApiLoad(id);
    expect(s().pendingApiLoad[id]).toBeUndefined();
  });
});

describe("uiStore session tab reorder (v4.1.0 draggable tabs)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  const t = (sessionId: string, extra: { splitWith?: string } = {}) => ({
    sessionId,
    deviceId: sessionId,
    ended: false,
    ...extra,
  });

  it("moves a tab into another tab's slot", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("a"), t("b"), t("c")], activeTabId: "a" });
    useUiStore.getState().moveSession("c", "a"); // drop C onto A → C first
    expect(useUiStore.getState().sessions.map((x) => x.sessionId)).toEqual(["c", "a", "b"]);
  });

  it("moves the first tab to the last slot", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("a"), t("b"), t("c")], activeTabId: "a" });
    useUiStore.getState().moveSession("a", "c");
    expect(useUiStore.getState().sessions.map((x) => x.sessionId)).toEqual(["b", "c", "a"]);
  });

  it("is a no-op for equal ids or a missing id", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("a"), t("b")], activeTabId: "a" });
    useUiStore.getState().moveSession("a", "a");
    useUiStore.getState().moveSession("a", "ghost");
    useUiStore.getState().moveSession("ghost", "b");
    expect(useUiStore.getState().sessions.map((x) => x.sessionId)).toEqual(["a", "b"]);
  });

  it("preserves a split right pane (found by splitWith, not adjacency)", async () => {
    const { useUiStore } = await import("./uiStore");
    // P1 hosts a right pane R1; the top-level tabs are P1 then P2.
    useUiStore.setState({
      sessions: [t("P1"), t("R1", { splitWith: "P1" }), t("P2")],
      activeTabId: "P1",
    });
    useUiStore.getState().moveSession("P2", "P1"); // P2 before P1
    const s = useUiStore.getState();
    const topLevel = s.sessions.filter((x) => !x.splitWith).map((x) => x.sessionId);
    expect(topLevel).toEqual(["P2", "P1"]);
    // The right pane survives and stays bound to its primary.
    expect(s.sessions.find((x) => x.sessionId === "R1")?.splitWith).toBe("P1");
  });

  it("does not change the active tab", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("a"), t("b"), t("c")], activeTabId: "b" });
    useUiStore.getState().moveSession("c", "a");
    expect(useUiStore.getState().activeTabId).toBe("b");
  });
});

describe("uiStore drag-to-split (v4.4.0 movePaneInto)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  const t = (
    sessionId: string,
    extra: {
      splitWith?: string;
      layout?: PaneNode;
      kind?: "api" | "local" | "files";
      apiSessionId?: string;
    } = {},
  ) => ({ sessionId, deviceId: sessionId, ended: false, ...extra });

  it("tiles a standalone tab into a single-pane primary (right) + follows focus", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("A"), t("B")], activeTabId: "B" });
    useUiStore.getState().movePaneInto("B", "A", "row", false); // drop B on A's right
    const s = useUiStore.getState();
    expect(s.sessions.filter((x) => !x.splitWith).map((x) => x.sessionId)).toEqual(["A"]);
    expect(s.sessions.find((x) => x.sessionId === "B")?.splitWith).toBe("A");
    expect(s.sessions.find((x) => x.sessionId === "A")?.layout).toEqual(
      split("row", [leaf("A"), leaf("B")]),
    );
    // Dragged tab was focused → focus follows into its new home (the primary).
    expect(s.activeTabId).toBe("A");
  });

  it("before=true inserts on the left/top side", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({ sessions: [t("A"), t("B")], activeTabId: "A" });
    useUiStore.getState().movePaneInto("B", "A", "col", true); // B ABOVE A
    expect(useUiStore.getState().sessions.find((x) => x.sessionId === "A")?.layout).toEqual(
      split("col", [leaf("B"), leaf("A")]),
    );
  });

  it("reparents ALL panes of a dragged multi-pane tab under the target primary", async () => {
    const { useUiStore } = await import("./uiStore");
    // Dragged tab D owns a pane E (D = [D | E]); target A is single-pane.
    useUiStore.setState({
      sessions: [
        t("A"),
        t("D", { layout: split("row", [leaf("D"), leaf("E")]) }),
        t("E", { splitWith: "D" }),
      ],
      activeTabId: "A",
    });
    useUiStore.getState().movePaneInto("D", "A", "col", false); // D's subtree below A
    const s = useUiStore.getState();
    // D + E both reparent under A; D loses its own layout.
    expect(s.sessions.find((x) => x.sessionId === "D")?.splitWith).toBe("A");
    expect(s.sessions.find((x) => x.sessionId === "D")?.layout).toBeUndefined();
    expect(s.sessions.find((x) => x.sessionId === "E")?.splitWith).toBe("A");
    expect(s.sessions.filter((x) => !x.splitWith).map((x) => x.sessionId)).toEqual(["A"]);
    expect(s.sessions.find((x) => x.sessionId === "A")?.layout).toEqual(
      split("col", [leaf("A"), split("row", [leaf("D"), leaf("E")])]),
    );
  });

  it("no-ops on same-tab drop, non-PTY (API/Files) source/target, or missing ids", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({
      sessions: [
        t("A"),
        t("B"),
        t("api1", { kind: "api", apiSessionId: "c1" }),
        t("files1", { kind: "files" }),
      ],
      activeTabId: "A",
    });
    const before = JSON.stringify(useUiStore.getState().sessions);
    useUiStore.getState().movePaneInto("A", "A", "row", false); // same tab
    useUiStore.getState().movePaneInto("api1", "A", "row", false); // API dragged
    useUiStore.getState().movePaneInto("B", "api1", "row", false); // API target
    // v5.0.0 — a Files tab has no TerminalPane, so tiling it either way must
    // be inert (plan decision 6: no tiling for Files in v1).
    useUiStore.getState().movePaneInto("files1", "A", "row", false); // Files dragged
    useUiStore.getState().movePaneInto("B", "files1", "row", false); // Files target
    useUiStore.getState().movePaneInto("ghost", "A", "row", false); // missing source
    useUiStore.getState().movePaneInto("B", "ghost", "row", false); // missing target
    expect(JSON.stringify(useUiStore.getState().sessions)).toBe(before);
  });

  it("splitPaneWith refuses a non-PTY target and falls back to a normal tab", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({
      sessions: [t("files1", { kind: "files" }), t("api1", { kind: "api", apiSessionId: "c1" })],
      activeTabId: "files1",
    });
    // Connecting with a split target that can't host a PaneTree must never
    // strand the new session as a pane nobody renders.
    useUiStore.getState().splitPaneWith("new1", "vEX9", "files1", "row");
    useUiStore.getState().splitPaneWith("new2", "vEX9", "api1", "col");
    const s = useUiStore.getState();
    expect(s.sessions.find((x) => x.sessionId === "new1")?.splitWith).toBeUndefined();
    expect(s.sessions.find((x) => x.sessionId === "new2")?.splitWith).toBeUndefined();
    expect(s.sessions.find((x) => x.sessionId === "files1")?.layout).toBeUndefined();
    expect(s.sessions.find((x) => x.sessionId === "api1")?.layout).toBeUndefined();
    expect(s.activeTabId).toBe("new2");
  });
});

describe("uiStore pane focus (v6.4.0 activePaneId)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  const t = (sessionId: string, extra: { splitWith?: string; layout?: PaneNode } = {}) => ({
    sessionId,
    deviceId: sessionId,
    ended: false,
    ...extra,
  });

  // A tab whose primary is A holding panes A | B.
  const splitAB = () => [
    t("A", { layout: split("row", [leaf("A"), leaf("B")]) }),
    t("B", { splitWith: "A" }),
  ];

  it("resolves to the tab id on an un-split tab (pre-v6.4.0 behaviour preserved)", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: [t("A")],
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    expect(resolveActivePaneId(useUiStore.getState())).toBe("A");
  });

  it("focuses a pane of the active tab", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: splitAB(),
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().setActivePane("B");
    expect(resolveActivePaneId(useUiStore.getState())).toBe("B");
  });

  it("REFUSES a pane that isn't in the active tab", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    // C is a separate top-level tab; focusing it while A is active is stale.
    useUiStore.setState({
      sessions: [...splitAB(), t("C")],
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().setActivePane("C");
    expect(useUiStore.getState().activePaneId).toBeNull();
    expect(resolveActivePaneId(useUiStore.getState())).toBe("A");
  });

  it("resolver falls back to the primary when the hint goes stale", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    // A hint naming a session that is no longer a pane of the active tab —
    // exactly what the many activeTabId-only actions leave behind.
    useUiStore.setState({
      sessions: [t("A")],
      activeTabId: "A",
      activePaneId: "ghost",
      lastPaneByTab: {},
    });
    expect(resolveActivePaneId(useUiStore.getState())).toBe("A");
  });

  it("splitting focuses the NEW pane", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: [t("A")],
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().splitPaneWith("B", "B", "A", "row");
    expect(useUiStore.getState().activeTabId).toBe("A");
    expect(resolveActivePaneId(useUiStore.getState())).toBe("B");
  });

  it("remembers the focused pane per tab across a tab switch", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: [...splitAB(), t("C")],
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().setActivePane("B");
    useUiStore.getState().setActiveTab("C");
    expect(resolveActivePaneId(useUiStore.getState())).toBe("C");
    useUiStore.getState().setActiveTab("A");
    // Back on A → the pane we were in, not A's primary.
    expect(resolveActivePaneId(useUiStore.getState())).toBe("B");
  });

  it("falls back to the primary when the remembered pane was closed meanwhile", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: [...splitAB(), t("C")],
      activeTabId: "A",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().setActivePane("B");
    useUiStore.getState().setActiveTab("C");
    useUiStore.getState().removeSession("B"); // closed while backgrounded
    useUiStore.getState().setActiveTab("A");
    expect(resolveActivePaneId(useUiStore.getState())).toBe("A");
  });

  it("closing the focused pane hands focus to its neighbour, not the primary", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    // Three panes A | B | C, focus on C. Closing C should land on B.
    useUiStore.setState({
      sessions: [
        t("A", { layout: split("row", [leaf("A"), leaf("B"), leaf("C")]) }),
        t("B", { splitWith: "A" }),
        t("C", { splitWith: "A" }),
      ],
      activeTabId: "A",
      activePaneId: "C",
      lastPaneByTab: { A: "C" },
    });
    useUiStore.getState().removeSession("C");
    expect(resolveActivePaneId(useUiStore.getState())).toBe("B");
  });

  it("closing a tab prunes its focus memory", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({
      sessions: [...splitAB(), t("C")],
      activeTabId: "A",
      activePaneId: "B",
      lastPaneByTab: { A: "B" },
    });
    useUiStore.getState().removeSession("A"); // cascades A + B
    const s = useUiStore.getState();
    expect(s.lastPaneByTab).not.toHaveProperty("A");
    expect(s.activePaneId).toBeNull();
  });

  it("movePaneOut lifts a pane into its own tab and focuses it", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: splitAB(),
      activeTabId: "A",
      activePaneId: "B",
      lastPaneByTab: { A: "B" },
    });
    useUiStore.getState().movePaneOut("B");
    const s = useUiStore.getState();
    expect(s.sessions.find((x) => x.sessionId === "B")?.splitWith).toBeUndefined();
    expect(
      s.sessions
        .filter((x) => !x.splitWith)
        .map((x) => x.sessionId)
        .sort(),
    ).toEqual(["A", "B"]);
    expect(s.activeTabId).toBe("B");
    expect(resolveActivePaneId(s)).toBe("B");
  });

  it("movePaneOut round-trips with movePaneInto", async () => {
    const { useUiStore } = await import("./uiStore");
    useUiStore.setState({
      sessions: [t("A"), t("B")],
      activeTabId: "B",
      activePaneId: null,
      lastPaneByTab: {},
    });
    useUiStore.getState().movePaneInto("B", "A", "row", false);
    useUiStore.getState().movePaneOut("B");
    const s = useUiStore.getState();
    // Back to two independent tabs, and A's tree no longer references B.
    expect(
      s.sessions
        .filter((x) => !x.splitWith)
        .map((x) => x.sessionId)
        .sort(),
    ).toEqual(["A", "B"]);
    const layout = s.sessions.find((x) => x.sessionId === "A")?.layout;
    expect(JSON.stringify(layout ?? null)).not.toContain('"B"');
  });

  it("movePaneOut no-ops on a primary (already its own tab)", async () => {
    const { useUiStore } = await import("./uiStore");
    const before = splitAB();
    useUiStore.setState({
      sessions: before,
      activeTabId: "A",
      activePaneId: "A",
      lastPaneByTab: {},
    });
    useUiStore.getState().movePaneOut("A");
    expect(useUiStore.getState().sessions).toEqual(before);
  });

  it("reconnectSession rewrites the focus hint through the id swap", async () => {
    const { useUiStore, resolveActivePaneId } = await import("./uiStore");
    useUiStore.setState({
      sessions: splitAB(),
      activeTabId: "A",
      activePaneId: "B",
      lastPaneByTab: { A: "B" },
    });
    useUiStore.getState().reconnectSession("B", "B2");
    const s = useUiStore.getState();
    expect(s.activePaneId).toBe("B2");
    expect(s.lastPaneByTab.A).toBe("B2");
    expect(resolveActivePaneId(s)).toBe("B2");
  });
});

describe("uiStore tab-kind predicates (v5.0.0)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("hasPty is true for SSH/console + local shells, false for API + Files", async () => {
    const { hasPty } = await import("./uiStore");
    expect(hasPty({ kind: undefined })).toBe(true); // SSH / console
    expect(hasPty({})).toBe(true); // same thing, field absent
    expect(hasPty({ kind: "local" })).toBe(true); // a real PTY
    expect(hasPty({ kind: "api" })).toBe(false);
    expect(hasPty({ kind: "files" })).toBe(false);
  });

  it("isFilesTab identifies only the SFTP kind (the disjoint teardown path)", async () => {
    const { isFilesTab } = await import("./uiStore");
    expect(isFilesTab({ kind: "files" })).toBe(true);
    expect(isFilesTab({ kind: "local" })).toBe(false);
    expect(isFilesTab({ kind: "api" })).toBe(false);
    expect(isFilesTab({ kind: undefined })).toBe(false);
  });
});

describe("uiStore captures dialog preselect (v3.2.1)", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("openCaptures() with no arg opens the dialog with no preselected session", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openCaptures();
    expect(s().capturesDialogOpen).toBe(true);
    expect(s().capturesPreselectSessionId).toBeNull();
  });

  it("openCaptures(sessionId) — from a tab right-click — records the preselect; consume clears it", async () => {
    const { useUiStore } = await import("./uiStore");
    const s = () => useUiStore.getState();
    s().openCaptures("sess-1");
    expect(s().capturesDialogOpen).toBe(true);
    expect(s().capturesPreselectSessionId).toBe("sess-1");
    // One-shot: the dialog consumes it on open so it can't override a later
    // manual change or re-fire when the live-session set shifts.
    s().consumeCapturesPreselect();
    expect(s().capturesPreselectSessionId).toBeNull();
    expect(s().capturesDialogOpen).toBe(true); // consume doesn't close the dialog
  });
});

describe("sortSessionsByLabel (v6.1.0)", () => {
  // The store reads localStorage at module-init, so this suite imports it
  // dynamically like the others above.
  let useUiStore: typeof import("@/stores/uiStore").useUiStore;

  beforeEach(async () => {
    localStorage.clear();
    ({ useUiStore } = await import("@/stores/uiStore"));
  });

  function seed(tabs: { sessionId: string; deviceId: string; customLabel?: string }[]) {
    useUiStore.setState({
      sessions: tabs.map((t) => ({
        sessionId: t.sessionId,
        deviceId: t.deviceId,
        kind: "ssh" as const,
        ended: false,
        customLabel: t.customLabel ?? null,
      })) as never,
      activeTabId: tabs[0]?.sessionId ?? null,
    });
  }

  it("reorders tabs alphabetically by displayed label", () => {
    seed([
      { sessionId: "s1", deviceId: "switch-b" },
      { sessionId: "s2", deviceId: "router-a" },
      { sessionId: "s3", deviceId: "firewall-c" },
    ]);
    useUiStore.getState().sortSessionsByLabel();
    expect(useUiStore.getState().sessions.map((t) => t.deviceId)).toEqual([
      "firewall-c",
      "router-a",
      "switch-b",
    ]);
  });

  it("sorts on the RENAME, not the device id", () => {
    // The user reads labels, so that is what must sort. Sorting on
    // deviceId would scatter renamed tabs against what's on screen.
    seed([
      { sessionId: "s1", deviceId: "zzz-device", customLabel: "aaa-core" },
      { sessionId: "s2", deviceId: "aaa-device" },
    ]);
    useUiStore.getState().sortSessionsByLabel();
    expect(useUiStore.getState().sessions.map((t) => t.sessionId)).toEqual(["s1", "s2"]);
  });

  it("orders duplicates naturally (2 before 10, not lexically)", () => {
    seed([
      { sessionId: "s1", deviceId: "sw" },
      { sessionId: "s2", deviceId: "sw" },
      { sessionId: "s3", deviceId: "sw" },
    ]);
    // Labels are sw, sw (2), sw (3) — already sorted; assert the numeric
    // collation holds rather than "sw (10)" sorting before "sw (2)".
    useUiStore.getState().sortSessionsByLabel();
    expect(useUiStore.getState().sessions.map((t) => t.sessionId)).toEqual(["s1", "s2", "s3"]);
  });

  it("leaves the active tab selected — only the ORDER changes", () => {
    seed([
      { sessionId: "s1", deviceId: "switch-b" },
      { sessionId: "s2", deviceId: "router-a" },
    ]);
    useUiStore.setState({ activeTabId: "s1" });
    useUiStore.getState().sortSessionsByLabel();
    expect(useUiStore.getState().activeTabId).toBe("s1");
    expect(useUiStore.getState().sessions).toHaveLength(2);
  });

  it("is a no-op on an empty strip", () => {
    seed([]);
    useUiStore.getState().sortSessionsByLabel();
    expect(useUiStore.getState().sessions).toEqual([]);
  });
});

describe("cachedModels preference (model discovery)", () => {
  it("sanitizeCachedModels keeps only well-formed entries and caps the list", async () => {
    const { sanitizeCachedModels } = await import("@/stores/uiStore");
    const good = {
      id: "claude-opus-5-5",
      display_name: "Claude Opus 5.5",
      created: 1,
      level: "advanced",
      context_window: 1000,
    };
    const out = sanitizeCachedModels({
      anthropic: [good, { id: 7 }, { id: "x", display_name: "x", level: "huge" }, "junk"],
      openai: "not a list",
      bogus: [good],
    });
    expect(out.anthropic).toEqual([good]);
    expect(out.openai).toBeUndefined();
    expect(Object.keys(out)).toEqual(["anthropic"]);
    const many = Array.from({ length: 250 }, (_, i) => ({ ...good, id: `m-${i}` }));
    expect(sanitizeCachedModels({ openai: many }).openai?.length).toBe(200);
  });
});
