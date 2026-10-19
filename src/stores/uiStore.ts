import { create } from "zustand";

import type { ProposeApiCallRequestPayload, ProposeCommandRequestPayload } from "@/lib/api";
import type { ApiRequestTemplate } from "@/lib/apiCollections";
import { isAccentValue, normalizeAccent } from "@/lib/deviceColors";
// Value import into a module that `sessionLabels` imports a TYPE from —
// type-only edges are erased, so there is no runtime cycle.
import { computeLabels } from "@/lib/sessionLabels";
import {
  hasPane,
  insertNodeAt,
  leaf,
  neighborPane,
  paneIds,
  removeLeaf,
  renameLeaf,
  splitLeaf,
  type PaneNode,
} from "@/lib/paneTree";

/** localStorage key for the persisted preferences blob. Exported so the
 *  v6.1.0 settings bundle can round-trip it verbatim without the export
 *  code re-deriving (and drifting from) the store's schema. */
export const PREFERENCES_KEY = "transit.preferences";

/** Max concurrent AI chat tabs (v2.5.0). Bounds concurrent LLM spend,
 *  backend HashMap growth, and live event-subscription sets. Mirrored by
 *  the backend's `RESTORE_TAB_CAP` (chat.rs, v6.3.0) — lowering this
 *  without lowering that strands restored sessions without tabs. */
export const CHAT_TABS_MAX = 8;

/** A single button-bar macro. `value` is the "Send
 *  String" — sent to the active session with escape codes expanded
 *  (\r Enter, \n newline, \p 1s delay, \v paste, \e/\033/\### ESC/octal). */
export interface ButtonBarButton {
  id: string;
  label: string;
  value: string;
  /** v6.1.0 — where the button's text goes.
   *
   *  `"session"` (default, and what every pre-v6.1.0 button is) sends the
   *  value to the active PTY with the escape codes expanded.
   *  `"agent"` drops it into the AI composer instead, turning the bar into
   *  a saved-prompt palette.
   *
   *  Rule 3 is untouched by the agent variant: a button that types a
   *  PROMPT is not a button that runs a COMMAND. Whatever the assistant
   *  then decides to do still passes the policy gate and the approval
   *  modal, exactly as if the text had been typed by hand. */
  target?: "session" | "agent";
  /** Optional palette token (`deviceColors.ts`) for a per-button background
   *  shade — shares one color vocabulary with per-host colors. Absent = the
   *  default outline style. */
  color?: string;
}

/** v2.7.0 — a named button bar. Users keep multiple bars (e.g. a
 *  "VOIP" set and a "Routers" set) and cycle between them with the
 *  bar's up/down chevrons or jump via the name popover. The ACTIVE
 *  bar is what renders and what the Map Button dialog edits. */
export interface ButtonBar {
  id: string;
  name: string;
  buttons: ButtonBarButton[];
}

interface PersistedPreferences {
  themeId: string | null;
  chatPanelWidth: number | null;
  /** Confirm before closing a session that still has a live connection —
   *  the tab's X and a pane's Disconnect button. `true` (default) is the
   *  v1.4.0 anti-misclick behaviour; `false` closes immediately.
   *
   *  Scoped deliberately to the PER-SESSION close. It does NOT suppress
   *  the Files-transfer confirm (that one warns about losing in-flight
   *  work, a different risk from "you will disconnect"), nor "Close all
   *  tabs", nor quitting the app — both of those are bulk actions whose
   *  blast radius is the whole workspace. User request 2026-09-02:
   *  "some users just want to click the X and it closes". */
  warnOnSessionClose: boolean;
  /** v6.5.2 — width of the left sidebar rail in CSS pixels. `null` means
   *  "use SIDEBAR_DEFAULT_WIDTH". ONE value across all five sidebar views
   *  (SSH / Terminal / Files / APIs / PCaps): the rail is one conceptual
   *  column, and per-view widths would make the layout jump on every view
   *  switch. Clamped by the drag handle, not here — the clamp is
   *  viewport-relative, so it can only be applied where a window exists. */
  sidebarWidth: number | null;
  /** Last user-set chat-panel-open value. `null` means the user has
   *  never explicitly toggled it — the store defaults to `true` so
   *  first-time users see the AI affordance immediately. After the
   *  first toggle this becomes a concrete boolean and is honored
   *  across launches. */
  chatPanelOpen: boolean | null;
  /** Global terminal-pane font size in CSS pixels. `null` means
   *  "use TERMINAL_FONT_SIZE_DEFAULT". Cmd+/Cmd-/Cmd+0 + the
   *  Settings → General control both mutate this; every TerminalPane
   *  subscribes and updates xterm.js's options.fontSize live. */
  terminalFontSize: number | null;
  /** Global terminal font family (a CSS font-family list, free text
   *  from Settings → General). `null` means "use
   *  TERMINAL_FONT_FAMILY_DEFAULT". TerminalPane always appends the
   *  default stack as a fallback, so an uninstalled (but CSS-valid)
   *  family degrades to the stock look rather than the renderer's
   *  serif fallback. */
  terminalFontFamily: string | null;
  /** Base font size (CSS pixels) for the agent chat panel's message
   *  thread. `null` means "use CHAT_FONT_SIZE_DEFAULT". The Settings →
   *  General control mutates this; ChatPanel sets it on the message
   *  scroll container and the bubbles render relative to it. Independent
   *  of `terminalFontSize` — chat prose reads better a touch larger than
   *  the terminal's monospace default. */
  chatFontSize: number | null;
  /** Extra provider model ids the user typed in Settings → API keys
   *  (a model newer than this build's registry). Routed by id prefix
   *  like every other provider model: `claude…` → Anthropic, else
   *  OpenAI. Rendered under the picker's "Other" group. */
  customModelIds: string[];
  /** The last model catalogue each provider returned (Settings → API keys
   *  discovery), so the picker is populated at launch and offline. Shape
   *  mirrors the `ProviderModel` wire type; sanitized on load. */
  cachedModels: Partial<Record<"anthropic" | "openai", CachedModel[]>>;
  /** Sidebar group collapse state, keyed by full group path
   *  ("Lab/Junos"). Stores only COLLAPSED groups (`true`) — an absent
   *  key means expanded, so the default-open behavior needs no
   *  migration and the map stays small. Survives app restarts. */
  collapsedGroups: Record<string, boolean>;
  /** v1.4.0 button bar visibility (View → Button Bar,
   *  or the bar's own hide). */
  showButtonBar: boolean;
  /** v2.7.0 — the user's named button bars (always ≥ 1). Replaces the
   *  flat v1.4.0 `buttonBarButtons` key; a legacy blob migrates into a
   *  single "Default" bar on load (one-way — only the new keys are
   *  written back). */
  buttonBars: ButtonBar[];
  /** Which bar renders + receives Map Button edits. Sanitized on load
   *  to an existing bar id (falls back to the first bar). */
  activeButtonBarId: string;
  /** v2.4.0 broadcast input bar visibility (View →
   *  Broadcast Input, or the bar's own close). Sends one typed line to
   *  every targeted live session at once — human input, NOT policy-gated
   *  (see BroadcastBar.tsx). Off by default. */
  showBroadcastBar: boolean;
  /** v2.5.0 — notify (a stacking card) when an agent prompt COMPLETES in
   *  a chat tab that isn't the active one. Only ever fires for unfocused
   *  completions, so it's silent in the normal single-foreground-chat
   *  flow — hence default ON. */
  notifyOnUnfocusedComplete: boolean;
  /** v6.3.0 — plain Enter sends in the chat composer (Shift+Enter for a
   *  newline); Cmd/Ctrl+Enter always sends in either mode. OFF restores
   *  the original Cmd/Ctrl+Enter-only behavior for people who type long
   *  multi-line prompts by hand. Default ON — every mainstream chat
   *  composer sends on Enter (community request, 2026-08). */
  chatSendOnEnter: boolean;
  /** v6.3.0 — persisted custom tab labels keyed by chat id, so a renamed
   *  chat restored from opt-in history keeps its name across restarts.
   *  Frontend-owned COSMETIC state (the backend history file stays
   *  metadata-minimal); pruned to live chat ids on every restore sync and
   *  on explicit close, so ids never accumulate. */
  chatLabelsById: Record<string, string>;
}

/** Allowed terminal font-size range. The clamp lives in the store so
 *  every callsite (keyboard shortcut, settings UI, malformed
 *  localStorage payload) goes through the same gate. */
export const TERMINAL_FONT_SIZE_MIN = 8;
export const TERMINAL_FONT_SIZE_MAX = 32;
export const TERMINAL_FONT_SIZE_DEFAULT = 13;

function clampFontSize(n: number): number {
  if (!Number.isFinite(n)) return TERMINAL_FONT_SIZE_DEFAULT;
  const rounded = Math.round(n);
  if (rounded < TERMINAL_FONT_SIZE_MIN) return TERMINAL_FONT_SIZE_MIN;
  if (rounded > TERMINAL_FONT_SIZE_MAX) return TERMINAL_FONT_SIZE_MAX;
  return rounded;
}

/** Allowed chat-panel font-size range. Default reads a touch larger
 *  than the terminal (prose vs. monospace). Same clamp-in-the-store
 *  discipline as the terminal size. */
export const CHAT_FONT_SIZE_MIN = 10;
export const CHAT_FONT_SIZE_MAX = 24;
export const CHAT_FONT_SIZE_DEFAULT = 14;

function clampChatFontSize(n: number): number {
  if (!Number.isFinite(n)) return CHAT_FONT_SIZE_DEFAULT;
  const rounded = Math.round(n);
  if (rounded < CHAT_FONT_SIZE_MIN) return CHAT_FONT_SIZE_MIN;
  if (rounded > CHAT_FONT_SIZE_MAX) return CHAT_FONT_SIZE_MAX;
  return rounded;
}

/** Coerce a persisted `collapsedGroups` blob to a clean
 *  `Record<string, boolean>`, keeping only the `true` entries (collapsed
 *  groups). Anything malformed collapses to an empty map = all open. */
function sanitizeCollapsedGroups(raw: unknown): Record<string, boolean> {
  if (typeof raw !== "object" || raw === null) return {};
  const out: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v === true) out[k] = true;
  }
  return out;
}

/** The stock terminal font stack — what every pane uses when the user
 *  hasn't set a family. Mirrored in TerminalPane's mount options. */
export const TERMINAL_FONT_FAMILY_DEFAULT =
  'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace';

/** Bound on the persisted family string — long enough for a
 *  hand-written fallback stack, short enough to keep the CSS value
 *  (and the localStorage payload) sane. */
export const TERMINAL_FONT_FAMILY_MAX_LEN = 160;

/** Trim + length-cap a user-supplied family; empty collapses to null
 *  (= "use the default stack"). CSS-validity is NOT checked here — an
 *  invalid value makes the style assignment a no-op in the webview,
 *  which is already the safe outcome. */
function sanitizeFontFamily(v: string): string | null {
  const trimmed = v.trim().slice(0, TERMINAL_FONT_FAMILY_MAX_LEN).trim();
  return trimmed.length === 0 ? null : trimmed;
}

/** Button-bar bounds. Caps keep a fat-fingered paste or a corrupted
 *  localStorage blob from ballooning the persisted preferences. */
export const BUTTON_BAR_MAX_BUTTONS = 50;
export const BUTTON_LABEL_MAX_LEN = 48;
export const BUTTON_VALUE_MAX_LEN = 1024;
/** v2.7.0 multi-bar bounds. */
export const BUTTON_BAR_MAX_BARS = 12;
export const BAR_NAME_MAX_LEN = 32;

/** Coerce a persisted button-list blob to a clean `ButtonBarButton[]` —
 *  drop malformed / empty-label entries, length-cap label + value, and cap
 *  the count. Anything malformed collapses to an empty list. */
function sanitizeButtons(raw: unknown): ButtonBarButton[] {
  if (!Array.isArray(raw)) return [];
  const out: ButtonBarButton[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const o = item as Record<string, unknown>;
    if (typeof o.id !== "string" || typeof o.label !== "string" || typeof o.value !== "string") {
      continue;
    }
    const label = o.label.slice(0, BUTTON_LABEL_MAX_LEN);
    if (label.trim().length === 0) continue;
    const entry: ButtonBarButton = {
      id: o.id,
      label,
      value: o.value.slice(0, BUTTON_VALUE_MAX_LEN),
    };
    // Keep a recognized palette token or a strict #rrggbb hex (v6.3.0);
    // drop anything else so a hand-edited blob can't inject an arbitrary
    // CSS value (isAccentValue is regex-strict — no url()/var()/keywords).
    if (typeof o.color === "string" && isAccentValue(o.color)) {
      entry.color = normalizeAccent(o.color);
    }
    // Only "agent" is honored; anything else (absent, misspelled, a
    // hand-edited blob) falls back to the PTY target. Coercing toward the
    // pre-v6.1.0 behavior keeps an unreadable value from silently
    // redirecting a button somewhere the user didn't choose.
    if (o.target === "agent") entry.target = "agent";
    out.push(entry);
    if (out.length >= BUTTON_BAR_MAX_BUTTONS) break;
  }
  return out;
}

/** Trim + cap a bar name; empty collapses to the fallback. */
/** Chat-label persistence bounds (v6.3.0). Same hostile-blob posture as
 *  every other persisted field: caps, trims, drops non-strings. */
const CHAT_LABEL_MAX_LEN = 60;
const CHAT_LABELS_MAX = 16;

function sanitizeChatLabel(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const label = value.trim().slice(0, CHAT_LABEL_MAX_LEN).trim();
  return label.length === 0 ? null : label;
}

function sanitizeChatLabels(raw: unknown): Record<string, string> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {};
  const entries: [string, string][] = [];
  for (const [id, value] of Object.entries(raw as Record<string, unknown>)) {
    const label = sanitizeChatLabel(value);
    if (label !== null) entries.push([id, label]);
  }
  // Keep the LAST entries when over the cap: insertion order is oldest-
  // first, and dropping the newest labels (the still-live chats the user
  // named most recently) in favor of long-dead ids is exactly backwards.
  return Object.fromEntries(entries.slice(-CHAT_LABELS_MAX));
}

function sanitizeBarName(raw: unknown, fallback = "Default"): string {
  if (typeof raw !== "string") return fallback;
  const trimmed = raw.trim().slice(0, BAR_NAME_MAX_LEN).trim();
  return trimmed.length === 0 ? fallback : trimmed;
}

function defaultButtonBar(): ButtonBar {
  return { id: crypto.randomUUID(), name: "Default", buttons: [] };
}

/** Coerce a persisted `buttonBars` blob (v2.7.0 shape) to a clean
 *  `ButtonBar[]`, falling back to the LEGACY v1.4.0 flat
 *  `buttonBarButtons` key (migrated into a single "Default" bar) and
 *  finally to one empty Default bar. The invariant every caller relies
 *  on: the result is never empty. One-way migration — only the new
 *  keys are ever written back. */
function sanitizeButtonBars(rawBars: unknown, legacyButtons: unknown): ButtonBar[] {
  if (Array.isArray(rawBars)) {
    const out: ButtonBar[] = [];
    for (const item of rawBars) {
      if (typeof item !== "object" || item === null) continue;
      const o = item as Record<string, unknown>;
      if (typeof o.id !== "string" || o.id.length === 0) continue;
      out.push({
        id: o.id,
        name: sanitizeBarName(o.name),
        buttons: sanitizeButtons(o.buttons),
      });
      if (out.length >= BUTTON_BAR_MAX_BARS) break;
    }
    if (out.length > 0) return out;
  }
  // v1.4.0 → v2.7.0 migration: wrap the flat macro list as "Default".
  const legacy = sanitizeButtons(legacyButtons);
  if (legacy.length > 0) {
    return [{ id: crypto.randomUUID(), name: "Default", buttons: legacy }];
  }
  return [defaultButtonBar()];
}

/** Resolve the persisted active-bar id against the sanitized bars —
 *  an unknown/malformed id falls back to the first bar. */
function sanitizeActiveBarId(raw: unknown, bars: ButtonBar[]): string {
  if (typeof raw === "string" && bars.some((b) => b.id === raw)) return raw;
  return bars[0].id;
}

/** Persisted copy of a provider's model entry (see `ProviderModel`). */
export interface CachedModel {
  id: string;
  display_name: string;
  created: number | null;
  level: "easy" | "medium" | "advanced";
  context_window: number | null;
}

const CACHED_MODELS_CAP = 200;

/** Shape-check every persisted model entry; drop anything malformed. */
export function sanitizeCachedModels(
  raw: unknown,
): Partial<Record<"anthropic" | "openai", CachedModel[]>> {
  if (!raw || typeof raw !== "object") return {};
  const out: Partial<Record<"anthropic" | "openai", CachedModel[]>> = {};
  for (const provider of ["anthropic", "openai"] as const) {
    const list = (raw as Record<string, unknown>)[provider];
    if (!Array.isArray(list)) continue;
    const clean: CachedModel[] = [];
    for (const v of list) {
      if (!v || typeof v !== "object") continue;
      const m = v as Record<string, unknown>;
      if (typeof m.id !== "string" || m.id.length === 0 || m.id.length > 100) continue;
      if (typeof m.display_name !== "string" || m.display_name.length > 100) continue;
      if (m.level !== "easy" && m.level !== "medium" && m.level !== "advanced") continue;
      clean.push({
        id: m.id,
        display_name: m.display_name,
        created: typeof m.created === "number" && Number.isFinite(m.created) ? m.created : null,
        level: m.level,
        context_window:
          typeof m.context_window === "number" && Number.isFinite(m.context_window)
            ? m.context_window
            : null,
      });
      if (clean.length >= CACHED_MODELS_CAP) break;
    }
    out[provider] = clean;
  }
  return out;
}

/** Model ids are provider wire names: printable ASCII, no whitespace,
 *  ≤ 100 chars, ≤ 20 entries, de-duplicated. Anything else is dropped. */
export function sanitizeCustomModelIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const v of raw) {
    if (typeof v !== "string") continue;
    const id = v.trim();
    if (id.length === 0 || id.length > 100) continue;
    if (!/^[\x21-\x7e]+$/.test(id)) continue;
    if (out.includes(id)) continue;
    out.push(id);
    if (out.length >= 20) break;
  }
  return out;
}

function defaultPreferences(): PersistedPreferences {
  const bar = defaultButtonBar();
  return {
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
    buttonBars: [bar],
    activeButtonBarId: bar.id,
    showBroadcastBar: false,
    notifyOnUnfocusedComplete: true,
    chatSendOnEnter: true,
    chatLabelsById: {},
    warnOnSessionClose: true,
  };
}

function loadPreferences(): PersistedPreferences {
  if (typeof localStorage === "undefined") return defaultPreferences();
  try {
    const raw = localStorage.getItem(PREFERENCES_KEY);
    if (!raw) return defaultPreferences();
    const parsed = JSON.parse(raw) as {
      themeId?: unknown;
      chatPanelWidth?: unknown;
      sidebarWidth?: unknown;
      chatPanelOpen?: unknown;
      terminalFontSize?: unknown;
      terminalFontFamily?: unknown;
      chatFontSize?: unknown;
      customModelIds?: unknown;
      cachedModels?: unknown;
      collapsedGroups?: unknown;
      showButtonBar?: unknown;
      buttonBars?: unknown;
      buttonBarButtons?: unknown;
      activeButtonBarId?: unknown;
      showBroadcastBar?: unknown;
      notifyOnUnfocusedComplete?: unknown;
      chatSendOnEnter?: unknown;
      chatLabelsById?: unknown;
      warnOnSessionClose?: unknown;
    };
    const buttonBars = sanitizeButtonBars(parsed.buttonBars, parsed.buttonBarButtons);
    return {
      themeId: typeof parsed.themeId === "string" ? parsed.themeId : null,
      chatPanelWidth:
        typeof parsed.chatPanelWidth === "number" && Number.isFinite(parsed.chatPanelWidth)
          ? parsed.chatPanelWidth
          : null,
      sidebarWidth:
        typeof parsed.sidebarWidth === "number" && Number.isFinite(parsed.sidebarWidth)
          ? parsed.sidebarWidth
          : null,
      chatPanelOpen: typeof parsed.chatPanelOpen === "boolean" ? parsed.chatPanelOpen : null,
      terminalFontSize:
        typeof parsed.terminalFontSize === "number" && Number.isFinite(parsed.terminalFontSize)
          ? clampFontSize(parsed.terminalFontSize)
          : null,
      terminalFontFamily:
        typeof parsed.terminalFontFamily === "string"
          ? sanitizeFontFamily(parsed.terminalFontFamily)
          : null,
      chatFontSize:
        typeof parsed.chatFontSize === "number" && Number.isFinite(parsed.chatFontSize)
          ? clampChatFontSize(parsed.chatFontSize)
          : null,
      customModelIds: sanitizeCustomModelIds(parsed.customModelIds),
      cachedModels: sanitizeCachedModels(parsed.cachedModels),
      collapsedGroups: sanitizeCollapsedGroups(parsed.collapsedGroups),
      showButtonBar: typeof parsed.showButtonBar === "boolean" ? parsed.showButtonBar : false,
      buttonBars,
      activeButtonBarId: sanitizeActiveBarId(parsed.activeButtonBarId, buttonBars),
      showBroadcastBar:
        typeof parsed.showBroadcastBar === "boolean" ? parsed.showBroadcastBar : false,
      notifyOnUnfocusedComplete:
        typeof parsed.notifyOnUnfocusedComplete === "boolean"
          ? parsed.notifyOnUnfocusedComplete
          : true,
      chatSendOnEnter: typeof parsed.chatSendOnEnter === "boolean" ? parsed.chatSendOnEnter : true,
      chatLabelsById: sanitizeChatLabels(parsed.chatLabelsById),
      // Defaults to true: a missing key means an install that predates
      // the setting, which had the warning, so absence must not read as
      // "the user turned it off".
      warnOnSessionClose:
        typeof parsed.warnOnSessionClose === "boolean" ? parsed.warnOnSessionClose : true,
    };
  } catch {
    return defaultPreferences();
  }
}

function savePreferences(prefs: PersistedPreferences): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(PREFERENCES_KEY, JSON.stringify(prefs));
  } catch {
    // ignore — quota or private-window restrictions
  }
}

/**
 * UI-only state, shared across components.
 *
 * Server-state (devices, sessions metadata, scrollback) lives in
 * TanStack Query's cache, NOT here — see CLAUDE.md §"State management".
 * Add fields here only when a piece of state is genuinely
 * cross-component AND not fetched from the backend.
 */

export interface SessionTab {
  /** Backend-assigned UUID. Drives the `pty:{sessionId}:output` event
   *  topic and is the key for every command (send_input, resize_pty,
   *  disconnect_session) targeting this session. */
  sessionId: string;
  /** Inventory device id this session was opened against. NOT unique
   *  across the sessions array — Phase 3 allows multiple sessions per
   *  device. */
  deviceId: string;
  /** Flips true when the remote closes the channel (`pty:{id}:closed`
   *  event). The tab stays in the array so the user can read the
   *  final scrollback; X-ing the tab while ended skips the close
   *  confirm dialog. */
  ended: boolean;
  /** Phase 7a C9 — user-supplied tab label (right-click → Rename). When
   *  null/empty, the auto-generated label (`computeLabels`) is used.
   *  Session-scoped: reconnecting the same device opens a fresh tab
   *  and the custom name does NOT carry over. */
  customLabel?: string | null;
  /** When set, this session is a PANE inside the tab whose PRIMARY session
   *  id is `splitWith` (v4.4.0 generalized "right pane" → "a pane in tab X").
   *  Non-primary panes don't get their own tab-strip entry; they render in
   *  the primary's `TabsContent` per the primary's `layout` tree. Closing the
   *  primary cascades to every pane whose `splitWith` points at it. */
  splitWith?: string | null;
  /** v4.4.0 tiling — the pane arrangement for THIS tab (set on the PRIMARY
   *  session only; `undefined` = a single pane). A `PaneNode` tree whose
   *  leaves reference session ids (the primary + its `splitWith` panes). Pane
   *  sizes live in react-resizable-panels, not here. */
  layout?: PaneNode;
  /** v2.7.0 — the device id the AGENT sees for this session
   *  (`SessionMeta.device_id` backend-side). Equals `deviceId` for SSH
   *  tabs and is therefore usually unset; console tabs differ (their
   *  `deviceId` carries a `console-` prefix for transport
   *  disambiguation while the agent sees the bare label). The chat
   *  scope popover matches on `agentDeviceId ?? deviceId` — scope
   *  entries must be in the backend's vocabulary or they'd never
   *  match. */
  agentDeviceId?: string;
  /** Tab transport discriminator. `"api"` (v4.0.0) renders `<ApiSessionPane>`
   *  (no PTY / backend session); `"local"` (v4.4.0) is a local-shell PTY tab
   *  that renders `<TerminalPane>` like SSH; `"files"` (v5.0.0) is an SFTP
   *  browse session that renders `<FilesPane>` (a REAL backend session, but no
   *  PTY and no scrollback ring). `undefined` = SSH/console.
   *
   *  Two axes decide how a tab behaves, and both have a predicate below
   *  rather than a string check at each site: `hasPty` gates every
   *  terminal-only affordance, and `isFilesTab` routes teardown to the
   *  disjoint `files_*` namespace (Files sessions are unreachable from
   *  `disconnect_session`). */
  kind?: "api" | "local" | "files" | "pcap";
  apiSessionId?: string;
}

/**
 * Does this tab own a PTY — an xterm.js instance plus a backend scrollback
 * ring? True for SSH/console (`kind` undefined) and local shells; false
 * for API and Files tabs.
 *
 * THE predicate for every terminal-only affordance: scrollback export,
 * session logging, capture targets, clear-terminal, button-bar macros, and
 * broadcast input. Before v5.0.0 those sites each hard-coded
 * `kind === "api"`, which meant a new non-PTY kind silently inherited all
 * of them (and API tabs were latently included in the broadcast/button-bar
 * paths). Route new checks through this instead of adding a third string
 * comparison.
 */
export function hasPty(tab: Pick<SessionTab, "kind">): boolean {
  return tab.kind === undefined || tab.kind === "local";
}

/** v6.4.0 — every session rendered inside the tab whose primary is
 *  `primaryId`: the primary itself plus every pane anchored to it. The tab's
 *  `layout` tree is the render authority, but this works off `splitWith` so it
 *  is correct for an un-split tab too (no layout yet) and for a pane that is in
 *  `sessions` but momentarily absent from the tree. */
export function tabPaneIds(sessions: SessionTab[], primaryId: string): string[] {
  // One pass, not filter().map(): this runs per render per tab (and inside
  // `resolveActivePaneId`, which the button bar hits on every click).
  const ids: string[] = [];
  for (const t of sessions) {
    if (t.sessionId === primaryId || t.splitWith === primaryId) ids.push(t.sessionId);
  }
  return ids;
}

/** v6.4.0 — the pane an app-level action should target: the focus hint when it
 *  is still a pane of the active tab, else that tab's remembered pane, else the
 *  tab's primary. THE resolver — read focus through this, never off
 *  `activePaneId` directly.
 *
 *  Self-healing is the point. Actions that focus a tab without knowing about
 *  panes (`addSession`, `openShellTab`, `openPcapTab`, …) leave a stale hint
 *  behind; resolving here means each of them stays correct without carrying
 *  pane bookkeeping, and a future tab-opening action inherits that for free.
 *  A single-pane tab resolves to `activeTabId`, which is exactly the
 *  pre-v6.4.0 behaviour — so nothing changes until a tab is actually tiled. */
export function resolveActivePaneId(
  state: Pick<UiState, "sessions" | "activeTabId" | "activePaneId" | "lastPaneByTab">,
): string | null {
  const { sessions, activeTabId, activePaneId, lastPaneByTab } = state;
  if (!activeTabId) return null;
  const panes = tabPaneIds(sessions, activeTabId);
  if (activePaneId && panes.includes(activePaneId)) return activePaneId;
  const remembered = lastPaneByTab[activeTabId];
  if (remembered && panes.includes(remembered)) return remembered;
  return activeTabId;
}

/** A Files (SFTP) tab. Its backend session is torn down through
 *  `files_disconnect`, never `disconnect_session` — the `files_*` IPC
 *  namespace is disjoint by design (plan decision 7), so a teardown path
 *  that gets this wrong leaks the session AND its SSH connection. */
export function isFilesTab(tab: Pick<SessionTab, "kind">): boolean {
  return tab.kind === "files";
}

/** A PCaps tab (v6.0.0). Closed through `pcap_close`, never
 *  `disconnect_session` — the `pcap_*` namespace is disjoint from every
 *  transport dispatch for the same reason `files_*` is. `hasPty` already
 *  returns false for it (it admits only `undefined` and `"local"`), which
 *  is the v5.0.0 predicate refactor paying for itself: every terminal-only
 *  affordance excluded a new tab kind without anyone having to remember. */
export function isPcapTab(tab: Pick<SessionTab, "kind">): boolean {
  return tab.kind === "pcap";
}

/** v2.5.0 — an open AI chat tab. Metadata ONLY; the message log +
 *  streaming state live in the per-tab `useChat(chatId)` hook (Query/
 *  hook layer), never in the store. Mirrors `SessionTab`'s role for the
 *  chat panel. */
export interface ChatTab {
  /** Backend chat UUID (from `chat_create`). Drives the `chat:{chatId}:*`
   *  event topics and every chat IPC command. */
  chatId: string;
  /** Currently-selected model id for THIS chat (per-chat, not panel-
   *  global). Mutated via `chat_set_model`. */
  model: string;
  /** Stable "Chat N" number, assigned from `chatSeq` at creation. Never
   *  reused, so closing an earlier tab doesn't renumber the survivors. */
  seq: number;
  /** User-supplied tab label (double-click → rename). Null/empty = the
   *  auto-numbered "Chat {seq}" label. Mirrors `SessionTab.customLabel`. */
  customLabel?: string | null;
  /** v2.7.0 — the chat's device scope (T31). `null` = unscoped (all
   *  devices; the default). NON-optional so `undefined` never exists
   *  as a third state — `addChat` initializes it explicitly. Mirrors
   *  the backend `ChatSession.scope` (set via `chat_set_scope`); the
   *  store copy only drives the popover UI + trigger badge, the
   *  backend wrappers are the enforcement. */
  scopedDeviceIds: string[] | null;
  /** v4.0.0 — UI mirror of the backend `ChatSession.auto_approve_api_gets`
   *  flag (set via `chat_set_auto_approve_gets`): when true, the agent's
   *  read-only GETs auto-run without the per-call modal (the gate still
   *  runs). Optional/defaults false; drives the header indicator + off-
   *  toggle so an opted-in chat can be turned back to per-call approval. */
  autoApproveGets?: boolean;
}

/** v4.0.0 rail + v4.4.0 Terminal + v5.0.0 Files — which sidebar the left
 *  panel shows. Deliberately NOT persisted: every launch starts on "ssh",
 *  the surface that owns the inventory. */
export type SidebarView = "ssh" | "apis" | "terminal" | "files" | "pcaps";

interface UiState {
  /** Device id of the currently-selected sidebar row, or null. */
  activeDeviceId: string | null;
  setActiveDeviceId: (id: string | null) => void;

  /** Sidebar collapsed/expanded. Cmd/Ctrl+B toggles. */
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;

  /** v4.0.0 — which sidebar the left panel shows: SSH devices or API
   *  controllers. Driven by the left-rail PanelSwitcher. UI-only. */
  sidebarView: SidebarView;
  setSidebarView: (view: SidebarView) => void;

  /**
   * Settings dialog visibility. Mounted once at App root, triggered
   * from the sidebar footer's gear. Hosts the API-keys tab + general
   * preferences.
   */
  settingsDialogOpen: boolean;
  /** Tab to open the Settings dialog on (e.g. "network" from the account
   *  chip's TLS-trust error). Null → default ("general"). */
  settingsInitialTab: string | null;
  openSettingsDialog: (tab?: string) => void;
  closeSettingsDialog: () => void;

  /**
   * Auth profile manager dialog visibility. Lifted from Sidebar's
   * local state so the command palette can open it without
   * prop-drilling. Mounted once in Sidebar (the natural parent
   * since this is inventory-adjacent state).
   */
  authProfileManagerOpen: boolean;
  openAuthProfileManager: () => void;
  closeAuthProfileManager: () => void;

  /**
   * Bulk connection import wizard visibility. The wizard is a full-pane
   * `MainArea` view (not a modal — a ~100-row grid needs the room), so
   * it's a uiStore flag like the dialogs above. Opened from the Sidebar
   * header, the empty-state Welcome CTA, and the command palette; the
   * view unmounts (discarding its in-progress draft) on close.
   */
  importOpen: boolean;
  openImport: () => void;
  closeImport: () => void;

  /**
   * Command palette visibility (Phase 7a C2). Cmd/Ctrl+K toggles.
   * Mounted once at App root; the palette reads device + session
   * state through its own hooks so any feature can register commands.
   */
  commandPaletteOpen: boolean;
  toggleCommandPalette: () => void;
  /** v6.1.0 — which slice of the registry the palette is showing.
   *
   *  `"all"` is the Cmd/Ctrl+K default. `"sessions"` is what
   *  **Window → Jump to Session…** opens: with a large inventory the
   *  Devices group ("Connect to …", one per device) runs to dozens of
   *  entries and pushes the handful of open-session entries below the
   *  fold, which reads as "there is no jump-to-session". Scoping shows
   *  only what the menu item promised. */
  commandPaletteScope: "all" | "sessions";
  /** Open the palette at a given scope (idempotent — never toggles shut). */
  openCommandPalette: (scope?: "all" | "sessions") => void;
  closeCommandPalette: () => void;

  /**
   * Captures & diff dialog (Phase 3). Capture command output and compare
   * two captures. Opened from the command palette; mounted at App root.
   */
  capturesDialogOpen: boolean;
  /** When set, the Captures dialog pre-selects this session on next open. */
  capturesPreselectSessionId: string | null;
  openCaptures: (sessionId?: string) => void;
  closeCaptures: () => void;
  /** Clear the one-shot pre-selection once the dialog consumes it. */
  consumeCapturesPreselect: () => void;

  /**
   * Per-user preferences (Phase 7a C5+). Persisted to localStorage
   * keyed by `transit.preferences` so the choice survives app
   * restarts. Subset for v1; future tabs add fields here:
   *   - C5: themeId
   *   - future: scrollback line cap
   */
  preferences: PersistedPreferences;
  setThemeId: (id: string) => void;
  setChatPanelWidth: (px: number) => void;
  /** v6.5.2 — set the shared left-sidebar width in CSS pixels. The caller
   *  (the drag handle) owns the clamp; the store only persists. */
  setSidebarWidth: (px: number) => void;
  /** Toggle the per-session close confirm. Persisted. */
  setWarnOnSessionClose: (warn: boolean) => void;
  /** Set the global terminal font size. Pass `null` to reset to
   *  TERMINAL_FONT_SIZE_DEFAULT. Numeric values are clamped to
   *  [TERMINAL_FONT_SIZE_MIN, TERMINAL_FONT_SIZE_MAX] and rounded so
   *  the persisted value is always a valid integer pixel size. */
  setTerminalFontSize: (size: number | null) => void;
  /** Set the global terminal font family. Pass `null` (or an
   *  empty/whitespace string) to reset to the default stack. Values
   *  are trimmed and length-capped before persisting. */
  setTerminalFontFamily: (family: string | null) => void;
  /** Set the agent chat-panel font size. Pass `null` to reset to
   *  CHAT_FONT_SIZE_DEFAULT. Numeric values are clamped to
   *  [CHAT_FONT_SIZE_MIN, CHAT_FONT_SIZE_MAX] and rounded. */
  setChatFontSize: (size: number | null) => void;
  /** Replace the user's extra provider model ids (Settings → API keys). */
  setCustomModelIds: (ids: string[]) => void;
  /** Mirror a provider's freshly discovered model list into preferences. */
  setCachedModels: (provider: "anthropic" | "openai", models: CachedModel[]) => void;
  /** Toggle a sidebar group's collapsed state (keyed by full path),
   *  persisting the result. Absent/false = expanded; true = collapsed. */
  toggleGroupCollapsed: (path: string) => void;
  /** Ensure each path AND its ancestors are expanded in the sidebar
   *  (deletes the relevant `collapsedGroups` keys; absent = expanded).
   *  Called after an import so the freshly-created groups are visible. */
  expandGroups: (paths: string[]) => void;

  /** v1.4.0 button bar. `showButtonBar` toggles the bar
   *  (View → Button Bar); the macros below are persisted with it. */
  setShowButtonBar: (visible: boolean) => void;
  /** v2.4.0 broadcast bar. Toggles the broadcast input
   *  bar (View → Broadcast Input, or the bar's own close). */
  setShowBroadcastBar: (visible: boolean) => void;
  /** Append a macro to the ACTIVE bar (id generated). Capped at
   *  BUTTON_BAR_MAX_BUTTONS per bar. The Map Button dialog calls this
   *  without knowing about bars — the active-bar indirection lives
   *  entirely here (v2.7.0). */
  addButton: (button: {
    label: string;
    value: string;
    color?: string;
    target?: "session" | "agent";
  }) => void;
  /** Replace a macro's label + value by id, in the ACTIVE bar. */
  updateButton: (
    id: string,
    patch: { label: string; value: string; color?: string; target?: "session" | "agent" },
  ) => void;
  /** Delete a macro by id, from the ACTIVE bar. */
  removeButton: (id: string) => void;
  /** v2.7.0 — create a bar (capped at BUTTON_BAR_MAX_BARS) and make it
   *  active. Empty/whitespace names collapse to "Default". */
  addBar: (name: string) => void;
  /** v2.7.0 — rename a bar (trim + cap; empty keeps the old name). */
  renameBar: (id: string, name: string) => void;
  /** v2.7.0 — delete a bar. No-op on the last bar (the strip always
   *  has ≥ 1); deleting the active bar activates a neighbor. */
  removeBar: (id: string) => void;
  /** v2.7.0 — make a bar active (no-op on unknown id). Persisted. */
  setActiveBar: (id: string) => void;
  /** v2.7.0 — step to the next (+1) / previous (-1) bar, wrapping. */
  cycleBar: (delta: 1 | -1) => void;

  /**
   * Right-hand chat panel visibility. Cmd/Ctrl+J toggles. Defaults
   * to OPEN on first launch so first-time users see the AI
   * affordance immediately; subsequent launches honor the user's
   * last toggle (persisted to localStorage under
   * `preferences.chatPanelOpen`).
   */
  chatPanelOpen: boolean;
  toggleChatPanel: () => void;

  /** v6.1.0 — text queued for the AI composer by an agent-target
   *  button-bar macro.
   *
   *  A store field rather than a Tauri event on purpose: the sender and
   *  the receiver are both in this webview, and the panel may still be
   *  mounting when the button is clicked. A parked value is read by
   *  whenever the composer appears; an event fired into a not-yet-mounted
   *  listener is simply lost. */
  pendingAgentPrompt: string | null;
  /** Queue text for the composer (replaces any unconsumed value). */
  setAgentPrompt: (text: string) => void;
  /** Take the queued text and clear it — call once, from the composer. */
  consumeAgentPrompt: () => string | null;

  /**
   * Right-hand session-info panel visibility (Phase 7a C7). Cmd/Ctrl+I
   * toggles. Mounted alongside the chat panel — both can be open at
   * the same time, occupying separate flex slots. Default closed.
   */
  sessionInfoPanelOpen: boolean;
  toggleSessionInfoPanel: () => void;

  /**
   * Phase 3: open SSH sessions, rendered as tabs in `TerminalArea`.
   * Append-on-connect, remove-on-close. The backend already supports
   * a `HashMap<SessionId, Session>` (see `src-tauri/src/ssh.rs`); this
   * store mirrors what the UI is currently showing.
   *
   * Order in the array == tab order on screen. Disambiguating labels
   * for multiple-sessions-to-same-device is computed at render time
   * (see `TerminalArea.computeLabels`).
   */
  sessions: SessionTab[];
  /** sessionId of the currently-focused tab, or null when no tabs. */
  activeTabId: string | null;
  /** v6.4.0 — the PANE inside the active tab that holds keyboard focus, i.e.
   *  the terminal an app-level action (button bar, View → Clear Terminal)
   *  should target. A tab with no split has exactly one pane, so this equals
   *  `activeTabId`; once a tab is tiled they diverge, and before v6.4.0 every
   *  such action hardcoded the tab's PRIMARY (the bug a user hit: button
   *  macros fired into the left pane no matter which pane you were typing in).
   *
   *  Treat this as a HINT, never as truth: read it through
   *  `resolveActivePaneId`, which falls back to the active tab's primary when
   *  the hint is stale. That keeps the invariant ("always a pane of the active
   *  tab") true by construction, so the many actions that set `activeTabId`
   *  without knowing about panes stay correct without each having to. */
  activePaneId: string | null;
  /** Per-tab memory of the last focused pane, so switching tabs away and back
   *  returns to the pane you were in (VSCode remembers per group; the customer
   *  cited VSCode as their frame of reference). Pruned when a tab closes. */
  lastPaneByTab: Record<string, string>;
  /** Focus a pane of the ACTIVE tab. No-ops on an id that isn't one — a stale
   *  focus event can't point focus off-tab. */
  setActivePane: (sessionId: string) => void;
  /** Append a new top-level session and focus its tab. `agentDeviceId`
   *  (v2.7.0) is the agent-visible device id when it differs from `deviceId`
   *  (console tabs). To add a session as a split PANE, use `splitPaneWith`. */
  addSession: (sessionId: string, deviceId: string, agentDeviceId?: string) => void;
  /** v4.4.0 tiling — add `sessionId` as a new pane by splitting the existing
   *  pane `targetPaneId` along `dir` (`row` = beside / `col` = below). The new
   *  pane joins `targetPaneId`'s tab (its `splitWith` = that tab's primary);
   *  focus stays on the tab. */
  splitPaneWith: (
    sessionId: string,
    deviceId: string,
    targetPaneId: string,
    dir: "row" | "col",
    agentDeviceId?: string,
  ) => void;
  /** v4.0.0 — open an API request tab bound to an api_session
   *  controller. Frontend-only (no backend session); focuses the tab. */
  openApiTab: (apiSessionId: string, name: string) => void;
  /** v4.4.0 — append a local-shell tab. `sessionId` is the REAL backend
   *  session from `open_local_shell`; `kind: "local"` → `<TerminalPane>`. */
  openShellTab: (sessionId: string, label: string) => void;
  /** v5.0.0 — append a Files (SFTP) tab. `sessionId` is the REAL backend
   *  session from `files_connect` and `deviceId` the inventory id, so the
   *  per-host tab accent and `computeLabels` work unchanged. */
  /** v6.0.0 — open (or focus) a tab for an indexed capture. */
  openPcapTab: (captureId: string, name: string) => void;
  openFilesTab: (sessionId: string, deviceId: string) => void;
  /** v4.0.0 — endpoint templates the sidebar handed a pane to load,
   *  keyed by TAB sessionId. The target pane consumes + clears its entry. */
  pendingApiLoad: Record<string, ApiRequestTemplate>;
  /** Open (or focus) the controller's tab AND load `template` into it —
   *  the sidebar "click an endpoint under a controller" action. */
  launchApiRequest: (apiSessionId: string, name: string, template: ApiRequestTemplate) => void;
  /** Clear a consumed pending-load entry for a tab. */
  consumeApiLoad: (sessionId: string) => void;
  /** Remove a session from the array. If it was active, focus shifts
   *  to the neighbor (next, then prev, then null if it was the last). */
  removeSession: (sessionId: string) => void;
  /** v4.1.0 — reorder tabs by drag: move the `activeId` session to the
   *  array slot of `overId` (both top-level tab ids). UI-only (tab order
   *  is pure frontend); right panes are found by `splitWith`, so their
   *  array position is irrelevant and splits are preserved. No-op if
   *  either id is missing or they're equal. */
  moveSession: (activeId: string, overId: string) => void;
  /** v4.4.0 drag-to-split — move an existing top-level tab `draggedId` INTO
   *  `targetPaneId`'s tab as a new pane, adjacent along `dir` on the `before`
   *  side (true = left/top, false = right/bottom). The dragged tab (and any
   *  panes it owned) reparent under the target's primary; its standalone tab
   *  disappears. No-op if either is missing, they're the same tab, or the
   *  target pane isn't a leaf in its tab's layout. */
  movePaneInto: (
    draggedId: string,
    targetPaneId: string,
    dir: "row" | "col",
    before: boolean,
  ) => void;
  /** v6.4.0 — the inverse of `movePaneInto`: lift a split PANE back out into
   *  its own top-level tab (pane header → "Move to own tab"). Before this,
   *  splitting was one-way — closing the pane was the only exit, which is what
   *  a user ran into. No-op on a session that isn't a pane, or is missing.
   *  Backend-neutral: the session keeps running, only its UI parent changes. */
  movePaneOut: (sessionId: string) => void;
  /** v2.3.4 "Close all tabs" — drop every session (top-level AND
   *  right panes) in one state update. The caller is responsible for
   *  disconnecting the backend sessions first, same contract as
   *  `removeSession`. */
  clearAllSessions: () => void;
  /** v6.1.0 — reorder the tab strip alphabetically by displayed label.
   *  A ONE-SHOT action, not a sticky mode: new tabs still append, which
   *  is what users expect from "sort" in a tab strip. The active tab and
   *  every split-pane anchor are unaffected — those reference sessionIds,
   *  and only the array ORDER changes. */
  sortSessionsByLabel: () => void;
  /** Switch the visible tab. No-op if `sessionId` is not in `sessions`. */
  setActiveTab: (sessionId: string) => void;
  /** Mark a session as remote-ended. Tab stays in the array. */
  markSessionEnded: (sessionId: string) => void;
  /** Un-end a session — console auto-reconnect resumed it under the same id. */
  markSessionReconnected: (sessionId: string) => void;
  /** Phase 7a C9 — set the user-visible tab label. Pass `null` to clear
   *  and revert to the auto-generated label. */
  setSessionLabel: (sessionId: string, label: string | null) => void;
  /** Swap a tab's sessionId in place. Used by the Enter-to-reconnect
   *  flow in a closed pane: the tab stays in its slot, customLabel
   *  and splitWith references are preserved, and any right pane that
   *  was anchored to the old sessionId is re-pointed at the new one.
   *  `ended` is cleared so the new session renders as live. */
  reconnectSession: (oldSessionId: string, newSessionId: string) => void;

  // --- v2.5.0 multi-chat AI tabs (mirrors sessions/activeTabId) ---
  /** Open AI chat tabs. Metadata only — message content lives in the
   *  per-tab `useChat` hook. */
  chats: ChatTab[];
  /** chatId of the focused chat tab, or null when none. */
  activeChatId: string | null;
  /** Monotonic "Chat N" counter; never decremented, so closing an
   *  earlier tab doesn't renumber the survivors. */
  chatSeq: number;
  /** Per-chat pending command approval awaiting the user (keyed by
   *  chat_id). Drives the yellow tab dot + the notification card; the
   *  approval modal renders the ACTIVE chat's entry. */
  pendingApprovalByChat: Record<string, ProposeCommandRequestPayload>;
  /** v4.0.0 — per-chat pending `propose_api_call` (GET-only controller)
   *  approval, keyed by chat_id. Separate map from `pendingApprovalByChat`
   *  because the two render different modals; the agent loop is sequential
   *  so at most one is set per chat at a time. */
  pendingApiCallByChat: Record<string, ProposeApiCallRequestPayload>;
  /** Per-chat "a prompt completed while this tab was NOT active" flag.
   *  Drives the green tab dot + (pref-gated) completion card; cleared on
   *  focus. */
  completedUnfocusedByChat: Record<string, boolean>;
  /** The default model for a NEW chat — the first provider model an
   *  enrolled key unlocks, else a local model; written by ChatPanel when
   *  the key/local status resolves. Lets the `newChat()` thunk (invoked
   *  from the "+", Cmd/Ctrl+T, or the palette — none of which have that
   *  query) create a chat at the right model even when the panel is
   *  collapsed. Null until the status resolves. */
  defaultChatModel: string | null;

  /** Append a chat tab (no-op past CHAT_TABS_MAX or on duplicate id) and
   *  focus it. The caller has already created the backend chat. */
  addChat: (chatId: string, model: string) => void;
  /** Remove a chat tab + purge its attention entries; focus a neighbor
   *  (next → prev → null). Caller destroys the backend chat. */
  removeChat: (chatId: string) => void;
  /** Focus a chat tab (no-op if absent). Clears that chat's green
   *  "completed" dot; leaves any pending approval intact for the modal. */
  setActiveChat: (chatId: string) => void;
  /** Set a chat's selected model (mirrors chat_set_model). */
  setChatModel: (chatId: string, model: string) => void;
  /** v2.7.0 — set a chat's device scope (mirrors chat_set_scope).
   *  `null` = unscoped. UI mirror only; enforcement is backend-side. */
  setChatScope: (chatId: string, deviceIds: string[] | null) => void;
  /** UI mirror of the backend auto-approve-GET flag (M1). */
  setChatAutoApproveGets: (chatId: string, enabled: boolean) => void;
  /** Set/clear a chat tab's custom label (null/empty → auto "Chat N"). */
  setChatLabel: (chatId: string, label: string | null) => void;
  /** v6.3.0 — one-shot restore-sync application: applies persisted
   *  labels to freshly-added tabs AND prunes the map to live ids in a
   *  single preferences write. No-ops on an empty live set (a transient
   *  empty backend list must not wipe the label map). */
  applyRestoredChatLabels: (labels: Record<string, string>, liveIds: string[]) => void;
  /** Drop every chat tab + attention in one update. */
  clearAllChats: () => void;
  /** Set (or clear, with null) a chat's pending-approval payload. */
  setChatPendingApproval: (chatId: string, payload: ProposeCommandRequestPayload | null) => void;
  /** Set (or clear, with null) a chat's pending API-call (GET) payload. */
  setChatPendingApiCall: (chatId: string, payload: ProposeApiCallRequestPayload | null) => void;
  /** Flag that a prompt completed in a non-active chat (no-op for the
   *  active chat, which needs no "done" dot). */
  markChatCompleted: (chatId: string) => void;
  /** Record the default new-chat model (see `defaultChatModel`). */
  setDefaultChatModel: (model: string) => void;
  /** Toggle + persist the unfocused-completion notification pref. */
  setNotifyOnUnfocusedComplete: (enabled: boolean) => void;
  /** Toggle + persist the Enter-sends chat-composer pref (v6.3.0). */
  setChatSendOnEnter: (enabled: boolean) => void;
}

export const useUiStore = create<UiState>((set, get) => {
  const initialPrefs = loadPreferences();
  return {
    activeDeviceId: null,
    setActiveDeviceId: (id) => set({ activeDeviceId: id }),

    sidebarCollapsed: false,
    toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

    sidebarView: "ssh",
    setSidebarView: (view) => set({ sidebarView: view }),

    settingsDialogOpen: false,
    settingsInitialTab: null,
    openSettingsDialog: (tab) => set({ settingsDialogOpen: true, settingsInitialTab: tab ?? null }),
    closeSettingsDialog: () => set({ settingsDialogOpen: false, settingsInitialTab: null }),

    authProfileManagerOpen: false,
    openAuthProfileManager: () => set({ authProfileManagerOpen: true }),
    closeAuthProfileManager: () => set({ authProfileManagerOpen: false }),

    importOpen: false,
    openImport: () => set({ importOpen: true }),
    closeImport: () => set({ importOpen: false }),

    commandPaletteOpen: false,
    commandPaletteScope: "all",
    // Cmd/Ctrl+K always returns to the full registry — a scope left over
    // from a menu click would silently hide half the palette.
    toggleCommandPalette: () =>
      set((s) => ({ commandPaletteOpen: !s.commandPaletteOpen, commandPaletteScope: "all" })),
    openCommandPalette: (scope = "all") =>
      set({ commandPaletteOpen: true, commandPaletteScope: scope }),
    closeCommandPalette: () => set({ commandPaletteOpen: false, commandPaletteScope: "all" }),

    capturesDialogOpen: false,
    capturesPreselectSessionId: null,
    openCaptures: (sessionId?: string) =>
      set({ capturesDialogOpen: true, capturesPreselectSessionId: sessionId ?? null }),
    closeCaptures: () => set({ capturesDialogOpen: false }),
    consumeCapturesPreselect: () => set({ capturesPreselectSessionId: null }),

    preferences: initialPrefs,
    setThemeId: (id) =>
      set((s) => {
        const next = { ...s.preferences, themeId: id };
        savePreferences(next);
        return { preferences: next };
      }),
    setChatPanelWidth: (px) =>
      set((s) => {
        const next = { ...s.preferences, chatPanelWidth: px };
        savePreferences(next);
        return { preferences: next };
      }),
    setSidebarWidth: (px) =>
      set((s) => {
        const next = { ...s.preferences, sidebarWidth: px };
        savePreferences(next);
        return { preferences: next };
      }),
    setWarnOnSessionClose: (warn) =>
      set((s) => {
        const next = { ...s.preferences, warnOnSessionClose: warn };
        savePreferences(next);
        return { preferences: next };
      }),
    setTerminalFontSize: (size) =>
      set((s) => {
        const clamped = size === null ? null : clampFontSize(size);
        const next = { ...s.preferences, terminalFontSize: clamped };
        savePreferences(next);
        return { preferences: next };
      }),
    setTerminalFontFamily: (family) =>
      set((s) => {
        const sanitized = family === null ? null : sanitizeFontFamily(family);
        const next = { ...s.preferences, terminalFontFamily: sanitized };
        savePreferences(next);
        return { preferences: next };
      }),
    setChatFontSize: (size) =>
      set((s) => {
        const clamped = size === null ? null : clampChatFontSize(size);
        const next = { ...s.preferences, chatFontSize: clamped };
        savePreferences(next);
        return { preferences: next };
      }),
    setCustomModelIds: (ids) =>
      set((s) => {
        const next = { ...s.preferences, customModelIds: sanitizeCustomModelIds(ids) };
        savePreferences(next);
        return { preferences: next };
      }),
    setCachedModels: (provider, models) =>
      set((s) => {
        const clean = sanitizeCachedModels({ [provider]: models })[provider] ?? [];
        const next = {
          ...s.preferences,
          cachedModels: { ...s.preferences.cachedModels, [provider]: clean },
        };
        savePreferences(next);
        return { preferences: next };
      }),
    setShowButtonBar: (visible) =>
      set((s) => {
        const next = { ...s.preferences, showButtonBar: visible };
        savePreferences(next);
        return { preferences: next };
      }),
    setShowBroadcastBar: (visible) =>
      set((s) => {
        const next = { ...s.preferences, showBroadcastBar: visible };
        savePreferences(next);
        return { preferences: next };
      }),
    addButton: (button) =>
      set((s) => {
        // Route to the ACTIVE bar (the Map Button dialog is bar-agnostic).
        const active = s.preferences.buttonBars.find(
          (b) => b.id === s.preferences.activeButtonBarId,
        );
        if (!active || active.buttons.length >= BUTTON_BAR_MAX_BUTTONS) return {};
        const entry: ButtonBarButton = {
          id: crypto.randomUUID(),
          label: button.label.slice(0, BUTTON_LABEL_MAX_LEN),
          value: button.value.slice(0, BUTTON_VALUE_MAX_LEN),
        };
        if (typeof button.color === "string" && isAccentValue(button.color)) {
          entry.color = normalizeAccent(button.color);
        }
        if (button.target === "agent") entry.target = "agent";
        const buttonBars = s.preferences.buttonBars.map((b) =>
          b.id === active.id ? { ...b, buttons: [...b.buttons, entry] } : b,
        );
        const next = { ...s.preferences, buttonBars };
        savePreferences(next);
        return { preferences: next };
      }),
    updateButton: (id, patch) =>
      set((s) => {
        const buttonBars = s.preferences.buttonBars.map((bar) =>
          bar.id === s.preferences.activeButtonBarId
            ? {
                ...bar,
                buttons: bar.buttons.map((b): ButtonBarButton =>
                  b.id === id
                    ? {
                        ...b,
                        label: patch.label.slice(0, BUTTON_LABEL_MAX_LEN),
                        value: patch.value.slice(0, BUTTON_VALUE_MAX_LEN),
                        // Explicit set/clear: a valid token or #rrggbb hex
                        // colors it (hex stored lowercase), "None" (or
                        // anything else) removes the shade.
                        color:
                          typeof patch.color === "string" && isAccentValue(patch.color)
                            ? normalizeAccent(patch.color)
                            : undefined,
                        // Same explicit set/clear for the destination —
                        // switching a button back to the terminal must
                        // actually drop the agent target, not leave it
                        // stale behind a spread.
                        target: patch.target === "agent" ? "agent" : undefined,
                      }
                    : b,
                ),
              }
            : bar,
        );
        const next = { ...s.preferences, buttonBars };
        savePreferences(next);
        return { preferences: next };
      }),
    removeButton: (id) =>
      set((s) => {
        const buttonBars = s.preferences.buttonBars.map((bar) =>
          bar.id === s.preferences.activeButtonBarId
            ? { ...bar, buttons: bar.buttons.filter((b) => b.id !== id) }
            : bar,
        );
        const next = { ...s.preferences, buttonBars };
        savePreferences(next);
        return { preferences: next };
      }),
    addBar: (name) =>
      set((s) => {
        if (s.preferences.buttonBars.length >= BUTTON_BAR_MAX_BARS) return {};
        const bar: ButtonBar = {
          id: crypto.randomUUID(),
          name: sanitizeBarName(name),
          buttons: [],
        };
        const next = {
          ...s.preferences,
          buttonBars: [...s.preferences.buttonBars, bar],
          // A freshly-created bar is what the user wants to fill next.
          activeButtonBarId: bar.id,
        };
        savePreferences(next);
        return { preferences: next };
      }),
    renameBar: (id, name) =>
      set((s) => {
        const buttonBars = s.preferences.buttonBars.map((b) =>
          b.id === id ? { ...b, name: sanitizeBarName(name, b.name) } : b,
        );
        const next = { ...s.preferences, buttonBars };
        savePreferences(next);
        return { preferences: next };
      }),
    removeBar: (id) =>
      set((s) => {
        const bars = s.preferences.buttonBars;
        // The strip always has ≥ 1 bar — deleting the last is a no-op
        // (the UI disables the item; this is belt-and-braces).
        if (bars.length <= 1) return {};
        const idx = bars.findIndex((b) => b.id === id);
        if (idx === -1) return {};
        const buttonBars = bars.filter((b) => b.id !== id);
        const activeButtonBarId =
          s.preferences.activeButtonBarId === id
            ? // Neighbor-focus: same index (the next bar slid into it),
              // else the previous one (mirrors removeSession/removeChat).
              (buttonBars[idx] ?? buttonBars[idx - 1]).id
            : s.preferences.activeButtonBarId;
        const next = { ...s.preferences, buttonBars, activeButtonBarId };
        savePreferences(next);
        return { preferences: next };
      }),
    setActiveBar: (id) =>
      set((s) => {
        if (!s.preferences.buttonBars.some((b) => b.id === id)) return {};
        const next = { ...s.preferences, activeButtonBarId: id };
        savePreferences(next);
        return { preferences: next };
      }),
    cycleBar: (delta) =>
      set((s) => {
        const bars = s.preferences.buttonBars;
        if (bars.length < 2) return {};
        const idx = bars.findIndex((b) => b.id === s.preferences.activeButtonBarId);
        const nextIdx = (idx + delta + bars.length) % bars.length;
        const next = { ...s.preferences, activeButtonBarId: bars[nextIdx].id };
        savePreferences(next);
        return { preferences: next };
      }),
    toggleGroupCollapsed: (path) =>
      set((s) => {
        const collapsedGroups = { ...s.preferences.collapsedGroups };
        if (collapsedGroups[path]) {
          delete collapsedGroups[path];
        } else {
          collapsedGroups[path] = true;
        }
        const next = { ...s.preferences, collapsedGroups };
        savePreferences(next);
        return { preferences: next };
      }),
    expandGroups: (paths) =>
      set((s) => {
        const collapsedGroups = { ...s.preferences.collapsedGroups };
        let changed = false;
        for (const path of paths) {
          // Expand the path AND every ancestor prefix so a nested group
          // is actually reachable in the tree.
          let prefix = "";
          for (const seg of path.split("/").filter(Boolean)) {
            prefix = prefix ? `${prefix}/${seg}` : seg;
            if (collapsedGroups[prefix]) {
              delete collapsedGroups[prefix];
              changed = true;
            }
          }
        }
        if (!changed) return s;
        const next = { ...s.preferences, collapsedGroups };
        savePreferences(next);
        return { preferences: next };
      }),

    // First launch (chatPanelOpen === null in storage): default OPEN.
    // Every subsequent launch honors the persisted last-toggled value.
    chatPanelOpen: initialPrefs.chatPanelOpen ?? true,
    pendingAgentPrompt: null,
    setAgentPrompt: (text) => set({ pendingAgentPrompt: text }),
    consumeAgentPrompt: () => {
      const text = get().pendingAgentPrompt;
      if (text !== null) set({ pendingAgentPrompt: null });
      return text;
    },
    toggleChatPanel: () =>
      set((s) => {
        const next = !s.chatPanelOpen;
        const prefs = { ...s.preferences, chatPanelOpen: next };
        savePreferences(prefs);
        return { chatPanelOpen: next, preferences: prefs };
      }),

    sessionInfoPanelOpen: false,
    toggleSessionInfoPanel: () => set((s) => ({ sessionInfoPanelOpen: !s.sessionInfoPanelOpen })),

    sessions: [],
    activeTabId: null,
    activePaneId: null,
    lastPaneByTab: {},
    setActivePane: (sessionId) =>
      set((s) => {
        if (!s.activeTabId) return s;
        // Only a pane of the ACTIVE tab may take focus. A background tab's
        // panes are `display:none` and can't hold DOM focus, so an event
        // naming one is stale (a teardown race) — ignoring it keeps the
        // invariant instead of pointing focus at an invisible terminal.
        if (!tabPaneIds(s.sessions, s.activeTabId).includes(sessionId)) return s;
        if (s.activePaneId === sessionId) return s;
        return {
          activePaneId: sessionId,
          lastPaneByTab: { ...s.lastPaneByTab, [s.activeTabId]: sessionId },
        };
      }),
    pendingApiLoad: {},
    addSession: (sessionId, deviceId, agentDeviceId) =>
      set((s) => {
        const next: SessionTab = { sessionId, deviceId, ended: false };
        if (agentDeviceId && agentDeviceId !== deviceId) next.agentDeviceId = agentDeviceId;
        return { sessions: [...s.sessions, next], activeTabId: sessionId };
      }),
    splitPaneWith: (sessionId, deviceId, targetPaneId, dir, agentDeviceId) =>
      set((s) => {
        // Resolve the tab (top-level primary) that owns targetPaneId: either
        // the target IS a primary, or it's a pane whose splitWith → primary.
        const target = s.sessions.find((t) => t.sessionId === targetPaneId);
        const primaryId = target && !target.splitWith ? target.sessionId : target?.splitWith;
        const primary = primaryId
          ? s.sessions.find((t) => t.sessionId === primaryId && !t.splitWith)
          : undefined;
        const pane: SessionTab = { sessionId, deviceId, ended: false };
        if (agentDeviceId && agentDeviceId !== deviceId) pane.agentDeviceId = agentDeviceId;
        if (!primary || !hasPty(primary)) {
          // No tileable target — either it vanished mid-connect, or it's an
          // API / Files tab, neither of which renders a `PaneTree` (whose
          // leaves hardcode `TerminalPane`). Fall back to a normal tab.
          return { sessions: [...s.sessions, pane], activeTabId: sessionId };
        }
        const nextLayout = splitLeaf(
          primary.layout ?? leaf(primary.sessionId),
          targetPaneId,
          sessionId,
          dir,
        );
        if (!hasPane(nextLayout, sessionId)) {
          // splitLeaf was a no-op — targetPaneId isn't a leaf in the primary's
          // tree (shouldn't happen via the UI, where the target is always the
          // primary leaf). Never strand a live pane that's in `sessions` but
          // absent from every rendered layout: fall back to a normal tab.
          return { sessions: [...s.sessions, pane], activeTabId: sessionId };
        }
        pane.splitWith = primary.sessionId;
        const sessions = s.sessions.map((t) =>
          t.sessionId === primary.sessionId ? { ...t, layout: nextLayout } : t,
        );
        sessions.push(pane);
        // Focus stays on the tab (the new pane lives inside it), and within it
        // moves to the pane just created — you split in order to work in the
        // new pane, and it matches what opening a plain tab does.
        return {
          sessions,
          activeTabId: primary.sessionId,
          activePaneId: sessionId,
          lastPaneByTab: { ...s.lastPaneByTab, [primary.sessionId]: sessionId },
        };
      }),
    openApiTab: (apiSessionId, name) =>
      set((s) => {
        // One tab per controller (like launchApiRequest): a stateless
        // controller gains nothing from a second tab — they'd share one
        // history ring — and it keeps the agent's register-on-open 1:1 with
        // the pane's mount/unmount. Reuse the existing tab if any.
        const existing = s.sessions.find(
          (t) => t.kind === "api" && t.apiSessionId === apiSessionId,
        );
        if (existing) {
          return { activeTabId: existing.sessionId };
        }
        // Synthetic, unique tab id — API tabs have no backend session.
        const sessionId = `api:${apiSessionId}:${crypto.randomUUID()}`;
        const next: SessionTab = {
          sessionId,
          deviceId: name,
          ended: false,
          kind: "api",
          apiSessionId,
        };
        return { sessions: [...s.sessions, next], activeTabId: sessionId };
      }),
    openShellTab: (sessionId, label) =>
      set((s) => {
        const next: SessionTab = {
          sessionId,
          deviceId: label,
          ended: false,
          kind: "local",
        };
        return { sessions: [...s.sessions, next], activeTabId: sessionId };
      }),
    openPcapTab: (captureId, name) =>
      set((s) => {
        // One tab per capture: re-opening a capture that is already open
        // focuses it rather than indexing the same file twice.
        const existing = s.sessions.find((t) => t.kind === "pcap" && t.sessionId === captureId);
        if (existing) return { activeTabId: captureId };
        const next: SessionTab = {
          sessionId: captureId,
          deviceId: name,
          ended: false,
          kind: "pcap",
        };
        return { sessions: [...s.sessions, next], activeTabId: captureId };
      }),
    openFilesTab: (sessionId, deviceId) =>
      set((s) => {
        // Always a NEW tab (the Connect semantics): a second file-transfer
        // session to the same device is a legitimate second connection, and
        // `computeLabels` disambiguates it ("vEX1 (2)") while the tab's
        // folder glyph distinguishes it from an SSH tab.
        const next: SessionTab = {
          sessionId,
          deviceId,
          ended: false,
          kind: "files",
        };
        return { sessions: [...s.sessions, next], activeTabId: sessionId };
      }),
    launchApiRequest: (apiSessionId, name, template) =>
      set((s) => {
        // Reuse the controller's first open tab if any, else create one.
        const existing = s.sessions.find(
          (t) => t.kind === "api" && t.apiSessionId === apiSessionId,
        );
        const sessionId = existing
          ? existing.sessionId
          : `api:${apiSessionId}:${crypto.randomUUID()}`;
        const sessions = existing
          ? s.sessions
          : [
              ...s.sessions,
              { sessionId, deviceId: name, ended: false, kind: "api" as const, apiSessionId },
            ];
        return {
          sessions,
          activeTabId: sessionId,
          pendingApiLoad: { ...s.pendingApiLoad, [sessionId]: template },
        };
      }),
    consumeApiLoad: (sessionId) =>
      set((s) => {
        if (!(sessionId in s.pendingApiLoad)) return s;
        const next = { ...s.pendingApiLoad };
        delete next[sessionId];
        return { pendingApiLoad: next };
      }),
    removeSession: (sessionId) =>
      set((s) => {
        const target = s.sessions.find((t) => t.sessionId === sessionId);
        if (!target) return s;

        // A non-primary PANE: remove just it, and drop its leaf from the tab's
        // layout. The primary + sibling panes stay; focus (activeTabId) is a
        // TAB concept, unaffected.
        if (target.splitWith) {
          const primaryId = target.splitWith;
          // v6.4.0 — if the closing pane held focus, hand it to the sibling
          // `neighborPane` picks (previous sibling, else first remaining leaf),
          // computed against the layout BEFORE the removal. Falling through to
          // the resolver would work but would jump focus to the primary, which
          // is wrong when you just closed the third of three panes.
          const primaryBefore = s.sessions.find((t) => t.sessionId === primaryId);
          const successor =
            s.activePaneId === sessionId && primaryBefore?.layout
              ? neighborPane(primaryBefore.layout, sessionId)
              : s.activePaneId;
          const sessions = s.sessions
            .filter((t) => t.sessionId !== sessionId)
            .map((t) => {
              if (t.sessionId !== primaryId || !t.layout) return t;
              // removeLeaf keeps single-child splits (render stability), so the
              // layout stays a PaneTree even when only the primary remains — it
              // renders identically and never remounts the primary's xterm. A
              // null result (whole tree emptied) is impossible here since the
              // primary leaf always survives a child-pane removal.
              const collapsed = removeLeaf(t.layout, sessionId);
              return { ...t, layout: collapsed ?? undefined };
            });
          const lastPaneByTab =
            s.lastPaneByTab[primaryId] === sessionId
              ? { ...s.lastPaneByTab, [primaryId]: successor ?? primaryId }
              : s.lastPaneByTab;
          return { sessions, activePaneId: successor, lastPaneByTab };
        }

        // A PRIMARY/tab: cascade — drop the primary AND every pane whose
        // splitWith points at it. The caller disconnects the backend
        // sessions; this handles UI bookkeeping only.
        const next = s.sessions.filter(
          (t) => t.sessionId !== sessionId && t.splitWith !== sessionId,
        );
        let activeTabId = s.activeTabId;
        if (s.activeTabId === sessionId) {
          const topLevelNext = next.filter((t) => !t.splitWith);
          const topLevelOldIdx = s.sessions
            .filter((t) => !t.splitWith)
            .findIndex((t) => t.sessionId === sessionId);
          activeTabId =
            topLevelNext[topLevelOldIdx]?.sessionId ??
            topLevelNext[topLevelOldIdx - 1]?.sessionId ??
            null;
        }
        // The tab and all its panes are gone: drop its focus memory (a closed
        // tab's id could otherwise be reused by a later session) and clear the
        // hint, letting the resolver re-derive focus for whichever tab is now
        // active.
        const { [sessionId]: _dropped, ...lastPaneByTab } = s.lastPaneByTab;
        return { sessions: next, activeTabId, activePaneId: null, lastPaneByTab };
      }),
    moveSession: (activeId, overId) =>
      set((s) => {
        if (activeId === overId) return s;
        const from = s.sessions.findIndex((t) => t.sessionId === activeId);
        const to = s.sessions.findIndex((t) => t.sessionId === overId);
        if (from === -1 || to === -1) return s;
        const next = [...s.sessions];
        const [moved] = next.splice(from, 1);
        next.splice(to, 0, moved);
        return { sessions: next };
      }),
    movePaneInto: (draggedId, targetPaneId, dir, before) =>
      set((s) => {
        // Resolve the target's owning tab (its primary): the target pane is
        // either a primary itself, or a pane whose splitWith points at one.
        const targetTab = s.sessions.find((t) => t.sessionId === targetPaneId);
        const primaryId =
          targetTab && !targetTab.splitWith ? targetTab.sessionId : targetTab?.splitWith;
        const primary = primaryId
          ? s.sessions.find((t) => t.sessionId === primaryId && !t.splitWith)
          : undefined;
        // The dragged item is always a TOP-LEVEL tab (only those live in the
        // strip). Dropping a tab onto its OWN pane is a no-op for now (same-tab
        // pane rearrange is a follow-up), as are missing ids.
        const dragged = s.sessions.find((t) => t.sessionId === draggedId && !t.splitWith);
        if (!primary || !dragged || primary.sessionId === dragged.sessionId) return s;
        // Only PTY tabs tile. `PaneTree` leaves hardcode `<TerminalPane>`, so
        // tiling a non-PTY tab would render a broken terminal for it: an API
        // tab has a synthetic id and no backend TerminalSession, and a Files
        // tab is a dual-pane browser. Neither exposes drop zones (only
        // PaneTree leaves do), so a layout never contains one — this guards
        // the drag-SOURCE side. v1 keeps Files out of tiling entirely
        // (plan decision 6); teaching leaves to dispatch on kind is later.
        if (!hasPty(dragged) || !hasPty(primary)) return s;
        const base = primary.layout ?? leaf(primary.sessionId);
        if (!hasPane(base, targetPaneId)) return s;

        // Insert the dragged tab's WHOLE subtree (it may own panes) adjacent to
        // the target pane, then reparent every session it contained under the
        // target's primary. The dragged primary loses its own layout — its
        // panes are now leaves of the merged tree.
        const draggedNode = dragged.layout ?? leaf(dragged.sessionId);
        const movedIds = new Set(paneIds(draggedNode));
        const nextLayout = insertNodeAt(base, targetPaneId, draggedNode, dir, before);

        const sessions = s.sessions.map((t) => {
          if (t.sessionId === primary.sessionId) return { ...t, layout: nextLayout };
          if (movedIds.has(t.sessionId)) {
            const reparented: SessionTab = { ...t, splitWith: primary.sessionId };
            delete reparented.layout;
            return reparented;
          }
          return t;
        });
        // If the dragged tab was focused, follow it into its new home — and
        // land on the dragged pane itself, not the target's primary: the tab
        // you were looking at is the one you just dropped.
        const followed = s.activeTabId === dragged.sessionId;
        const activeTabId = followed ? primary.sessionId : s.activeTabId;
        const activePaneId = followed ? dragged.sessionId : s.activePaneId;
        const lastPaneByTab = followed
          ? { ...s.lastPaneByTab, [primary.sessionId]: dragged.sessionId }
          : s.lastPaneByTab;
        return { sessions, activeTabId, activePaneId, lastPaneByTab };
      }),
    movePaneOut: (sessionId) =>
      set((s) => {
        const pane = s.sessions.find((t) => t.sessionId === sessionId);
        // Only a PANE lifts out. A primary is already its own tab, and a
        // missing id is a teardown race.
        if (!pane?.splitWith) return s;
        const primaryId = pane.splitWith;
        const primary = s.sessions.find((t) => t.sessionId === primaryId && !t.splitWith);
        if (!primary) return s;

        // Detach: drop the pane's leaf from the old tab's tree and clear its
        // `splitWith` so it renders as a top-level tab again. Like the pane
        // branch of `removeSession` this relies on `removeLeaf` keeping
        // single-child splits, so the old tab's surviving panes never remount
        // and never lose scrollback. The lifted pane itself DOES remount — it
        // moves from a PaneTree leaf to a bare `<TerminalPane>`, the same
        // unavoidable position change as a tab's first split. Its scrollback
        // survives because the backend ring, not the xterm, is the store.
        const nextLayout = primary.layout ? removeLeaf(primary.layout, sessionId) : undefined;
        const sessions = s.sessions.map((t) => {
          if (t.sessionId === primaryId) return { ...t, layout: nextLayout ?? undefined };
          if (t.sessionId !== sessionId) return t;
          const lifted: SessionTab = { ...t };
          delete lifted.splitWith;
          return lifted;
        });

        // Focus the pane in its new home — the user asked for it to be its own
        // tab, so show them that tab.
        const successor =
          s.activePaneId === sessionId && primary.layout
            ? neighborPane(primary.layout, sessionId)
            : s.activePaneId;
        const lastPaneByTab = { ...s.lastPaneByTab };
        if (lastPaneByTab[primaryId] === sessionId) {
          lastPaneByTab[primaryId] = successor ?? primaryId;
        }
        return { sessions, activeTabId: sessionId, activePaneId: sessionId, lastPaneByTab };
      }),
    clearAllSessions: () =>
      set({ sessions: [], activeTabId: null, activePaneId: null, lastPaneByTab: {} }),
    sortSessionsByLabel: () =>
      set((s) => {
        // Sort on the DISPLAYED label (a rename, else the disambiguated
        // device name) so the result matches what the user reads on the
        // strip — sorting on `deviceId` would scatter renamed tabs.
        // `computeLabels` disambiguates by position, so labels are paired
        // with their tab BEFORE sorting; recomputing after would renumber
        // the duplicates and make the order look wrong.
        const labels = computeLabels(s.sessions);
        const paired = s.sessions.map((tab, i) => ({ tab, label: labels[i] }));
        paired.sort((a, b) =>
          a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: "base" }),
        );
        return { sessions: paired.map((p) => p.tab) };
      }),
    setActiveTab: (sessionId) =>
      set((s) => {
        if (!s.sessions.some((t) => t.sessionId === sessionId)) return s;
        // Restore the pane you were last in on this tab, else its primary.
        // Validated against the CURRENT pane set — the remembered pane may
        // have been closed while the tab sat in the background.
        const panes = tabPaneIds(s.sessions, sessionId);
        const remembered = s.lastPaneByTab[sessionId];
        return {
          activeTabId: sessionId,
          activePaneId: remembered && panes.includes(remembered) ? remembered : sessionId,
        };
      }),
    markSessionEnded: (sessionId) =>
      set((s) => ({
        sessions: s.sessions.map((t) => (t.sessionId === sessionId ? { ...t, ended: true } : t)),
      })),
    markSessionReconnected: (sessionId) =>
      set((s) => ({
        sessions: s.sessions.map((t) => (t.sessionId === sessionId ? { ...t, ended: false } : t)),
      })),
    setSessionLabel: (sessionId, label) =>
      set((s) => ({
        sessions: s.sessions.map((t) =>
          t.sessionId === sessionId
            ? { ...t, customLabel: label && label.length > 0 ? label : null }
            : t,
        ),
      })),
    reconnectSession: (oldSessionId, newSessionId) =>
      set((s) => {
        const idx = s.sessions.findIndex((t) => t.sessionId === oldSessionId);
        if (idx === -1) return s;
        const sessions = s.sessions.map((t, i) => {
          let nt = t;
          if (i === idx) nt = { ...nt, sessionId: newSessionId, ended: false };
          // A pane of the reconnecting tab — rewrite the anchor so the split
          // survives the id swap.
          if (nt.splitWith === oldSessionId) nt = { ...nt, splitWith: newSessionId };
          // Any layout referencing the old id (the reconnecting primary's own
          // tree) — rename the leaf so the pane keeps its slot.
          if (nt.layout && hasPane(nt.layout, oldSessionId)) {
            nt = { ...nt, layout: renameLeaf(nt.layout, oldSessionId, newSessionId) };
          }
          return nt;
        });
        const activeTabId = s.activeTabId === oldSessionId ? newSessionId : s.activeTabId;
        // Rewrite the focus hint + per-tab memory through the id swap, same as
        // the layout leaves above: an Enter-to-reconnect in a split pane must
        // not leave focus pointing at the retired id.
        const activePaneId = s.activePaneId === oldSessionId ? newSessionId : s.activePaneId;
        const lastPaneByTab = Object.fromEntries(
          Object.entries(s.lastPaneByTab).map(([tab, panePick]) => [
            tab === oldSessionId ? newSessionId : tab,
            panePick === oldSessionId ? newSessionId : panePick,
          ]),
        );
        return { sessions, activeTabId, activePaneId, lastPaneByTab };
      }),

    // --- v2.5.0 multi-chat AI tabs ---
    chats: [],
    activeChatId: null,
    chatSeq: 0,
    pendingApprovalByChat: {},
    pendingApiCallByChat: {},
    completedUnfocusedByChat: {},
    defaultChatModel: null,
    addChat: (chatId, model) =>
      set((s) => {
        if (s.chats.length >= CHAT_TABS_MAX) return s;
        if (s.chats.some((c) => c.chatId === chatId)) return s;
        const seq = s.chatSeq + 1;
        return {
          // scopedDeviceIds starts null (unscoped); autoApproveGets false —
          // a fresh chat always starts at per-call approval (M1: opt-in
          // resets on new chat).
          chats: [
            ...s.chats,
            { chatId, model, seq, scopedDeviceIds: null, autoApproveGets: false },
          ],
          activeChatId: chatId,
          chatSeq: seq,
        };
      }),
    removeChat: (chatId) =>
      set((s) => {
        const idx = s.chats.findIndex((c) => c.chatId === chatId);
        if (idx === -1) return s;
        const chats = s.chats.filter((c) => c.chatId !== chatId);
        let activeChatId = s.activeChatId;
        if (s.activeChatId === chatId) {
          // Neighbor-focus: next, then prev, then null (mirrors removeSession).
          activeChatId = chats[idx]?.chatId ?? chats[idx - 1]?.chatId ?? null;
        }
        const pendingApprovalByChat = { ...s.pendingApprovalByChat };
        delete pendingApprovalByChat[chatId];
        const pendingApiCallByChat = { ...s.pendingApiCallByChat };
        delete pendingApiCallByChat[chatId];
        const completedUnfocusedByChat = { ...s.completedUnfocusedByChat };
        delete completedUnfocusedByChat[chatId];
        // v6.3.0 — the FOURTH per-chat map: an explicitly closed chat's
        // persisted label goes with it ("pruned on explicit close" is a
        // documented claim, and close deletes the history file too).
        let preferences = s.preferences;
        if (chatId in s.preferences.chatLabelsById) {
          const chatLabelsById = { ...s.preferences.chatLabelsById };
          delete chatLabelsById[chatId];
          preferences = { ...s.preferences, chatLabelsById };
          savePreferences(preferences);
        }
        return {
          chats,
          activeChatId,
          preferences,
          pendingApprovalByChat,
          pendingApiCallByChat,
          completedUnfocusedByChat,
        };
      }),
    setActiveChat: (chatId) =>
      set((s) => {
        if (!s.chats.some((c) => c.chatId === chatId)) return s;
        if (!s.completedUnfocusedByChat[chatId]) return { activeChatId: chatId };
        // Focusing clears the "completed while unfocused" green dot; a
        // pending approval is left intact (the modal renders it).
        const completedUnfocusedByChat = { ...s.completedUnfocusedByChat };
        delete completedUnfocusedByChat[chatId];
        return { activeChatId: chatId, completedUnfocusedByChat };
      }),
    setChatModel: (chatId, model) =>
      set((s) => ({
        chats: s.chats.map((c) => (c.chatId === chatId ? { ...c, model } : c)),
      })),
    setChatScope: (chatId, deviceIds) =>
      set((s) => ({
        chats: s.chats.map((c) => (c.chatId === chatId ? { ...c, scopedDeviceIds: deviceIds } : c)),
      })),
    setChatAutoApproveGets: (chatId, enabled) =>
      set((s) => ({
        chats: s.chats.map((c) => (c.chatId === chatId ? { ...c, autoApproveGets: enabled } : c)),
      })),
    setChatLabel: (chatId, label) =>
      set((s) => {
        const clean = label && label.length > 0 ? label : null;
        // v6.3.0 — mirror the label into the persisted map so a renamed
        // chat restored from history keeps its name. Sanitized on the
        // way in, and the MERGED map is re-capped — the loader's cap
        // alone let the map grow unbounded during a session and then
        // truncate the newest labels at next launch (review finding).
        const merged = { ...s.preferences.chatLabelsById };
        const persisted = clean ? sanitizeChatLabel(clean) : null;
        if (persisted) merged[chatId] = persisted;
        else delete merged[chatId];
        const next = { ...s.preferences, chatLabelsById: sanitizeChatLabels(merged) };
        savePreferences(next);
        return {
          preferences: next,
          chats: s.chats.map((c) => (c.chatId === chatId ? { ...c, customLabel: clean } : c)),
        };
      }),
    clearAllChats: () =>
      set((s) => {
        // Same close semantics as removeChat: labels go with the chats.
        let preferences = s.preferences;
        if (Object.keys(s.preferences.chatLabelsById).length > 0) {
          preferences = { ...s.preferences, chatLabelsById: {} };
          savePreferences(preferences);
        }
        return {
          chats: [],
          activeChatId: null,
          preferences,
          pendingApprovalByChat: {},
          pendingApiCallByChat: {},
          completedUnfocusedByChat: {},
        };
      }),
    applyRestoredChatLabels: (labels, liveIds) =>
      set((s) => {
        // v6.3.0 — ONE prefs write for the whole restore sync (labels
        // applied to freshly-added tabs + the prune), instead of one
        // localStorage stringify per label at panel-paint time. NEVER
        // prunes on an empty live set: a transiently-empty backend list
        // (feature off, resolver error) must not wipe labels the user
        // will want when persistence comes back (review finding).
        const live = new Set(liveIds);
        if (live.size === 0) return s;
        const kept = Object.entries(s.preferences.chatLabelsById).filter(([id]) => live.has(id));
        const next = {
          ...s.preferences,
          chatLabelsById: sanitizeChatLabels(Object.fromEntries(kept)),
        };
        const changed =
          JSON.stringify(next.chatLabelsById) !== JSON.stringify(s.preferences.chatLabelsById);
        if (changed) savePreferences(next);
        return {
          preferences: changed ? next : s.preferences,
          chats: s.chats.map((c) => {
            const label = labels[c.chatId];
            return label && !c.customLabel ? { ...c, customLabel: label } : c;
          }),
        };
      }),
    setChatPendingApproval: (chatId, payload) =>
      set((s) => {
        const pendingApprovalByChat = { ...s.pendingApprovalByChat };
        if (payload) pendingApprovalByChat[chatId] = payload;
        else delete pendingApprovalByChat[chatId];
        return { pendingApprovalByChat };
      }),
    setChatPendingApiCall: (chatId, payload) =>
      set((s) => {
        const pendingApiCallByChat = { ...s.pendingApiCallByChat };
        if (payload) pendingApiCallByChat[chatId] = payload;
        else delete pendingApiCallByChat[chatId];
        return { pendingApiCallByChat };
      }),
    markChatCompleted: (chatId) =>
      set((s) => {
        // The active chat needs no "done" dot (the user is looking at it).
        if (chatId === s.activeChatId) return s;
        if (s.completedUnfocusedByChat[chatId]) return s;
        return {
          completedUnfocusedByChat: { ...s.completedUnfocusedByChat, [chatId]: true },
        };
      }),
    setDefaultChatModel: (model) => set({ defaultChatModel: model }),
    setNotifyOnUnfocusedComplete: (enabled) =>
      set((s) => {
        const next = { ...s.preferences, notifyOnUnfocusedComplete: enabled };
        savePreferences(next);
        return { preferences: next };
      }),
    setChatSendOnEnter: (enabled) =>
      set((s) => {
        const next = { ...s.preferences, chatSendOnEnter: enabled };
        savePreferences(next);
        return { preferences: next };
      }),
  };
});
