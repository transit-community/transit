import { useEffect, useState } from "react";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getVersion } from "@tauri-apps/api/app";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Check,
  Cpu,
  ExternalLink,
  Eye,
  EyeOff,
  FileCog,
  Info,
  KeyRound,
  MessageSquare,
  Minus,
  Plus,
  RefreshCw,
  Settings,
  ShieldCheck,
  Trash2,
  Wrench,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  AGENT_CHAT_SETTINGS_QUERY_KEY,
  getAgentChatSettings,
  getNetworkSettings,
  getPolicySettings,
  localEndpointClearToken,
  localEndpointDelete,
  localEndpointSetToken,
  localEndpointUpsert,
  localEndpointsList,
  providerKeyClear,
  chatgptSigninCancel,
  chatgptSigninStart,
  chatgptSignout,
  providerKeySet,
  providerKeysStatus as providerKeysStatusIpc,
  providerOpenaiMethodSet,
  setLocalModelsSettings,
  setAgentChatSettings,
  setStrictTls,
  setUserPoliciesDir,
  type LocalEndpointKind,
  type LocalEndpointStatus,
  type LocalEndpointView,
  type LocalModelsSettings,
  type NetworkSettings,
  type PolicySettings,
  type OpenAiMethod,
  type Provider,
  type ProviderKeysStatus,
} from "@/lib/api";
import { CHATGPT_STATUS_QUERY_KEY, useChatGptStatus } from "@/lib/chatgpt";
import { BACKEND_CHATS_QUERY_KEY } from "@/lib/chat";
import { PROVIDER_KEYS_QUERY_KEY } from "@/components/ChatPanel";
import { useProviderModels } from "@/lib/providerModels";
import {
  LOCAL_ENDPOINTS_LIST_QUERY_KEY,
  LOCAL_ENDPOINTS_STATUS_QUERY_KEY,
  LOCAL_SETTINGS_QUERY_KEY,
  LOCAL_STATUS_QUERY_KEY,
  useLocalEndpointsStatus,
  useLocalModelsSettings,
  useLocalModelsStatus,
} from "@/lib/localModels";
import { developerSettings, openLogDir, setDeveloperSettings } from "@/lib/api";
import { loadSelectableMonospaceFonts } from "@/lib/fonts";
import { DEFAULT_THEME_ID, THEME_LIST } from "@/lib/themes";
import { pcapCapturesDir, pcapConfiguredDir, setPcapDir, usePcapEnabled } from "@/lib/pcap";
import { applyBundle, exportBundle, pickAndPreviewBundle } from "@/lib/settingsBundle";
import { toastError, toastInfo, toastSuccess } from "@/lib/toast";

/** Query key for the Developers tab's settings. */
const DEVELOPER_SETTINGS_KEY = ["developerSettings"] as const;
/** Mirrors `FILE_LOG_KEEP` in commands.rs — shown so the retention is
 *  visible rather than a surprise. */
const FILE_LOG_KEEP_DAYS = 7;
import {
  CHAT_FONT_SIZE_DEFAULT,
  CHAT_FONT_SIZE_MAX,
  CHAT_FONT_SIZE_MIN,
  TERMINAL_FONT_SIZE_DEFAULT,
  TERMINAL_FONT_SIZE_MAX,
  TERMINAL_FONT_SIZE_MIN,
  useUiStore,
} from "@/stores/uiStore";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const QUERY_KEY = PROVIDER_KEYS_QUERY_KEY;
/** The public repository — issues, source, releases. The ONLY URL the
 *  About tab opens; `capabilities/default.json` pins the opener to it. */
const REPO_URL = "https://github.com/transit-community/transit";
const ISSUES_URL = `${REPO_URL}/issues`;

function providerLabel(provider: Provider): string {
  return provider === "anthropic" ? "Anthropic" : "OpenAI";
}

/**
 * Settings dialog. Eight tabs — General, Agent Chat, AI providers, Local
 * models, Policies, Network, Developers, About. Per-tab behavior is
 * documented on each `*Tab` component below.
 *
 * Layout: a LEFT NAV RAIL (`<Tabs orientation="vertical">`), not a
 * horizontal strip. At this tab count the strip's nowrap min-content width
 * exceeded the dialog's max width, and because `DialogContent` is a CSS
 * grid (grid items default to `min-width: auto`) the overflowing strip
 * inflated the shared column track — dragging EVERY row's right-side
 * control past the clipped edge, not just the tabs (same
 * `min-width: auto` family as the v2.3.6 tab-strip bug). The rail
 * scales with tab count; the dialog is fixed-size so the rail can't
 * scroll away, and each pane scrolls independently. `min-w-0` on the
 * Tabs root is load-bearing: it lets grid/flex compress content instead
 * of inflating the dialog — keep it when restyling.
 *
 * Mounted at the App root; opened via `useUiStore.openSettingsDialog()`
 * (triggered from the sidebar footer's gear OR the command palette).
 */
export function SettingsDialog() {
  const open = useUiStore((s) => s.settingsDialogOpen);
  const close = useUiStore((s) => s.closeSettingsDialog);

  return (
    <Dialog open={open} onOpenChange={(next) => !next && close()}>
      {/* Fixed-size workspace: explicit rows (header / rail+pane / footer)
          with a minmax(0,1fr) middle so the pane scrolls internally instead
          of stretching the dialog. 60rem leaves 32px margins at the 1024px
          minimum window width (tauri.conf.json). */}
      <DialogContent className="h-[min(44rem,85vh)] grid-rows-[auto_minmax(0,1fr)_auto] sm:max-w-[60rem]">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>
            Preferences for this machine. Nothing here is synced anywhere.
          </DialogDescription>
        </DialogHeader>

        <SettingsBody />

        <DialogFooter>
          <Button type="button" variant="outline" onClick={close}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Rail items: left-aligned full-width rows (the primitive centers). */
const RAIL_TRIGGER_CLASSES = "w-full justify-start";

/**
 * Every pane: `flex-1 overflow-y-auto` makes the PANE the scroll
 * container (the rail + header stay put), `min-w-0` lets it shrink
 * below content min-width so one long unbreakable string clips inside
 * the pane instead of re-inflating the whole dialog, and `mt-0`
 * cancels the primitive's `mt-2` (the root's `gap-4` already separates
 * rail from pane).
 */
const PANE_CLASSES = "mt-0 min-w-0 flex-1 overflow-y-auto pr-1";

function SettingsBody() {
  // Deep-link target (e.g. the chat panel's "Add an API key" → "api-keys");
  // default "general". Keying the Tabs on it remounts to the right tab on
  // reopen.
  const initialTab = useUiStore((s) => s.settingsInitialTab) ?? "general";

  return (
    <Tabs
      orientation="vertical"
      defaultValue={initialTab}
      key={initialTab}
      className="flex min-h-0 min-w-0 w-full gap-4"
    >
      <TabsList className="h-auto w-44 shrink-0 flex-col items-stretch gap-1 overflow-y-auto">
        <TabsTrigger value="general" className={RAIL_TRIGGER_CLASSES}>
          <Settings className="mr-1.5 h-3.5 w-3.5" />
          General
        </TabsTrigger>
        <TabsTrigger value="agent-chat" className={RAIL_TRIGGER_CLASSES}>
          <MessageSquare className="mr-1.5 h-3.5 w-3.5" />
          Agent Chat
        </TabsTrigger>
        <TabsTrigger value="api-keys" className={RAIL_TRIGGER_CLASSES}>
          <KeyRound className="mr-1.5 h-3.5 w-3.5" />
          AI providers
        </TabsTrigger>
        <TabsTrigger value="local-models" className={RAIL_TRIGGER_CLASSES}>
          <Cpu className="mr-1.5 h-3.5 w-3.5" />
          Local models
        </TabsTrigger>
        <TabsTrigger value="policies" className={RAIL_TRIGGER_CLASSES}>
          <FileCog className="mr-1.5 h-3.5 w-3.5" />
          Policies
        </TabsTrigger>
        <TabsTrigger value="network" className={RAIL_TRIGGER_CLASSES}>
          <ShieldCheck className="mr-1.5 h-3.5 w-3.5" />
          Network
        </TabsTrigger>
        <TabsTrigger value="developers" className={RAIL_TRIGGER_CLASSES}>
          <Wrench className="mr-1.5 h-3.5 w-3.5" />
          Developers
        </TabsTrigger>
        <TabsTrigger value="about" className={RAIL_TRIGGER_CLASSES}>
          <Info className="mr-1.5 h-3.5 w-3.5" />
          About
        </TabsTrigger>
      </TabsList>
      <TabsContent value="general" className={PANE_CLASSES}>
        <GeneralTab />
      </TabsContent>
      <TabsContent value="agent-chat" className={PANE_CLASSES}>
        <AgentChatTab />
      </TabsContent>
      <TabsContent value="api-keys" className={PANE_CLASSES}>
        <ApiKeysTab />
      </TabsContent>
      <TabsContent value="local-models" className={PANE_CLASSES}>
        <LocalModelsTab />
      </TabsContent>
      <TabsContent value="policies" className={PANE_CLASSES}>
        <PoliciesTab />
      </TabsContent>
      <TabsContent value="network" className={PANE_CLASSES}>
        <NetworkTab />
      </TabsContent>
      <TabsContent value="developers" className={PANE_CLASSES}>
        <DevelopersTab />
      </TabsContent>
      <TabsContent value="about" className={PANE_CLASSES}>
        <AboutTab />
      </TabsContent>
    </Tabs>
  );
}

/**
 * Agent Chat tab (v6.3.0) — behavior preferences for the AI chat panel.
 * The composer send-key is a client-only preference (uiStore-persisted,
 * like chat font size — no IPC). The opt-in Agent Chat features
 * (save-to-file on code blocks, keep chat history) land in this tab next
 * release with backend-enforced `[agent_chat]` config; this tab is their
 * designated home.
 */
/** One Agent Chat opt-in feature: toggle + directory chooser + env-
 *  override explainers + the backend's validation error when the dir is
 *  broken (an "On" toggle over an inert feature must say WHY). One
 *  component so the third feature can't forget the explainer the way a
 *  hand-copied second group already did (review finding). */
function AgentChatFeatureRow({
  title,
  description,
  enabled,
  enabledEnvVar,
  enabledEnvOverride,
  dir,
  dirConfigured,
  dirError,
  dirEnvVar,
  dirEnvOverride,
  busy,
  onToggle,
  onChooseDir,
  onResetDir,
  testIdPrefix,
}: {
  title: string;
  description: React.ReactNode;
  enabled: boolean;
  enabledEnvVar: string;
  enabledEnvOverride: boolean;
  dir: string;
  dirConfigured: string | null;
  dirError: string | null;
  dirEnvVar: string;
  dirEnvOverride: boolean;
  busy: boolean;
  onToggle: () => void;
  onChooseDir: () => void;
  onResetDir: () => void;
  testIdPrefix: string;
}) {
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="font-medium">{title}</p>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Button
          type="button"
          variant={enabled ? "default" : "outline"}
          size="sm"
          role="switch"
          aria-checked={enabled}
          disabled={busy || enabledEnvOverride}
          onClick={onToggle}
          className="shrink-0"
          data-testid={`${testIdPrefix}-toggle`}
        >
          {enabled ? "On" : "Off"}
        </Button>
      </div>
      <div className="flex items-center justify-between gap-4">
        <p className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={dir}>
          {dir || "…"}
        </p>
        <div className="flex shrink-0 gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy || dirEnvOverride}
            onClick={onChooseDir}
            data-testid={`${testIdPrefix}-dir-choose`}
          >
            Choose…
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy || dirEnvOverride || dirConfigured === null}
            onClick={onResetDir}
            data-testid={`${testIdPrefix}-dir-reset`}
          >
            Reset
          </Button>
        </div>
      </div>
      {dirError && (
        <p
          className="text-xs text-amber-700 dark:text-amber-400"
          data-testid={`${testIdPrefix}-dir-error`}
        >
          This folder can't be used, so the feature is inactive until it's fixed: {dirError}
        </p>
      )}
      {enabledEnvOverride && (
        <p className="text-xs text-muted-foreground">
          Set by <code className="font-mono">{enabledEnvVar}</code> — unset it to manage this here.
        </p>
      )}
      {dirEnvOverride && (
        <p className="text-xs text-muted-foreground">
          Folder set by <code className="font-mono">{dirEnvVar}</code> — unset it to choose one
          here.
        </p>
      )}
    </div>
  );
}

function AgentChatTab() {
  const sendOnEnter = useUiStore((s) => s.preferences.chatSendOnEnter);
  const setChatSendOnEnter = useUiStore((s) => s.setChatSendOnEnter);
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: AGENT_CHAT_SETTINGS_QUERY_KEY,
    queryFn: getAgentChatSettings,
    staleTime: 0,
  });
  const [busy, setBusy] = useState(false);

  /** Every write sends the full four-tuple, patched — the configured
   *  dirs round-trip from `*_configured` (never the effective value, or
   *  the default would get pinned as an explicit choice). Invalidates
   *  BOTH this key and the backend chat list: toggling history on must
   *  let the panel's next mount actually restore. */
  async function update(patch: {
    persistHistory?: boolean;
    historyDir?: string | null;
    saveToFile?: boolean;
    saveDir?: string | null;
  }) {
    if (!data || busy) return;
    setBusy(true);
    try {
      await setAgentChatSettings({
        persistHistory: patch.persistHistory ?? data.persist_history,
        historyDir: patch.historyDir !== undefined ? patch.historyDir : data.history_dir_configured,
        saveToFile: patch.saveToFile ?? data.save_to_file,
        saveDir: patch.saveDir !== undefined ? patch.saveDir : data.save_dir_configured,
      });
      await queryClient.invalidateQueries({ queryKey: AGENT_CHAT_SETTINGS_QUERY_KEY });
      await queryClient.invalidateQueries({ queryKey: BACKEND_CHATS_QUERY_KEY });
    } catch (err: unknown) {
      toastError("Couldn't update Agent Chat settings", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  async function chooseDir(key: "historyDir" | "saveDir") {
    if (busy) return;
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked !== "string") return;
    await update({ [key]: picked });
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4 rounded-md border bg-muted/20 p-3">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="font-medium">Press Enter to send</p>
          <p className="text-xs text-muted-foreground">
            When <strong>on</strong> (default), Enter sends your message and Shift+Enter inserts a
            new line. When <strong>off</strong>, Enter inserts a new line and only ⌘/Ctrl+Enter
            sends — handy for long, hand-typed multi-line prompts. ⌘/Ctrl+Enter always sends in
            either mode.
          </p>
        </div>
        <Button
          type="button"
          variant={sendOnEnter ? "default" : "outline"}
          size="sm"
          role="switch"
          aria-checked={sendOnEnter}
          onClick={() => setChatSendOnEnter(!sendOnEnter)}
          className="shrink-0"
          data-testid="agent-chat-send-on-enter"
        >
          {sendOnEnter ? "On" : "Off"}
        </Button>
      </div>

      <AgentChatFeatureRow
        title="Keep chat history"
        description={
          <>
            <strong>Off by default.</strong> When on, each chat's transcript is saved to the folder
            below after every turn — turns you stop midway included — and your open chats come back
            after a restart. Restored chats always start with fresh approval state: command
            auto-approvals, device scopes, and API auto-approve never persist. Transcripts pass
            Transit's redaction filter again at the write boundary. Closing a chat deletes its file;
            turning this off stops new writes and leaves existing files in place.
          </>
        }
        enabled={data?.persist_history ?? false}
        enabledEnvVar="TRANSIT_AGENT_CHAT_PERSIST_HISTORY"
        enabledEnvOverride={data?.persist_history_env_override ?? false}
        dir={data?.history_dir ?? ""}
        dirConfigured={data?.history_dir_configured ?? null}
        dirError={data?.history_dir_error ?? null}
        dirEnvVar="TRANSIT_AGENT_CHAT_HISTORY_DIR"
        dirEnvOverride={data?.history_dir_env_override ?? false}
        busy={busy || !data}
        onToggle={() => void update({ persistHistory: !(data?.persist_history ?? false) })}
        onChooseDir={() => void chooseDir("historyDir")}
        onResetDir={() => void update({ historyDir: null })}
        testIdPrefix="agent-chat-history"
      />

      <AgentChatFeatureRow
        title="Save code blocks to file"
        description={
          <>
            <strong>Off by default.</strong> When on, every code block the AI writes gets a Save
            button. Saving always opens the system save dialog — you pick the destination each time
            (it starts at the folder below), and the AI itself has no way to write files: the button
            click is the entire authority.
          </>
        }
        enabled={data?.save_to_file ?? false}
        enabledEnvVar="TRANSIT_AGENT_CHAT_SAVE_TO_FILE"
        enabledEnvOverride={data?.save_to_file_env_override ?? false}
        dir={data?.save_dir ?? ""}
        dirConfigured={data?.save_dir_configured ?? null}
        dirError={data?.save_dir_error ?? null}
        dirEnvVar="TRANSIT_AGENT_CHAT_SAVE_DIR"
        dirEnvOverride={data?.save_dir_env_override ?? false}
        busy={busy || !data}
        onToggle={() => void update({ saveToFile: !(data?.save_to_file ?? false) })}
        onChooseDir={() => void chooseDir("saveDir")}
        onResetDir={() => void update({ saveDir: null })}
        testIdPrefix="agent-chat-save"
      />
    </div>
  );
}

/**
 * Where packet captures are written.
 *
 * Lives in General rather than a PCaps-only corner because it is a
 * disk-usage decision as much as a capture one: a full-snaplen capture on
 * a busy interface reaches the 2 GB rotation ceiling, and the default sits
 * inside the app's data directory where nobody thinks to look for large
 * files.
 *
 * `TRANSIT_PCAP_DIR` wins over anything set here and makes the field
 * read-only, matching the policy-folder row — a centrally-managed
 * deployment should not present an editable control that silently loses.
 */
function CaptureFolderRow() {
  const queryClient = useQueryClient();
  // The DLP off-switch hides this too. Every command behind it refuses
  // when the surface is off, so leaving the row would render a folder
  // picker whose path never resolves and whose Save changes nothing
  // visible — a control that lies about being connected to something.
  const { data: pcapOn = true } = usePcapEnabled();
  const { data: resolved } = useQuery({
    queryKey: ["pcapCapturesDir"],
    queryFn: pcapCapturesDir,
    staleTime: 30_000,
  });
  const { data: configured } = useQuery({
    queryKey: ["pcapConfiguredDir"],
    queryFn: pcapConfiguredDir,
    staleTime: 30_000,
  });
  const [busy, setBusy] = useState(false);
  const isCustom = (configured ?? null) !== null;

  async function choose() {
    if (busy) return;
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked !== "string") return;
    await apply(picked);
  }

  async function apply(dir: string | null) {
    setBusy(true);
    try {
      await setPcapDir(dir);
      await queryClient.invalidateQueries({ queryKey: ["pcapCapturesDir"] });
      await queryClient.invalidateQueries({ queryKey: ["pcapConfiguredDir"] });
      toastSuccess(dir ? "Capture folder saved" : "Capture folder reset", {
        description: "New captures are written here. Existing files are left where they are.",
      });
    } catch (err: unknown) {
      toastError("Couldn't set the capture folder", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  if (!pcapOn) return null;

  return (
    <div className="rounded-md border bg-muted/20 p-3" data-testid="general-capture-folder-row">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">Capture folder</p>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
            {resolved ?? "…"}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Where packet captures are written. Captures rotate up to a 2 GB ceiling each, so a
            volume with room is worth choosing.
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void choose()}>
            Choose…
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={busy || !isCustom}
            onClick={() => void apply(null)}
          >
            Reset
          </Button>
        </div>
      </div>
    </div>
  );
}

/**
 * Diagnostics: an opt-in rolling log, for the machine nobody on the team
 * will ever touch.
 *
 * Two limits govern what reaches the file, and they are different limits.
 *
 * **No secrets** — `CLAUDE.md` §10, unchanged. The file receives the same
 * events stderr already gets, so credentials, host keys, tokens and prompt
 * content stay out of it for the same reason they stay out of stderr.
 *
 * **No architecture** — enforced in the backend, where the release channel
 * is known. Production builds cap at `info` with module paths omitted,
 * because `debug`/`trace` with targets is a runtime map of a closed-source
 * product and a file a user can read is one they can publish. The UI
 * offers only the levels this build actually allows rather than showing
 * choices the backend will silently clamp.
 */
function DevelopersTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: DEVELOPER_SETTINGS_KEY,
    queryFn: developerSettings,
    staleTime: 30_000,
  });
  const [busy, setBusy] = useState(false);

  const enabled = data?.log_to_file ?? false;
  const level = data?.log_level ?? "info";
  const verbose = data?.verbose_available ?? false;
  const levels = verbose ? ["info", "debug", "trace"] : ["info"];

  async function save(next: {
    logToFile?: boolean;
    logDir?: string | null;
    logLevel?: string | null;
  }) {
    if (busy || !data) return;
    setBusy(true);
    try {
      await setDeveloperSettings(
        next.logToFile ?? data.log_to_file,
        next.logDir === undefined ? data.log_dir : next.logDir,
        next.logLevel ?? data.log_level,
      );
      await queryClient.invalidateQueries({ queryKey: DEVELOPER_SETTINGS_KEY });
      toastSuccess("Diagnostics saved", {
        description: "Restart Transit for the change to take effect.",
      });
    } catch (err: unknown) {
      toastError("Couldn't save diagnostics settings", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  async function chooseFolder() {
    const picked = await openDialog({ directory: true, multiple: false });
    if (typeof picked === "string") await save({ logDir: picked });
  }

  return (
    <div className="space-y-4 text-sm" data-testid="developers-tab">
      <p className="text-xs text-muted-foreground">
        Writes a diagnostic log to a file so a problem on a machine we cannot reach can still be
        diagnosed. Off unless you turn it on, and it applies from the next launch.
      </p>

      <div className="rounded-md border bg-muted/20 p-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Log to a file</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Keeps {FILE_LOG_KEEP_DAYS} days of daily files, so leaving it on cannot fill a disk.
            </p>
          </div>
          <Button
            size="sm"
            variant={enabled ? "default" : "outline"}
            disabled={busy}
            onClick={() => void save({ logToFile: !enabled })}
            data-testid="developers-log-toggle"
          >
            {enabled ? "On" : "Off"}
          </Button>
        </div>
      </div>

      <div className="rounded-md border bg-muted/20 p-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Log folder</p>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
              {data?.log_dir ?? "…"}
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void chooseFolder()}>
              Choose…
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void openLogDir()}>
              Open
            </Button>
          </div>
        </div>
      </div>

      <div className="rounded-md border bg-muted/20 p-3">
        <p className="text-sm font-medium">Detail</p>
        <div className="mt-2 flex gap-2">
          {levels.map((l) => (
            <Button
              key={l}
              size="sm"
              variant={level === l ? "default" : "outline"}
              disabled={busy}
              onClick={() => void save({ logLevel: l })}
            >
              {l}
            </Button>
          ))}
        </div>
        {!verbose && (
          <p className="mt-2 text-xs text-muted-foreground">
            Release builds record what Transit did and what the operating system said back. The
            deeper levels describe how Transit is built rather than what went wrong, so they are
            limited to development builds.
          </p>
        )}
      </div>

      {/* Stated plainly, because a log the user may send onward is a log
          they are entitled to understand before sending it. */}
      <div className="rounded-md border p-3">
        <p className="text-sm font-medium">What is never written</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
          <li>Passwords, keys, passphrases, and API tokens of any kind</li>
          <li>SSH host keys and the contents of your known-hosts file</li>
          <li>Terminal output, command text, and packet contents</li>
          <li>Anything you send to or receive from an AI model</li>
        </ul>
        <p className="mt-2 text-xs text-muted-foreground">
          The log records that an operation happened, when, and whether it failed — not the data it
          carried.
        </p>
      </div>
    </div>
  );
}

function GeneralTab() {
  const themeId = useUiStore((s) => s.preferences.themeId) ?? DEFAULT_THEME_ID;
  const setThemeId = useUiStore((s) => s.setThemeId);
  const fontSize = useUiStore((s) => s.preferences.terminalFontSize) ?? TERMINAL_FONT_SIZE_DEFAULT;
  const setTerminalFontSize = useUiStore((s) => s.setTerminalFontSize);
  const fontIsDefault = fontSize === TERMINAL_FONT_SIZE_DEFAULT;
  const canGrow = fontSize < TERMINAL_FONT_SIZE_MAX;
  const canShrink = fontSize > TERMINAL_FONT_SIZE_MIN;
  const chatFontSize = useUiStore((s) => s.preferences.chatFontSize) ?? CHAT_FONT_SIZE_DEFAULT;
  const setChatFontSize = useUiStore((s) => s.setChatFontSize);
  const chatFontIsDefault = chatFontSize === CHAT_FONT_SIZE_DEFAULT;
  const chatCanGrow = chatFontSize < CHAT_FONT_SIZE_MAX;
  const chatCanShrink = chatFontSize > CHAT_FONT_SIZE_MIN;
  const warnOnSessionClose = useUiStore((s) => s.preferences.warnOnSessionClose);
  const setWarnOnSessionClose = useUiStore((s) => s.setWarnOnSessionClose);

  return (
    <div className="space-y-3 text-sm">
      <div className="rounded-md border bg-muted/20 p-3" data-testid="general-theme-row">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Theme</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Applies to chrome (sidebar, dialogs) and the terminal foreground / background /
              cursor. Per-device override coming in a follow-up.
            </p>
          </div>
          <Select
            value={themeId}
            onValueChange={(v) => {
              setThemeId(v);
              toastSuccess(`Theme: ${THEME_LIST.find((t) => t.id === v)?.name ?? v}`);
            }}
          >
            <SelectTrigger
              data-testid="general-theme-select"
              className="h-8 w-48 text-xs"
              aria-label="Theme"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {THEME_LIST.map((t) => (
                <SelectItem key={t.id} value={t.id} className="text-xs">
                  {t.name}
                  <span className="ml-2 text-[10px] uppercase text-muted-foreground">{t.mode}</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="rounded-md border bg-muted/20 p-3" data-testid="general-close-warning-row">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Confirm before closing a connected session</p>
            <p className="mt-1 text-xs text-muted-foreground">
              On by default, so a misclick on a tab&apos;s ✕ can&apos;t drop a live session. Turn it
              off to close on the click. Two prompts are deliberately kept either way:{" "}
              <strong>Close all tabs</strong> and quitting the app, because those close your whole
              workspace at once — and a Files tab with transfers still in flight, because that one
              warns about losing work rather than about disconnecting.
            </p>
          </div>
          <Button
            type="button"
            variant={warnOnSessionClose ? "default" : "outline"}
            size="sm"
            role="switch"
            aria-checked={warnOnSessionClose}
            onClick={() => setWarnOnSessionClose(!warnOnSessionClose)}
            className="shrink-0"
            data-testid="general-close-warning-toggle"
          >
            {warnOnSessionClose ? "On" : "Off"}
          </Button>
        </div>
      </div>
      <div className="rounded-md border bg-muted/20 p-3" data-testid="general-font-size-row">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Terminal font size</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Applies to every terminal pane. Shortcut: ⌘+ / ⌘− / ⌘0 inside a pane.
            </p>
          </div>
          <div className="flex items-center gap-1">
            <Button
              size="icon"
              variant="outline"
              className="h-8 w-8"
              aria-label="Decrease terminal font size"
              data-testid="general-font-size-shrink"
              disabled={!canShrink}
              onClick={() => setTerminalFontSize(fontSize - 1)}
            >
              <Minus className="h-3.5 w-3.5" />
            </Button>
            <span
              data-testid="general-font-size-value"
              className="w-12 text-center font-mono text-xs tabular-nums"
              aria-live="polite"
            >
              {fontSize} px
            </span>
            <Button
              size="icon"
              variant="outline"
              className="h-8 w-8"
              aria-label="Increase terminal font size"
              data-testid="general-font-size-grow"
              disabled={!canGrow}
              onClick={() => setTerminalFontSize(fontSize + 1)}
            >
              <Plus className="h-3.5 w-3.5" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="ml-1 h-8 px-2 text-xs"
              data-testid="general-font-size-reset"
              disabled={fontIsDefault}
              onClick={() => setTerminalFontSize(null)}
            >
              Reset
            </Button>
          </div>
        </div>
      </div>
      <div className="rounded-md border bg-muted/20 p-3" data-testid="general-chat-font-size-row">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Chat font size</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Applies to the agent chat panel&apos;s messages. Independent of the terminal font
              size.
            </p>
          </div>
          <div className="flex items-center gap-1">
            <Button
              size="icon"
              variant="outline"
              className="h-8 w-8"
              aria-label="Decrease chat font size"
              data-testid="general-chat-font-size-shrink"
              disabled={!chatCanShrink}
              onClick={() => setChatFontSize(chatFontSize - 1)}
            >
              <Minus className="h-3.5 w-3.5" />
            </Button>
            <span
              data-testid="general-chat-font-size-value"
              className="w-12 text-center font-mono text-xs tabular-nums"
              aria-live="polite"
            >
              {chatFontSize} px
            </span>
            <Button
              size="icon"
              variant="outline"
              className="h-8 w-8"
              aria-label="Increase chat font size"
              data-testid="general-chat-font-size-grow"
              disabled={!chatCanGrow}
              onClick={() => setChatFontSize(chatFontSize + 1)}
            >
              <Plus className="h-3.5 w-3.5" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="ml-1 h-8 px-2 text-xs"
              data-testid="general-chat-font-size-reset"
              disabled={chatFontIsDefault}
              onClick={() => setChatFontSize(null)}
            >
              Reset
            </Button>
          </div>
        </div>
      </div>
      <FontFamilyRow />
      <CaptureFolderRow />
      <SettingsBundleRow />
      <PlaceholderCard
        title="Scrollback size"
        body="Per-session terminal scrollback cap. Today's defaults (4 MiB / 32K lines) are hardcoded; the picker arrives when we wire the backend to honor a per-device override."
      />
    </div>
  );
}

/** Sentinel Select values — Radix forbids empty-string item values,
 *  and neither sentinel can collide with a real family name. */
const FONT_PICK_DEFAULT = "__system_default__";
const FONT_PICK_CUSTOM = "__custom__";

/**
 * Terminal font-family control. v1.0.2 turns the free-text field
 * into a picker: the backend scans the OS font database for
 * monospace families and the frontend keeps only the ones this
 * webview can actually render (`lib/fonts.ts`), so OS-shipped but
 * web-blocked fonts (SF Mono) never appear as options that would
 * silently fall back. "Custom…" keeps the v1.0.1 free-text path for
 * hand-written fallback stacks and fonts whose metadata doesn't
 * declare fixed pitch — still draft-then-commit (blur / Enter),
 * since write-through would re-measure + refit every open pane per
 * keystroke.
 */
function FontFamilyRow() {
  const fontFamily = useUiStore((s) => s.preferences.terminalFontFamily);
  const setTerminalFontFamily = useUiStore((s) => s.setTerminalFontFamily);
  const { data: fonts } = useQuery({
    queryKey: ["fonts", "monospace"] as const,
    queryFn: loadSelectableMonospaceFonts,
    staleTime: Infinity,
  });
  // Sticky while the dialog is open so picking "Custom…" doesn't
  // bounce back to a list entry the moment the input commits a
  // value that happens to be in the list.
  const [customMode, setCustomMode] = useState(false);
  const [draft, setDraft] = useState(fontFamily ?? "");
  // Re-sync the draft when the store value changes underneath the
  // dialog (System default picked, a future per-device override).
  useEffect(() => {
    setDraft(fontFamily ?? "");
  }, [fontFamily]);

  // Until the scan resolves, a set family stands in for the list so
  // the trigger shows it instead of flashing the Custom input.
  const detected = fonts ?? (fontFamily !== null ? [fontFamily] : []);
  const selectValue = customMode
    ? FONT_PICK_CUSTOM
    : fontFamily === null
      ? FONT_PICK_DEFAULT
      : detected.includes(fontFamily)
        ? fontFamily
        : FONT_PICK_CUSTOM;
  const commitDraft = () => setTerminalFontFamily(draft.trim().length === 0 ? null : draft);

  return (
    <div className="rounded-md border bg-muted/20 p-3" data-testid="general-font-family-row">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">Terminal font</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Monospace fonts installed on this machine — only ones the terminal renderer can actually
            use are listed. Applies to every pane. Custom… accepts a hand-written family or fallback
            stack.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <Select
            value={selectValue}
            onValueChange={(v) => {
              if (v === FONT_PICK_DEFAULT) {
                setCustomMode(false);
                setTerminalFontFamily(null);
              } else if (v === FONT_PICK_CUSTOM) {
                setCustomMode(true);
              } else {
                setCustomMode(false);
                setTerminalFontFamily(v);
              }
            }}
          >
            <SelectTrigger
              data-testid="general-font-family-select"
              className="h-8 w-56 text-xs"
              aria-label="Terminal font family"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FONT_PICK_DEFAULT} className="text-xs">
                System default
              </SelectItem>
              {detected.map((f) => (
                <SelectItem
                  key={f}
                  value={f}
                  className="text-xs"
                  style={{ fontFamily: `"${f.replaceAll('"', "")}", monospace` }}
                >
                  {f}
                </SelectItem>
              ))}
              <SelectItem value={FONT_PICK_CUSTOM} className="text-xs">
                Custom…
              </SelectItem>
            </SelectContent>
          </Select>
          {selectValue === FONT_PICK_CUSTOM && (
            <Input
              value={draft}
              placeholder="e.g. JetBrains Mono, Menlo"
              onChange={(e) => setDraft(e.target.value)}
              onBlur={commitDraft}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commitDraft();
                }
              }}
              className="h-8 w-56 text-xs"
              aria-label="Custom terminal font family"
              data-testid="general-font-family-input"
            />
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Export / import Transit's settings to a file (v6.1.0) — the "I got a
 * new laptop" path. Occupies the slot where a Telemetry placeholder used
 * to promise a toggle for data we don't collect.
 *
 * The copy is explicit about the two exclusions because they are the
 * questions a security-minded user will actually have: there are no
 * secrets in the file, and host-key pins stay behind.
 */
function SettingsBundleRow() {
  const [busy, setBusy] = useState(false);

  const doExport = async () => {
    setBusy(true);
    try {
      const outcome = await exportBundle(true);
      if (!outcome) return; // cancelled
      toastSuccess("Settings exported", {
        description: `${outcome.deviceCount} connection${
          outcome.deviceCount === 1 ? "" : "s"
        } + preferences written to ${outcome.path}`,
      });
    } catch (e) {
      toastError("Export failed", { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const doImport = async () => {
    setBusy(true);
    try {
      const preview = await pickAndPreviewBundle();
      if (!preview) return; // cancelled
      const outcome = await applyBundle(preview, { preferences: true, connections: true });
      toastSuccess("Settings imported", {
        description: `${outcome.devicesImported} connection${
          outcome.devicesImported === 1 ? "" : "s"
        } imported${outcome.preferencesApplied ? "; restart Transit to apply preferences" : ""}`,
      });
    } catch (e) {
      toastError("Import failed", { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-md border p-3" data-testid="settings-bundle-row">
      <p className="text-sm font-medium">Export / import settings</p>
      <p className="mt-1 text-xs text-muted-foreground">
        Move your preferences and saved connections to another machine. Passwords are never included
        — they stay in your OS keychain — and neither are host-key fingerprints, so the new machine
        verifies each device itself the first time it connects.
      </p>
      <div className="mt-2 flex gap-2">
        <Button size="sm" variant="outline" onClick={doExport} disabled={busy}>
          Export…
        </Button>
        <Button size="sm" variant="outline" onClick={doImport} disabled={busy}>
          Import…
        </Button>
      </div>
    </div>
  );
}

function PlaceholderCard({ title, body }: { title: string; body: string }) {
  return (
    <div
      className="rounded-md border bg-muted/20 p-3"
      data-testid={`general-placeholder-${title.toLowerCase()}`}
    >
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 text-xs text-muted-foreground">{body}</p>
    </div>
  );
}

const NETWORK_SETTINGS_QUERY_KEY = ["network", "settings"] as const;

function NetworkTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery<NetworkSettings>({
    queryKey: NETWORK_SETTINGS_QUERY_KEY,
    queryFn: getNetworkSettings,
    staleTime: 0,
  });
  const [busy, setBusy] = useState(false);

  const strict = data?.strict_tls ?? false;
  const envOverride = data?.env_override ?? false;

  async function toggle() {
    if (busy || envOverride || !data) return;
    setBusy(true);
    try {
      await setStrictTls(!strict);
      await queryClient.invalidateQueries({ queryKey: NETWORK_SETTINGS_QUERY_KEY });
      toastSuccess(strict ? "Strict TLS disabled" : "Strict TLS enabled", {
        description: "Applies to your next AI message.",
      });
    } catch (err: unknown) {
      toastError("Couldn't update Strict TLS", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 text-sm" data-testid="network-tab">
      <div className="flex items-start justify-between gap-4 rounded-md border bg-muted/20 p-3">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="font-medium">Strict TLS</p>
          <p className="text-xs text-muted-foreground">
            When <strong>off</strong> (default), Transit trusts your operating system&apos;s
            certificate store, so it keeps working on networks that inspect TLS traffic — a
            corporate firewall&apos;s certificate installed in your system store is honored. When{" "}
            <strong>on</strong>, Transit trusts only the built-in public certificate authorities and
            refuses any inspected connection. Applies to your next AI message.
          </p>
        </div>
        <Button
          type="button"
          variant={strict ? "default" : "outline"}
          size="sm"
          role="switch"
          aria-checked={strict}
          disabled={busy || envOverride || !data}
          onClick={() => void toggle()}
          className="shrink-0"
        >
          {strict ? "On" : "Off"}
        </Button>
      </div>

      {envOverride && (
        <div className="rounded-md border bg-muted/20 p-3 text-xs">
          Set by the <code className="font-mono">TRANSIT_STRICT_TLS</code> environment variable —
          unset it to manage Strict TLS here.
        </div>
      )}

      <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs text-amber-700 dark:text-amber-400">
        <p className="font-medium">Inspected networks can read your AI traffic.</p>
        <p className="mt-1">
          With Strict TLS off on a network that inspects TLS, the inspecting proxy can read the
          prompts Transit sends to the AI provider (your device output) and your provider API key.
          This is expected on a corporate-managed network; turn Strict TLS on to refuse it. Device
          SSH connections use a separate trust model and are unaffected.
        </p>
      </div>
    </div>
  );
}

function AboutTab() {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getVersion()
      .then((v) => {
        if (!cancelled) setVersion(v);
      })
      .catch(() => {
        if (!cancelled) setVersion(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-4 text-sm">
      <div className="space-y-1">
        <p className="text-base font-semibold">Transit Community Edition</p>
        <p className="text-xs text-muted-foreground">
          Cross-platform GUI SSH client with an embedded agentic AI for read-only network
          investigation. Open source; runs on your own provider key or your own hardware. Makes no
          network connection except to the devices, endpoints and providers you configure.
        </p>
      </div>
      <KeyValueRow label="Version" value={version ?? "loading..."} mono />
      <KeyValueRow label="License" value="Apache-2.0" />
      <div className="flex flex-wrap gap-2 pt-1">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => void openUrl(REPO_URL)}
          data-testid="about-repo-link"
        >
          <ExternalLink className="mr-1 h-3.5 w-3.5" />
          Source code
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => void openUrl(ISSUES_URL)}
          data-testid="about-issues-link"
        >
          <ExternalLink className="mr-1 h-3.5 w-3.5" />
          Report an issue
        </Button>
      </div>
    </div>
  );
}

function KeyValueRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[120px_1fr] items-center gap-2">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className={mono ? "break-all font-mono text-xs" : "text-sm"}>{value}</span>
    </div>
  );
}

const POLICY_SETTINGS_QUERY_KEY = ["policy", "settings"] as const;

function PoliciesTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery<PolicySettings>({
    queryKey: POLICY_SETTINGS_QUERY_KEY,
    queryFn: getPolicySettings,
    staleTime: 0,
  });

  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);

  const envOverride = data?.env_override ?? false;
  const loadedDir = data?.user_dir ?? null;

  // Sync the input with the persisted value once it loads (only when the
  // path is editable — an env override is read-only).
  useEffect(() => {
    if (data && !data.env_override) setPath(data.user_dir ?? "");
  }, [data]);

  async function save() {
    if (busy) return;
    setBusy(true);
    try {
      const trimmed = path.trim();
      await setUserPoliciesDir(trimmed === "" ? null : trimmed);
      await queryClient.invalidateQueries({ queryKey: POLICY_SETTINGS_QUERY_KEY });
      toastSuccess("Policy directory saved", {
        description: "Restart Transit to load the change.",
      });
    } catch (err: unknown) {
      toastError("Couldn't save policy directory", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 text-sm" data-testid="policies-tab">
      <p className="text-xs text-muted-foreground">
        Bring Your Own Policy. Point Transit at a folder of{" "}
        <code className="font-mono">&lt;vendor&gt;.yaml</code> files to add read-only commands to a
        built-in vendor or define your own (e.g. <code className="font-mono">fortios</code>). Your
        additions can never weaken a built-in block — config mode, write commands, and shell escapes
        stay blocked — and a custom vendor still requires per-command approval. The folder may live
        on a shared drive for team use. Changes apply on next launch.
      </p>

      {envOverride ? (
        <div className="space-y-1 rounded-md border bg-muted/20 p-3">
          <p className="text-xs">
            Set by the <code className="font-mono">TRANSIT_USER_POLICIES</code> environment
            variable:
          </p>
          <p className="break-all font-mono text-xs">{loadedDir}</p>
          <p className="text-xs text-muted-foreground">
            Unset the variable to manage the folder here.
          </p>
        </div>
      ) : (
        <div className="space-y-1.5">
          <label htmlFor="policy-user-dir" className="font-medium">
            User policy folder
          </label>
          <div className="flex gap-2">
            <Input
              id="policy-user-dir"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/Volumes/nas/transit-policies"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <Button type="button" onClick={() => void save()} disabled={busy}>
              Save
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Leave empty for none. Saved changes load on the next launch.
          </p>
        </div>
      )}

      <KeyValueRow label="Loaded vendors" value={data?.vendors.join(", ") || "none"} mono />

      {data && data.warnings.length > 0 && (
        <div className="space-y-1 rounded-md border border-amber-500/40 bg-amber-500/10 p-3">
          <p className="font-medium text-amber-700 dark:text-amber-400">
            Policy warnings ({data.warnings.length})
          </p>
          <ul className="list-disc space-y-0.5 pl-4 text-xs">
            {data.warnings.map((w, i) => (
              <li key={i} className="break-all font-mono">
                {w}
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            The built-in policies still loaded; only the flagged user files were skipped or
            adjusted.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Local models (BYOM). Always available in this edition.
// Everything here is names/booleans/URLs — endpoint bearer tokens are
// write-only (Rule 1) and never round-trip to the UI.
// ---------------------------------------------------------------------

// Upper choices match the backend ceiling (LOCAL_MODELS_MAX_NUM_CTX =
// 262,144, commands.rs) and Ollama's own settings slider — the UI
// previously stopped at 65,536 for no backend reason (maintainer
// 2026-07-22). Big windows are labeled with a RAM/VRAM warning: the
// KV cache grows linearly with num_ctx and a 256k window can OOM or
// swap-thrash consumer hardware.
const NUM_CTX_CHOICES = [4096, 8192, 16_384, 32_768, 65_536, 131_072, 262_144] as const;
const NUM_CTX_HEAVY_THRESHOLD = 65_536;
const KEEP_ALIVE_CHOICES = ["5m", "15m", "30m", "1h"] as const;
const ENDPOINT_KIND_LABELS: Record<LocalEndpointKind, string> = {
  ollama: "Ollama (native)",
  openai_compat: "OpenAI-compatible",
};

function LocalModelsTab() {
  const queryClient = useQueryClient();
  const settings = useLocalModelsSettings();
  const enabled = settings.data?.enabled ?? false;
  const status = useLocalModelsStatus(enabled);
  const endpointStatuses = useLocalEndpointsStatus(enabled);
  const [busy, setBusy] = useState(false);

  async function invalidateAll() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: LOCAL_SETTINGS_QUERY_KEY }),
      queryClient.invalidateQueries({ queryKey: LOCAL_STATUS_QUERY_KEY }),
      queryClient.invalidateQueries({ queryKey: LOCAL_ENDPOINTS_STATUS_QUERY_KEY }),
      queryClient.invalidateQueries({ queryKey: LOCAL_ENDPOINTS_LIST_QUERY_KEY }),
    ]);
  }

  async function toggle() {
    if (busy || !settings.data) return;
    setBusy(true);
    try {
      await setLocalModelsSettings({
        enabled: !enabled,
        baseUrl: settings.data.base_url,
        numCtx: settings.data.num_ctx,
        keepAlive: settings.data.keep_alive,
      });
      await invalidateAll();
      toastSuccess(enabled ? "Local models disabled" : "Local models enabled", {
        description: "Applies to your next chat message — no restart needed.",
      });
    } catch (err: unknown) {
      toastError("Couldn't update local models", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 text-sm" data-testid="local-models-tab">
      <div className="flex items-start justify-between gap-4 rounded-md border bg-muted/20 p-3">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="font-medium">Bring Your Own Model</p>
          <p className="text-xs text-muted-foreground">
            Chat with models running on <strong>your own hardware</strong> — Ollama on this machine,
            or a self-hosted endpoint you configure below. Conversations with local models never
            leave the endpoints you configure, and proposed commands still go through the policy
            gate and your explicit approval.
          </p>
        </div>
        <Button
          type="button"
          variant={enabled ? "default" : "outline"}
          size="sm"
          role="switch"
          aria-checked={enabled}
          disabled={busy || !settings.data}
          onClick={() => void toggle()}
          className="shrink-0"
          data-testid="local-models-toggle"
        >
          {enabled ? "On" : "Off"}
        </Button>
      </div>

      {settings.data?.warning && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs text-amber-700 dark:text-amber-400">
          {settings.data.warning}
        </div>
      )}
      {settings.data?.env_override && (
        <div className="rounded-md border bg-muted/20 p-3 text-xs">
          The server URL is set by the <code className="font-mono">TRANSIT_LOCAL_MODELS_URL</code>{" "}
          environment variable — unset it to manage the URL here.
        </div>
      )}

      {enabled && (
        <>
          <OllamaStatusCard
            statusQuery={status}
            onRefresh={() =>
              void queryClient.invalidateQueries({ queryKey: LOCAL_STATUS_QUERY_KEY })
            }
          />
          {settings.data && (
            <LocalModelsConfigForm settings={settings.data} onSaved={invalidateAll} />
          )}
          <EndpointsSection statuses={endpointStatuses.data ?? []} onChanged={invalidateAll} />
          <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Choosing a model</p>
            <p className="mt-1">
              The agent needs <strong>tool calling</strong>, so only tool-capable models appear in
              the chat picker. Small models propose weaker investigations — 8B parameters and up
              from a recent tool-tuned family (Qwen, Gemma, gpt-oss) is a practical floor. Pull one
              with e.g. <code className="font-mono">ollama pull qwen3:8b</code>. Local model quality
              varies; the approval gate is what keeps your network safe either way.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

function OllamaStatusCard({
  statusQuery,
  onRefresh,
}: {
  statusQuery: ReturnType<typeof useLocalModelsStatus>;
  onRefresh: () => void;
}) {
  const s = statusQuery.data;
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3" data-testid="ollama-status-card">
      <div className="flex items-center justify-between gap-2">
        <p className="font-medium">
          Ollama{" "}
          {s?.reachable ? (
            <span className="text-xs font-normal text-emerald-600 dark:text-emerald-400">
              running · v{s.version}
            </span>
          ) : (
            <span className="text-xs font-normal text-muted-foreground">not detected</span>
          )}
        </p>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={onRefresh}
          disabled={statusQuery.isFetching}
          aria-label="Refresh Ollama status"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${statusQuery.isFetching ? "animate-spin" : ""}`} />
        </Button>
      </div>
      {!s?.reachable && (
        <p className="text-xs text-muted-foreground">
          {s?.error ?? "Checking…"} Install Ollama from ollama.com, run{" "}
          <code className="font-mono">ollama serve</code> (the desktop app does this automatically),
          then refresh.
        </p>
      )}
      {s?.reachable && s.version_supported === false && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          This Ollama version predates model-capability discovery — update to 0.6.4 or newer so
          Transit can tell which models support tools.
        </p>
      )}
      {s?.reachable && (
        <ul className="space-y-1 text-xs">
          {s.models.length === 0 && (
            <li className="text-muted-foreground">
              No models installed yet — try <code className="font-mono">ollama pull qwen3:8b</code>.
            </li>
          )}
          {s.models.map((m) => (
            <li key={m.id} className="flex items-center gap-2">
              <span className="font-mono">{m.name}</span>
              <span className="text-muted-foreground">{formatSizeGb(m.size_bytes)}</span>
              {m.tools_capable ? (
                <span className="rounded bg-emerald-500/15 px-1 py-px text-[10px] text-emerald-600 dark:text-emerald-400">
                  tools
                </span>
              ) : (
                <span className="rounded bg-muted px-1 py-px text-[10px] text-muted-foreground">
                  no tools — hidden from picker
                </span>
              )}
            </li>
          ))}
          {s.hidden_cloud_models.length > 0 && (
            <li className="pt-1 text-[11px] text-muted-foreground">
              {s.hidden_cloud_models.length} cloud-proxied model
              {s.hidden_cloud_models.length === 1 ? "" : "s"} hidden (
              {s.hidden_cloud_models.join(", ")}) — they run on ollama.com, not your machine.
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

function formatSizeGb(bytes: number): string {
  if (bytes <= 0) return "";
  return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
}

function LocalModelsConfigForm({
  settings,
  onSaved,
}: {
  settings: LocalModelsSettings;
  onSaved: () => Promise<void>;
}) {
  const [numCtx, setNumCtx] = useState(String(settings.num_ctx));
  const [keepAlive, setKeepAlive] = useState(settings.keep_alive);
  const [baseUrl, setBaseUrl] = useState(settings.base_url);
  const [busy, setBusy] = useState(false);
  const dirty =
    numCtx !== String(settings.num_ctx) ||
    keepAlive !== settings.keep_alive ||
    baseUrl !== settings.base_url;

  async function save() {
    if (busy) return;
    setBusy(true);
    try {
      await setLocalModelsSettings({
        enabled: settings.enabled,
        baseUrl,
        numCtx: Number(numCtx),
        keepAlive,
      });
      await onSaved();
      toastSuccess("Local model settings saved", {
        description: "Applies to your next chat message.",
      });
    } catch (err: unknown) {
      toastError("Couldn't save local model settings", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 rounded-md border bg-muted/20 p-3" data-testid="local-models-config">
      <p className="font-medium">Ollama settings</p>
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Context window (num_ctx)</span>
          <Select value={numCtx} onValueChange={setNumCtx}>
            <SelectTrigger className="h-8 text-xs" data-testid="local-num-ctx">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {NUM_CTX_CHOICES.map((n) => (
                <SelectItem key={n} value={String(n)} className="text-xs">
                  {n.toLocaleString()} tokens
                  {n > NUM_CTX_HEAVY_THRESHOLD ? " — heavy RAM/VRAM use" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted-foreground">Keep model loaded</span>
          <Select value={keepAlive} onValueChange={setKeepAlive}>
            <SelectTrigger className="h-8 text-xs" data-testid="local-keep-alive">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {KEEP_ALIVE_CHOICES.map((k) => (
                <SelectItem key={k} value={k} className="text-xs">
                  {k}
                </SelectItem>
              ))}
              {!KEEP_ALIVE_CHOICES.includes(keepAlive as (typeof KEEP_ALIVE_CHOICES)[number]) && (
                <SelectItem value={keepAlive} className="text-xs">
                  {keepAlive}
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </label>
      </div>
      <label className="block space-y-1 text-xs">
        <span className="text-muted-foreground">Server URL (loopback only)</span>
        <Input
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          disabled={settings.env_override}
          className="h-8 font-mono text-xs"
          data-testid="local-base-url"
        />
      </label>
      <p className="text-[11px] text-muted-foreground">
        Larger context windows survive longer investigations but use more memory — lower this if
        responses are very slow. Transit refuses a conversation that would overflow the window
        instead of letting the model silently forget its instructions.
      </p>
      {dirty && (
        <Button type="button" size="sm" disabled={busy} onClick={() => void save()}>
          {busy ? "Saving…" : "Save"}
        </Button>
      )}
    </div>
  );
}

const EMPTY_ENDPOINT_DRAFT = {
  id: "",
  name: "",
  kind: "openai_compat" as LocalEndpointKind,
  base_url: "",
  context_length: "8192",
};

function EndpointsSection({
  statuses,
  onChanged,
}: {
  statuses: LocalEndpointStatus[];
  onChanged: () => Promise<void>;
}) {
  const { data: endpoints } = useQuery<LocalEndpointView[]>({
    queryKey: LOCAL_ENDPOINTS_LIST_QUERY_KEY,
    queryFn: localEndpointsList,
    staleTime: 15_000,
  });
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState(EMPTY_ENDPOINT_DRAFT);
  const [busy, setBusy] = useState(false);

  async function saveDraft() {
    if (busy) return;
    setBusy(true);
    try {
      await localEndpointUpsert({
        id: draft.id.trim(),
        name: draft.name.trim(),
        kind: draft.kind,
        base_url: draft.base_url.trim(),
        context_length: Number(draft.context_length) || 0,
      });
      await onChanged();
      setAdding(false);
      setDraft(EMPTY_ENDPOINT_DRAFT);
      toastSuccess("Endpoint saved");
    } catch (err: unknown) {
      toastError("Couldn't save endpoint", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    try {
      await localEndpointDelete(id);
      await onChanged();
      toastSuccess("Endpoint removed");
    } catch (err: unknown) {
      toastError("Couldn't remove endpoint", {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return (
    <div className="space-y-3 rounded-md border bg-muted/20 p-3" data-testid="local-endpoints">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium">Custom endpoints</p>
          <p className="text-xs text-muted-foreground">
            Remote Ollama or OpenAI-compatible servers (vLLM, LM Studio, llama.cpp, LiteLLM) on your
            own infrastructure. Off this machine, HTTPS is required — your OS trust store (including
            enterprise CAs) is honored. Conversation content goes to servers you list here, nowhere
            else.
          </p>
        </div>
        {!adding && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="shrink-0"
            onClick={() => setAdding(true)}
            data-testid="local-endpoint-add"
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add
          </Button>
        )}
      </div>

      {(endpoints ?? []).map((ep) => (
        <EndpointRow
          key={ep.id}
          endpoint={ep}
          status={statuses.find((s) => s.id === ep.id) ?? null}
          onDelete={() => void remove(ep.id)}
          onChanged={onChanged}
        />
      ))}
      {(endpoints ?? []).length === 0 && !adding && (
        <p className="text-xs text-muted-foreground">No custom endpoints configured.</p>
      )}

      {adding && (
        <div className="space-y-2 rounded-md border bg-background p-2" data-testid="endpoint-form">
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Name</span>
              <Input
                value={draft.name}
                onChange={(e) => {
                  const name = e.target.value;
                  setDraft((d) => ({
                    ...d,
                    name,
                    // Auto-suggest a stable id from the name until the
                    // user edits the id field themselves.
                    id: d.id === slugify(d.name) || d.id === "" ? slugify(name) : d.id,
                  }));
                }}
                placeholder="Lab vLLM"
                className="h-8 text-xs"
                data-testid="endpoint-name"
              />
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Id (a-z, 0-9, -)</span>
              <Input
                value={draft.id}
                onChange={(e) => setDraft((d) => ({ ...d, id: e.target.value }))}
                placeholder="lab-vllm"
                className="h-8 font-mono text-xs"
                data-testid="endpoint-id"
              />
            </label>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Kind</span>
              <Select
                value={draft.kind}
                onValueChange={(kind) =>
                  setDraft((d) => ({ ...d, kind: kind as LocalEndpointKind }))
                }
              >
                <SelectTrigger className="h-8 text-xs" data-testid="endpoint-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(ENDPOINT_KIND_LABELS) as LocalEndpointKind[]).map((k) => (
                    <SelectItem key={k} value={k} className="text-xs">
                      {ENDPOINT_KIND_LABELS[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">Context window (tokens)</span>
              <Input
                value={draft.context_length}
                onChange={(e) => setDraft((d) => ({ ...d, context_length: e.target.value }))}
                inputMode="numeric"
                className="h-8 text-xs"
                data-testid="endpoint-context"
              />
            </label>
          </div>
          <label className="block space-y-1 text-xs">
            <span className="text-muted-foreground">
              Base URL{draft.kind === "openai_compat" ? " (include /v1)" : ""}
            </span>
            <Input
              value={draft.base_url}
              onChange={(e) => setDraft((d) => ({ ...d, base_url: e.target.value }))}
              placeholder={
                draft.kind === "openai_compat"
                  ? "https://vllm.lab.internal:8000/v1"
                  : "https://ollama.rack.internal:11434"
              }
              className="h-8 font-mono text-xs"
              data-testid="endpoint-url"
            />
          </label>
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              disabled={busy}
              onClick={() => void saveDraft()}
              data-testid="endpoint-save"
            >
              Save endpoint
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => {
                setAdding(false);
                setDraft(EMPTY_ENDPOINT_DRAFT);
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
}

function EndpointRow({
  endpoint,
  status,
  onDelete,
  onChanged,
}: {
  endpoint: LocalEndpointView;
  status: LocalEndpointStatus | null;
  onDelete: () => void;
  onChanged: () => Promise<void>;
}) {
  const [tokenOpen, setTokenOpen] = useState(false);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);

  async function saveToken() {
    if (busy) return;
    setBusy(true);
    try {
      await localEndpointSetToken(endpoint.id, token);
      setToken("");
      setTokenOpen(false);
      await onChanged();
      toastSuccess("Token stored in the OS keychain", {
        description: "Sent only to this endpoint, as an Authorization header.",
      });
    } catch (err: unknown) {
      toastError("Couldn't store the token", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  async function clearToken() {
    try {
      await localEndpointClearToken(endpoint.id);
      await onChanged();
      toastSuccess("Token removed");
    } catch (err: unknown) {
      toastError("Couldn't remove the token", {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return (
    <div
      className="space-y-1 rounded-md border bg-background p-2"
      data-testid={`endpoint-row-${endpoint.id}`}
    >
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium">{endpoint.name}</span>
        <span className="rounded bg-muted px-1 py-px text-[10px] text-muted-foreground">
          {ENDPOINT_KIND_LABELS[endpoint.kind]}
        </span>
        {status &&
          (status.reachable ? (
            <span className="text-[10px] text-emerald-600 dark:text-emerald-400">
              reachable · {status.models.length} model{status.models.length === 1 ? "" : "s"}
            </span>
          ) : (
            <span
              className="text-[10px] text-amber-600 dark:text-amber-400"
              title={status.error ?? ""}
            >
              unreachable
            </span>
          ))}
        <div className="flex-1" />
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-xs"
          onClick={() => setTokenOpen((v) => !v)}
        >
          <KeyRound className="mr-1 h-3 w-3" />
          {endpoint.has_token ? "Token set" : "Token"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-xs text-destructive"
          onClick={onDelete}
          aria-label={`Delete ${endpoint.name}`}
        >
          <Trash2 className="h-3 w-3" />
        </Button>
      </div>
      <p className="font-mono text-[11px] text-muted-foreground">
        {endpoint.base_url} · {endpoint.context_length.toLocaleString()} tokens
      </p>
      {status?.hidden_cloud_models.length ? (
        <p className="text-[11px] text-muted-foreground">
          {status.hidden_cloud_models.length} cloud-proxied model
          {status.hidden_cloud_models.length === 1 ? "" : "s"} hidden — they run on ollama.com.
        </p>
      ) : null}
      {tokenOpen && (
        <div className="flex items-center gap-2 pt-1">
          <Input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Bearer token (write-only)"
            className="h-7 flex-1 font-mono text-xs"
            data-testid={`endpoint-token-${endpoint.id}`}
          />
          <Button
            type="button"
            size="sm"
            className="h-7"
            disabled={busy}
            onClick={() => void saveToken()}
          >
            Save
          </Button>
          {endpoint.has_token && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="h-7"
              onClick={() => void clearToken()}
            >
              Clear
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function ApiKeysTab() {
  const { data: status } = useQuery<ProviderKeysStatus>({
    queryKey: QUERY_KEY,
    queryFn: providerKeysStatusIpc,
    staleTime: 0,
  });

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        Chat with Claude or GPT on your own API key. The key is stored in the macOS / Windows /
        Linux keychain on this machine and sent{" "}
        <strong>only to that provider&apos;s own API</strong>, over TLS verified against your OS
        trust store — there is no intermediary, no account, and no metering. Usage is billed by the
        provider to you.
      </p>
      <ProviderKeyRow
        provider="anthropic"
        label="Anthropic"
        configured={status?.anthropic ?? false}
        placeholder="sk-ant-…"
      />
      <OpenAiProviderCard configured={status?.openai ?? false} />
      <CustomModelIdsRow />
    </div>
  );
}

/**
 * The OpenAI card: one credential at a time — a platform API key, or a
 * ChatGPT Plus/Pro plan via Sign in with ChatGPT (OpenAI's open-source
 * preview). The radio persists `[providers] openai_method`; the chat
 * factory re-reads it per send.
 */
function OpenAiProviderCard({ configured }: { configured: boolean }) {
  const queryClient = useQueryClient();
  const status = useChatGptStatus({
    onError: (reason) => toastError("Sign in with ChatGPT failed", { description: reason }),
  });
  const method: OpenAiMethod = status.data?.method ?? "api_key";
  const [busy, setBusy] = useState(false);

  async function setMethod(next: OpenAiMethod) {
    if (busy || next === method) return;
    setBusy(true);
    try {
      await providerOpenaiMethodSet(next);
      await queryClient.invalidateQueries({ queryKey: CHATGPT_STATUS_QUERY_KEY });
      await queryClient.invalidateQueries({ queryKey: ["provider-models", "openai"] });
    } catch (err: unknown) {
      toastError("Couldn't switch the OpenAI method", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3" data-testid="openai-provider-card">
      <div
        className="flex items-center gap-2 rounded-md border bg-muted/20 p-2"
        role="radiogroup"
        aria-label="OpenAI credential"
      >
        <span className="px-1 text-sm font-medium">OpenAI</span>
        <Button
          type="button"
          size="sm"
          role="radio"
          aria-checked={method === "api_key"}
          variant={method === "api_key" ? "default" : "outline"}
          disabled={busy}
          onClick={() => void setMethod("api_key")}
          data-testid="openai-method-api-key"
        >
          API key
        </Button>
        <Button
          type="button"
          size="sm"
          role="radio"
          aria-checked={method === "chatgpt"}
          variant={method === "chatgpt" ? "default" : "outline"}
          disabled={busy}
          onClick={() => void setMethod("chatgpt")}
          data-testid="openai-method-chatgpt"
        >
          Sign in with ChatGPT
          <span className="ml-1 rounded bg-background/60 px-1 text-[10px] uppercase tracking-wide">
            Preview
          </span>
        </Button>
      </div>
      {method === "api_key" ? (
        <ProviderKeyRow
          provider="openai"
          label="OpenAI"
          configured={configured}
          placeholder="sk-…"
        />
      ) : (
        <ChatGptPlanRow
          signedIn={status.data?.signed_in ?? false}
          email={status.data?.email ?? null}
        />
      )}
    </div>
  );
}

/** Signed-out: a Sign in button that opens the browser and waits on the
 *  loopback callback. Signed-in: the account, the plan note, Sign out. */
function ChatGptPlanRow({ signedIn, email }: { signedIn: boolean; email: string | null }) {
  const queryClient = useQueryClient();
  const [waiting, setWaiting] = useState(false);
  const [busy, setBusy] = useState(false);

  // The Rust side emits success/error; the status hook invalidates on
  // both. Stop the spinner when the status settles either way.
  useEffect(() => {
    if (signedIn) setWaiting(false);
  }, [signedIn]);

  async function signIn() {
    setBusy(true);
    try {
      await chatgptSigninStart();
      setWaiting(true);
    } catch (err: unknown) {
      toastError("Couldn't start the sign-in", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }
  async function cancel() {
    await chatgptSigninCancel().catch(() => {});
    setWaiting(false);
  }
  async function signOut() {
    setBusy(true);
    try {
      const { revoked } = await chatgptSignout();
      await queryClient.invalidateQueries({ queryKey: CHATGPT_STATUS_QUERY_KEY });
      await queryClient.invalidateQueries({ queryKey: ["provider-models", "openai"] });
      if (revoked) {
        toastSuccess("Signed out of ChatGPT");
      } else {
        toastInfo("Signed out on this machine", {
          description:
            "OpenAI did not confirm the revocation. Disconnect Transit under ChatGPT Settings → Security and login to be sure.",
        });
      }
    } catch (err: unknown) {
      toastError("Couldn't sign out", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3" data-testid="chatgpt-plan-row">
      <p className="text-xs text-muted-foreground">
        Use a <strong>personal</strong> ChatGPT Plus or Pro plan for the OpenAI side instead of an
        API key. Sign-in opens your browser; this app keeps only a refresh token in your OS keychain
        and talks to OpenAI&apos;s own API. Usage counts against your plan — set a weekly cap for
        this app in ChatGPT&apos;s settings. OpenAI controls eligibility and limits while this is a
        preview.
      </p>
      <p className="text-xs text-muted-foreground" data-testid="chatgpt-plan-caveat">
        Workspace accounts (Business, Enterprise, Team) are blocked by OpenAI&apos;s organisation
        policy and cannot be allow-listed for open-source apps; use the API key instead. If the
        browser shows an error page, nothing comes back to this app — press Cancel here.
      </p>
      {signedIn ? (
        <div className="flex items-center gap-2 text-sm">
          <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          <span data-testid="chatgpt-account">{email ?? "Signed in"}</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="ml-auto h-8"
            disabled={busy}
            onClick={() => void signOut()}
            data-testid="chatgpt-signout"
          >
            Sign out
          </Button>
        </div>
      ) : waiting ? (
        <div className="flex items-center gap-2 text-sm">
          <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />
          <span>Waiting for the browser…</span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="ml-auto h-8"
            onClick={() => void cancel()}
            data-testid="chatgpt-cancel"
          >
            Cancel
          </Button>
        </div>
      ) : (
        <Button
          type="button"
          size="sm"
          className="h-8"
          disabled={busy}
          onClick={() => void signIn()}
          data-testid="chatgpt-signin"
        >
          <ExternalLink className="mr-1 h-3.5 w-3.5" />
          Sign in with ChatGPT
        </Button>
      )}
      <ProviderModelsRow provider="openai" enabled={signedIn} />
    </div>
  );
}

/** Extra model ids beyond this build's picker registry — how a model that
 *  ships after this release becomes selectable without an app update.
 *  Routed by id like every other provider model (`claude…` → Anthropic,
 *  else OpenAI); a typo simply gets the provider's own error back. */
function CustomModelIdsRow() {
  const ids = useUiStore((s) => s.preferences.customModelIds);
  const setIds = useUiStore((s) => s.setCustomModelIds);
  const [draft, setDraft] = useState("");

  function add() {
    const id = draft.trim();
    if (id.length === 0) return;
    setIds([...ids, id]);
    setDraft("");
  }

  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3" data-testid="custom-models-row">
      <p className="text-sm font-medium">Additional model ids</p>
      <p className="text-xs text-muted-foreground">
        Models newer than this build can be added by their API id (e.g.{" "}
        <code className="font-mono">claude-opus-6</code>). Ids containing{" "}
        <code className="font-mono">claude</code> use the Anthropic key; everything else uses the
        OpenAI key. They appear under &quot;Other&quot; in the chat model picker.
      </p>
      <div className="flex items-center gap-2">
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          placeholder="model-id"
          className="h-8 font-mono text-xs"
          autoComplete="off"
          spellCheck={false}
          data-testid="custom-model-input"
        />
        <Button
          type="button"
          size="sm"
          className="h-8"
          disabled={draft.trim().length === 0}
          onClick={add}
          data-testid="custom-model-add"
        >
          <Plus className="mr-1 h-3.5 w-3.5" />
          Add
        </Button>
      </div>
      {ids.length > 0 && (
        <ul className="space-y-1" data-testid="custom-model-list">
          {ids.map((id) => (
            <li key={id} className="flex items-center gap-2 text-xs">
              <code className="flex-1 truncate font-mono">{id}</code>
              <span className="text-muted-foreground">
                {providerLabel(id.includes("claude") ? "anthropic" : "openai")}
              </span>
              <button
                type="button"
                onClick={() => setIds(ids.filter((x) => x !== id))}
                className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                aria-label={`Remove ${id}`}
                title={`Remove ${id}`}
              >
                <Minus className="h-3.5 w-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ProviderKeyRow({
  provider,
  label,
  configured,
  placeholder,
}: {
  provider: Provider;
  label: string;
  configured: boolean;
  placeholder: string;
}) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState("");
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  // Reset transient UI when the row's configured state changes —
  // e.g., user clears via another window, status refetches.
  useEffect(() => {
    setValue("");
    setError(null);
  }, [configured]);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await providerKeySet(provider, value);
      setSavedAt(Date.now());
      setValue("");
      await queryClient.invalidateQueries({ queryKey: QUERY_KEY });
      toastSuccess(`${providerLabel(provider)} key saved`, {
        description: "Stored in the OS keychain; sent only to the provider, per request.",
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      toastError(`Failed to save ${providerLabel(provider)} key`, { description: msg });
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    setError(null);
    try {
      await providerKeyClear(provider);
      await queryClient.invalidateQueries({ queryKey: QUERY_KEY });
      toastSuccess(`${providerLabel(provider)} key cleared`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      toastError(`Failed to clear ${providerLabel(provider)} key`, { description: msg });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="space-y-2 rounded-md border bg-muted/20 p-3"
      data-testid={`provider-key-row-${provider}`}
    >
      <div className="flex items-center gap-2">
        <KeyRound className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">{label}</span>
        <span className="ml-auto text-xs text-muted-foreground">
          {configured ? (
            <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
              <Check className="h-3 w-3" /> Configured
            </span>
          ) : (
            "Not configured"
          )}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Input
          type={reveal ? "text" : "password"}
          placeholder={placeholder}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="h-8 text-xs"
          autoComplete="off"
          spellCheck={false}
          data-testid={`provider-key-input-${provider}`}
        />
        <button
          type="button"
          onClick={() => setReveal((r) => !r)}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label={reveal ? "Hide key" : "Show key"}
          title={reveal ? "Hide key" : "Show key"}
        >
          {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
        <Button
          type="button"
          size="sm"
          className="h-8"
          disabled={busy || value.trim().length === 0}
          onClick={() => void save()}
        >
          {busy ? "Saving…" : "Save"}
        </Button>
        {configured && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-8 px-2"
            disabled={busy}
            onClick={() => void clear()}
            aria-label={`Clear ${label} key`}
            title={`Clear ${label} key`}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
      {savedAt !== null && !error && (
        <p className="text-xs text-emerald-600 dark:text-emerald-400">Saved.</p>
      )}
      {configured && <ProviderModelsRow provider={provider} />}
    </div>
  );
}

function relativeTime(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

/** Live model discovery status for an enrolled key: count, age, Refresh.
 *  The list itself drives the chat picker (see `lib/providerModels.ts`). */
function ProviderModelsRow({
  provider,
  enabled = true,
}: {
  provider: Provider;
  enabled?: boolean;
}) {
  const q = useProviderModels(provider, enabled);
  const cached = useUiStore((s) => s.preferences.cachedModels[provider]);
  const count = q.data?.length ?? cached?.length ?? 0;
  const source = q.data ? "live" : cached && cached.length > 0 ? "cached" : "none";
  return (
    <div
      className="flex items-center gap-2 text-xs text-muted-foreground"
      data-testid={`provider-models-row-${provider}`}
    >
      <span data-testid={`provider-models-count-${provider}`}>
        {q.isFetching
          ? "Refreshing models…"
          : source === "none"
            ? "No models listed yet"
            : `${count} model${count === 1 ? "" : "s"}${
                source === "cached" ? " (cached)" : ""
              }${q.dataUpdatedAt ? ` · refreshed ${relativeTime(q.dataUpdatedAt)}` : ""}`}
      </span>
      {q.isError && (
        <span className="text-amber-700 dark:text-amber-400" role="status">
          couldn&apos;t list models — using {source === "cached" ? "the cached list" : "defaults"}
        </span>
      )}
      <button
        type="button"
        onClick={() => void q.refetch()}
        disabled={q.isFetching}
        className="ml-auto inline-flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-accent hover:text-foreground disabled:opacity-50"
        data-testid={`provider-models-refresh-${provider}`}
      >
        <RefreshCw className={`h-3 w-3 ${q.isFetching ? "animate-spin" : ""}`} />
        Refresh
      </button>
    </div>
  );
}
