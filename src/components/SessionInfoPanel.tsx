import { useQuery } from "@tanstack/react-query";
import { Info, Plus, Settings as SettingsIcon, Unplug, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { listDevices, listOpenSessions } from "@/lib/api";
import type { DeviceMeta, SessionMetaWire } from "@/lib/api";
import { useFilesDisconnectSession } from "@/lib/files";
import { useConnectDevice, useDisconnectSession } from "@/lib/mutations";
import { isFilesTab, resolveActivePaneId, useUiStore } from "@/stores/uiStore";
import type { SessionTab } from "@/stores/uiStore";

/**
 * Phase 7a C7 — right-hand session-info panel.
 *
 * Companion to the chat panel: surfaces metadata for the currently-
 * focused terminal tab so the user can answer "what am I connected
 * to, and when did it open?" without poking around the sidebar.
 *
 * Layout mirrors the ChatPanel: a 40px-wide collapsed rail with an
 * Info icon, expanding to a 288px (w-72) panel on toggle. Both
 * panels can be open simultaneously — they're sibling flex slots in
 * App.tsx so the order is: Sidebar | MainArea | SessionInfoPanel |
 * ChatPanel.
 *
 * V1 scope (Phase 7a):
 *   - Device identity (id, host:port, vendor, group).
 *   - Auth profile name.
 *   - Session opened-at + ended state.
 *   - Quick actions: Disconnect, Open another session, Edit device.
 *
 * Deferred to a follow-up (needs new IPC):
 *   - PTY cols/rows (no `pty_size` IPC today).
 *   - TOFU host-key fingerprint (host_keys.toml is backend-private).
 *   - Recent propose_command history (chat-id → session-id bridging
 *     not yet plumbed).
 */
export function SessionInfoPanel() {
  const open = useUiStore((s) => s.sessionInfoPanelOpen);
  const toggle = useUiStore((s) => s.toggleSessionInfoPanel);

  if (!open) {
    return (
      <aside
        data-testid="session-info-panel-closed"
        className="flex h-full w-10 flex-col items-center border-l border-border bg-background py-2"
        aria-label="Session info (closed)"
      >
        <button
          type="button"
          onClick={toggle}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Open session info panel"
          title="Open session info (⌘/Ctrl+I)"
        >
          <Info className="h-4 w-4" />
        </button>
      </aside>
    );
  }

  return (
    <aside
      data-testid="session-info-panel"
      className="flex h-full w-72 flex-col border-l border-border bg-background"
      aria-label="Session info"
    >
      <SessionInfoInner onClose={toggle} />
    </aside>
  );
}

function SessionInfoInner({ onClose }: { onClose: () => void }) {
  // v6.4.0 — describe the FOCUSED PANE, not the tab's primary: in a tiled tab
  // the panel was reporting the left pane's device while the user worked in the
  // right one. Subscribe to each input so the panel re-renders on a pane focus
  // change, then resolve (the resolver falls back to the tab's primary).
  const sessions = useUiStore((s) => s.sessions);
  const activeTabId = useUiStore((s) => s.activeTabId);
  const activePaneId = useUiStore((s) => s.activePaneId);
  const lastPaneByTab = useUiStore((s) => s.lastPaneByTab);
  const focusedId = resolveActivePaneId({ sessions, activeTabId, activePaneId, lastPaneByTab });
  const activeTab = sessions.find((s) => s.sessionId === focusedId) ?? null;

  return (
    <>
      <header className="flex h-12 items-center gap-2 border-b border-border px-3">
        <Info className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold tracking-wide">Session</h2>
        <div className="flex-1" />
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Close session info panel"
          title="Close (⌘/Ctrl+I)"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="flex-1 overflow-y-auto p-3">
        {!activeTab ? (
          <EmptyState />
        ) : isFilesTab(activeTab) ? (
          // A Files session matches nothing in `list_open_sessions` (the
          // `files_*` namespace is disjoint) and none of the SSH connect /
          // disconnect mutations apply to it, so it gets its own minimal
          // card rather than a panel full of em dashes.
          <FilesSessionDetails tab={activeTab} />
        ) : (
          <SessionDetails tab={activeTab} />
        )}
      </div>
    </>
  );
}

function SessionDetails({ tab }: { tab: SessionTab }) {
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listOpenSessions });

  const device: DeviceMeta | undefined = devicesQuery.data?.find((d) => d.id === tab.deviceId);
  const session: SessionMetaWire | undefined = sessionsQuery.data?.find(
    (s) => s.session_id === tab.sessionId,
  );

  return (
    <div className="space-y-5">
      <StateHeader tab={tab} device={device} />

      <Section title="Device">
        <Row label="Host">
          <code className="font-mono text-xs">
            {device ? `${device.host}:${device.port}` : "—"}
          </code>
        </Row>
        {device?.jump_via && (
          <Row label="Via">
            <code className="font-mono text-xs" title="Tunneled through this jump host (v6.5.0)">
              {device.jump_via}
            </code>
          </Row>
        )}
        <Row label="Vendor">
          <span className="text-xs">{device?.vendor ?? "—"}</span>
        </Row>
        <Row label="Group">
          <span className="text-xs">{device?.group ?? <Muted>(no group)</Muted>}</span>
        </Row>
        <Row label="Auth">
          <span className="text-xs">{device?.auth ?? "—"}</span>
        </Row>
      </Section>

      <Section title="Session">
        <Row label="ID">
          <code
            className="font-mono text-xs"
            title={tab.sessionId}
          >{`${tab.sessionId.slice(0, 8)}…`}</code>
        </Row>
        <Row label="Opened">
          <span className="text-xs" data-testid="session-info-opened-at">
            {session ? (
              relativeTime(session.opened_at)
            ) : tab.ended ? (
              "—"
            ) : (
              <Muted>(loading…)</Muted>
            )}
          </span>
        </Row>
        <Row label="Username">
          <span className="text-xs">{session?.username ?? "—"}</span>
        </Row>
      </Section>

      <Actions tab={tab} device={device} />
    </div>
  );
}

/**
 * v5.0.0 — the card for a Files (SFTP) tab. Deliberately minimal and
 * deliberately NOT wired to `listOpenSessions` / `useConnectDevice` /
 * `useDisconnectSession`: those are the SSH transport's, and a Files
 * session is torn down only through `files_disconnect`.
 */
function FilesSessionDetails({ tab }: { tab: SessionTab }) {
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const device: DeviceMeta | undefined = devicesQuery.data?.find((d) => d.id === tab.deviceId);
  const disconnect = useFilesDisconnectSession();

  return (
    <div className="space-y-5" data-testid="session-info-files">
      <div>
        <div className="font-mono text-sm font-semibold">{tab.deviceId}</div>
        <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
          <span
            aria-hidden
            className={
              tab.ended
                ? "h-1.5 w-1.5 rounded-full bg-muted-foreground/40"
                : "h-1.5 w-1.5 rounded-full bg-emerald-500"
            }
          />
          <span data-testid="session-info-state">{tab.ended ? "Ended" : "Connected"}</span>
          <span>·</span>
          <span>SFTP file transfer</span>
        </div>
      </div>

      <Section title="Device">
        <Row label="Host">
          <code className="font-mono text-xs">
            {device ? `${device.host}:${device.port}` : "—"}
          </code>
        </Row>
        <Row label="Group">
          <span className="text-xs">{device?.group ?? <Muted>(no group)</Muted>}</span>
        </Row>
        <Row label="Auth">
          <span className="text-xs">{device?.auth ?? "—"}</span>
        </Row>
      </Section>

      <Section title="Session">
        <Row label="ID">
          <code
            className="font-mono text-xs"
            title={tab.sessionId}
          >{`${tab.sessionId.slice(0, 8)}…`}</code>
        </Row>
      </Section>

      <div className="space-y-2 border-t border-border pt-4">
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="w-full justify-start gap-2"
          disabled={tab.ended || disconnect.isPending}
          onClick={() => disconnect.mutate(tab.sessionId)}
          data-testid="session-info-files-disconnect"
        >
          <Unplug className="h-3.5 w-3.5" />
          {tab.ended ? "Already disconnected" : "Disconnect session"}
        </Button>
      </div>
    </div>
  );
}

function StateHeader({ tab, device }: { tab: SessionTab; device: DeviceMeta | undefined }) {
  const connected = !tab.ended;
  return (
    <div>
      <div className="font-mono text-sm font-semibold">{tab.deviceId}</div>
      <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
        <span
          aria-hidden
          className={
            connected
              ? "h-1.5 w-1.5 rounded-full bg-emerald-500"
              : "h-1.5 w-1.5 rounded-full bg-muted-foreground/40"
          }
        />
        <span data-testid="session-info-state">{connected ? "Connected" : "Ended"}</span>
        {device && (
          <>
            <span>·</span>
            <span>SSH</span>
          </>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
        {title}
      </div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="min-w-0 truncate text-right">{children}</div>
    </div>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <span className="text-muted-foreground/60">{children}</span>;
}

function Actions({ tab, device }: { tab: SessionTab; device: DeviceMeta | undefined }) {
  const disconnect = useDisconnectSession();
  const connect = useConnectDevice();
  const setActiveDeviceId = useUiStore((s) => s.setActiveDeviceId);

  const canDisconnect = !tab.ended && !disconnect.isPending;

  return (
    <div className="space-y-2 border-t border-border pt-4">
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-full justify-start gap-2"
        disabled={!canDisconnect}
        onClick={() => disconnect.mutate(tab.sessionId)}
        data-testid="session-info-disconnect"
      >
        <Unplug className="h-3.5 w-3.5" />
        {tab.ended ? "Already disconnected" : "Disconnect session"}
      </Button>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-full justify-start gap-2"
        disabled={!device || connect.isPending}
        onClick={() => device && connect.mutate(device.id)}
      >
        <Plus className="h-3.5 w-3.5" />
        Open another session
      </Button>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="w-full justify-start gap-2"
        disabled={!device}
        onClick={() => device && setActiveDeviceId(device.id)}
      >
        <SettingsIcon className="h-3.5 w-3.5" />
        Select in sidebar
      </Button>
    </div>
  );
}

function EmptyState() {
  return (
    <div
      className="flex h-full items-center justify-center px-4 text-center text-xs text-muted-foreground"
      data-testid="session-info-empty"
    >
      Open a session to see its details here.
    </div>
  );
}

/**
 * Render an ISO timestamp as a coarse relative string (e.g. "3m ago"
 * / "2h ago" / "Jan 12"). Pure — no timezone-dependent branches that
 * would make snapshot tests flaky.
 */
export function relativeTime(iso: string, nowMs: number = Date.now()): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const diffSec = Math.max(0, Math.floor((nowMs - t) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const min = Math.floor(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  return new Date(t).toISOString().slice(0, 10);
}
