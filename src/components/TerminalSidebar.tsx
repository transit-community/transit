import { PanelLeft, PanelLeftClose, Plus, RefreshCw, TerminalSquare } from "lucide-react";

import { EditionChip, SettingsButton } from "@/components/SettingsButton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SidebarResizeHandle, useSidebarWidth } from "@/components/SidebarResizeHandle";
import { useQueryClient } from "@tanstack/react-query";

import { type ShellInfo } from "@/lib/api";
import { useAvailableShells, useOpenLocalShell } from "@/lib/localShell";
import { useUiStore } from "@/stores/uiStore";

/**
 * v4.4.0 — the launcher for the local Terminal surface (3rd rail tab).
 *
 * Lists the shells/REPLs discovered on this machine (with versions — the
 * "look under the hood" ask) and launches one in a local PTY tab. A
 * HUMAN-only surface: the AI agent is structurally blind to local shells
 * (they're never wired into the agent's session sources), so nothing
 * here touches chat/scope. Mirrors `ApiSidebar`'s chrome.
 */
const KIND_GROUPS: { kind: ShellInfo["kind"]; label: string }[] = [
  { kind: "shell", label: "Shells" },
  { kind: "repl", label: "REPLs" },
  { kind: "wsl", label: "WSL" },
];

export function TerminalSidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const queryClient = useQueryClient();

  const { data: shells = [], isLoading, isRefetching } = useAvailableShells();
  const open = useOpenLocalShell();

  const launch = (shell: ShellInfo) => {
    open.mutate({ program: shell.program, label: shell.label, args: shell.args });
  };

  const newDefaultShell = () => {
    const def = shells.find((s) => s.is_default) ?? shells[0];
    if (def) launch(def);
  };

  // v6.5.2 — shared, user-draggable rail width.
  const sidebarWidth = useSidebarWidth();

  if (collapsed) {
    return (
      <aside
        data-testid="terminal-sidebar-collapsed"
        className="flex h-full w-10 flex-col items-center border-r border-border bg-background py-2"
        aria-label="Local terminal (collapsed)"
      >
        <button
          type="button"
          onClick={toggleSidebar}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Expand sidebar"
          title="Expand sidebar (⌘/Ctrl+B)"
        >
          <PanelLeft className="h-4 w-4" />
        </button>
      </aside>
    );
  }

  return (
    <aside
      data-testid="terminal-sidebar"
      style={{ width: `${sidebarWidth}px` }}
      className="relative flex h-full shrink-0 flex-col border-r border-border bg-background"
    >
      <SidebarResizeHandle />
      <header className="flex h-12 items-center gap-1 border-b border-border px-3">
        <h1 className="flex-1 text-sm font-semibold tracking-wide">Terminal</h1>
        <button
          type="button"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["availableShells"] })}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Rescan shells"
          title="Rescan installed shells"
        >
          <RefreshCw className={isRefetching ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
        </button>
        <button
          type="button"
          onClick={newDefaultShell}
          disabled={shells.length === 0}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent disabled:opacity-40"
          aria-label="New local shell"
          title="New local shell (default)"
        >
          <Plus className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={toggleSidebar}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Collapse sidebar"
          title="Collapse sidebar (⌘/Ctrl+B)"
        >
          <PanelLeftClose className="h-4 w-4" />
        </button>
      </header>

      <ScrollArea className="flex-1">
        <div className="min-h-full py-1">
          {isLoading ? (
            <div className="px-4 py-8 text-center text-xs text-muted-foreground">Scanning…</div>
          ) : shells.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-muted-foreground">
              No shells found on this machine.
            </div>
          ) : (
            KIND_GROUPS.map(({ kind, label }) => {
              const rows = shells.filter((s) => s.kind === kind);
              if (rows.length === 0) return null;
              return (
                <div key={kind} className="mb-1">
                  <div className="px-3 pb-0.5 pt-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                    {label}
                  </div>
                  {rows.map((shell) => (
                    <ShellRow key={shell.id} shell={shell} onLaunch={() => launch(shell)} />
                  ))}
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>

      <footer className="border-t border-border p-2">
        <div className="flex items-center gap-1.5">
          <div className="min-w-0 flex-1">
            <EditionChip />
          </div>
          <SettingsButton />
        </div>
      </footer>
    </aside>
  );
}

/** One launchable shell. Clicking opens it in a new local PTY tab. The
 *  hover title exposes the resolved path + argv — the transparency the
 *  "look under the hood" ask wants before you launch. */
function ShellRow({ shell, onLaunch }: { shell: ShellInfo; onLaunch: () => void }) {
  const argv = shell.args.length > 0 ? ` ${shell.args.join(" ")}` : "";
  return (
    <div className="group flex items-center hover:bg-accent">
      <button
        type="button"
        onClick={onLaunch}
        title={`${shell.path}${argv}${shell.version ? `\n${shell.version}` : ""}`}
        className="flex min-w-0 flex-1 items-center gap-2 px-3 py-1.5 text-left text-sm"
      >
        <TerminalSquare className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        <span className="min-w-0 flex-1 truncate">{shell.label}</span>
        {shell.is_default && (
          <span className="shrink-0 rounded bg-muted px-1 text-[10px] text-muted-foreground">
            default
          </span>
        )}
        {shell.version && (
          <span className="shrink-0 truncate text-[10px] text-muted-foreground opacity-70 group-hover:opacity-100">
            {firstToken(shell.version)}
          </span>
        )}
      </button>
    </div>
  );
}

/** A shell's `--version` line can be verbose ("zsh 5.9 (x86_64-apple…)").
 *  Show a compact token in the row; the full string is in the title. */
function firstToken(version: string): string {
  const m = version.match(/\d+[\w.]*/);
  return m ? m[0] : version.split(/\s+/).slice(0, 2).join(" ");
}
