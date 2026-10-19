import { useQuery } from "@tanstack/react-query";

import { terminalEnabled } from "@/lib/api";
import { useFilesEnabled } from "@/lib/files";
import { usePcapEnabled } from "@/lib/pcap";
import { useUiStore } from "@/stores/uiStore";

/**
 * v4.0.0 — the far-left vertical rail that switches the sidebar between
 * SSH devices and API controllers, as rotated tabs. UI-only state
 * (`uiStore.sidebarView`); the active view decides which sidebar App
 * renders.
 *
 * v5.0.0 adds the fourth entry, Files (SFTP); v6.0.0 the fifth, PCaps.
 * Five rotated labels are ~290px of the column at `py-3` — still well
 * inside any usable window height, but this is the entry that makes a
 * sixth worth turning the rail into a scrollable strip rather than
 * assuming it fits.
 */
const VIEWS = [
  { id: "ssh", label: "SSH", title: "SSH sessions" },
  { id: "apis", label: "APIs", title: "API sessions" },
  { id: "terminal", label: "Terminal", title: "Local terminal" },
  { id: "files", label: "Files", title: "File transfer" },
  { id: "pcaps", label: "pcaps", title: "Packet captures" },
] as const;

export function PanelSwitcher() {
  const view = useUiStore((s) => s.sidebarView);
  const setView = useUiStore((s) => s.setSidebarView);
  // The local Terminal surface is on by default; a locked-down deployment can
  // disable it (`[terminal] enabled = false`), and then the rail entry hides.
  const { data: terminalOn = true } = useQuery({
    queryKey: ["terminalEnabled"],
    queryFn: terminalEnabled,
    staleTime: Infinity,
    placeholderData: true,
  });
  // Same shape for Files (`[files] enabled = false` — the MDM / DLP
  // off-switch). Hiding the rail entry is convenience only; the backend
  // refuses `files_connect` independently (defense in depth).
  const { data: filesOn = true } = useFilesEnabled();
  // Same shape again for PCaps (`[pcap] enabled = false`). Packet capture
  // is the most sensitive thing Transit can do on a machine, so a
  // locked-down deployment needs to be able to remove it — and, as with
  // the others, hiding the rail entry is convenience only: every `pcap_*`
  // command refuses independently and re-reads the flag per call.
  const { data: pcapOn = true } = usePcapEnabled();
  const views = VIEWS.filter(
    (v) =>
      (v.id !== "terminal" || terminalOn) &&
      (v.id !== "files" || filesOn) &&
      (v.id !== "pcaps" || pcapOn),
  );

  return (
    <div
      className="flex h-full w-8 shrink-0 flex-col border-r border-border bg-muted/30"
      role="tablist"
      aria-label="Sidebar view"
      data-testid="panel-switcher"
    >
      {views.map((v) => {
        const active = view === v.id;
        return (
          <button
            key={v.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => setView(v.id)}
            title={v.title}
            className={
              "flex items-center justify-center border-b border-border py-3 text-xs font-medium tracking-wide transition-colors " +
              (active
                ? "bg-background text-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground")
            }
          >
            <span className="[writing-mode:vertical-rl] rotate-180">{v.label}</span>
          </button>
        );
      })}
    </div>
  );
}
