import { useQueryClient } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import { EditionChip, SettingsButton } from "@/components/SettingsButton";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { FolderOpen, PanelLeft, X } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SidebarResizeHandle, useSidebarWidth } from "@/components/SidebarResizeHandle";
import {
  bytesHuman,
  CAPTURE_UPDATE_EVENT,
  OPEN_CAPTURES_KEY,
  pcapCaptureStart,
  pcapCaptureStop,
  pcapClose,
  pcapOpenFile,
  SNAPLEN_FULL,
  SNAPLEN_HEADERS_ONLY,
  pcapOpenCapturesDir,
  useCaptureInterfaces,
  useCapturesDir,
  usePcapOpenCaptures,
  type CaptureStats,
  type CaptureSummary,
} from "@/lib/pcap";
import { useUiStore } from "@/stores/uiStore";

/**
 * The PCaps sidebar: start a capture, or open one.
 *
 * Two sections because there are two ways in, and they have different
 * risk profiles. Opening a file touches nothing. Starting a capture
 * records a network — so the controls that bound it (snaplen, rotation)
 * are visible rather than buried in a settings page, and "headers only"
 * is one click.
 */
export function PcapSidebar() {
  const openPcapTab = useUiStore((s) => s.openPcapTab);
  const removeSession = useUiStore((s) => s.removeSession);
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const [iface, setIface] = useState("");
  const [bpf, setBpf] = useState("");
  const [headersOnly, setHeadersOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  /** Capture id while one is recording. Non-null means Stop is armed —
   *  and a running capture must always have a way to stop it, or the
   *  only remaining route is quitting the app. */
  const [recording, setRecording] = useState<string | null>(null);
  const { data: nics = [], isLoading, error: nicError } = useCaptureInterfaces(true);
  const queryClient = useQueryClient();
  const { data: openCaptures = [] } = usePcapOpenCaptures(true);
  const { data: capturesDir } = useCapturesDir();
  /** Live progress for the recording capture, from `pcap:capture:update`. */
  const [progress, setProgress] = useState<CaptureStats | null>(null);

  // Without this the Start button is the last thing that happens until the
  // user gives up and hits Stop — which is how a capture that never had
  // permission to record looked identical to one that was working. A byte
  // counter that stays at zero says which one you have.
  useEffect(() => {
    if (!recording) {
      setProgress(null);
      return;
    }
    let cancelled = false;
    const un = listen<CaptureStats>(CAPTURE_UPDATE_EVENT, (e) => {
      if (cancelled || e.payload.capture_id !== recording) return;
      setProgress(e.payload);
    });
    return () => {
      cancelled = true;
      // Both halves matter. `.catch` covers the listen() that never
      // resolved; the inner try covers unlistening one that HMR already
      // tore down — which throws INSIDE a .then, so it surfaces as an
      // unhandled rejection rather than something the caller can catch.
      // `network.ts` learned this first and wrote `safeUnlisten` for it.
      void un
        .then((f) => {
          try {
            f();
          } catch {
            // already gone; nothing to do.
          }
        })
        .catch(() => {});
    };
  }, [recording]);

  const landCapture = (summary: CaptureSummary) => {
    void queryClient.invalidateQueries({ queryKey: OPEN_CAPTURES_KEY });
    openPcapTab(summary.capture_id, summary.name);
  };

  /** Close a capture: free its index in the backend, drop its tab, and let
   *  the list re-fetch. The list IS the set of open captures, so removing a
   *  row and closing the capture are the same action rather than two that
   *  can disagree. */
  const closeCapture = async (captureId: string) => {
    await pcapClose(captureId).catch(() => {});
    removeSession(captureId);
    void queryClient.invalidateQueries({ queryKey: OPEN_CAPTURES_KEY });
  };

  const onOpenFile = async () => {
    const picked = await openFileDialog({
      multiple: false,
      filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap", "gz"] }],
    });
    if (typeof picked !== "string") return;
    setBusy(true);
    try {
      const summary = await pcapOpenFile(picked);
      landCapture(summary);
      if (summary.index_truncated) {
        // Never silent: a partially-indexed capture reads as a complete
        // one, and every number below it would be quietly wrong.
        toast.warning("Capture partially indexed", {
          description:
            "This capture is larger than the indexing ceiling. Counts and analysis cover the indexed portion only.",
        });
      }
    } catch (e) {
      toast.error("Could not open capture", { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const onStart = async () => {
    if (!iface) return;
    setBusy(true);
    try {
      const id = await pcapCaptureStart({
        interface: iface,
        bpf: bpf.trim() || null,
        snaplen: headersOnly ? SNAPLEN_HEADERS_ONLY : SNAPLEN_FULL,
        max_file_mb: 256,
        max_files: 8,
        max_duration_secs: 3600,
      });
      setRecording(id);
      toast.success("Capture started", {
        description: `Recording on ${iface}.`,
      });
    } catch (e) {
      toast.error("Could not start capture", { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const onStop = async () => {
    if (!recording) return;
    setBusy(true);
    try {
      const summary = await pcapCaptureStop(recording);
      setRecording(null);
      // Land the user in the explorer looking at what they just
      // captured, rather than at an empty pane and a file path.
      landCapture(summary);
    } catch (e) {
      // The backend stops the capture BEFORE it tries to open the file,
      // so by the time an error reaches here the capture really has
      // stopped. Leaving the button on "Stop" would strand the UI
      // offering an action with nothing behind it.
      setRecording(null);
      toast.error("Capture stopped, but could not be opened", {
        description: String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  // v6.5.2 — shared, user-draggable rail width.
  const sidebarWidth = useSidebarWidth();

  // Collapsed render (⌘/Ctrl+B). After all hooks, per rules-of-hooks.
  if (collapsed) {
    return (
      <aside
        data-testid="pcap-sidebar-collapsed"
        className="flex h-full w-10 flex-col items-center gap-2 border-r border-border bg-background py-2"
        aria-label="Packet captures (collapsed)"
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

        {/* Collapsing must not strand a running capture. Stop stays
            reachable here, because the alternative to a visible Stop is
            quitting the app — and this surface records a network. */}
        {recording && (
          <button
            type="button"
            onClick={onStop}
            disabled={busy}
            className="rounded-md p-1.5 text-destructive hover:bg-accent disabled:opacity-50"
            aria-label={busy ? "Stopping capture" : "Stop capture"}
            title={busy ? "Stopping…" : "Recording — click to stop"}
            data-testid="pcap-collapsed-stop"
          >
            <span
              className={
                "block h-2.5 w-2.5 rounded-full " +
                (busy ? "bg-muted-foreground" : "animate-pulse bg-destructive")
              }
            />
          </button>
        )}
      </aside>
    );
  }

  return (
    <aside
      style={{ width: `${sidebarWidth}px` }}
      className="relative flex h-full shrink-0 flex-col border-r border-border bg-muted/20"
      aria-label="Packet captures"
      data-testid="pcap-sidebar"
    >
      <SidebarResizeHandle />
      {/* Content scrolls; the footer does not. Scrolling the whole aside
          (as this did) pushed the footer off the bottom — which is how the
          Settings button went missing from this view and only this view. */}
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-3">
        <section className="flex flex-col gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Capture
          </h2>

          <Label htmlFor="pcap-iface" className="text-xs">
            Interface
          </Label>
          <select
            id="pcap-iface"
            className="h-8 rounded border border-input bg-background px-2 text-sm text-foreground"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            disabled={isLoading || busy}
          >
            <option value="">
              {isLoading
                ? "Looking for interfaces…"
                : nicError
                  ? "Interfaces unavailable"
                  : nics.length === 0
                    ? "No interfaces found"
                    : "Choose an interface"}
            </option>
            {nics.map((n) => (
              <option key={n.name} value={n.name}>
                {n.name}
                {n.loopback ? " (loopback)" : ""}
                {n.description ? ` — ${n.description}` : ""}
              </option>
            ))}
          </select>

          {/* The reason, not just the absence. An empty dropdown says "this
              machine has no network adapters", which is almost never what
              actually happened — the enumeration command failed and its
              explanation was being discarded. */}
          {nicError && (
            <p
              className="rounded border border-destructive/40 bg-destructive/10 px-2 py-1 text-[11px] leading-snug text-destructive"
              data-testid="pcap-interface-error"
            >
              {String(nicError instanceof Error ? nicError.message : nicError)}
            </p>
          )}

          <Label htmlFor="pcap-bpf" className="text-xs">
            Capture filter (BPF, optional)
          </Label>
          <Input
            id="pcap-bpf"
            value={bpf}
            onChange={(e) => setBpf(e.target.value)}
            placeholder="tcp port 443 and host 10.0.0.1"
            className="h-8 font-mono text-xs"
            disabled={busy}
          />

          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={headersOnly}
              onChange={(e) => setHeadersOnly(e.target.checked)}
              disabled={busy}
            />
            Headers only (128 bytes per packet)
          </label>
          <p className="text-[11px] leading-snug text-muted-foreground">
            Headers-only records enough for flow and protocol analysis while capturing no payload at
            all.
          </p>

          {recording ? (
            <>
              <div
                className="flex items-center gap-2 rounded border border-border px-2 py-1.5 text-xs"
                data-testid="pcap-recording-status"
                role="status"
              >
                <span
                  className={
                    "h-2 w-2 shrink-0 animate-pulse rounded-full " +
                    (busy ? "bg-muted-foreground" : "bg-destructive")
                  }
                />
                <span className="font-medium">{busy ? "Stopping…" : "Recording"}</span>
                <span className="ml-auto tabular-nums text-muted-foreground">
                  {busy
                    ? "flushing"
                    : progress
                      ? `${bytesHuman(progress.file_bytes)} · ${progress.elapsed_secs}s`
                      : "…"}
                </span>
              </div>
              {/* A capture that has run for a while with nothing on disk is
                either filtered to nothing or not really capturing. Say so
                rather than letting a zero sit there looking healthy. */}
              {progress && progress.elapsed_secs >= 10 && progress.file_bytes === 0 && (
                <p className="text-[11px] leading-snug text-amber-600 dark:text-amber-400">
                  Nothing written yet. The capture filter may match no traffic, or the interface may
                  be seeing none.
                </p>
              )}
              {/* Stop is not instant: the supervisor has to notice, signal
                the capture, wait for it to flush, and then the file gets
                indexed. Several seconds of an unchanged button reads as a
                click that didn't land, and the natural response is to
                click it again. */}
              <Button size="sm" variant="destructive" onClick={onStop} disabled={busy}>
                {busy ? "Stopping…" : "Stop capture"}
              </Button>
            </>
          ) : (
            <Button size="sm" onClick={onStart} disabled={!iface || busy}>
              Start capture
            </Button>
          )}
          <p className="text-[11px] leading-snug text-muted-foreground">
            Transit drives your system&rsquo;s own capture tool. You may be asked for an
            administrator password if the OS requires it.
          </p>
        </section>

        <section className="flex flex-col gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Captures
          </h2>
          <Button size="sm" variant="secondary" onClick={onOpenFile} disabled={busy}>
            Open capture file…
          </Button>

          {/* Where the files actually are. A capture is a file on disk that
              can get large, and until now nothing in the app said where —
              which made "delete the big ones" a hunt through Application
              Support. The path is shown as well as opened, because a
              file manager that will not launch leaves the link useless. */}
          <button
            type="button"
            onClick={() =>
              void pcapOpenCapturesDir().catch((e) =>
                toast.error("Could not open the capture folder", { description: String(e) }),
              )
            }
            className="flex items-start gap-1.5 rounded px-1 py-1 text-left text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
            title={capturesDir ?? undefined}
            data-testid="pcap-open-folder"
          >
            <FolderOpen className="mt-px h-3 w-3 shrink-0" aria-hidden />
            <span className="min-w-0">
              <span className="block">Capture folder</span>
              {capturesDir && (
                <span className="block break-all font-mono text-[10px] opacity-70">
                  {capturesDir}
                </span>
              )}
            </span>
          </button>
          {openCaptures.length === 0 ? (
            <p className="text-[11px] text-muted-foreground">No captures open yet.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {openCaptures.map((c) => (
                <li
                  key={c.capture_id}
                  className="group flex items-center gap-1 rounded hover:bg-accent"
                >
                  <button
                    type="button"
                    className="min-w-0 flex-1 px-2 py-1 text-left text-xs"
                    onClick={() => openPcapTab(c.capture_id, c.name)}
                  >
                    <span className="block truncate font-medium">{c.name}</span>
                    <span className="block text-[11px] text-muted-foreground">
                      {c.packets.toLocaleString()} packets · {bytesHuman(c.bytes)}
                      {c.findings > 0 ? ` · ${c.findings} findings` : ""}
                    </span>
                  </button>
                  <button
                    type="button"
                    className="mr-1 shrink-0 rounded p-1 text-muted-foreground opacity-0 hover:bg-background hover:text-foreground focus-visible:opacity-100 group-hover:opacity-100"
                    onClick={() => void closeCapture(c.capture_id)}
                    aria-label={`Close ${c.name}`}
                    title="Close this capture"
                  >
                    <X className="h-3 w-3" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* The same footer every other rail view carries. Its absence here
          was the one difference between this sidebar and the other four. */}
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
