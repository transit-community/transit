import {
  ArrowDownToLine,
  ArrowUpFromLine,
  ChevronDown,
  ChevronUp,
  TriangleAlert,
  X,
} from "lucide-react";
import { memo, useMemo } from "react";

import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { filesCancel, type TransferUpdate } from "@/lib/api";
import {
  formatBytes,
  formatEta,
  formatRate,
  transferPercent,
  truncateMiddle,
} from "@/lib/fileBrowser";
import { computeLabels } from "@/lib/sessionLabels";
import { cn } from "@/lib/utils";
import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

/**
 * v5.0.0 — the transfer queue.
 *
 * **Global across Files sessions** and rendered at the bottom of every Files
 * tab: transfers survive tab switches (the engine runs per session,
 * independent of what is on screen), so a strip scoped to one session would
 * hide work in progress. Rows come exclusively from the
 * `files:transfer:update` event mirror in `filesStore` — subscribed once at
 * the app level (`lib/filesTransfers.ts`), never polled.
 *
 * Hidden entirely when there is nothing to show, so a browse-only session
 * gives its full height to the panes.
 *
 * Reading the numbers (the engine's contract, not a UI choice):
 * `bytes_done`/`bytes_total` describe the **current file** — a recursive
 * directory transfer has no pre-scan in v1, so there is no job-wide byte
 * total — `files_done` counts finished files, and `rate_bps` is job-wide. So
 * the bar is per-file, the ETA is per-file, and a recursive job additionally
 * says which file it is on (keyed off `files_total`, never `files_done`; see
 * `TransferRow`).
 */
export function TransferQueueStrip() {
  const transfers = useFilesStore((s) => s.transfers);
  const collapsed = useFilesStore((s) => s.queueCollapsed);
  const setQueueCollapsed = useFilesStore((s) => s.setQueueCollapsed);
  const clearFinished = useFilesStore((s) => s.clearFinishedTransfers);
  const transferTargets = useFilesStore((s) => s.transferTargets);
  const sessions = useUiStore((s) => s.sessions);

  // Labels exactly as the tab strip computes them, so a queue row names a
  // device the way the tab above it does ("vEX1 (2)").
  const labelBySession = useMemo(() => {
    const topLevel = sessions.filter((t) => !t.splitWith);
    const labels = computeLabels(topLevel);
    return new Map(topLevel.map((t, i) => [t.sessionId, labels[i]]));
  }, [sessions]);

  const rows = useMemo(() => Array.from(transfers.values()), [transfers]);
  if (rows.length === 0) return null;

  const running = rows.filter((t) => t.state === "running").length;
  const queued = rows.filter((t) => t.state === "queued").length;
  const finished = rows.length - running - queued;

  return (
    <div
      className="flex shrink-0 flex-col border-t border-border bg-muted/20"
      data-testid="transfer-queue"
    >
      <div className="flex items-center gap-2 px-2 py-1">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Transfers
        </span>
        <span className="text-xs text-muted-foreground" data-testid="transfer-queue-counts">
          ({running} running · {queued} queued)
        </span>
        <div className="flex-1" />
        {finished > 0 && (
          <button
            type="button"
            onClick={clearFinished}
            className="rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
            data-testid="transfer-queue-clear"
          >
            Clear finished
          </button>
        )}
        <button
          type="button"
          onClick={() => setQueueCollapsed(!collapsed)}
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expand transfers" : "Collapse transfers"}
          title={collapsed ? "Expand transfers" : "Collapse transfers"}
          className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
          data-testid="transfer-queue-collapse"
        >
          {collapsed ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
        </button>
      </div>

      {!collapsed && (
        // Own scroller with a modest cap: a hundred queued files must never
        // push the panes off screen.
        <div className="max-h-40 overflow-y-auto px-2 pb-1" data-testid="transfer-queue-rows">
          {rows.map((t) => (
            <TransferRow
              key={t.id}
              transfer={t}
              device={
                labelBySession.get(t.session_id) ?? transferTargets.get(t.id)?.deviceLabel ?? "—"
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Memoized so a progress event for ONE transfer doesn't re-render the other
// N rows: `applyTransferUpdate` replaces only the changed id's value (unchanged
// rows keep their object identity) and the `device` label is stable per row, so
// the default shallow prop compare skips every row but the one that moved.
// Without this, at 1000 rows × N mounted Files tabs every ~10 Hz event repainted
// every row (F3).
const TransferRow = memo(function TransferRow({
  transfer,
  device,
}: {
  transfer: TransferUpdate;
  device: string;
}) {
  const t = transfer;
  const active = t.state === "queued" || t.state === "running";
  const percent = transferPercent(t.bytes_done, t.bytes_total);
  const rate = t.state === "running" ? formatRate(t.rate_bps) : null;
  const eta = t.state === "running" ? formatEta(t.bytes_done, t.bytes_total, t.rate_bps) : null;
  const Arrow = t.direction === "upload" ? ArrowUpFromLine : ArrowDownToLine;
  // A recursive directory job is the ONLY one without a known single-file
  // count: the backend sends `files_total === 1` for a single-file /
  // non-directory transfer and `null` for a recursive directory walk (and
  // `> 1` is honored defensively should a future job carry a real count). A
  // one-file transfer therefore never claims a file number. NOT the old
  // `files_done >= 1` heuristic — that lit "file 2" the instant the second
  // file of any multi-file job started.
  const recursive = t.files_total === null || t.files_total > 1;

  return (
    <div
      className="flex items-center gap-2 py-0.5 text-xs"
      data-testid={`transfer-row-${t.id}`}
      data-state={t.state}
    >
      <Arrow
        className={cn(
          "h-3.5 w-3.5 shrink-0",
          // Transit blue for uploads (house tokens; the amber/emerald status
          // colors elsewhere are intentional, this was the odd raw blue-*).
          t.direction === "upload" ? "text-primary" : "text-muted-foreground",
        )}
        aria-label={t.direction === "upload" ? "Upload" : "Download"}
      />
      {/* Truncated in the MIDDLE: the tail of a filename (extension, index)
          is what tells two rows apart. */}
      <span className="min-w-0 flex-1 truncate font-mono" title={t.name}>
        {truncateMiddle(t.name)}
      </span>
      <span className="w-24 shrink-0 truncate font-mono text-muted-foreground" title={device}>
        {device}
      </span>

      {percent === null ? (
        // No total for this file yet: an indeterminate bar plus the byte
        // counter, rather than a percentage we'd be inventing.
        <div className="h-1.5 w-24 shrink-0 overflow-hidden rounded bg-border">
          {t.state === "running" && <div className="h-full w-1/3 animate-pulse bg-primary" />}
        </div>
      ) : (
        <div
          className="h-1.5 w-24 shrink-0 overflow-hidden rounded bg-border"
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          data-testid={`transfer-progress-${t.id}`}
        >
          <div
            className={cn("h-full", t.state === "error" ? "bg-destructive" : "bg-primary")}
            style={{ width: `${percent}%` }}
          />
        </div>
      )}

      <span className="w-10 shrink-0 text-right tabular-nums text-muted-foreground">
        {percent === null ? "" : `${percent}%`}
      </span>
      <span className="w-16 shrink-0 truncate text-right tabular-nums text-muted-foreground">
        {formatBytes(t.bytes_done)}
      </span>
      <span className="w-20 shrink-0 truncate text-right tabular-nums text-muted-foreground">
        {rate ?? ""}
      </span>
      <span className="w-12 shrink-0 text-right tabular-nums text-muted-foreground">
        {eta ?? ""}
      </span>

      {recursive && t.state === "running" && (
        <span className="shrink-0 text-muted-foreground" data-testid={`transfer-file-n-${t.id}`}>
          file {t.files_done + 1}
        </span>
      )}

      {t.state === "queued" && <span className="shrink-0 text-muted-foreground">Queued</span>}
      {t.state === "done" && (
        <span className="shrink-0 text-emerald-600 dark:text-emerald-400">Done</span>
      )}
      {t.state === "cancelled" && <span className="shrink-0 text-muted-foreground">Cancelled</span>}
      {t.state === "error" && (
        <span
          className="min-w-0 shrink truncate text-destructive"
          title={t.error ?? "Transfer failed"}
          data-testid={`transfer-error-${t.id}`}
        >
          {t.error ?? "Transfer failed"}
        </span>
      )}

      {t.skipped > 0 && (
        <Popover>
          <PopoverTrigger asChild>
            <button
              type="button"
              className="flex shrink-0 items-center gap-1 rounded px-1 text-amber-700 hover:bg-amber-500/15 dark:text-amber-400"
              data-testid={`transfer-skipped-${t.id}`}
              title={`${t.skipped} skipped`}
            >
              <TriangleAlert className="h-3 w-3" />
              {t.skipped}
            </button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-72 p-2 text-xs">
            <div className="pb-1 font-medium">
              {t.skipped} skipped
              {t.warnings.length < t.skipped && " (first 20 shown)"}
            </div>
            <ul className="max-h-40 space-y-0.5 overflow-y-auto font-mono text-muted-foreground">
              {t.warnings.map((w, i) => (
                // Warning text embeds remote-supplied names; a React text
                // node is the whole defense needed (T43). The index is part
                // of the key on purpose: the engine can emit the same warning
                // twice and this list is append-only, never reordered.
                <li key={`${i}-${w}`} className="break-all">
                  {w}
                </li>
              ))}
            </ul>
          </PopoverContent>
        </Popover>
      )}

      {active && (
        <button
          type="button"
          onClick={() => void filesCancel(t.id).catch(() => {})}
          aria-label={`Cancel transfer of ${t.name}`}
          title="Cancel this transfer"
          className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
          data-testid={`transfer-cancel-${t.id}`}
        >
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
});
