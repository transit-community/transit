import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  captureCommand,
  capturesDirPath,
  deleteCapture,
  diffCaptures,
  listCaptures,
  runCollection,
  type CaptureMeta,
  type DiffResult,
} from "@/lib/api";
import { loadCollections, saveCollections, type Collection } from "@/lib/collections";
import { computeLabels } from "@/lib/sessionLabels";
import { toastError, toastSuccess } from "@/lib/toast";
import { cn } from "@/lib/utils";
import { hasPty, useUiStore } from "@/stores/uiStore";

/** A saved capture's one-line summary. */
function fmtCapture(c: CaptureMeta): string {
  return `${c.device_id} · ${c.command} · ${c.captured_at}`;
}

/**
 * Phase 3 — capture command output and diff two captures (config drift over
 * time or between devices). Capturing runs the command in the chosen session
 * (human-initiated, not policy-gated) and saves the redacted output.
 */
export function CapturesDialog() {
  const open = useUiStore((s) => s.capturesDialogOpen);
  const close = useUiStore((s) => s.closeCaptures);
  const sessions = useUiStore((s) => s.sessions);
  const preselect = useUiStore((s) => s.capturesPreselectSessionId);
  const consumePreselect = useUiStore((s) => s.consumeCapturesPreselect);
  const queryClient = useQueryClient();

  // Capture runs a command and reads its output, so only PTY tabs can be
  // targets — an API tab has no scrollback ring and a Files tab is SFTP.
  const labels = useMemo(() => computeLabels(sessions), [sessions]);
  const liveSessions = sessions
    .map((tab, i) => ({ tab, label: labels[i] }))
    .filter(({ tab }) => !tab.ended && hasPty(tab));

  const capturesQuery = useQuery({
    queryKey: ["captures"],
    queryFn: listCaptures,
    enabled: open,
  });
  const captures = capturesQuery.data ?? [];
  const capturesDir = useQuery({
    queryKey: ["capturesDir"],
    queryFn: capturesDirPath,
    enabled: open,
  });

  const [sessionId, setSessionId] = useState("");
  const [command, setCommand] = useState("show running-config");
  const [capturing, setCapturing] = useState(false);
  const [idA, setIdA] = useState("");
  const [idB, setIdB] = useState("");
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [comparing, setComparing] = useState(false);

  const [collections, setCollections] = useState<Collection[]>(loadCollections);
  const [newName, setNewName] = useState("");
  const [newCommands, setNewCommands] = useState("");
  const [running, setRunning] = useState<string | null>(null);

  // Pre-select the session when opened from a tab's right-click menu.
  // One-shot: consume the hint so it never overrides a manual change or
  // re-fires when the live-session set shifts.
  useEffect(() => {
    if (open && preselect) {
      if (sessions.some((t) => t.sessionId === preselect && !t.ended)) {
        setSessionId(preselect);
      }
      consumePreselect();
    }
  }, [open, preselect, sessions, consumePreselect]);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["captures"] });

  const persistCollections = (next: Collection[]) => {
    setCollections(next);
    saveCollections(next);
  };

  const addCollection = () => {
    const commands = newCommands
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (newName.trim() === "" || commands.length === 0) return;
    persistCollections([
      ...collections,
      { id: crypto.randomUUID(), name: newName.trim(), commands },
    ]);
    setNewName("");
    setNewCommands("");
  };

  const runColl = async (c: Collection) => {
    if (!sessionId) return;
    setRunning(c.id);
    try {
      const metas = await runCollection(sessionId, c.commands);
      toastSuccess(`Ran "${c.name}" — ${metas.length} capture${metas.length === 1 ? "" : "s"}`);
      void refresh();
    } catch (e) {
      toastError(`Run failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setRunning(null);
    }
  };

  const doCapture = async () => {
    if (!sessionId || command.trim() === "") return;
    setCapturing(true);
    try {
      const meta = await captureCommand(sessionId, command.trim());
      toastSuccess(`Captured "${meta.command}" from ${meta.device_id}`);
      void refresh();
    } catch (e) {
      toastError(`Capture failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setCapturing(false);
    }
  };

  const doCompare = async () => {
    if (!idA || !idB) return;
    setComparing(true);
    try {
      setDiff(await diffCaptures(idA, idB));
    } catch (e) {
      toastError(`Compare failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setComparing(false);
    }
  };

  const doDelete = async (id: string) => {
    await deleteCapture(id).catch(() => {});
    if (idA === id) setIdA("");
    if (idB === id) setIdB("");
    void refresh();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Captures and diff</DialogTitle>
          <DialogDescription>
            Capture a command output, then compare two captures — across time or between devices.
            Output is redacted before being saved.
          </DialogDescription>
        </DialogHeader>

        {/* New capture */}
        <div className="flex items-end gap-2">
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Session</span>
            <Select value={sessionId} onValueChange={setSessionId}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Pick a session" />
              </SelectTrigger>
              <SelectContent>
                {liveSessions.map(({ tab, label }) => (
                  <SelectItem key={tab.sessionId} value={tab.sessionId}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-1 flex-col gap-1">
            <span className="text-xs text-muted-foreground">Command</span>
            <input
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              className="rounded border border-input bg-background px-2 py-1 font-mono text-sm outline-none focus:ring-1 focus:ring-ring"
              spellCheck={false}
              data-testid="capture-command-input"
            />
          </div>
          <Button onClick={() => void doCapture()} disabled={!sessionId || capturing}>
            {capturing ? "Capturing…" : "Capture"}
          </Button>
        </div>

        {/* Collections — saved command sets run as one sweep against the
            selected session (human input; not policy-gated). */}
        <div className="rounded border border-border p-2">
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Collections — run multiple commands to capture, one per line
          </div>
          {collections.length > 0 && (
            <ul className="mb-2 flex flex-col gap-1">
              {collections.map((c) => (
                <li key={c.id} className="flex items-center gap-2 text-xs">
                  <span className="flex-1 truncate" title={c.commands.join("\n")}>
                    {c.name} <span className="text-muted-foreground">({c.commands.length})</span>
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!sessionId || running !== null}
                    onClick={() => void runColl(c)}
                  >
                    {running === c.id ? "Running…" : "Run"}
                  </Button>
                  <button
                    type="button"
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                    onClick={() => persistCollections(collections.filter((x) => x.id !== c.id))}
                    aria-label={`Delete collection ${c.name}`}
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="flex items-start gap-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="New collection name"
              className="w-40 rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:ring-1 focus:ring-ring"
              data-testid="collection-name-input"
            />
            <textarea
              value={newCommands}
              onChange={(e) => setNewCommands(e.target.value)}
              placeholder="One command per line"
              rows={2}
              className="flex-1 rounded border border-input bg-background px-2 py-1 font-mono text-xs outline-none focus:ring-1 focus:ring-ring"
              spellCheck={false}
              data-testid="collection-commands-input"
            />
            <Button
              size="sm"
              variant="outline"
              disabled={newName.trim() === "" || newCommands.trim() === ""}
              onClick={addCollection}
            >
              Save
            </Button>
          </div>
        </div>

        {/* Captures list */}
        <div className="max-h-40 overflow-y-auto rounded border border-border">
          {captures.length === 0 ? (
            <div className="p-3 text-xs text-muted-foreground">No captures yet.</div>
          ) : (
            <ul className="divide-y divide-border">
              {captures.map((c) => (
                <li key={c.id} className="flex items-center gap-2 px-2 py-1 text-xs">
                  <span className="flex-1 truncate font-mono" title={fmtCapture(c)}>
                    {fmtCapture(c)}
                  </span>
                  <button
                    type="button"
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                    onClick={() => void doDelete(c.id)}
                    aria-label={`Delete capture from ${c.device_id}`}
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Compare */}
        <div className="flex items-end gap-2">
          <CaptureSelect label="Old (A)" value={idA} onChange={setIdA} captures={captures} />
          <CaptureSelect label="New (B)" value={idB} onChange={setIdB} captures={captures} />
          <Button
            variant="outline"
            onClick={() => void doCompare()}
            disabled={!idA || !idB || idA === idB || comparing}
          >
            {comparing ? "Comparing…" : "Compare"}
          </Button>
        </div>

        {/* Diff output */}
        {diff && (
          <div className="rounded border border-border">
            <div className="border-b border-border px-2 py-1 text-xs tabular-nums">
              <span className="text-emerald-600 dark:text-emerald-400">+{diff.added}</span>{" "}
              <span className="text-red-600 dark:text-red-400">-{diff.removed}</span>
              {diff.added === 0 && diff.removed === 0 && (
                <span className="ml-2 text-muted-foreground">identical</span>
              )}
            </div>
            <div
              className="max-h-72 overflow-auto bg-black/90 p-2 font-mono text-xs leading-tight"
              data-testid="diff-output"
            >
              {diff.lines.map((l, i) => (
                <div
                  key={i}
                  className={cn(
                    "whitespace-pre",
                    l.op === "insert" && "bg-emerald-500/15 text-emerald-300",
                    l.op === "delete" && "bg-red-500/15 text-red-300",
                    l.op === "equal" && "text-muted-foreground",
                  )}
                >
                  {l.op === "insert" ? "+" : l.op === "delete" ? "-" : " "} {l.text}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="text-[10px] text-muted-foreground">
          Saved to {capturesDir.data ?? "…/TransitCommunity/captures"}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function CaptureSelect({
  label,
  value,
  onChange,
  captures,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  captures: CaptureMeta[];
}) {
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger>
          <SelectValue placeholder="Pick a capture" />
        </SelectTrigger>
        <SelectContent>
          {captures.map((c) => (
            <SelectItem key={c.id} value={c.id}>
              {fmtCapture(c)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
