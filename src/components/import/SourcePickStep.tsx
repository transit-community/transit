import { open } from "@tauri-apps/plugin-dialog";
import {
  Boxes,
  FileText,
  Loader2,
  Network,
  PanelsTopLeft,
  Table,
  TerminalSquare,
} from "lucide-react";

import { previewImport, type ImportSource } from "@/lib/api";

import type { ImportAction, ImportState } from "./importReducer";

const FORMAT_OPTIONS: {
  value: ImportSource;
  label: string;
  hint: string;
  icon: typeof FileText;
  extensions: string[];
}[] = [
  {
    value: "secure_crt",
    label: "SecureCRT",
    hint: "An exported SCRTConfig.xml",
    icon: Network,
    extensions: ["xml"],
  },
  {
    value: "ssh_config",
    label: "OpenSSH config",
    hint: "Your ~/.ssh/config file",
    icon: FileText,
    extensions: [],
  },
  {
    value: "mt_putty",
    label: "MTPuTTY",
    hint: "A Server → Export file, or mtputty.xml itself",
    icon: TerminalSquare,
    extensions: ["xml"],
  },
  {
    value: "moba_xterm",
    label: "MobaXterm",
    hint: "A sessions export, config backup, or MobaXterm.ini",
    icon: PanelsTopLeft,
    extensions: ["mxtsessions", "mobaconf", "ini"],
  },
  {
    value: "csv",
    label: "CSV",
    hint: "host, name, vendor, group, …",
    icon: Table,
    extensions: ["csv"],
  },
];

export function SourcePickStep({
  state,
  dispatch,
}: {
  state: ImportState;
  dispatch: React.Dispatch<ImportAction>;
}) {
  const pick = async (opt: (typeof FORMAT_OPTIONS)[number]) => {
    const filters =
      opt.extensions.length > 0
        ? [
            { name: opt.label, extensions: opt.extensions },
            { name: "All files", extensions: ["*"] },
          ]
        : undefined;
    let path: string | null;
    try {
      const picked = await open({
        multiple: false,
        directory: false,
        title: `Choose your ${opt.label} file`,
        filters,
      });
      path = typeof picked === "string" ? picked : null;
    } catch (e) {
      dispatch({ type: "PARSE_ERR", message: e instanceof Error ? e.message : String(e) });
      return;
    }
    if (!path) return; // cancelled

    dispatch({ type: "PARSE_START", format: opt.value, path });
    try {
      const preview = await previewImport(opt.value, path);
      if (preview.rows.length === 0) {
        dispatch({ type: "PARSE_ERR", message: "No connections were found in that file." });
        return;
      }
      dispatch({
        type: "PARSE_OK",
        rows: preview.rows,
        identities: preview.identities,
        warnings: preview.warnings,
      });
    } catch (e) {
      dispatch({ type: "PARSE_ERR", message: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <div className="mx-auto flex h-full max-w-lg flex-col justify-center px-6 py-10">
      <h2 className="text-xl font-semibold tracking-tight">Import connections</h2>
      <p className="mt-2 text-sm text-muted-foreground">
        Pick where your saved sessions come from. Transit reads host, port, username, folder, and
        key-file paths — never your stored passwords.
      </p>

      <div className="mt-6 grid gap-3">
        {FORMAT_OPTIONS.map((opt) => {
          const Icon = opt.icon;
          return (
            <button
              key={opt.value}
              type="button"
              disabled={state.parsing}
              onClick={() => void pick(opt)}
              data-testid={`import-source-${opt.value}`}
              className="flex items-center gap-3 rounded-lg border border-border bg-background p-4 text-left transition-colors hover:border-primary/50 hover:bg-accent disabled:opacity-60"
            >
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 text-primary">
                <Icon className="h-5 w-5" />
              </span>
              <span className="flex-1">
                <span className="block text-sm font-medium">{opt.label}</span>
                <span className="block text-xs text-muted-foreground">{opt.hint}</span>
              </span>
            </button>
          );
        })}
      </div>

      <div className="mt-6 border-t border-border pt-4">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Or sync from a live source
        </p>
        <button
          type="button"
          disabled={state.parsing}
          onClick={() => dispatch({ type: "NETBOX_OPEN" })}
          data-testid="import-source-netbox"
          className="mt-3 flex w-full items-center gap-3 rounded-lg border border-border bg-background p-4 text-left transition-colors hover:border-primary/50 hover:bg-accent disabled:opacity-60"
        >
          <span className="inline-flex size-10 items-center justify-center rounded-md bg-primary/10 text-primary">
            <Boxes className="size-5" />
          </span>
          <span className="flex-1">
            <span className="block text-sm font-medium">NetBox</span>
            <span className="block text-xs text-muted-foreground">
              Diff a NetBox instance against this inventory: import new devices, accept drift,
              review stale ones
            </span>
          </span>
        </button>
      </div>

      {state.parsing && (
        <p className="mt-4 inline-flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Reading and analyzing…
        </p>
      )}
      {state.parseError && (
        <p
          role="alert"
          className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {state.parseError}
        </p>
      )}
    </div>
  );
}
