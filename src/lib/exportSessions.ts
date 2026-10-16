import { useQuery } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";
import { useState } from "react";

import { exportConnections, listDevices } from "@/lib/api";
import { toastError, toastInfo, toastSuccess } from "@/lib/toast";

/**
 * "Export sessions..." — write the whole inventory to an
 * import-compatible CSV. A global action (never scoped to the clicked
 * node) wired into every sidebar context menu, so right-clicking anywhere
 * offers it.
 *
 * Extracted from `Sidebar` when the v5.0.0 Files sidebar grew the same
 * menu: `DeviceTree` requires the handler, and one implementation keeps
 * both sidebars writing identical files. Secrets are never exported
 * (Rule 1) — the backend writes references only (usernames + key paths).
 */
export function useExportSessions() {
  const [exporting, setExporting] = useState(false);
  const { data } = useQuery({ queryKey: ["devices"], queryFn: listDevices });

  const exportSessions = async (): Promise<void> => {
    if (exporting) return;
    if (!data || data.length === 0) {
      toastInfo("No sessions to export");
      return;
    }
    setExporting(true);
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const destination = await save({
        title: "Export sessions to CSV",
        defaultPath: `transit-sessions-${stamp}.csv`,
        filters: [{ name: "CSV file", extensions: ["csv"] }],
      });
      if (!destination) return; // user cancelled the native dialog
      const result = await exportConnections(destination);
      toastSuccess("Sessions exported", {
        description: `${result.count} session${result.count === 1 ? "" : "s"} written to ${result.path}`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toastError("Export failed", { description: msg });
    } finally {
      setExporting(false);
    }
  };

  return { exportSessions, exporting };
}
