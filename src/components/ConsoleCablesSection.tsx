import { AlertTriangle, Cable } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cableLabel, useConsoleCables, useConsoleDriverStatus } from "@/lib/console";
import type { SerialPortInfo } from "@/lib/api";

/**
 * Sidebar section listing currently-attached USB-to-serial cables.
 *
 * Renders nothing when there are no cables — by design, per the maintainer's
 * directive: "The console cable entry should not be present if no
 * console cable is plugged in." (Phase 7b plan §"Locked decisions"
 * #3.)
 *
 * Placement is at the bottom of the device tree — SSH is the
 * primary workflow; console cables are a less-frequent secondary
 * tool that shouldn't push the usual gear off-screen.
 */
export function ConsoleCablesSection({
  onSelectCable,
}: {
  onSelectCable: (cable: SerialPortInfo) => void;
}) {
  const { data: cables = [] } = useConsoleCables();
  const { data: driverStatus } = useConsoleDriverStatus();
  const missing = driverStatus?.missing_drivers ?? [];

  // Hide the entire section only when both lists are empty — a
  // missing-driver banner is the most useful thing we can show
  // a user whose cable isn't appearing.
  if (cables.length === 0 && missing.length === 0) return null;

  return (
    <div className="border-t border-border px-2 pb-3 pt-2">
      <div className="px-2 pb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Console cables
      </div>
      {missing.map((m) => (
        <div
          key={`${m.vid}-${m.pid}`}
          className="mb-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-200"
          role="alert"
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              <div className="font-medium">
                {m.chip} chip detected ({m.vid}/{m.pid}) — driver not loaded
              </div>
              <div className="mt-0.5 leading-snug opacity-90">{m.instruction}</div>
            </div>
          </div>
        </div>
      ))}
      {cables.map((cable) => (
        <Button
          key={cable.port_path}
          variant="ghost"
          size="sm"
          className="w-full justify-start gap-2 px-2 text-left font-normal"
          onClick={() => onSelectCable(cable)}
        >
          <Cable className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="truncate">{cableLabel(cable)}</span>
        </Button>
      ))}
    </div>
  );
}
