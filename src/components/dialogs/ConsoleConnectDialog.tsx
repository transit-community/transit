import { useEffect, useState } from "react";

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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cableLabel, useConnectConsoleCable } from "@/lib/console";
import { VENDOR_OPTIONS } from "@/lib/schemas";
import type { DataBits, FlowControl, Parity, SerialPortInfo, StopBits } from "@/lib/api";

const BAUD_PRESETS = [9600, 19200, 38400, 57600, 115200] as const;

const DATA_BITS: { value: DataBits; label: string }[] = [
  { value: "five", label: "5" },
  { value: "six", label: "6" },
  { value: "seven", label: "7" },
  { value: "eight", label: "8" },
];

const PARITY: { value: Parity; label: string }[] = [
  { value: "none", label: "None" },
  { value: "odd", label: "Odd" },
  { value: "even", label: "Even" },
];

const STOP_BITS: { value: StopBits; label: string }[] = [
  { value: "one", label: "1" },
  { value: "two", label: "2" },
];

const FLOW_CONTROL: { value: FlowControl; label: string }[] = [
  { value: "none", label: "None" },
  { value: "software", label: "Software (XON/XOFF)" },
  { value: "hardware", label: "Hardware (RTS/CTS)" },
];

export interface ConsoleConnectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  cable: SerialPortInfo | null;
}

/**
 * "Configure console connection" modal. Opens when the user clicks
 * a row in `ConsoleCablesSection`. Vendor defaults to Junos because
 * A typical lab cable terminates at a Juniper switch — once we add a
 * per-cable preference (USB-serial-keyed), this default flips to
 * "last-used for this cable".
 */
export function ConsoleConnectDialog({ open, onOpenChange, cable }: ConsoleConnectDialogProps) {
  const [vendor, setVendor] = useState<string>("junos");
  const [baud, setBaud] = useState<number>(9600);
  const [dataBits, setDataBits] = useState<DataBits>("eight");
  const [parity, setParity] = useState<Parity>("none");
  const [stopBits, setStopBits] = useState<StopBits>("one");
  const [flowControl, setFlowControl] = useState<FlowControl>("none");
  const [error, setError] = useState<string | null>(null);

  const connect = useConnectConsoleCable();

  // Reset defaults each time the dialog opens — closes-and-reopens
  // should land at factory defaults, not whatever the user picked
  // last session.
  useEffect(() => {
    if (open) {
      setVendor("junos");
      setBaud(9600);
      setDataBits("eight");
      setParity("none");
      setStopBits("one");
      setFlowControl("none");
      setError(null);
    }
  }, [open]);

  if (!cable) return null;

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    connect.mutate(
      {
        port_path: cable.port_path,
        baud,
        vendor,
        data_bits: dataBits,
        parity,
        stop_bits: stopBits,
        flow_control: flowControl,
      },
      {
        onSuccess: () => onOpenChange(false),
        onError: (err) => setError(err instanceof Error ? err.message : String(err)),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Configure console connection</DialogTitle>
          <DialogDescription>
            <span className="font-mono">{cableLabel(cable)}</span>
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="console-vendor">Vendor</Label>
            <Select value={vendor} onValueChange={setVendor}>
              <SelectTrigger id="console-vendor">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {VENDOR_OPTIONS.filter((v) => v.value !== "unknown").map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="console-baud">Baud</Label>
            <div className="flex gap-2">
              <Input
                id="console-baud"
                type="number"
                min={300}
                max={4_000_000}
                value={baud}
                onChange={(e) => {
                  const n = e.target.valueAsNumber;
                  if (Number.isFinite(n)) setBaud(n);
                }}
                className="flex-1"
              />
              <Select value={String(baud)} onValueChange={(v) => setBaud(Number.parseInt(v, 10))}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Presets" />
                </SelectTrigger>
                <SelectContent>
                  {BAUD_PRESETS.map((b) => (
                    <SelectItem key={b} value={String(b)}>
                      {b}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <details className="grid gap-2 rounded-md border border-border p-3 text-sm">
            <summary className="cursor-pointer font-medium">Advanced</summary>
            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="grid gap-1">
                <Label htmlFor="console-data-bits" className="text-xs">
                  Data bits
                </Label>
                <Select value={dataBits} onValueChange={(v) => setDataBits(v as DataBits)}>
                  <SelectTrigger id="console-data-bits">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DATA_BITS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="console-parity" className="text-xs">
                  Parity
                </Label>
                <Select value={parity} onValueChange={(v) => setParity(v as Parity)}>
                  <SelectTrigger id="console-parity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PARITY.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="console-stop-bits" className="text-xs">
                  Stop bits
                </Label>
                <Select value={stopBits} onValueChange={(v) => setStopBits(v as StopBits)}>
                  <SelectTrigger id="console-stop-bits">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {STOP_BITS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="console-flow-control" className="text-xs">
                  Flow control
                </Label>
                <Select value={flowControl} onValueChange={(v) => setFlowControl(v as FlowControl)}>
                  <SelectTrigger id="console-flow-control">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FLOW_CONTROL.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </details>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={connect.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={connect.isPending}>
              {connect.isPending ? "Connecting..." : "Connect"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
