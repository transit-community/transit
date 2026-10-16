import { useState } from "react";

import { Check, ChevronsUpDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export interface JumpHostOption {
  id: string;
  host: string;
  port: number;
}

export interface JumpHostComboboxProps {
  /** `""` = direct connection (only offered when `allowDirect`). */
  value: string;
  onChange: (value: string) => void;
  /** Eligible jump targets (caller owns exclusion of self / cycles). */
  options: JumpHostOption[];
  /** Offer a "Direct connection" row that commits `""`. The device
   *  dialog wants it; the bulk row doesn't (Clear is its own mode). */
  allowDirect?: boolean;
  /** Shown when `options` is empty and nothing is searched. */
  emptyText?: string;
  /** Forwarded to the trigger so RHF's `<FormControl>` wires label /
   *  aria-describedby. */
  id?: string;
  "data-testid"?: string;
}

/**
 * Searchable jump-host picker (v6.5.0 smoke-test finding: a plain
 * `<Select>` is unusable on a real-world inventory — dozens of devices,
 * no typeahead). Same Popover+cmdk pattern as [`VendorCombobox`]; the
 * filter matches BOTH the device id and its host, since operators know
 * bastions by either. A stored reference that isn't in `options`
 * (hand-edited transit.toml) still renders as a selectable
 * "(unknown device)" row so the form stays submittable — the `color`
 * graceful-fallback contract.
 */
export function JumpHostCombobox({
  value,
  onChange,
  options,
  allowDirect = false,
  emptyText = "No matching device.",
  id,
  "data-testid": dataTestId,
}: JumpHostComboboxProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const commit = (next: string) => {
    onChange(next);
    setOpen(false);
    setQuery("");
  };

  const listboxId = `${id ?? "jump-host-combobox"}-listbox`;
  const selected = options.find((o) => o.id === value);
  const unknown = value !== "" && !selected;

  const display =
    value === "" ? (
      allowDirect ? (
        "Direct connection"
      ) : (
        <span className="text-muted-foreground">Pick a jump host</span>
      )
    ) : (
      <>
        <span className="font-mono">{value}</span>
        <span className="ml-1.5 text-xs text-muted-foreground">
          {selected ? `${selected.host}:${selected.port}` : "(unknown device)"}
        </span>
      </>
    );

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-controls={listboxId}
          data-testid={dataTestId}
          className="w-full justify-between font-normal"
        >
          <span className="truncate">{display}</span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        id={listboxId}
        className="w-[--radix-popover-trigger-width] p-0"
        align="start"
      >
        <Command shouldFilter>
          <CommandInput
            placeholder="Search by name or host..."
            value={query}
            onValueChange={setQuery}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          <CommandList>
            <CommandEmpty>{options.length === 0 ? emptyText : "No matching device."}</CommandEmpty>
            <CommandGroup>
              {allowDirect && (
                <CommandItem value="__direct-connection__" onSelect={() => commit("")}>
                  <Check
                    className={cn("mr-2 h-4 w-4", value === "" ? "opacity-100" : "opacity-0")}
                  />
                  Direct connection
                </CommandItem>
              )}
              {unknown && (
                <CommandItem value={`__unknown__ ${value}`} onSelect={() => commit(value)}>
                  <Check className="mr-2 h-4 w-4 opacity-100" />
                  <span className="font-mono">{value}</span>
                  <span className="ml-2 text-xs text-muted-foreground">(unknown device)</span>
                </CommandItem>
              )}
              {options.map((d) => (
                // cmdk filters on `value`: include id AND host so the
                // operator can type either ("eve" or "192.0.2.66").
                <CommandItem key={d.id} value={`${d.id} ${d.host}`} onSelect={() => commit(d.id)}>
                  <Check
                    className={cn("mr-2 h-4 w-4", value === d.id ? "opacity-100" : "opacity-0")}
                  />
                  <span className="font-mono">{d.id}</span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {d.host}:{d.port}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
