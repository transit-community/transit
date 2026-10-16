import { useState } from "react";

import { Check, ChevronsUpDown, Plus } from "lucide-react";

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
import { CUSTOM_VENDOR_PATTERN, VENDOR_OPTIONS } from "@/lib/schemas";
import { cn } from "@/lib/utils";

export interface VendorComboboxProps {
  value: string;
  onChange: (value: string) => void;
  /** Forwarded to the trigger so RHF's `<FormControl>` wires label /
   *  aria-describedby. */
  id?: string;
}

/**
 * Combobox for the device-form `vendor` field. Lists the built-in
 * vendors (friendly labels) and lets a power user type a CUSTOM vendor
 * name for Bring Your Own Policy (Phase 2b): the typed name is the
 * policy-file stem (`<name>.yaml`) and the inventory `vendor = "<name>"`
 * tag, so it's constrained to a filename-safe charset
 * ([`CUSTOM_VENDOR_PATTERN`], mirrored by the zod schema). A custom name
 * gates exactly like a built-in once its policy loads, and default-denies
 * until then.
 */
export function VendorCombobox({ value, onChange, id }: VendorComboboxProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  // Vendor tags are lowercase (they map to `<tag>.yaml`); normalize so
  // a user typing "FortiOS" lands on the same tag the gate will match.
  const trimmed = query.trim().toLowerCase();
  const known = VENDOR_OPTIONS.find((o) => o.value === value);
  // Widen to `string[]` — VENDOR_OPTIONS is `as const`, so `.value` is a
  // literal union that `.includes(string)` would reject.
  const knownValues: string[] = VENDOR_OPTIONS.map((o) => o.value);
  const isKnown = knownValues.includes(trimmed);
  const isValidCustom = trimmed.length > 0 && !isKnown && CUSTOM_VENDOR_PATTERN.test(trimmed);

  const commit = (next: string) => {
    onChange(next);
    setOpen(false);
    setQuery("");
  };

  const listboxId = `${id ?? "vendor-combobox"}-listbox`;

  // Display the friendly label for a built-in; otherwise the raw custom
  // tag (rendered monospace below to read as the file stem it is).
  const display = known ? known.label : value || "Pick a vendor";

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
          className={cn("w-full justify-between font-normal", !value && "text-muted-foreground")}
        >
          <span className="truncate">
            {display}
            {value && !known && <span className="ml-1.5 text-muted-foreground">(custom)</span>}
          </span>
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
            placeholder="Search or type a custom vendor..."
            value={query}
            onValueChange={setQuery}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          <CommandList>
            <CommandGroup>
              {VENDOR_OPTIONS.map((opt) => (
                <CommandItem key={opt.value} value={opt.value} onSelect={() => commit(opt.value)}>
                  <Check
                    className={cn(
                      "mr-2 h-4 w-4",
                      value === opt.value ? "opacity-100" : "opacity-0",
                    )}
                  />
                  {opt.label}
                </CommandItem>
              ))}
            </CommandGroup>
            {isValidCustom && (
              <CommandGroup heading="Custom vendor (Bring Your Own Policy)">
                <CommandItem value={`__custom__:${trimmed}`} onSelect={() => commit(trimmed)}>
                  <Plus className="mr-2 h-4 w-4" />
                  <span>
                    Use <span className="font-mono">{trimmed}</span> — needs a{" "}
                    <span className="font-mono">{trimmed}.yaml</span> policy
                  </span>
                </CommandItem>
              </CommandGroup>
            )}
            {trimmed.length > 0 && !isValidCustom && !isKnown && (
              <CommandEmpty>
                Custom vendor names use lowercase letters, digits, and underscores only.
              </CommandEmpty>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
