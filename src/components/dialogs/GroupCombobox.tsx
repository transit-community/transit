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
import { cn } from "@/lib/utils";

export interface GroupComboboxProps {
  value: string;
  onChange: (value: string) => void;
  existingGroups: string[];
  /** Forwarded to the trigger button so RHF's `<FormControl>` can wire
   *  it up for label / aria-describedby. */
  id?: string;
}

/**
 * Combobox for the device-form `group` field. Shows existing group
 * paths (full + every prefix) plus an explicit "Create new group"
 * row that, when selected, commits whatever the user typed as a new
 * group path. Empty string means "ungrouped" — render that as a
 * dedicated row too, so it's discoverable.
 */
export function GroupCombobox({ value, onChange, existingGroups, id }: GroupComboboxProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const trimmed = query.trim();
  const exactMatch =
    trimmed === "" || existingGroups.some((g) => g.toLowerCase() === trimmed.toLowerCase());

  const commit = (next: string) => {
    onChange(next);
    setOpen(false);
    setQuery("");
  };

  // ARIA spec requires `combobox` to point at the listbox it
  // controls. The listbox lives inside the `PopoverContent` rendered
  // below; we generate a stable id and reference it from
  // `aria-controls` so screen readers can follow the relationship.
  const listboxId = `${id ?? "group-combobox"}-listbox`;

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
          <span className="truncate">{value || "Ungrouped"}</span>
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
            placeholder="Search or type to create new..."
            value={query}
            onValueChange={setQuery}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          <CommandList>
            <CommandGroup>
              <CommandItem value="__ungrouped__" onSelect={() => commit("")}>
                <Check className={cn("mr-2 h-4 w-4", value === "" ? "opacity-100" : "opacity-0")} />
                <span className="text-muted-foreground">Ungrouped (root)</span>
              </CommandItem>
              {existingGroups.map((g) => (
                <CommandItem key={g} value={g} onSelect={() => commit(g)}>
                  <Check
                    className={cn("mr-2 h-4 w-4", value === g ? "opacity-100" : "opacity-0")}
                  />
                  <span className="font-mono">{g}</span>
                </CommandItem>
              ))}
            </CommandGroup>
            {trimmed.length > 0 && !exactMatch && (
              <CommandGroup heading="Create new">
                <CommandItem value={`__create__:${trimmed}`} onSelect={() => commit(trimmed)}>
                  <Plus className="mr-2 h-4 w-4" />
                  <span>
                    Create <span className="font-mono">{trimmed}</span>
                  </span>
                </CommandItem>
              </CommandGroup>
            )}
            {trimmed.length > 0 && exactMatch && <CommandEmpty>No groups match.</CommandEmpty>}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
