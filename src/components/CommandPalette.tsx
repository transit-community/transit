import { useMemo } from "react";

import * as VisuallyHidden from "@radix-ui/react-visually-hidden";

import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { type CommandItem as CommandItemSpec, useCommands } from "@/lib/commands";
import { useUiStore } from "@/stores/uiStore";

/**
 * Phase 7a C2 — global command palette. Mounted once at App root.
 * Cmd-K / Ctrl-K toggles via `useGlobalHotkeys`.
 *
 * Items come from `useCommands()`, the centralized registry (Decision
 * A3). Groups render in the registry's natural order (Navigation →
 * Devices → Sessions). cmdk handles the fuzzy filter against label +
 * description + keywords.
 *
 * Selecting an item runs its `perform()` and closes the palette.
 */
export function CommandPalette() {
  const open = useUiStore((s) => s.commandPaletteOpen);
  const close = useUiStore((s) => s.closeCommandPalette);
  const scope = useUiStore((s) => s.commandPaletteScope);
  const items = useCommands();
  const sessionsOnly = scope === "sessions";

  const groups = useMemo(() => {
    const byGroup = new Map<CommandItemSpec["group"], CommandItemSpec[]>();
    for (const item of items) {
      const list = byGroup.get(item.group) ?? [];
      list.push(item);
      byGroup.set(item.group, list);
    }
    // Stable order: Navigation → Devices → Sessions. The registry's
    // group enum is the source of truth; this just imposes the
    // render order.
    // Window → Jump to Session… scopes to the Sessions group. Without
    // that, "Connect to …" (one per inventory device) dominates the list
    // and the open sessions sit below the fold.
    const order: CommandItemSpec["group"][] = sessionsOnly
      ? ["Sessions"]
      : ["Navigation", "Devices", "Sessions"];
    return order
      .map((name) => ({ name, items: byGroup.get(name) ?? [] }))
      .filter((g) => g.items.length > 0);
  }, [items, sessionsOnly]);

  return (
    <CommandDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) close();
      }}
    >
      <VisuallyHidden.Root>
        <DialogTitle>Command palette</DialogTitle>
        <DialogDescription>
          Run a navigation command or search for devices and sessions.
        </DialogDescription>
      </VisuallyHidden.Root>
      <CommandInput
        placeholder={
          sessionsOnly ? "Jump to an open session..." : "Type a command or search devices..."
        }
      />
      <CommandList data-testid="command-palette-list">
        <CommandEmpty>{sessionsOnly ? "No open sessions to jump to." : "No matches."}</CommandEmpty>
        {groups.map((group, idx) => (
          <div key={group.name}>
            {idx > 0 && <CommandSeparator />}
            <CommandGroup heading={group.name}>
              {group.items.map((item) => (
                <CommandItem
                  key={item.id}
                  value={`${item.label} ${item.description ?? ""} ${(item.keywords ?? []).join(" ")}`}
                  onSelect={() => {
                    item.perform();
                    close();
                  }}
                  data-testid={`command-item-${item.id}`}
                >
                  <item.icon />
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate">{item.label}</span>
                    {item.description && (
                      <span className="truncate text-xs text-muted-foreground">
                        {item.description}
                      </span>
                    )}
                  </div>
                  {item.shortcut && <CommandShortcut>{item.shortcut}</CommandShortcut>}
                </CommandItem>
              ))}
            </CommandGroup>
          </div>
        ))}
      </CommandList>
    </CommandDialog>
  );
}
