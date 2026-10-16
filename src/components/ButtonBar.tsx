import { emit } from "@tauri-apps/api/event";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { ChevronDown, ChevronUp, Plus, Sparkles } from "lucide-react";
import { useState } from "react";

import { ScrollChevron } from "@/components/ScrollChevron";
import {
  ButtonBarNameDialog,
  type ButtonBarNameState,
} from "@/components/dialogs/ButtonBarNameDialog";
import { MapButtonDialog, type MapButtonState } from "@/components/dialogs/MapButtonDialog";
import { Button } from "@/components/ui/button";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { sendInput } from "@/lib/api";
import { deviceColorTint } from "@/lib/deviceColors";
import { executeButtonString } from "@/lib/terminal/buttonString";
import { useOverflowScroll } from "@/lib/useOverflowScroll";
import { hasPty, resolveActivePaneId, useUiStore } from "@/stores/uiStore";

/**
 * v1.4.0 SecureCRT-style button bar. A strip below the terminal, shown when
 * `preferences.showButtonBar` (toggled from View → Button Bar). Each button
 * sends its macro to the ACTIVE session via the escape-code executor — this
 * is human input over the existing `send_input` PTY path (identical to
 * typing), so it is NOT policy-gated. Right-click the bar to add a button or
 * hide the bar; right-click a button to edit or delete it.
 *
 * v2.7.0 — multiple NAMED bars (e.g. a "VOIP" set vs a "Routers" set,
 * SecureCRT parity). Only the active bar renders; with 2+ bars a compact
 * left cluster appears: stacked up/down chevrons cycle (up = previous,
 * down = next, wrapping) and the bar's name opens a jump popover. Bars are
 * managed from the strip's context menu (New / Rename / Delete — Delete is
 * disabled on the last bar). The Map Button dialog is bar-agnostic: the
 * store routes add/edit/delete to the active bar.
 */
export function ButtonBar() {
  const showButtonBar = useUiStore((s) => s.preferences.showButtonBar);
  const bars = useUiStore((s) => s.preferences.buttonBars);
  const activeBarId = useUiStore((s) => s.preferences.activeButtonBarId);
  const setShowButtonBar = useUiStore((s) => s.setShowButtonBar);
  const removeButton = useUiStore((s) => s.removeButton);
  const setActiveBar = useUiStore((s) => s.setActiveBar);
  const cycleBar = useUiStore((s) => s.cycleBar);
  const removeBar = useUiStore((s) => s.removeBar);
  const [dialog, setDialog] = useState<MapButtonState>({ kind: "none" });
  const [barDialog, setBarDialog] = useState<ButtonBarNameState>({ kind: "none" });
  const [jumpOpen, setJumpOpen] = useState(false);
  // v2.3.4 — the bar is a single row: with many buttons it scrolls
  // horizontally behind chevrons (MTPuTTY-style) instead of wrapping
  // into extra rows that eat terminal height.
  const { ref, canLeft, canRight, overflowing, update, scrollByStep } =
    useOverflowScroll<HTMLDivElement>();

  // The loader guarantees ≥ 1 bar; the fallback covers a mid-session
  // state where the active id points at a just-deleted bar.
  const activeBar = bars.find((b) => b.id === activeBarId) ?? bars[0];

  if (!showButtonBar) return null;

  const buttons = activeBar.buttons;

  const runButton = (value: string, target?: "session" | "agent") => {
    // v6.1.0 — an agent button types a PROMPT into the AI composer
    // instead of sending bytes to a device. Deliberately fills rather
    // than sends: the user reads it and presses Enter, which keeps a
    // saved prompt one glance from being edited for the case at hand,
    // and avoids racing a panel that is still mounting.
    //
    // Rule 3 is unaffected — whatever the assistant does with the prompt
    // still passes the policy gate and the approval modal.
    if (target === "agent") {
      const { chatPanelOpen, toggleChatPanel, setAgentPrompt } = useUiStore.getState();
      // Park the text FIRST: the composer may not be mounted yet (the
      // panel could still be opening), and a parked value is read
      // whenever it appears. Firing an event at a listener that doesn't
      // exist yet would just lose the click.
      setAgentPrompt(value);
      if (!chatPanelOpen) toggleChatPanel();
      return;
    }
    // v6.4.0 — target the FOCUSED PANE, not the tab's primary. In a tiled tab
    // these differ, and using the tab id sent every macro to the left pane no
    // matter which one the user was working in (user report, 2026-08-26).
    // On an un-split tab the resolver returns the tab id, so nothing changes.
    const targetId = resolveActivePaneId(useUiStore.getState());
    if (!targetId) return;
    const { sessions } = useUiStore.getState();
    const tab = sessions.find((t) => t.sessionId === targetId);
    // No-op on a dead or absent session (mirrors the keystroke `ended` guard),
    // or on a tab with no PTY to type into: an API tab (which this silently
    // misfired at before v5.0.0) or a Files tab.
    if (!tab || tab.ended || !hasPty(tab)) return;
    void executeButtonString(value, targetId, {
      sendInput,
      readClipboard: async () => (await readText()) ?? "",
      delay: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    });
    // Clicking the button stole DOM focus from the terminal; hand it
    // back to the pane we just typed into so the user can keep going.
    // The pane listens for this per-session event (TerminalPane).
    // Must be the same `targetId` — emitting the TAB id here was the second
    // half of the v6.4.0 bug: it dragged the cursor out of the pane the user
    // was in, on every button press.
    void emit(`ui:focus-terminal:${targetId}`);
  };

  return (
    <>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div
            className="flex shrink-0 items-center gap-0.5 border-t bg-muted/30 px-2 py-1"
            data-testid="button-bar"
          >
            {bars.length > 1 && (
              <div className="flex shrink-0 items-center gap-0.5">
                <div className="flex flex-col">
                  <button
                    type="button"
                    onClick={() => cycleBar(-1)}
                    aria-label="Previous button bar"
                    title="Previous button bar"
                    data-testid="button-bar-cycle-up"
                    className="flex h-3.5 w-4 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground"
                  >
                    <ChevronUp className="h-3 w-3" />
                  </button>
                  <button
                    type="button"
                    onClick={() => cycleBar(1)}
                    aria-label="Next button bar"
                    title="Next button bar"
                    data-testid="button-bar-cycle-down"
                    className="flex h-3.5 w-4 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground"
                  >
                    <ChevronDown className="h-3 w-3" />
                  </button>
                </div>
                <Popover open={jumpOpen} onOpenChange={setJumpOpen}>
                  <PopoverTrigger asChild>
                    <button
                      type="button"
                      data-testid="button-bar-name"
                      title="Jump to a button bar"
                      className="max-w-32 truncate rounded px-1.5 py-0.5 text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground"
                    >
                      {activeBar.name}
                    </button>
                  </PopoverTrigger>
                  <PopoverContent align="start" className="w-48 p-1">
                    {bars.map((b) => (
                      <button
                        key={b.id}
                        type="button"
                        data-testid={`button-bar-jump-${b.id}`}
                        onClick={() => {
                          setActiveBar(b.id);
                          setJumpOpen(false);
                        }}
                        className={`flex w-full items-center rounded px-2 py-1 text-left text-xs hover:bg-accent ${
                          b.id === activeBar.id ? "font-semibold" : ""
                        }`}
                      >
                        <span className="truncate">{b.name}</span>
                        <span className="ml-auto shrink-0 pl-2 text-[10px] text-muted-foreground">
                          {b.buttons.length}
                        </span>
                      </button>
                    ))}
                    <div className="mt-1 border-t pt-1">
                      <button
                        type="button"
                        onClick={() => {
                          setJumpOpen(false);
                          setBarDialog({ kind: "new" });
                        }}
                        className="flex w-full items-center gap-1 rounded px-2 py-1 text-left text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                      >
                        <Plus className="h-3 w-3" /> New bar…
                      </button>
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
            )}
            {overflowing && (
              <ScrollChevron
                dir="left"
                enabled={canLeft}
                onClick={() => scrollByStep(-1)}
                label="Scroll buttons left"
              />
            )}
            <div
              ref={ref}
              onScroll={update}
              className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
              data-testid="button-bar-strip"
            >
              {buttons.length === 0 ? (
                <button
                  type="button"
                  onClick={() => setDialog({ kind: "new" })}
                  className="flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <Plus className="h-3 w-3" /> New button…
                </button>
              ) : (
                buttons.map((b) => (
                  <ContextMenu key={b.id}>
                    <ContextMenuTrigger asChild>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 shrink-0"
                        style={deviceColorTint(b.color)}
                        onClick={() => runButton(b.value, b.target)}
                        title={b.target === "agent" ? `Ask the AI: ${b.value}` : b.value}
                        data-testid={
                          b.target === "agent" ? "button-bar-agent-button" : "button-bar-button"
                        }
                      >
                        {/* A mixed bar must be readable at a glance: an
                            agent button types a prompt, a plain one sends
                            bytes to the device. The icon is the tell. */}
                        {b.target === "agent" && (
                          <Sparkles className="mr-1 h-3 w-3 opacity-70" aria-hidden />
                        )}
                        {b.label}
                      </Button>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <ContextMenuItem onSelect={() => setDialog({ kind: "edit", button: b })}>
                        Edit…
                      </ContextMenuItem>
                      <ContextMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() => removeButton(b.id)}
                      >
                        Delete
                      </ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                ))
              )}
            </div>
            {overflowing && (
              <ScrollChevron
                dir="right"
                enabled={canRight}
                onClick={() => scrollByStep(1)}
                label="Scroll buttons right"
              />
            )}
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem onSelect={() => setDialog({ kind: "new" })}>New button…</ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onSelect={() => setBarDialog({ kind: "new" })}>New bar…</ContextMenuItem>
          <ContextMenuItem onSelect={() => setBarDialog({ kind: "rename", bar: activeBar })}>
            Rename bar…
          </ContextMenuItem>
          <ContextMenuItem
            className="text-destructive focus:text-destructive"
            disabled={bars.length <= 1}
            onSelect={() => removeBar(activeBar.id)}
          >
            Delete bar
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onSelect={() => setShowButtonBar(false)}>
            Hide button bar
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
      <MapButtonDialog state={dialog} onClose={() => setDialog({ kind: "none" })} />
      <ButtonBarNameDialog state={barDialog} onClose={() => setBarDialog({ kind: "none" })} />
    </>
  );
}
