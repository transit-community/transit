# Sessions

Phase 3 lifts Transit from one-session-at-a-time to a tabbed
multi-session UI, modeled on SecureCRT's session-tabs experience.

## Opening sessions

Three equivalent paths — pick whichever your hands are already on:

- **Right-click** any device in the sidebar → **Connect**.
- **Double-click** the device row.
- **Click once** to focus the row, then **press Enter**.

All three open a new tab at the top of the work area and focus it.

- Connect again on the same device → another tab opens. The label
  disambiguates as `vEX1`, `vEX1 (2)`, `vEX1 (3)`, etc. — the
  numeric suffix is positional in tab order, not a "session
  number".
- Connect on a different device → a third tab. Tabs render in the
  order they were opened; left-most tab is the oldest.

The backend has supported multi-session since Phase 2b
(`HashMap<SessionId, SessionEntry>` in `transit_ssh`), so opening
many tabs in parallel works without backend changes.

## Switching tabs

Click any tab in the strip. The previous tab's `TerminalPane` stays
mounted (its xterm.js instance keeps its scrollback intact) and is
hidden via CSS until you switch back. Resizing the window while
hidden doesn't break dimensions — `TerminalPane` re-fits xterm.js
when its tab regains focus.

## Closing tabs

- Click the small **X** on any tab.
- If the session is still **connected**, a confirmation dialog
  appears ("Close session?"). Accepting calls
  `disconnectSession(sessionId)` on the backend, then removes the
  tab.
- If the session has already **ended** (remote sent EOF, or you
  typed `exit`), the X removes the tab immediately — no confirm,
  no backend call.

The "Disconnect" button inside each `TerminalPane` does the same
thing as clicking that tab's X (skipping the confirm flow when
already ended).

## Reconnecting an ended session

When the remote closes the channel (you typed `exit` / `logout`, or
the device kicked you), the tab stays in place with an amber
"session ended" banner so you can still scroll the final output.
**Press Enter** inside the pane to reconnect: Transit best-effort
cleans up the dead backend entry, opens a fresh SSH session to the
same device, and swaps the new session into the same tab slot. The
custom tab label and any split anchor survive the swap.

Reconnect failures land in a toast; the dead pane stays so you can
retry with another Enter (or close it with the **X**).

## Connection state in the sidebar

Each device row in the sidebar shows a connection pill:

- `not connected` — no open sessions to this device.
- `connected` — one open session.
- `connected · 3` — three open sessions.

The count includes only **active** sessions; tabs in the `ended`
state don't count. Closing all tabs for a device flips the pill
back to `not connected`.

## Per-session resource caps

- **Scrollback ring**: 32K lines / 4 MiB per session, hard-capped
  in `transit_ssh::ScrollbackRing`. With 16 open sessions that's
  ~64 MiB worst case.
- **Concurrent sessions**: unbounded by Transit. The OS-level limits
  on file descriptors and TCP connections apply.

## Coming in Phase 7

- **Auto-reconnect on blip**: a session that drops due to a TCP
  hiccup (rather than user-initiated close) will retry with
  exponential backoff. Manual reconnect already works in-place —
  press Enter in the ended pane (see "Reconnecting an ended session"
  above) — auto-reconnect just removes the keypress.
- **Split-pane / tile view**: see two tabs side-by-side instead of
  switching. v1 is tabs only.
- **Drag-to-reorder tabs** + **drag-to-detach into a new window**.
- **Per-tab unread indicator**: a badge when a hidden tab receives
  new bytes.
