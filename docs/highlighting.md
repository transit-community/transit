# Terminal syntax highlighting

Transit's terminal pane (Phase 2c+) supports optional **per-device**
keyword highlighting — color matching for interface states, BGP
states, severity keywords, and network identifiers. Inspired by
[`feralpacket/securecrt-keyword-highlighting`][feralpacket]; rendered
client-side via line-buffered ANSI injection so it pauses correctly
on alt-screen apps (`vi`, `less`, `top`).

## Enabling

Highlighting is **off by default**. To enable for a specific device:

1. Right-click the device in the sidebar → **Edit**.
2. Tick the **Syntax highlighting** checkbox.
3. **Save**. Reconnect (or open a new session) to see the change.

A small `syntax highlighting` badge appears in the terminal-pane
header while a session with highlighting enabled is open.

The setting is **per-device** — each connection in the inventory has
its own preference, mirroring SecureCRT's session-config model.
Disabling on one device leaves others untouched.

## Default pattern set

Patterns are defined in `src/lib/terminal/patterns.ts`. Order matters
— earlier patterns win when matches overlap.

| Pattern | Color | Notes |
|---|---|---|
| `CRITICAL`, `EMERGENCY`, `ALERT`, `FATAL` | bright red | severity tier 1 |
| `ERROR`, `ERR`, `FAIL(ED|URE)?` | red | severity tier 2 |
| `WARN(ING)?`, `NOTICE` | yellow | severity tier 3 |
| `ESTABLISHED`, `ACTIVE`, `OPENSENT`, `OPENCONFIRM` | green | BGP up states |
| `IDLE`, `CONNECT`, `INIT`, `2-WAY`, `EXSTART`, `EXCHANGE`, `LOADING` | yellow | transitional states |
| `administratively down` | red | multi-word; pre-empts the bare `down` match |
| `down` / `DOWN` | red | bare interface/link state |
| `up` / `UP` | green | bare interface/link state |
| IPv4 with optional `/prefix` | cyan | e.g. `10.0.0.0/24` |
| MAC (`xx:xx:xx:xx:xx:xx` or `xxxx.xxxx.xxxx`) | magenta | listed before IPv6 to prevent the IPv6 regex from claiming the same span |
| IPv6 (compressed and expanded forms) | cyan | not RFC-strict; pragmatic |
| `vlan <n>` | bright yellow | case-insensitive |

## How it works

The highlighter (`src/lib/terminal/highlighter.ts`) runs **before** bytes
reach `term.write()`. Strategy:

- **Line-buffered.** The PTY chunk stream is split on `\n`. Each
  completed line passes through the regex set; matches are wrapped in
  ANSI SGR escapes. Trailing partial lines flush after a 30 ms idle
  so prompts that lack a final newline still render promptly.
- **Alt-screen bypass.** When the device sends `\x1b[?1049h` (or 1047
  / 47), the highlighter pauses until the matching `…l` exit
  sequence. Cell-level cursor positioning by `vi` / `less` / `top`
  doesn't survive line-based regex injection, so we step out of the
  way.
- **Match resolution.** Matches are sorted by start position, then by
  pattern array order. Greedy non-overlap: the first match for any
  region wins; later overlapping matches are dropped. To prefer a
  more specific pattern, list it earlier (see the MAC-before-IPv6
  ordering).

## Adding a new pattern

1. Append to `DEFAULT_PATTERNS` in `src/lib/terminal/patterns.ts`.
   Place the new entry where ordering makes sense (more-specific
   before less-specific).
2. Add a unit test in `src/lib/terminal/highlighter.test.ts`:
   - one positive match (the pattern fires when expected)
   - one false-positive guard (the pattern does NOT fire on a
     misleading near-match — for example, the bare `down` pattern
     does not fire on `download`)
3. If the new color isn't in `escapes.ts::AnsiColor`, add it there
   with the appropriate SGR code.

## Roadmap

- **Per-vendor packs** (Phase 2c+ follow-up) — Cisco-specific BGP
  state names, Junos `commit complete` / `commit failed`, Arista
  `bgp default ipv4-unicast` etc. The `Device.vendor` field is
  already plumbed through `DeviceMeta`, so the highlighter
  constructor is the natural extension point.
- **User-editable patterns** (Phase 7) — settings UI for adding
  custom regex/color pairs without recompiling.
- **Background highlighting** (Phase 7) — currently we wrap
  foreground color only; a future tier could use background for
  high-severity matches (CRITICAL / FAIL).

[feralpacket]: https://github.com/feralpacket/securecrt-keyword-highlighting
