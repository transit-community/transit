/**
 * Keyword-highlighting pattern sets.
 *
 * The base set
 * (`DEFAULT_PATTERNS`) is vendor-agnostic — each pattern is
 * word-bounded and case-insensitive where it should be. Per-vendor
 * packs layer vendor-specific vocabulary (Cisco syslog mnemonics,
 * Junos commit/alarm phrasing) on top via `patternsForVendor`.
 *
 * Pattern ordering matters: when two patterns overlap on the same
 * span, the one earlier in the array wins. Put the most specific
 * patterns first — vendor packs are prepended so they beat the
 * generic set on overlap.
 */

import type { AnsiColor } from "./escapes";

export interface Pattern {
  /** Stable identifier — used in tests and (future) settings UI. */
  name: string;
  /** Must be sticky-flagged (`y`) or have the global flag — the highlighter walks with `lastIndex`. */
  regex: RegExp;
  color: AnsiColor;
}

/**
 * Match a token only when surrounded by non-word boundaries OR start /
 * end of string. Standard `\b` does the job for most patterns.
 *
 * Severity & state keywords are case-insensitive because device
 * vendors disagree (Junos `Up` vs Cisco `up` vs syslog `UP`).
 */
/** Qualifiers that appear immediately before "error(s)" in interface
 *  counter output across vendors — `5 input errors`, `0 CRC errors`,
 *  `Framing errors: 0`. Deliberately a closed list rather than `\w+`:
 *  a greedy qualifier would swallow the preceding word in prose like
 *  "configuration errors", turning a sentence into a counter. */
const ERROR_QUALIFIER =
  "(?:input|output|inbound|outbound|crc|fcs|frame|framing|giant|runt|abort|overrun|underrun|carrier|symbol|align(?:ment)?|rx|tx)";

/** Interface error counters, in the two shapes vendors actually print:
 *  count-BEFORE (`5 input errors` — Cisco/Arista `show interface`) and
 *  count-AFTER (`Framing errors: 0` — Junos `show interfaces extensive`,
 *  Arista counter tables). */
//
// ⚠️ The unqualified form requires the PLURAL. An optional qualifier plus
// `errors?` looks tidier and is wrong: it reads the day-of-month in a
// syslog line as a count, so `Mar 10 ERROR something failed` matched
// "10 ERROR" as a counter. A syslog severity is singular (`ERROR`); a
// counter is plural (`errors`). That asymmetry is the discriminator, and
// the repo's own false-positive test caught the greedy version.
const ERRORS_PREFIXED = (count: string) =>
  new RegExp(`\\b${count}\\s+(?:${ERROR_QUALIFIER}\\s+errors?|errors)\\b`, "gi");
const ERRORS_SUFFIXED = (count: string) =>
  new RegExp(`\\b(?:${ERROR_QUALIFIER}\\s+errors?|errors):\\s*${count}\\b`, "gi");

export const DEFAULT_PATTERNS: Pattern[] = [
  // ---------------------------------------------------------------------
  // Interface error counters — ZERO-AWARE, and first so they win.
  //
  // User request (2026-09-02) was "highlight errors / input errors /
  // output errors". Taken literally that paints `0 input errors` red on
  // every healthy interface, which teaches the eye to ignore the colour —
  // the opposite of the point. So a non-zero count is red (the thing you
  // are hunting) and a zero count is green (an affirmative all-clear),
  // matching how `state-up` already uses green.
  //
  // These also close a real gap rather than adding a nicety: the plural
  // never matched at all. `severity-error`'s trailing `\b` cannot hold
  // between the `r` and the `s`, so "error" highlighted and "errors" did
  // not — and "errors" is the form every interface counter uses.
  //
  // Why these win the overlap: `highlightLine` keeps matches by EARLIEST
  // START (array order only breaks same-start ties), and these spans
  // include the count, so they begin before a bare "errors" match and
  // claim the region. The suffixed forms can tie with `severity-error` on
  // the same start, which is the other reason they sit above it here.
  // ---------------------------------------------------------------------
  {
    name: "counter-errors-zero",
    regex: ERRORS_PREFIXED("0+"),
    color: "green",
  },
  {
    name: "counter-errors-zero-suffixed",
    regex: ERRORS_SUFFIXED("0+"),
    color: "green",
  },
  {
    name: "counter-errors-nonzero",
    regex: ERRORS_PREFIXED("[1-9]\\d*"),
    color: "red",
  },
  {
    name: "counter-errors-nonzero-suffixed",
    regex: ERRORS_SUFFIXED("[1-9]\\d*"),
    color: "red",
  },
  // ---------------------------------------------------------------------
  // Severity / log level keywords. Pre-empts the bare "up"/"down"
  // patterns so e.g. "FAIL" inside an interface table still wins red.
  // ---------------------------------------------------------------------
  {
    name: "severity-critical",
    regex: /\b(CRITICAL|EMERGENCY|ALERT|FATAL)\b/gi,
    color: "brightRed",
  },
  {
    // `ERRORS?` — the plural was previously unmatchable (see the
    // error-counter block above). A bare mention with no count reaches
    // here: a table header ("Input Errors") or prose ("errors detected").
    name: "severity-error",
    regex: /\b(ERRORS?|ERR|FAIL(?:ED|URE)?)\b/gi,
    color: "red",
  },
  {
    name: "severity-warning",
    regex: /\b(WARN(?:ING)?|NOTICE)\b/gi,
    color: "yellow",
  },
  // ---------------------------------------------------------------------
  // Protocol states — BGP, OSPF, interface/link state.
  // ---------------------------------------------------------------------
  {
    name: "state-up",
    regex: /\b(ESTABLISHED|ACTIVE|OPENSENT|OPENCONFIRM)\b/g,
    color: "green",
  },
  {
    name: "state-transitional",
    regex: /\b(IDLE|CONNECT|INIT|2-WAY|EXSTART|EXCHANGE|LOADING)\b/g,
    color: "yellow",
  },
  {
    name: "state-link-down",
    regex: /\b(administratively\s+down)\b/gi,
    color: "red",
  },
  {
    name: "state-down",
    regex: /\b(down|DOWN)\b/g,
    color: "red",
  },
  {
    name: "state-up-bare",
    regex: /\b(up|UP)\b/g,
    color: "green",
  },
  // ---------------------------------------------------------------------
  // Network identifiers — IP, MAC, VLAN. Cyan/magenta/yellow.
  // ---------------------------------------------------------------------
  {
    // IPv4 with optional /prefix.
    name: "ipv4",
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g,
    color: "cyan",
  },
  {
    // MAC: colon form (xx:xx:xx:xx:xx:xx) and Cisco dot form (xxxx.xxxx.xxxx).
    // MUST come before the IPv6 pattern below — a 6-segment MAC also
    // matches IPv6's "2-7 hex groups" shape, and we want the more
    // specific magenta wrap to win on the same span.
    name: "mac",
    regex: /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b|\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b/g,
    color: "magenta",
  },
  {
    // IPv6 — matches the common shapes (fully expanded, leading-zero
    // compressed, double-colon compressed). Not RFC-strict, but won't
    // false-match on plain text.
    name: "ipv6",
    regex: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|::1\b|\bfe80::[0-9a-fA-F:]+\b/g,
    color: "cyan",
  },
  {
    name: "vlan",
    regex: /\bvlan\s+\d+\b/gi,
    color: "brightYellow",
  },
];

// ---------------------------------------------------------------------
// Per-vendor packs (§17 follow-up). Each pack carries vocabulary the
// generic set can't safely match globally — e.g. bare "connected"
// would be noise on a Linux box but is the load-bearing status word
// in `show interfaces status` on the Cisco family.
// ---------------------------------------------------------------------

/**
 * Cisco-family pack — IOS / IOS-XE / NX-OS / Arista EOS share the
 * `%FACILITY-SEVERITY-MNEMONIC` syslog shape and the interface-status
 * vocabulary (`connected` / `notconnect` / `err-disabled`).
 */
const CISCO_FAMILY_PATTERNS: Pattern[] = [
  {
    // Severities 0-2: emergencies / alerts / critical.
    name: "cisco-syslog-critical",
    regex: /%[A-Z][A-Z0-9_]*-[0-2]-[A-Z0-9_]+/g,
    color: "brightRed",
  },
  {
    // Severities 3-4: errors / warnings.
    name: "cisco-syslog-warning",
    regex: /%[A-Z][A-Z0-9_]*-[3-4]-[A-Z0-9_]+/g,
    color: "yellow",
  },
  {
    // Severities 5-7: notifications / informational / debugging.
    name: "cisco-syslog-info",
    regex: /%[A-Z][A-Z0-9_]*-[5-7]-[A-Z0-9_]+/g,
    color: "cyan",
  },
  {
    // `show interfaces status` Err-disabled state (security violation,
    // BPDU guard, …) — the one status that always deserves attention.
    // Cisco renders `err-disabled`, Arista renders `errdisabled`.
    name: "cisco-err-disabled",
    regex: /\b(err-?disabled)\b/gi,
    color: "brightRed",
  },
  {
    name: "cisco-port-notconnect",
    regex: /\b(notconnect)\b/gi,
    color: "red",
  },
  {
    name: "cisco-port-connected",
    regex: /\b(connected)\b/g,
    color: "green",
  },
];

/**
 * Junos pack. Mixed-case state words (`Establ`, `Idle`) are deliberate
 * — Junos renders BGP states capitalized where the generic set only
 * matches the all-caps forms, and `show bgp summary` truncates
 * Established to `Establ`.
 */
const JUNOS_PATTERNS: Pattern[] = [
  {
    // The §17 canonical example — a successful commit/check.
    name: "junos-commit-complete",
    regex: /\bcommit (complete|check succeeds)\b/g,
    color: "brightGreen",
  },
  {
    name: "junos-bgp-established",
    regex: /\bEstabl(ished)?\b/g,
    color: "green",
  },
  {
    // BGP not-established states in `show bgp summary` — attention,
    // not necessarily failure.
    name: "junos-bgp-down",
    regex: /\b(Idle|Active|Connect|OpenSent|OpenConfirm)\b/g,
    color: "yellow",
  },
  {
    // `show chassis alarms` class column.
    name: "junos-alarm-major",
    regex: /\b(Major|Critical)\b/g,
    color: "brightRed",
  },
  {
    name: "junos-alarm-minor",
    regex: /\bMinor\b/g,
    color: "yellow",
  },
];

/**
 * Vendor tag (`Vendor::as_str` — the same string `DeviceMeta.vendor`
 * carries over IPC) → pack. `cisco_nxos` is the loader's accepted
 * alias for `nxos`; both spellings are mapped so a hand-authored
 * inventory hits the pack either way. Vendors with no pack (pan_os,
 * linux, custom tags) get the generic set only.
 */
const VENDOR_PACKS: Readonly<Record<string, Pattern[]>> = {
  cisco_ios: CISCO_FAMILY_PATTERNS,
  cisco_ios_xe: CISCO_FAMILY_PATTERNS,
  nxos: CISCO_FAMILY_PATTERNS,
  cisco_nxos: CISCO_FAMILY_PATTERNS,
  arista_eos: CISCO_FAMILY_PATTERNS,
  junos: JUNOS_PATTERNS,
};

/**
 * Pattern set for a device's vendor: the vendor pack (when one exists)
 * prepended to the generic set, so vendor-specific wraps win overlaps.
 */
export function patternsForVendor(vendor: string | null | undefined): Pattern[] {
  const pack = vendor ? VENDOR_PACKS[vendor] : undefined;
  return pack ? [...pack, ...DEFAULT_PATTERNS] : DEFAULT_PATTERNS;
}
