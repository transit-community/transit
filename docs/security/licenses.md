# License audit

> Refreshed every phase. Last update: 2026-06-16 (connection import: roxmltree + csv).
>
> Transit is closed-source commercial. Every third-party dependency
> must be redistributable under terms compatible with that. The
> `cargo deny` license allowlist + npm `license:check` allowlist
> together gate every PR.

## Allowlist

Both Rust and npm tooling allow only:

| License | Why it's safe for closed-source bundling |
|---|---|
| **MIT** | Permissive. Notice + license text required in distribution. |
| **Apache-2.0** | Permissive. Notice required. Patent grant + retaliation clause. |
| **Apache-2.0 WITH LLVM-exception** | Same as Apache-2.0. |
| **BSD-2-Clause** | Permissive. Notice required. |
| **BSD-3-Clause** | Permissive. Notice required + no-endorsement clause. |
| **ISC** | Permissive. Notice required. |
| **0BSD** | Public-domain-equivalent. No notice required. |
| **Unicode-3.0**, **Unicode-DFS-2016** | Permissive (Unicode data). |
| **CC0-1.0** | Public-domain-equivalent. |
| **Zlib** | Permissive. |
| **MPL-2.0** | Weakly copyleft (file-level). Acceptable so long as we **do not modify** the MPL-licensed source files themselves. We use these as binary deps; modifying them would require releasing the modified files under MPL. **Justification**: see "MPL-2.0 audit" below. |
| **BSL-1.0** | Boost Software License 1.0. Permissive. OSI-approved. FSF-approved. No copyleft, no advertising clause; only obligation is reproducing the license text in source distributions (we ship binaries — installer obligations covered below). Pulled in transitively via `arboard` → `clipboard-win` + `error-code` (Windows clipboard backend for `tauri-plugin-clipboard-manager`). |
| **CDLA-Permissive-2.0** | Community Data License Agreement, Permissive 2.0. Originally drafted by The Linux Foundation for data sets; a handful of code projects use it too. Permissive: no copyleft on derivative works, explicit patent grant, no source-disclosure obligation. Compatible with closed-source commercial bundling. Pulled in transitively via `transit_cloud_client` → `reqwest` → `rustls` → `webpki-roots` (the Mozilla-derived TLS trust-root list rustls uses). |

Any license outside this list fails CI. Adding a license requires:
- Written justification in this file.
- A note on whether the license has copyleft / patent / attribution
  requirements that affect the installer.
- Approval recorded in the PR description.

## Adding a dependency: checklist

1. Run `cargo add <dep>` (Rust) or `npm install <dep>` (npm).
2. Run `cargo deny check licenses` / `npm run license:check`.
3. If it fails: stop. Look up the license, add a written
   justification here if appropriate, then update `deny.toml` /
   `package.json` allowlist in the same PR.
4. If new transitive deps appear, list them in this doc's audit
   table.

## Headline direct dependencies (Rust)

These are the user-facing dep choices; transitive deps are tracked
by `cargo deny` and not enumerated here.

| Crate | License | Purpose |
|---|---|---|
| `tauri` | Apache-2.0 / MIT | Desktop shell. |
| `tauri-build`, `tauri-plugin-log` | Apache-2.0 / MIT | Tauri 2 build + logging plugin. |
| `serde` / `serde_json` | MIT / Apache-2.0 | (de)serialization. |
| `tracing` / `tracing-subscriber` | MIT | Structured logging. |
| `tracing-appender` | MIT | Rolling file sink for the opt-in diagnostic log (Settings → Developers). Same org and release train as `tracing-subscriber`. |
| `secrecy` | MIT / Apache-2.0 | `SecretBox<T>` wrapper. |
| `zeroize` | MIT / Apache-2.0 | Buffer zeroing on drop. |
| `thiserror` | MIT / Apache-2.0 | Derive `Error`. |
| `anyhow` | MIT / Apache-2.0 | Error type for app boundaries. |
| `log` | MIT / Apache-2.0 | (legacy logging interface; required by tauri-plugin-log). |
| `insta` (dev) | Apache-2.0 | Snapshot tests. |
| `trybuild` (dev) | MIT / Apache-2.0 | Compile-fail tests. |
| `tokio-serial` | MIT | Async wrapper over `serialport` for `transit_console` (Phase 7b USB-to-serial transport). Pulls in `serialport` (MPL-2.0, used unmodified — covered by MPL-2.0 audit below) and `mio-serial` (MIT). |
| `portable-pty` | MIT | v4.4.0 local OS terminal (`transit_localpty`): cross-platform PTY spawn (ConPTY on Windows, openpty on Unix). **Pinned to 0.8.x** — 0.9.0's `PSUEDOCONSOLE_INHERIT_CURSOR` flag wedges every Windows shell (see the Cargo.toml pin comment). 0.8.1 pulls the unmaintained `serial` 0.4 family (MIT) as a non-optional transitive; Transit never constructs that serial backend (RUSTSEC-2017-0008 carve-out in `deny.toml`). Other transitives: `filedescriptor`, `shell-words`, `downcast-rs` (MIT / Apache-2.0), `nix` (MIT). |
| `russh-sftp` | Apache-2.0 | v5.0.0 Files pane (`transit_files`): SFTP client over the `sftp` subsystem stream from `transit_ssh::Connection::open_subsystem_stream`. Stream-generic (`AsyncRead + AsyncWrite`), which is what keeps `transit_files` free of any `russh` / `transit_ssh` / `transit_auth` dependency; its **server** half is reused as the in-memory test harness over `tokio::io::duplex`, so the SFTP tests need no SSH server. Transitives new to the tree: `dashmap` (MIT) and `serde_bytes` (MIT OR Apache-2.0) — both allowlisted. `chrono`, `bitflags`, `tokio-util`, `bytes`, `log` were already present (their patch/minor lines move up to satisfy russh-sftp's floors). |
| `dashmap` | MIT | Transitive via `russh-sftp`: the concurrent in-flight-request map keyed by SFTP request id — what makes browsing during a transfer work on one session. Not a direct dependency. |
| `serde_bytes` | MIT OR Apache-2.0 | Transitive via `russh-sftp`: efficient `Vec<u8>` (de)serialization for SFTP `DATA` packets. The SPDX `OR` resolves to MIT under the allowlist. Not a direct dependency. |
| `tokio-util` | MIT | v5.0.0 `transit_files`: `CancellationToken`, one per transfer, so cancelling interrupts a *blocked* chunk read instead of waiting out the 60 s request timeout. Declared with `default-features = false` (the `sync` module is unconditional); already in the tree transitively via `russh-sftp`. |
| `etherparse` | MIT OR Apache-2.0 | v6.0.0 PCaps (`transit_pcap`): zero-copy L2–L4 dissection — Ethernet, 802.1Q stacking, IPv4 options, IPv6 extension-header chains, fragmentation, TCP/UDP/ICMP. Those edge cases are exactly where hand-rolled packet parsers grow CVEs, which is why this one layer is a dependency while the application-layer dissectors above it are ours. New transitive: `arrayvec` (MIT OR Apache-2.0), allowlisted. |
| `arrayvec` | MIT OR Apache-2.0 | Transitive via `etherparse`: fixed-capacity stack arrays for the IPv6 extension-header chain, so dissecting a packet allocates nothing. Not a direct dependency. |
| `flate2` | MIT OR Apache-2.0 | v6.0.0 `transit_pcap`: `.pcap.gz` captures (anything that has been through a bug tracker or an email attachment) are decompressed to a bounded temp file on open, so every downstream path — random-access packet fetch included — sees a plain seekable file. A direct dependency. |

**No packet-capture library is used, and that is deliberate.** The pcap
and pcapng readers in `transit_pcap::reader` are ours (~600 lines for two
frozen, fully-specified formats). Transit links no `libpcap` and — most
importantly — **no Npcap**: Npcap's free license permits five installs and
exempts only Nmap, Wireshark, and Microsoft Defender, so a redistributed
product depending on it would need a paid OEM redistribution licence from
the Nmap Project. Live capture instead drives the capture
binary the OS already ships (`tcpdump`, BSD-licensed, on macOS/Linux;
`pktmon`, in-box, on Windows) as a separate process. Nothing GPL is
linked, bundled, or shipped — no `libwireshark`, `tshark`, or `dumpcap`.
See the PCaps plan §11 for the full IP-hygiene rules.
| `age` | MIT / Apache-2.0 | Phase 8b session export passphrase encryption. scrypt KDF + ChaCha20-Poly1305 envelope, decryptable via `age -d file.age` from the CLI. |
| `tauri-plugin-dialog` | Apache-2.0 / MIT | Native Save dialog for the session-export destination path + native Open dialog for the connection-import file picker. Capability surface restricted to `dialog:allow-save` + `dialog:allow-open` — no open-multiple / ask / message. |
| `fontdb` | MIT | v1.0.2 Settings font picker — OS font-database scan behind `list_monospace_fonts` (family names only, never paths/bytes over IPC). Transitives: `ttf-parser` (MIT/Apache-2.0), `memmap2` (MIT/Apache-2.0), `slotmap` (Zlib), `tinyvec` (Zlib/MIT/Apache-2.0) — all on the allowlist. |
| `roxmltree` | MIT / Apache-2.0 | Read-only XML DOM for parsing SecureCRT's `SCRTConfig.xml` on connection import (`transit_core::import`). Pure-Rust; one transitive (`xmlparser`, MIT/Apache-2.0). |
| `csv` | Unlicense OR MIT | RFC4180 CSV parsing for the connection-import CSV source (`transit_core::import`). The SPDX `OR` resolves to **MIT** under the allowlist — `Unlicense` is **not** separately required. Transitives: `csv-core` (Unlicense/MIT), `itoa`/`ryu` (MIT/Apache-2.0), `bstr` (MIT/Apache-2.0). |
| `rustls`, `rustls-platform-verifier`, `webpki-roots` | Apache-2.0 / ISC / MIT (rustls); MIT / Apache-2.0 (platform-verifier); MPL-2.0 (webpki-roots) | Strict-TLS trust-anchor control for every outbound HTTPS client (threat-model T27). `transit_tls::build_http_client(strict)` hands `reqwest` an explicit rustls `ClientConfig`: `rustls-platform-verifier` (OS trust store — honors a corporate inspection CA) when Strict TLS is off, else `webpki-roots` (Mozilla public roots only). `webpki-roots` (MPL-2.0, used unmodified) is covered by the MPL-2.0 audit below. |
| `rcgen` (dev), `tokio-rustls` (dev) | MIT / Apache-2.0 | TLS handshake test fixture (`transit_tls/tests/tls_trust.rs`): `rcgen` mints a self-signed `localhost` cert and `tokio-rustls` serves it, so the test can assert both trust modes reject an untrusted cert. Test-only; not shipped. |

## Headline direct dependencies (npm)

| Package | License | Purpose |
|---|---|---|
| `react`, `react-dom` | MIT | UI framework. |
| `@tauri-apps/api` | MIT / Apache-2.0 | Frontend Tauri bridge. |
| `@tauri-apps/cli` (dev) | MIT / Apache-2.0 | CLI. |
| `@vitejs/plugin-react` (dev) | MIT | Vite React plugin. |
| `vite` (dev) | MIT | Bundler. |
| `vitest` (dev) | MIT | Test runner. |
| `tailwindcss`, `@tailwindcss/postcss`, `tw-animate-css` (dev) | MIT | Styling (Tailwind v4). `@tailwindcss/postcss` pulls `lightningcss` (MPL-2.0) — dev-only build tool, not shipped, so excluded from the `--production` license gate. |
| `postcss` (dev) | MIT | CSS pipeline (autoprefixer dropped — v4 prefixes via Lightning CSS). |
| `class-variance-authority`, `clsx`, `tailwind-merge` | MIT | shadcn/ui helpers. |
| `lucide-react` | ISC | Icons. |
| `@dnd-kit/core`, `@dnd-kit/utilities` | MIT | Drag-and-drop for the connections sidebar (move a device between groups). Webview-side only — no Tauri capability or IPC surface. |
| `@tanstack/react-virtual` | MIT | Virtualized directory listings in the v5.0.0 Files (SFTP) panes — a 10k-entry server directory is routine and the backend caps a listing at 20 000 entries. Pulls one transitive, `@tanstack/virtual-core` (MIT). Pure client-side layout math; no IPC, capability, or CSP surface. |
| `typescript` (dev) | Apache-2.0 | TS compiler. |
| `eslint`, `@typescript-eslint/*` (dev) | MIT | Lint. |
| `prettier` (dev) | MIT | Format. |
| `husky` (dev) | MIT | Git hooks. |
| `lint-staged` (dev) | MIT | Per-file lint runner. |
| `license-checker-rseidelsohn` (dev) | BSD-3-Clause | License audit. |
| `@types/*` (dev) | MIT | Type definitions. |

## MPL-2.0 audit

MPL-2.0 crates pulled in transitively (as of Phase 0.5):

| Crate | Where it comes in | Modified? |
|---|---|---|
| `cssparser` | tauri-utils → tauri | No |
| `cssparser-macros` | cssparser | No |
| `dtoa-short` | cssparser | No |
| `selectors` | tauri-utils | No |
| `servo_arc` | (transitive) | No |

We use these as binary dependencies; their source is not modified.
Under MPL-2.0, distributing unmodified source as part of a product is
permitted, with the obligation to provide the source on request and
to retain the license notice. Both obligations are met by Tauri's
upstream packaging (which carries license metadata that we propagate
into installer "licenses.txt" bundles in Phase 8c).

If we ever need to modify any of these files, the modified file's
source must be released under MPL-2.0. That's a per-file boundary,
not a project-wide one.

## Carve-outs for transitive unmaintained advisories

These are documented in `deny.toml` `[advisories].ignore` with a
RUSTSEC ID + a one-line justification:

| RUSTSEC ID | Crate | Status |
|---|---|---|
| RUSTSEC-2024-0370 | `proc-macro-error` | unmaintained; transitive via tauri-build / wry |
| RUSTSEC-2024-0411 .. 0420 | gtk3-rs family | Linux WebKitGTK stack; awaiting Tauri to migrate to gtk4-rs |
| RUSTSEC-2025-0075 | `unic-char-range` | unmaintained; transitive via tauri-utils |
| RUSTSEC-2025-0080 | `unic-common` | unmaintained; transitive |
| RUSTSEC-2025-0081 | `unic-char-property` | unmaintained; transitive |
| RUSTSEC-2025-0098 | `unic-ucd-version` | unmaintained; transitive |
| RUSTSEC-2025-0100 | `unic-ucd-ident` | unmaintained; transitive |

Each carve-out comes off the list when the upstream chain ships an
update.

## Installer obligations

Every binary distributed in Phase 8c will bundle a `LICENSES` file
generated from `cargo about generate` + `license-checker-rseidelsohn
--customPath` output. Notice and license texts for every direct +
transitive dep are concatenated. CI will fail the release job if the
generation step misses a dep that appears in the lockfile.

## Bundled fonts (v6.1.0)

Transit ships two monospace faces as `@font-face` webfonts
(`src/assets/fonts/`, declared in `src/index.css`). Unlike the themes
below, these are the upstream **binary files verbatim**, not a
transcription — so the OFL's requirement that the licence accompany the
font is satisfied by shipping each licence text next to its `.woff2`.

**Why bundle at all**, since every OS has monospace fonts: WKWebView
refuses to serve **user-installed** fonts to web content as an
anti-fingerprinting measure (Safari 12+, never announced in release
notes). xterm.js draws through a canvas and inherits that restriction, so
on macOS an app-served webfont is the only way to offer any face Apple
did not ship. Verified by driving the real WKWebView engine, 2026-08-13.

| Family | Files | Licence | Copyright line (verbatim) | Upstream | Licence confirmed |
|---|---|---|---|---|---|
| JetBrains Mono | `JetBrainsMono-{Regular,Bold}.woff2` (90 KB + 92 KB) | SIL OFL 1.1 | "Copyright 2020 The JetBrains Mono Project Authors" | https://github.com/JetBrains/JetBrainsMono (v2.304) | **2026-08-13** — read `OFL.txt` from the upstream release archive |
| Cascadia Mono | `CascadiaMono-{Regular,Bold}.woff2` (141 KB + 143 KB) | SIL OFL 1.1 | "Copyright (c) 2019 - Present, Microsoft Corporation, with Reserved Font Name Cascadia Code." | https://github.com/microsoft/cascadia-code (v2407.24) | **2026-08-13** — read `LICENSE` from the upstream repository |

Licence texts ship as `JetBrainsMono-OFL.txt` and `CascadiaMono-OFL.txt`
in the same directory, and feed the installer's `LICENSES` aggregation
alongside the theme entries below.

**Both are OFL 1.1, which permits bundling in a closed-source commercial
application** provided the licence accompanies the font, the Reserved
Font Names are not used for modified versions, and the font is not sold
by itself. Transit does none of the prohibited things: the files are
shipped unmodified under their own names.

Glyph coverage was measured from each font's own `cmap` rather than
assumed (`document.fonts.check()` reports `true` for text a font cannot
actually draw, so it is not a coverage test):

| Range | JetBrains Mono | Cascadia Mono |
|---|---|---|
| ASCII + Latin-1 | 100% | 100% |
| Box drawing (U+2500–257F) | 128/128 | 128/128 |
| Block elements | 32/32 | 32/32 |
| Braille (U+2800–28FF) | 0/256 | 256/256 |
| Powerline separators (U+E0B0–E0B3) | 4/4 | 0/4 |

Box drawing at 100% is the load-bearing number — network CLIs draw
tables with those constantly, and a gap would surface on the first
`show interface`. The two complement each other on the remaining rows.

**Adding another font:** verify the licence by reading the upstream
licence file (never infer it), record the confirmation date in this
table, ship the licence text alongside the binary, measure `cmap`
coverage for the ranges above, and add the family to `BUNDLED_FONTS` in
`src/lib/fonts.ts`.

## Bundled themes

Thirteen UI themes ship. Four are project-authored (`Transit Default`,
`Transit Classic`, `Royal & Gold`, `Transit Twilight`) and carry this
repository's Apache-2.0 license; the other nine transcribe palettes from
MIT-licensed upstream sources. Each theme file in
`src/lib/themes/themes.ts` records the upstream URL on its `Theme`
object; the listing below is the canonical reference for the
installer's `LICENSES` aggregation.

Theme palettes are transcribed by hand — we copy the hex colors,
not the upstream source files. The MIT license obligation is
satisfied by reproducing the upstream copyright notice + license
text in the `LICENSES` bundle alongside the URL of record.

| Theme id | Name | License | Upstream |
|---|---|---|---|
| `transit-default` | Transit Default | Apache-2.0 | — (own, 2026-07 brand palette) |
| `transit-classic` | Transit Classic | Apache-2.0 | — (own, pre-2026-07 default) |
| `one-dark-pro` | One Dark Pro | MIT | https://github.com/Binaryify/OneDark-Pro |
| `dracula` | Dracula | MIT | https://github.com/dracula/dracula-theme |
| `github-dark` | GitHub Dark | MIT | https://primer.style/foundations/primitives/color |
| `github-light` | GitHub Light | MIT | https://primer.style/foundations/primitives/color |
| `tokyo-night` | Tokyo Night | MIT | https://github.com/enkia/tokyo-night-vscode-theme |
| `catppuccin-mocha` | Catppuccin Mocha | MIT | https://github.com/catppuccin/catppuccin |
| `catppuccin-latte` | Catppuccin Latte | MIT | https://github.com/catppuccin/catppuccin |
| `nord` | Nord | MIT | https://www.nordtheme.com/ |
| `gruvbox-dark` | Gruvbox Dark | MIT | https://github.com/morhetz/gruvbox |
| `royal-gold` | Royal & Gold | Apache-2.0 | — (own, purple + gold) |
| `transit-twilight` | Transit Twilight | Apache-2.0 | — (own, original palette) |
