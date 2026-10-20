# Changelog

All notable changes to Transit Community Edition are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions map 1:1 to git tags (`vX.Y.Z`) and GitHub Releases. When a tag
is pushed, `release.yml` runs `scripts/extract-changelog.mjs X.Y.Z` to
pull the matching `## [X.Y.Z]` section into the release body; a missing
or empty section fails the release. `scripts/bump-version.mjs X.Y.Z`
bumps the version files in lockstep.

## [Unreleased]

## [6.5.9] - 2026-10-19

The first Community Edition release: the proprietary Transit desktop
client at 6.5.9, open-sourced under Apache-2.0, plus everything below.

### Changed
- **October dependency train (post-fork).** Tauri 2.12.4 with its plugins
  on both sides, React 19.3.1, Vite 8.3.4, Vitest 5.0.5, the Radix
  primitives, TanStack Query/Virtual, zod, and the in-range Rust crates;
  `russh-sftp` 3.0 (two new SFTP client tunables, left at the library
  defaults) and `dirs` 7; `sha2` 0.11. Held deliberately: `age` 0.12
  (pulls a pre-release `kem` that does not compile) and
  `react-resizable-panels` v4 (API rewrite, separate migration); both
  carry Dependabot ignores with the reason. The four GitHub Actions are
  re-pinned to their new commit SHAs.

### Fixed
- **Cancelling a transfer waited on in-flight reads.** With russh-sftp 3.0
  pipelining up to sixteen reads, the cancel path's awaited handle close
  could outlast the session's two-second drain and the worker was aborted
  before the transfer reported Cancelled. The cancel path now drops the
  handle (3.0 closes it server-side without waiting); completed transfers
  still await the close status. A transfer is also
  deregistered from the active set before its terminal event is emitted, so
  the quit guard cannot see a transfer the UI has just been told is over.
- **Tab rename lost the draft on a click inside the field.** Radix tabs
  1.2 focuses the tab button on mousedown, so a click to place the caret
  in the inline rename input bubbled up, blurred the input and committed
  the draft early. Mousedown now stays inside the input.

### Security
- Updated **russh** to 0.64.1 (GHSA-4wc5-f2rc-q74m: unbounded allocation
  in the agent-protocol server; GHSA-j7h2-66j4-ghjf: a server accepting a
  publickey signature in an algorithm other than the negotiated one).
  Neither code path ships in this client (Transit never serves the agent
  protocol, and russh's server exists here only in test harnesses), but
  the first public release should not carry a dependency with a known
  advisory. 0.64 also enforces rekey byte/time limits on long sessions and
  fixes the `auth-agent-req@openssh.com` reply handling that agent
  forwarding relies on.
- Updated the SSH transport, **russh**, from 0.62 to 0.63.3: channel-scoped
  event handlers no longer fire for channel ids the client never opened
  (GHSA-47hw-gvq5-r2gm), the hybrid ML-KEM key exchange rejects an all-zero
  X25519 value (GHSA-w3jg-pjxf-73p4), and a server can no longer steer the
  session into a MAC-requiring cipher with no MAC (GHSA-p8qx-h547-fjw9).
- **SSH host certificates are refused.** russh 0.63 adds host-certificate
  support, which replaces the host-key check rather than adding to it.
  The trust model is the pinned host key you approved on first connect and
  there is no certificate-authority store, so certificate algorithms are
  never offered and a certificate presented anyway is refused with a clear
  error — no prompt, no pin. Servers holding a certificate still offer
  their plain host key, so nothing changes for them.
- Updated **pageant** to 0.2.3 (GHSA-g4mp-vgx3-xrvm) and **rustls** to
  0.23.45 (RUSTSEC-2026-0285); refreshed the yanked `der` and `wnaf` crates.
- Pinned the build-time-only npm transitives **ip-address** (10.7.2),
  **undici** (6.29.0) and **brace-expansion** (5.0.12) past their
  advisories via `overrides`. None ships in the Tauri bundle.
- Pinned three further build-time-only npm transitives past advisories
  published after that train: **http-cache-semantics** 4.3.0
  (GHSA-ch52-4w7c-c8xp), **postcss-selector-parser** 7.1.6
  (GHSA-rj75-hqrm-r3gf) and **smol-toml** 1.9.0 (GHSA-r4xh-jqrq-34v2).
  `overrides` entries do not self-heal through Dependabot, so each is a
  deliberate bump.

### Changed
- Updated **Tauri** from 2.11 to 2.12 with its plugins (clipboard, dialog,
  opener) in lockstep on both sides; React 19.3, TanStack Query 5.104,
  Vite 8.3, zod 4.6, Vitest 5. `build.windows.staticVCRuntime` is pinned
  `false` so the Windows binary keeps dynamic CRT linkage (Tauri 2.12
  flipped the default). `happy-dom` is held at 20.12.0 (see
  `.github/dependabot.yml`).

### Added
- **One-line installers.** `install.sh` for macOS and Linux (dmg; deb,
  rpm, or a pacman package built from the deb; AppImage elsewhere) and
  `install.ps1` for Windows. Both resolve the newest GitHub release, verify
  the published SHA-256 before anything runs, print their plan and ask
  first, and never run as root (the package-manager step alone uses sudo;
  Windows installs per-user). A weekly workflow dry-runs them on every OS.
- **First-launch import from the Transit app.** When this edition has no
  inventory yet and the proprietary client's folder holds one, `transit.toml`
  and `known_hosts.toml` are copied across once (never overwritten, never
  removed from the source). Device passwords need no import: both editions
  use the same keychain entries.
- **Linux AppImage**, x86_64 and aarch64, beside the `.deb` and `.rpm` —
  the install path for Arch and other distributions without one of those
  package formats.
- **Contribution process.** `CONTRIBUTING.md` (issue before PR, PR must
  reference the issue, DCO sign-off, the review checklist), issue
  templates for bugs and feature requests with a private-reporting link
  for security bugs, and a PR template that asks for the tests performed.
  README gained *Contributing* and an expanded *License* section.
- **Live model lists.** The chat picker is no longer a hard-coded
  registry: with a key enrolled, the app lists the provider's own
  `/v1/models` (Anthropic's with real display names and context sizes;
  OpenAI's filtered to chat models), caches the result for offline use,
  and refreshes every 24 h or on demand from Settings → AI providers. A
  model released after this build simply appears. *Additional model
  ids* remains as the escape hatch for anything the filter hides.
- **Sign in with ChatGPT (preview).** The OpenAI side can run on a
  ChatGPT Plus/Pro plan instead of an API key, via OpenAI's
  open-source-app sign-in (PKCE in your browser, one-shot loopback
  callback). One method at a time per the radio on the OpenAI card. The
  refresh token lives in the OS keychain, the hourly access token in
  memory, neither ever reaches the UI; plan-specific errors (weekly cap
  reached, re-sign-in needed) are explained in the chat with a shortcut
  to Settings; Sign out revokes the grant at OpenAI before forgetting it
  locally. Threat model T55. Personal Plus/Pro accounts only: workspace
  tenants (Business/Enterprise/Edu) block open-source apps at the consent
  page and cannot allow-list them, so the Settings copy says so and
  points at the API key. Anthropic plans are not supported: Anthropic's
  terms prohibit consumer-plan OAuth in third-party apps.
- **Community Edition.** Forked from the proprietary Transit desktop
  client at 6.5.9. The AI assistant runs on **your own Anthropic or
  OpenAI API key**, sent directly to that provider (Settings → API keys),
  or on **your own hardware** (Ollama / OpenAI-compatible endpoints,
  Settings → Local models). Both are free and need no account.
- **No phone-home.** The binary makes no network connection except to
  the devices, endpoints and providers you configure. Verified on every
  release by `scripts/no-phone-home-scan.sh`.
- **Additional model ids.** Newer provider models can be added by API id
  in Settings → API keys and appear under "Other" in the model picker.

### Removed
- Accounts, sign-in, subscriptions, billing, trials, usage budgets and
  spend limits, in-app notices, and the in-app updater. Updates are
  GitHub Releases.
- The cloud proxy path for AI traffic and every reference to hosted
  infrastructure.

### Changed
- Product identity: **Transit Community Edition**, bundle id
  `app.transit.community`, config directory `TransitCommunity`, keychain
  services `transit-ce-*` — so it installs side by side with any other
  Transit build without sharing state.
- Strict TLS (Settings → Network) now governs the direct provider
  connection and applies to the next AI message, no restart needed.
- License: Apache-2.0.
