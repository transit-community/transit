# Transit Community Edition

A cross-platform GUI SSH client for network engineers with an embedded,
**read-only** AI agent that investigates your gear — on **your own
Anthropic or OpenAI API key**, on **your ChatGPT plan**, or on **models
running on your own hardware**. No account of ours, no subscription of
ours, no telemetry.

Forked from the proprietary Transit desktop client at 6.5.9 and released
under the [Apache License 2.0](LICENSE) (see *License* below). Builds
are published as
[GitHub Releases](https://github.com/transit-community/transit/releases).

## What it does

- **SSH terminal** built on `russh` and xterm.js: tabs, split panes,
  jump hosts (up to four hops), per-device colours, session logging,
  a programmable button bar, broadcast input to many sessions, and
  bulk "launch all" from the inventory.
- **USB-to-serial console** cables, a **local OS shell**, an **SFTP Files**
  pane, a **REST API** surface for controllers (UniFi, Meraki, NetBox, …),
  and a **packet-capture** explorer that the agent can read as a digest.
- **The agent.** A chat panel whose model can list your open sessions,
  read their scrollback (through a redaction filter), propose a command,
  ask you a question, propose a read-only API GET, or query an open
  capture. That is the whole tool surface — exactly six tools.
- **Every proposed command** passes a per-vendor **policy gate** (Junos,
  IOS, IOS-XE, IOS-XR, NX-OS, EOS, PAN-OS, plus your own YAML policies)
  **and** an **approval modal**. Both, always. Nothing runs unattended.

## How the AI runs — and what it never touches

| Path | Where the model runs | What leaves your machine |
|---|---|---|
| **Your API key** (Settings → AI providers) | Anthropic's or OpenAI's API | Redacted prompts + your key, to that provider's own host only, over TLS verified against your OS trust store. No redirects, no ambient proxy. |
| **Your ChatGPT plan** (Settings → AI providers → *Sign in with ChatGPT*, preview) | OpenAI's API, billed to your personal Plus/Pro plan | A one-time browser sign-in at `auth.openai.com`; then redacted prompts + a short-lived token to OpenAI's API. The refresh token stays in your OS keychain and is revoked at OpenAI when you sign out. |
| **Your hardware** (Settings → Local models) | Ollama on this machine, or a self-hosted OpenAI-compatible endpoint (vLLM, LM Studio, llama.cpp, LiteLLM) | Prompts to the endpoint you configured. Nothing else. |

The binary makes no other network connection. There is no update check,
no crash reporter, no usage ping. This is enforced, not promised:
`scripts/no-phone-home-scan.sh` runs on every release binary and fails
the build if any hosted-infrastructure hostname or client symbol is
present. Run it yourself:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml --bin transit_app
./scripts/no-phone-home-scan.sh src-tauri/target/release/transit_app
```

Your provider key (or ChatGPT refresh token) is stored in the OS
keychain (macOS Keychain, Windows Credential Manager, Linux Secret
Service), written through a one-way IPC command, and never returned to
the UI. Device credentials never enter the
inventory file and never reach the agent — the crate that holds the
agent's tools is forbidden by `cargo deny` from depending on the crate
that holds secrets.

## Install

Use the one-line installer, or download the artifact for your platform
from the [latest release](https://github.com/transit-community/transit/releases/latest)
and verify it against `SHA256SUMS.txt`. **Builds are unsigned.**

- **One-line install.** Each script prints its plan and asks before
  installing (`-y` / `-Yes` skips the prompt, `--dry-run` / `-DryRun`
  only downloads and verifies the checksum). macOS and Linux share one
  script; it picks the dmg, deb, rpm, or a pacman package built from the
  deb, and falls back to the AppImage on distributions without one of
  those. Windows installs for the current user with no administrator
  prompt and needs **PowerShell 7** (`winget install Microsoft.PowerShell`);
  the built-in Windows PowerShell 5.1 is not supported.

  ```bash
  curl -fsSL https://raw.githubusercontent.com/transit-community/transit/main/install.sh | sh
  ```

  ```powershell
  irm https://raw.githubusercontent.com/transit-community/transit/main/install.ps1 | iex
  ```

- **macOS** (`.dmg`, Apple Silicon and Intel): after copying the app,
  clear the quarantine bit once: `xattr -d com.apple.quarantine "/Applications/Transit Community Edition.app"`.
- **Windows** (`-setup.exe` or `.msi`): SmartScreen will warn about an
  unrecognised publisher; choose *More info → Run anyway*. The one-line
  installer requires PowerShell 7; the installers themselves do not.
- **Linux**, x86_64 and aarch64 for every format: `.deb` for Ubuntu
  24.04+ / Debian 13+, `.rpm` for Fedora 41+ and EL10 with EPEL, and an
  `.AppImage` for everything else (Arch and derivatives such as Omarchy,
  openSUSE, NixOS with `appimage-run`). Make the AppImage executable and
  run it; it needs FUSE 2 (`fuse2` on Arch), or run it with
  `--appimage-extract-and-run`. RHEL/EL9 has no WebKitGTK 4.1 package and
  is not supported by any format.

## Get an API key

The assistant runs on your own provider account. You pay the provider
directly, per token, and nothing passes through anyone else. Either
provider takes about five minutes to set up; you only need one.

**Anthropic (Claude)**

1. Sign in or create an account at the Claude Developer Platform,
   [platform.claude.com](https://platform.claude.com/) (the old
   `console.anthropic.com` address redirects there).
2. Open **Billing** and add credits. API access is prepaid; a small
   top-up is plenty to start, and a spend limit can be set on the same
   page.
3. Open **API keys**, create a key, name it (for example `transit`), and
   copy it once. It is shown only at creation; if you lose it, create a
   new one and delete the old.
4. In Transit, **Settings → AI providers → Anthropic**, paste the key and
   save. The model list fills in from your account within a few seconds.

**OpenAI (GPT)**

1. Sign in or create an account at the OpenAI developer platform,
   [platform.openai.com](https://platform.openai.com/). This is separate
   from a ChatGPT subscription; a ChatGPT plan does not include API
   access (see *Sign in with ChatGPT* below for the plan route).
2. Open **Settings → Billing** and add a payment method or prepaid
   credits, and set a monthly usage limit while you are there.
3. Open **API keys** and create a new secret key. If offered, make it a
   **restricted** key with access to *Models* (read) and *Responses*
   (write); that is all Transit uses. Copy it once.
4. In Transit, **Settings → AI providers → OpenAI**, choose **API key**,
   paste it and save.

Where the key goes: into your operating system's keychain, through a
one-way command, and from there only into the `Authorization` header of
requests to that provider's own API. It is never written to a file, never
shown again in the UI, and never sent anywhere else. Delete a key from
the provider's dashboard to revoke it at any time.

Prefer no key at all? **Settings → Local models** runs the assistant on
Ollama or any OpenAI-compatible server on your own hardware.

## Moving from the Transit app

The Community Edition keeps its files in its own folder (`TransitCommunity`
beside the old `Transit` one), so both can be installed at once. On its
first launch, when it has no inventory of its own yet, it imports your
devices (`transit.toml`) and your host-key pins (`known_hosts.toml`) from
the Transit app, so nothing needs re-adding or re-trusting. Device
passwords stored in the OS keychain carry over as well: both editions keep
them under the same keychain entry. What does not carry over is anything
tied to the hosted service: the AI runs on your own provider key or local
model, entered under Settings → AI providers or Settings → Local models.
Set `$TRANSIT_INVENTORY` to point at a specific inventory file instead.

## Quick start

1. Open **Settings → AI providers** and save an Anthropic or OpenAI key,
   or pick **Sign in with ChatGPT** on the OpenAI card to use a personal
   Plus/Pro plan (see below) — or open **Settings → Local models**, turn
   it on, and point it at Ollama. The model list is fetched live from the
   provider (and cached for offline use), so a model released after this
   build simply appears; *Additional model ids* remains for anything the
   list hides.
2. Add a device with **+ New device** (host, port, vendor, and an auth
   profile whose secret lives in your keychain, SSH agent, 1Password, or
   an on-disk key). Or **Import** a fleet from SecureCRT, MTPuTTY,
   MobaXterm, `~/.ssh/config`, or CSV.
3. Connect, then ask the chat panel a question. Approve or deny each
   command it proposes.

## Sign in with ChatGPT (preview)

The OpenAI card offers one credential at a time: an API key, or your
ChatGPT plan through OpenAI's **Sign in with ChatGPT** for open-source
apps. Picking the plan opens your browser on `auth.openai.com`; after
consent, OpenAI hands a short-lived token back to a one-shot listener on
`127.0.0.1`, and from then on chats go to OpenAI's API billed to the plan
instead of to a key. What Transit keeps is a refresh token in your OS
keychain (never shown to the UI); the hourly access token lives in memory.
**Sign out** revokes the grant at OpenAI and clears both; if OpenAI does
not confirm the revocation you are told to disconnect Transit under
ChatGPT → Settings → Security and login.

What works and what does not, as of October 2026:

- **Personal Plus or Pro accounts work.** OpenAI documents plan usage in
  apps for Go, Plus and Pro. Set a weekly cap for this app under ChatGPT →
  Settings → Usage → App limits; when it is hit, chats stop with a clear
  message rather than switching to another bill.
- **Workspace accounts do not work** — Business (formerly Team),
  Enterprise and Edu. Their tenant policy decides which third-party apps
  members may sign in to (OpenAI Admin Console → *External access*), and
  that list only holds OpenAI's catalogued partner apps. Open-source apps
  register dynamically at consent time, so they can never be on the list,
  and the consent page shows *"Your organization hasn't enabled access for
  this app"*. Nothing is sent back to Transit in that case; press
  **Cancel** in Settings and use an API key for the workspace.
- **Anthropic plans are not offered.** Anthropic's terms do not allow
  consumer-plan sign-in from third-party apps, so the Anthropic side is
  API-key only.
- **It is a preview.** OpenAI controls eligibility, limits, and the
  request shape; the flow may change or be withdrawn. Everything
  plan-specific sits in one Rust module (`src-tauri/src/chatgpt_auth.rs`)
  and one client branch, so the API-key path is unaffected either way.

## Inventory and credentials

`transit.toml` (in your config directory — `~/Library/Application Support/TransitCommunity/`,
`%APPDATA%\TransitCommunity\`, or `~/.config/TransitCommunity/`) is the
inventory the app rewrites for you; the GUI covers create/edit/delete,
groups, drag-between-groups, bulk edit, import and CSV export. It holds
device metadata and **references** to credentials — never a credential.
The loader rejects inline secret-shaped values with a file:line error.

Credentials live in:
1. **SSH agent** — including the 1Password SSH Agent (auto-detected on macOS).
2. **SSH key file on disk** — OpenSSH, PEM or PuTTY `.ppk`; an optional passphrase is enrolled to the OS keychain.
3. **1Password CLI** (`op read op://…`).
4. **OS keystore** via the `keyring` crate.
5. **Environment / age-encrypted file** for headless installs.

Password-backed profiles fall back to keyboard-interactive automatically
(ESXi, some MFA setups). Host keys are trusted on first use and pinned;
a changed key is a hard warning with an explicit verified replace.

See [`transit.toml.example`](transit.toml.example) for the file shape.

## Bring your own policy

Layer your own command policies over the built-in set: add read-only
commands to a shipped vendor, or define a custom vendor with its own
`<vendor>.yaml` (Settings → Policies). A user policy can **add** allowed
commands but can never punch through a shipped block, and a custom
vendor always gets the per-command modal with no auto-approve shortcut.
Sample policies are under [`policies/samples/`](policies/samples/).

## Build from source

Prerequisites: Rust via `rustup` (the toolchain is pinned in
`rust-toolchain.toml`), **Node 22+**, and the Tauri 2 system
dependencies for your platform. On Linux:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libdbus-1-dev
```

```bash
npm install
npm run tauri dev        # development
npm run tauri build      # unsigned release bundles for this platform
```

## Test and audit

```bash
cargo test --workspace --manifest-path src-tauri/Cargo.toml
npm run test
(cd src-tauri && cargo deny check)      # advisories + license allowlist + agent-firewall bans
npm audit --audit-level=high
npm run license:check
gitleaks detect --source . --no-banner
```

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — the contributor manual: the Three Inviolable
  Rules, the crate map, and the runbooks for adding a vendor policy, a
  secret backend, or (deliberately hard) an agent tool.
- [`docs/security/threat-model.md`](docs/security/threat-model.md) — every
  attack surface and its mitigation.
- [`docs/security/secrets.md`](docs/security/secrets.md) — where secrets
  live and where they do not.
- [`docs/design/`](docs/design/) — the record of how this edition was
  derived from the proprietary client and what was removed.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how changes get in.

## Contributing

Contributions are welcome, and the process is deliberately strict
because most of this app's value is a handful of security invariants
(see *How the AI runs* above and `CLAUDE.md` §3–§4).

1. **Open an issue first**, using the bug-report or feature-request
   template. Agree the approach there before writing code.
2. **Open the pull request** with `Closes #<issue>` in the description.
   A PR without a prior, referenced issue is closed without review.
3. **Fill the PR template honestly**: what you ran, on which OS, against
   which device or lab, and which tests you added.
4. **Pass the checklist** in [`CONTRIBUTING.md`](CONTRIBUTING.md): the
   Rust and frontend gates (CI runs them on Ubuntu, macOS and Windows),
   a test for every behaviour change, the security-path questions for
   anything under `CLAUDE.md` §9, and a `CHANGELOG.md` entry.

Every commit needs a `Signed-off-by:` line (`git commit -s`, the
Developer Certificate of Origin). Security bugs go through
[private vulnerability reporting](SECURITY.md), never a public issue.
Some things are not accepted at all — a seventh agent tool, any bypass of
the policy gate or the approval modal, any outbound connection the user
did not configure; `CONTRIBUTING.md` lists them so nobody wastes a
weekend.

## License

Transit Community Edition is free software under the
**Apache License 2.0**. The full text is in [`LICENSE`](LICENSE) at the
root of this repository, and [`NOTICE`](NOTICE) carries the copyright and
attribution notices that Apache-2.0 §4(d) asks you to preserve. In short:
you may use, modify, and redistribute it, commercially or not, as long as
you keep the license and notices, state your changes, and do not use the
Transit name or logo to suggest endorsement. The license includes an
express patent grant from contributors and no warranty.

Contributions are accepted under the same license (Apache-2.0 §5); there
is no separate contributor agreement. The Rust crates and the npm package
declare `Apache-2.0` in their manifests, and `cargo deny` plus
`npm run license:check` keep third-party dependencies inside the allowlist
documented in [`docs/security/licenses.md`](docs/security/licenses.md).
Bundled fonts (Cascadia Mono, JetBrains Mono) are under the SIL Open Font
License; see `src/assets/fonts/`.
